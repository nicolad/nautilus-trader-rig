//! MCP (Model Context Protocol) Server for Nautilus Trader Rig
//! 
//! This module implements an MCP server using rmcp with DeepSeek and FastEmbed integration
//! for trading system analysis and vector similarity search.

use std::sync::Arc;
use std::future::Future;
use std::path::Path;
use tokio::fs as async_fs;
use rmcp::ServiceExt;
use crate::config::Config;
use crate::logging::{log_file_processing, log_directory_op, log_mcp_op};

use rig::{
    client::{CompletionClient, ProviderClient},
    completion::Prompt,
    providers::deepseek,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde_json::json;
use tokio::sync::Mutex;
use chrono;

use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};

use crate::vector_store::VectorStoreManager;
use crate::deepseek::DeepSeekClient;
use anyhow::Result;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SimilaritySearchRequest {
    pub query: String,
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CodeAnalysisRequest {
    pub code: String,
    pub language: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BugConfirmationRequest {
    pub bug_description: String,
    pub code_sample: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AdapterAnalysisRequest {
    pub adapter_name: String,
    pub adapter_path: Option<String>,
    pub analysis_type: String, // "security", "performance", "compatibility"
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BugStoreRequest {
    pub bug_id: String,
    pub severity: String,
    pub description: String,
    pub adapter_name: Option<String>,
    pub code_sample: Option<String>,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FileReadRequest {
    pub file_path: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FileWriteRequest {
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DirectoryListRequest {
    pub directory_path: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AdapterFileRequest {
    pub adapter_name: String,
}

#[derive(Clone)]
pub struct NautilusMcpServer {
    pub vector_store: Arc<Mutex<Option<VectorStoreManager>>>,
    pub deepseek_client: Arc<Mutex<Option<DeepSeekClient>>>,
    tool_router: ToolRouter<NautilusMcpServer>,
}

impl Default for NautilusMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl NautilusMcpServer {
    pub fn new() -> Self {
        Self {
            vector_store: Arc::new(Mutex::new(None)),
            deepseek_client: Arc::new(Mutex::new(None)),
            tool_router: Self::tool_router(),
        }
    }

    pub async fn initialize_services(&self) -> Result<()> {
        // Initialize vector store with FastEmbed
        if let Ok(vector_store) = VectorStoreManager::new().await {
            let mut vs = self.vector_store.lock().await;
            *vs = Some(vector_store);
            tracing::info!("✅ Vector store initialized with FastEmbed");
        } else {
            tracing::warn!("⚠️ Failed to initialize vector store");
        }

        // Initialize DeepSeek client
        if let Ok(deepseek_client) = DeepSeekClient::from_env() {
            let mut ds = self.deepseek_client.lock().await;
            *ds = Some(deepseek_client);
            tracing::info!("✅ DeepSeek client initialized");
        } else {
            tracing::warn!("⚠️ Failed to initialize DeepSeek client (DEEPSEEK_API_KEY required)");
        }

        Ok(())
    }

    fn _create_resource_text(&self, uri: &str, name: &str) -> Resource {
        RawResource::new(uri, name.to_string()).no_annotation()
    }

    #[tool(description = "Search for similar bug patterns using FastEmbed vector embeddings")]
    async fn similarity_search(
        &self,
        Parameters(SimilaritySearchRequest { query, limit }): Parameters<SimilaritySearchRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let search_limit = limit.unwrap_or(5);
        
        let vector_store = self.vector_store.lock().await;
        if let Some(vs) = vector_store.as_ref() {
            match vs.similarity_search(&query, search_limit).await {
                Ok(results) => {
                    let response = if results.is_empty() {
                        format!("No similar bug patterns found for query: '{}'", query)
                    } else {
                        format!("Found {} similar bug patterns for query '{}':\n{}", 
                            results.len(), 
                            query,
                            serde_json::to_string_pretty(&results).unwrap_or_default()
                        )
                    };
                    
                    Ok(CallToolResult::success(vec![Content::text(response)]))
                }
                Err(e) => {
                    Ok(CallToolResult::success(vec![Content::text(
                        format!("Error performing vector similarity search: {}", e)
                    )]))
                }
            }
        } else {
            Ok(CallToolResult::success(vec![Content::text(
                "Vector store not available".to_string()
            )]))
        }
    }

    #[tool(description = "Analyze code for security vulnerabilities and issues using DeepSeek AI")]
    async fn analyze_code(
        &self,
        Parameters(CodeAnalysisRequest { code, language }): Parameters<CodeAnalysisRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let deepseek_client = self.deepseek_client.lock().await;
        if let Some(client) = deepseek_client.as_ref() {
            let lang = language.unwrap_or_else(|| "unknown".to_string());
            let prompt = format!(
                "Analyze this {} code for security vulnerabilities, performance issues, and potential bugs:\n\n```{}\n{}\n```\n\nProvide a detailed analysis including:\n1. Security vulnerabilities\n2. Performance issues\n3. Code quality problems\n4. Recommended fixes",
                lang, lang, code
            );
            
            match client.analyze_code(&prompt).await {
                Ok(analysis) => {
                    Ok(CallToolResult::success(vec![Content::text(
                        format!("🔍 DeepSeek Code Analysis:\n\n{}", analysis)
                    )]))
                }
                Err(e) => {
                    Ok(CallToolResult::success(vec![Content::text(
                        format!("❌ Code analysis failed: {}", e)
                    )]))
                }
            }
        } else {
            Ok(CallToolResult::success(vec![Content::text(
                "⚠️ DeepSeek client not available (API key not set)".to_string()
            )]))
        }
    }

    #[tool(description = "Confirm if a bug is critical using DeepSeek AI analysis")]
    async fn confirm_critical_bug(
        &self,
        Parameters(BugConfirmationRequest { bug_description, code_sample }): Parameters<BugConfirmationRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let deepseek_client = self.deepseek_client.lock().await;
        if let Some(client) = deepseek_client.as_ref() {
            match client.confirm_critical_bug(&bug_description, &code_sample).await {
                Ok(analysis) => {
                    Ok(CallToolResult::success(vec![Content::text(
                        format!("🤖 DeepSeek Critical Bug Analysis:\n\n{}", analysis)
                    )]))
                }
                Err(e) => {
                    Ok(CallToolResult::success(vec![Content::text(
                        format!("❌ Bug confirmation failed: {}", e)
                    )]))
                }
            }
        } else {
            Ok(CallToolResult::success(vec![Content::text(
                "⚠️ DeepSeek client not available (API key not set)".to_string()
            )]))
        }
    }

    #[tool(description = "Get server status and available capabilities")]
    async fn get_status(&self) -> Result<CallToolResult, ErrorData> {
        let vector_store_status = {
            let vs = self.vector_store.lock().await;
            if vs.is_some() { "✅ Available (FastEmbed)" } else { "❌ Not available" }
        };
        
        let deepseek_status = {
            let ds = self.deepseek_client.lock().await;
            if ds.is_some() { "✅ Available" } else { "❌ Not available" }
        };
        
        let status = format!(
            "🔧 Nautilus Trader Rig MCP Server Status:\n\
             📊 Vector Store: {}\n\
             🤖 DeepSeek Client: {}\n\
             🛠️ Available Tools:\n\
             - similarity_search: Search bug patterns with FastEmbed\n\
             - analyze_code: Analyze code with DeepSeek AI\n\
             - confirm_critical_bug: Validate critical bugs\n\
             - get_status: Get server status\n\
             - read_file: Read file contents\n\
             - write_file: Write content to file\n\
             - list_directory: List directory contents\n\
             - read_adapter: Read adapter source files\n\
             - store_bug: Store bug analysis to JSON file",
            vector_store_status, deepseek_status
        );
        
        Ok(CallToolResult::success(vec![Content::text(status)]))
    }

    #[tool(description = "Read contents of a file")]
    async fn read_file(
        &self,
        Parameters(FileReadRequest { file_path }): Parameters<FileReadRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        // Security check: only allow access to certain directories
        let allowed_paths = [
            "nautilus_trader/adapters/",
            "nautilus-trader-rig/",
            "examples/",
            "crates/adapters/",
        ];
        
        let is_allowed = allowed_paths.iter().any(|allowed| file_path.starts_with(allowed));
        
        if !is_allowed {
            return Ok(CallToolResult::success(vec![Content::text(
                format!("❌ Access denied: File path '{}' is not in allowed directories", file_path)
            )]));
        }

        match async_fs::read_to_string(&file_path).await {
            Ok(content) => {
                Ok(CallToolResult::success(vec![Content::text(
                    format!("📄 File: {}\n\n```\n{}\n```", file_path, content)
                )]))
            }
            Err(e) => {
                Ok(CallToolResult::success(vec![Content::text(
                    format!("❌ Failed to read file '{}': {}", file_path, e)
                )]))
            }
        }
    }

    #[tool(description = "Write content to a file")]
    async fn write_file(
        &self,
        Parameters(FileWriteRequest { file_path, content }): Parameters<FileWriteRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        // Security check: only allow writing to bugs directory and certain areas
        let allowed_write_paths = [
            Config::BUGS_DIRECTORY,
            "nautilus-trader-rig/logs/",
        ];
        
        let is_allowed = allowed_write_paths.iter().any(|allowed| file_path.starts_with(allowed));
        
        if !is_allowed {
            return Ok(CallToolResult::success(vec![Content::text(
                format!("❌ Write access denied: File path '{}' is not in allowed write directories", file_path)
            )]));
        }

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&file_path).parent() {
            if let Err(e) = async_fs::create_dir_all(parent).await {
                return Ok(CallToolResult::success(vec![Content::text(
                    format!("❌ Failed to create directory '{}': {}", parent.display(), e)
                )]));
            }
        }

        match async_fs::write(&file_path, &content).await {
            Ok(_) => {
                Ok(CallToolResult::success(vec![Content::text(
                    format!("✅ Successfully wrote to file: {}", file_path)
                )]))
            }
            Err(e) => {
                Ok(CallToolResult::success(vec![Content::text(
                    format!("❌ Failed to write file '{}': {}", file_path, e)
                )]))
            }
        }
    }

    #[tool(description = "List contents of a directory")]
    async fn list_directory(
        &self,
        Parameters(DirectoryListRequest { directory_path }): Parameters<DirectoryListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        // Security check: only allow access to certain directories
        let allowed_paths = [
            "nautilus_trader/adapters/",
            "nautilus-trader-rig/",
            "examples/",
            "crates/adapters/",
        ];
        
        let is_allowed = allowed_paths.iter().any(|allowed| directory_path.starts_with(allowed));
        
        if !is_allowed {
            return Ok(CallToolResult::success(vec![Content::text(
                format!("❌ Access denied: Directory path '{}' is not in allowed directories", directory_path)
            )]));
        }

        match async_fs::read_dir(&directory_path).await {
            Ok(mut entries) => {
                let mut files = Vec::new();
                let mut dirs = Vec::new();
                
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    
                    if path.is_dir() {
                        dirs.push(format!("📁 {}/", name));
                    } else {
                        files.push(format!("📄 {}", name));
                    }
                }
                
                dirs.sort();
                files.sort();
                
                let mut contents = dirs;
                contents.extend(files);
                
                let result = if contents.is_empty() {
                    format!("📂 Directory '{}' is empty", directory_path)
                } else {
                    format!("📂 Directory '{}' contents:\n{}", directory_path, contents.join("\n"))
                };
                
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => {
                Ok(CallToolResult::success(vec![Content::text(
                    format!("❌ Failed to list directory '{}': {}", directory_path, e)
                )]))
            }
        }
    }

    #[tool(description = "Read Rust adapter source files from Nautilus Trader")]
    async fn read_adapter(
        &self,
        Parameters(AdapterFileRequest { adapter_name }): Parameters<AdapterFileRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        log_mcp_op!(info, "read_adapter", format!("Processing request for adapter: {}", adapter_name));
        
        // Try multiple Rust adapter directories
        let rust_directories = Config::all_rust_adapter_directories();
        let mut found_files = Vec::new();
        let mut processed_files = Vec::new();
        
        for rust_dir in rust_directories {
            let adapter_path = rust_dir.join(&adapter_name.to_lowercase());
            log_directory_op!(debug, "Checking adapter directory", adapter_path);
            
            if adapter_path.exists() {
                log_directory_op!(info, "Found adapter directory", adapter_path);
                match async_fs::read_dir(&adapter_path).await {
                    Ok(mut entries) => {
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            let path = entry.path();
                            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                            log_file_processing!(debug, "Examining file", file_name);
                            
                            if let Some(ext) = path.extension() {
                                // Use configured Rust extensions
                                let ext_str = ext.to_string_lossy();
                                if Config::rust_extensions().iter().any(|&allowed_ext| {
                                    ext_str == allowed_ext.trim_start_matches('.')
                                }) {
                                    tracing::info!("📄 Processing Rust file: {:?}", path);
                                    processed_files.push(path.display().to_string());
                                    
                                    if let Ok(content) = async_fs::read_to_string(&path).await {
                                        tracing::debug!("✅ Successfully read file: {} ({} bytes)", file_name, content.len());
                                        found_files.push(format!(
                                            "📄 File: {}\n```rust\n{}\n```\n",
                                            path.display(),
                                            content
                                        ));
                                    } else {
                                        tracing::warn!("❌ Failed to read file content: {}", file_name);
                                    }
                                } else {
                                    tracing::debug!("⏭️ Skipping non-Rust file: {}", file_name);
                                }
                            } else {
                                tracing::debug!("⏭️ Skipping file without extension: {}", file_name);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("❌ Failed to read directory {:?}: {}", adapter_path, e);
                        continue; // Try next directory
                    }
                }
            } else {
                tracing::debug!("❌ Adapter directory not found: {:?}", adapter_path);
            }
        }
        
        tracing::info!("📊 Summary: Found {} Rust files for adapter '{}'", found_files.len(), adapter_name);
        for file in &processed_files {
            tracing::info!("   📄 {}", file);
        }
        
        if !found_files.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                format!("🦀 Rust Adapter '{}' source files:\n\n{}", adapter_name, found_files.join("\n"))
            )]));
        }
        
        Ok(CallToolResult::success(vec![Content::text(
            format!("❌ No Rust adapter files found for '{}'", adapter_name)
        )]))
    }

    #[tool(description = "Store bug analysis as JSON file in bugs directory")]
    async fn store_bug(
        &self,
        Parameters(BugStoreRequest { 
            bug_id, 
            severity, 
            description, 
            adapter_name, 
            code_sample, 
            fix_suggestion 
        }): Parameters<BugStoreRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let adapter_suffix = adapter_name.as_ref().map(|s| format!("_{}", s)).unwrap_or_default();
        let filename = format!("{}/{}{}_{}.json", Config::BUGS_DIRECTORY, bug_id, adapter_suffix, timestamp);
        
        let bug_data = serde_json::json!({
            "bug_id": bug_id,
            "severity": severity,
            "description": description,
            "adapter_name": adapter_name,
            "code_sample": code_sample,
            "fix_suggestion": fix_suggestion,
            "timestamp": timestamp,
            "analysis_context": "Automated detection via RMCP"
        });
        
        match async_fs::write(&filename, serde_json::to_string_pretty(&bug_data).unwrap()).await {
            Ok(_) => {
                Ok(CallToolResult::success(vec![Content::text(
                    format!("✅ Bug stored successfully: {}", filename)
                )]))
            }
            Err(e) => {
                Ok(CallToolResult::success(vec![Content::text(
                    format!("❌ Failed to store bug: {}", e)
                )]))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for NautilusMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_resources()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("This server provides AI-powered trading system analysis tools using DeepSeek and FastEmbed. Available tools: similarity_search for finding similar bug patterns, analyze_code for security analysis, confirm_critical_bug for bug validation, and get_status for server information.".to_string()),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult {
            resources: vec![
                self._create_resource_text("nautilus://vector_store", "Bug Pattern Vector Store"),
                self._create_resource_text("nautilus://deepseek_client", "DeepSeek AI Client"),
                self._create_resource_text("nautilus://analysis_results", "Analysis Results"),
            ],
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        ReadResourceRequestParam { uri }: ReadResourceRequestParam,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        match uri.as_str() {
            "nautilus://vector_store" => {
                let vs = self.vector_store.lock().await;
                let content = if vs.is_some() {
                    "Vector Store Status: Active\nType: FastEmbed with SQLite\nCapabilities: Local embeddings, similarity search, bug pattern storage"
                } else {
                    "Vector Store Status: Inactive"
                };
                Ok(ReadResourceResult {
                    contents: vec![ResourceContents::text(content, uri)],
                })
            }
            "nautilus://deepseek_client" => {
                let ds = self.deepseek_client.lock().await;
                let content = if ds.is_some() {
                    "DeepSeek Client Status: Active\nCapabilities: Code analysis, bug confirmation, critical vulnerability assessment"
                } else {
                    "DeepSeek Client Status: Inactive (API key required)"
                };
                Ok(ReadResourceResult {
                    contents: vec![ResourceContents::text(content, uri)],
                })
            }
            "nautilus://analysis_results" => {
                let content = "Analysis Results Repository\n\nThis resource provides access to stored analysis results and bug patterns from the Nautilus Trader Rig system.";
                Ok(ReadResourceResult {
                    contents: vec![ResourceContents::text(content, uri)],
                })
            }
            _ => Err(ErrorData::resource_not_found(
                "resource_not_found",
                Some(json!({
                    "uri": uri
                })),
            )),
        }
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult {
            next_cursor: None,
            resource_templates: Vec::new(),
        })
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        if let Some(http_request_part) = context.extensions.get::<axum::http::request::Parts>() {
            let initialize_headers = &http_request_part.headers;
            let initialize_uri = &http_request_part.uri;
            tracing::info!(?initialize_headers, %initialize_uri, "initialize from http server");
        }
        
        // Initialize services asynchronously
        tokio::spawn({
            let server = self.clone();
            async move {
                if let Err(e) = server.initialize_services().await {
                    tracing::error!("Failed to initialize services: {}", e);
                }
            }
        });
        
        Ok(self.get_info())
    }
}

pub async fn run_mcp_server() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    tracing::info!("🚀 Starting Nautilus Trader Rig MCP Server...");

    let service = TowerToHyperService::new(StreamableHttpService::new(
        || Ok(NautilusMcpServer::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    ));
    let listener = tokio::net::TcpListener::bind("localhost:8080").await?;
    
    tracing::info!("🌐 MCP Server listening on http://localhost:8080");

    tokio::spawn({
        let service = service.clone();
        async move {
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        println!("Received Ctrl+C, shutting down MCP server");
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, addr)) => {
                                tracing::debug!("New connection from: {}", addr);
                                let io = TokioIo::new(stream);
                                let service = service.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = Builder::new(TokioExecutor::default())
                                        .serve_connection(io, service)
                                        .await
                                    {
                                        tracing::error!("Connection error: {e:?}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("Accept error: {e:?}");
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

pub async fn test_mcp_client() -> anyhow::Result<()> {
    let transport =
        rmcp::transport::StreamableHttpClientTransport::from_uri("http://localhost:8080");

    let client_info = ClientInfo {
        protocol_version: Default::default(),
        capabilities: ClientCapabilities::default(),
        client_info: Implementation {
            name: "nautilus-trader-rig".to_string(),
            version: "0.1.0".to_string(),
        },
    };

    let client = client_info.serve(transport).await.inspect_err(|e| {
        tracing::error!("client error: {:?}", e);
    })?;

    // Initialize
    let server_info = client.peer_info();
    tracing::info!("Connected to MCP server: {server_info:#?}");

    // List tools
    let tools: Vec<Tool> = client.list_tools(Default::default()).await?.tools;
    tracing::info!("Available tools: {:?}", tools.iter().map(|t| &t.name).collect::<Vec<_>>());

    // Test with DeepSeek if available
    let deepseek_client = deepseek::Client::from_env();
    let agent = deepseek_client
        .agent(deepseek::DEEPSEEK_CHAT)
        .preamble("You are a helpful assistant with access to Nautilus Trader Rig MCP tools for trading system analysis.")
        .build();

    let res = agent.prompt("Search for authentication vulnerabilities and analyze them").await?;

    println!("DeepSeek response: {res}");

    Ok(())
}
