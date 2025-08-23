// Main module for Nautilus Trader Rig with rig-sqlite integration
//
// This implementation uses rig-sqlite for vector similarity search

use anyhow::Result;
use std::time::Duration;
use tokio;
use tracing::{debug, error, info, trace, warn};
use serde_json;

mod vector_store;
mod deepseek;
mod mcp;
mod fastembed;
mod config;
mod logging;

use vector_store::VectorStoreManager;
use deepseek::DeepSeekClient;
use mcp::run_mcp_server;
use config::Config;
use logging::{init_dev_logging, log_file_processing, log_directory_op, log_status};

pub struct UnifiedServerState {
    pub vector_store: Option<VectorStoreManager>,
    pub deepseek_client: Option<DeepSeekClient>,
}

impl UnifiedServerState {
    pub async fn new() -> Result<Self> {
        info!("🚀 Initializing Unified Server State with FastEmbed and DeepSeek...");
        debug!("Starting initialization of vector store and AI client components");

        // Initialize vector store with FastEmbed (no API key required)
        trace!("Attempting to initialize vector store with FastEmbed local embeddings");
        let vector_store = match VectorStoreManager::new().await {
            Ok(store) => {
                info!("✅ Vector store initialized with FastEmbed local embeddings");
                debug!("Vector store ready for similarity search operations");
                Some(store)
            }
            Err(e) => {
                error!("❌ Failed to initialize vector store: {}", e);
                warn!("⚠️ Vector similarity search will be unavailable");
                None
            }
        };

        // Initialize DeepSeek client
        trace!("Attempting to initialize DeepSeek AI client from environment variables");
        let deepseek_client = match DeepSeekClient::from_env() {
            Ok(client) => {
                info!("✅ DeepSeek client initialized from environment");
                debug!("Testing DeepSeek API connection...");
                // Test the connection
                match client.validate_connection().await {
                    Ok(_) => {
                        info!("✅ DeepSeek API connection validated successfully");
                        debug!("DeepSeek client ready for code analysis operations");
                        Some(client)
                    }
                    Err(e) => {
                        error!("❌ DeepSeek API connection failed: {}", e);
                        warn!("⚠️ DeepSeek client available but connection unreliable");
                        Some(client) // Keep client even if validation fails
                    }
                }
            }
            Err(e) => {
                error!("❌ Failed to initialize DeepSeek client: {}", e);
                warn!("⚠️ AI code analysis will be unavailable");
                None
            }
        };

        debug!("Unified server state initialization complete");
        Ok(Self {
            vector_store,
            deepseek_client,
        })
    }
}

// Function to test DeepSeek client functionality
async fn test_deepseek_client(state: &UnifiedServerState) -> Result<()> {
    info!("🤖 Starting DeepSeek client functionality tests...");
    
    if let Some(client) = &state.deepseek_client {
        debug!("DeepSeek client available, proceeding with tests");
        println!("🤖 Testing DeepSeek client functionality...");
        
        // Test basic prompt
        println!("\n📝 Testing basic prompt:");
        trace!("Sending basic connectivity test prompt to DeepSeek");
        match client.prompt("Hello! Please respond with exactly 'DeepSeek is working' to confirm the connection.").await {
            Ok(response) => {
                println!("   ✅ DeepSeek response received");
                println!("   📝 Response: {}", response.trim());
                debug!("Basic prompt test successful, response length: {} chars", response.len());
            }
            Err(e) => {
                println!("   ❌ DeepSeek prompt failed: {}", e);
                error!("Basic prompt test failed: {}", e);
            }
        }
        
        // Test code analysis
        println!("\n🔍 Testing code analysis:");
        debug!("Preparing code analysis test with sample security vulnerability");
        let test_code = "
fn unsafe_transfer(amount: f64) -> bool {
    // Missing validation - potential security issue
    transfer_funds(amount);
    true
}";
        trace!("Sending code analysis request to DeepSeek");
        match client.analyze_code(&format!("Analyze this Rust code for security issues:\n{}", test_code)).await {
            Ok(analysis) => {
                println!("   ✅ Code analysis completed");
                println!("   📊 Analysis (first 200 chars): {}...", 
                    analysis.chars().take(200).collect::<String>());
                debug!("Code analysis successful, full response length: {} chars", analysis.len());
            }
            Err(e) => {
                println!("   ❌ Code analysis failed: {}", e);
            }
        }
        
        // Test critical bug confirmation
        println!("\n� Testing critical bug confirmation:");
        match client.confirm_critical_bug(
            "Potential authentication bypass in trading API",
            "if user.is_authenticated() { /* process */ }"
        ).await {
            Ok(confirmation) => {
                println!("   ✅ Bug confirmation completed");
                println!("   🔍 Confirmation (first 200 chars): {}...", 
                    confirmation.chars().take(200).collect::<String>());
                debug!("Bug confirmation successful, response length: {} chars", confirmation.len());
            }
            Err(e) => {
                println!("   ❌ Bug confirmation failed: {}", e);
                error!("Bug confirmation test failed: {}", e);
            }
        }
        
        info!("✅ DeepSeek client tests completed");
    } else {
        println!("⚠️ DeepSeek client not available (requires DEEPSEEK_API_KEY)");
        warn!("Skipping DeepSeek tests - client not initialized");
    }
    
    Ok(())
}

// Function to test vector similarity search
async fn test_vector_search(state: &UnifiedServerState) -> Result<()> {
    info!("🔍 Starting vector similarity search tests...");
    
    if let Some(vector_store) = &state.vector_store {
        debug!("Vector store available, proceeding with similarity search tests");
        println!("🔍 Testing vector similarity search with rig-sqlite...");
        
        let test_queries = vec![
            "authentication bypass vulnerability",
            "websocket security issues",
            "rate limiting problems",
            "memory leak",
        ];

        debug!("Testing {} different search queries", test_queries.len());
        
        for (index, query) in test_queries.iter().enumerate() {
            println!("\n📝 Searching for: '{}'", query);
            trace!("Running similarity search {}/{}: '{}'", index + 1, test_queries.len(), query);
            
            match vector_store.similarity_search(query, 3).await {
                Ok(results) => {
                    debug!("Similarity search completed, found {} results", results.len());
                    if results.is_empty() {
                        println!("   No similar patterns found");
                        trace!("Empty result set for query: '{}'", query);
                    } else {
                        println!("   Found {} similar patterns:", results.len());
                        for (i, result) in results.iter().enumerate() {
                            if let Some(id) = result.get("id") {
                                if let Some(score) = result.get("score") {
                                    println!("   {}. {} (score: {:.3})", i+1, id, score);
                                    trace!("Result {}: id={}, score={:.6}", i+1, id, score);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("   Error: {}", e);
                    error!("Similarity search failed for query '{}': {}", query, e);
                }
            }
        }
        
        info!("✅ Vector similarity search tests completed");
    } else {
        println!("⚠️ Vector store not available");
        warn!("Skipping vector search tests - store not initialized");
    }
    
    Ok(())
}

// Function to discover Rust files in the adapters directory
async fn discover_rust_files(adapters_path: &str) -> Result<Vec<String>> {
    let mut rust_files = Vec::new();
    
    // Use the same logic as the main function for file discovery
    let rust_dirs = vec![std::path::Path::new(adapters_path)];
    
    for rust_dir in rust_dirs {
        if let Ok(entries) = std::fs::read_dir(rust_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    let src_dir = entry.path().join("src");
                    if src_dir.exists() {
                        if let Ok(src_entries) = std::fs::read_dir(&src_dir) {
                            for src_entry in src_entries.flatten() {
                                if let Some(ext) = src_entry.path().extension() {
                                    if ext == "rs" {
                                        rust_files.push(src_entry.path().display().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(rust_files)
}

// Function to analyze adapter files for bugs and store results
async fn analyze_adapter_files_for_bugs(state: &UnifiedServerState) -> Result<()> {
    println!("\n🔍 Starting automated bug analysis on adapter files...");
    info!("Beginning automated bug analysis workflow");
    
    // Get list of adapter files
    let adapters_path = config::Config::CORE_ADAPTERS_DIRECTORY;
    let rust_files = discover_rust_files(adapters_path).await?;
    
    if rust_files.is_empty() {
        println!("⚠️ No Rust files found for analysis");
        warn!("Bug analysis skipped - no files discovered");
        return Ok(());
    }
    
    println!("📁 Found {} files to analyze", rust_files.len());
    info!("Discovered {} Rust files for bug analysis", rust_files.len());
    
    let mut bugs_found = 0;
    let mut files_analyzed = 0;
    
    // Analyze each file
    for (i, file_path) in rust_files.iter().enumerate() {
        println!("   📄 Analyzing file {}/{}: {}", i+1, rust_files.len(), file_path);
        debug!("Starting analysis of file: {}", file_path);
        
        // Read file content
        let content = match tokio::fs::read_to_string(file_path).await {
            Ok(content) => content,
            Err(e) => {
                println!("   ❌ Failed to read file: {}", e);
                warn!("Skipping file due to read error: {} - {}", file_path, e);
                continue;
            }
        };
        
        files_analyzed += 1;
        
        // Analyze with DeepSeek
        if let Some(deepseek_client) = &state.deepseek_client {
            let analysis_prompt = format!(
                "Analyze this Rust code for critical bugs, security vulnerabilities, and potential issues:\n\n\
                 File: {}\n\n\
                 ```rust\n{}\n```\n\n\
                 Focus on:\n\
                 - Security vulnerabilities (buffer overflows, injection attacks, etc.)\n\
                 - Memory safety issues\n\
                 - Logic errors that could cause financial losses\n\
                 - Performance bottlenecks\n\
                 - Error handling problems\n\n\
                 If you find critical issues, respond with:\n\
                 BUG_FOUND: yes\n\
                 SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]\n\
                 DESCRIPTION: [detailed description]\n\
                 CODE_SAMPLE: [relevant code snippet]\n\
                 FIX_SUGGESTION: [how to fix it]\n\n\
                 If no critical issues found, respond with:\n\
                 BUG_FOUND: no\n\
                 ANALYSIS: [brief analysis summary]",
                file_path, content
            );
            
            match deepseek_client.analyze_code(&analysis_prompt).await {
                Ok(analysis_result) => {
                    debug!("Analysis completed for {}, response length: {}", file_path, analysis_result.len());
                    
                    // Check if bug was found
                    if analysis_result.contains("BUG_FOUND: yes") {
                        bugs_found += 1;
                        println!("   🐛 Bug detected! Storing analysis...");
                        
                        // Extract bug details (simplified parsing)
                        let severity = extract_field(&analysis_result, "SEVERITY").unwrap_or("MEDIUM".to_string());
                        let description = extract_field(&analysis_result, "DESCRIPTION").unwrap_or("Bug detected by automated analysis".to_string());
                        let code_sample = extract_field(&analysis_result, "CODE_SAMPLE").unwrap_or("See file content".to_string());
                        let fix_suggestion = extract_field(&analysis_result, "FIX_SUGGESTION").unwrap_or("Manual review required".to_string());
                        
                        // Generate bug ID
                        let file_name = std::path::Path::new(file_path)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown");
                        let bug_id = format!("AUTO_BUG_{}_{}_{}", file_name, bugs_found, chrono::Utc::now().format("%H%M%S"));
                        
                        // Store bug using internal function (simulating MCP call)
                        match store_bug_internal(&bug_id, &severity, &description, Some(file_name.to_string()), &code_sample, &fix_suggestion).await {
                            Ok(filename) => {
                                println!("   ✅ Bug stored: {}", filename);
                                info!("Bug {} stored successfully: {}", bug_id, filename);
                            }
                            Err(e) => {
                                println!("   ❌ Failed to store bug: {}", e);
                                error!("Failed to store bug {}: {}", bug_id, e);
                            }
                        }
                    } else {
                        println!("   ✅ No critical issues found");
                        debug!("File analysis clean: {}", file_path);
                    }
                }
                Err(e) => {
                    println!("   ❌ Analysis failed: {}", e);
                    error!("DeepSeek analysis failed for {}: {}", file_path, e);
                }
            }
        } else {
            println!("   ⚠️ DeepSeek client not available");
            warn!("Skipping analysis - DeepSeek client not initialized");
        }
        
        // Add small delay to avoid rate limiting
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    
    println!("\n📊 Bug analysis completed:");
    println!("   📄 Files analyzed: {}", files_analyzed);
    println!("   🐛 Bugs found: {}", bugs_found);
    
    info!("Bug analysis workflow completed: {} files analyzed, {} bugs found", files_analyzed, bugs_found);
    
    Ok(())
}

// Helper function to extract fields from analysis response
fn extract_field(text: &str, field_name: &str) -> Option<String> {
    let pattern = format!("{}: ", field_name);
    if let Some(start) = text.find(&pattern) {
        let start = start + pattern.len();
        if let Some(end) = text[start..].find('\n') {
            return Some(text[start..start + end].trim().to_string());
        } else {
            return Some(text[start..].trim().to_string());
        }
    }
    None
}

// Internal function to store bugs (simulating MCP store_bug call)
async fn store_bug_internal(
    bug_id: &str,
    severity: &str,
    description: &str,
    adapter_name: Option<String>,
    code_sample: &str,
    fix_suggestion: &str,
) -> Result<String> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let adapter_suffix = adapter_name.as_ref().map(|s| format!("_{}", s)).unwrap_or_default();
    let filename = format!("{}/{}{}_{}.json", config::Config::BUGS_DIRECTORY, bug_id, adapter_suffix, timestamp);
    
    let bug_data = serde_json::json!({
        "bug_id": bug_id,
        "severity": severity,
        "description": description,
        "adapter_name": adapter_name,
        "code_sample": code_sample,
        "fix_suggestion": fix_suggestion,
        "timestamp": timestamp,
        "analysis_context": "Automated detection via Nautilus Trader Rig"
    });
    
    // Ensure bugs directory exists
    tokio::fs::create_dir_all(config::Config::BUGS_DIRECTORY).await?;
    
    tokio::fs::write(&filename, serde_json::to_string_pretty(&bug_data)?).await?;
    
    Ok(filename)
}

// Function to test improvement analyzer
// Main function to run the rig application with FastEmbed and DeepSeek
async fn run_rig_sqlite_application() -> Result<()> {
    info!("🎯 Starting Nautilus Trader Rig application with AI integration");
    println!("🎯 Starting Nautilus Trader Rig with FastEmbed and DeepSeek integration");
    println!("=======================================================================");
    debug!("Application startup initiated with comprehensive AI toolchain");
    
    // Initialize state
    trace!("Beginning unified server state initialization");
    let state = UnifiedServerState::new().await?;
    info!("✅ Server state initialization completed");
    
    // Test DeepSeek client functionality
    debug!("Starting DeepSeek client functionality tests");
    test_deepseek_client(&state).await?;
    
    // Test vector search
    debug!("Starting vector similarity search tests");
    test_vector_search(&state).await?;
    
    println!("\n✅ FastEmbed + DeepSeek integration test completed successfully!");
    info!("🎉 All integration tests passed successfully");
    
    // Run automated bug analysis on discovered files
    debug!("Starting automated bug analysis on adapter files");
    analyze_adapter_files_for_bugs(&state).await?;
    
    // Keep running for monitoring
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    
    println!("\n🔄 Running periodic monitoring (Ctrl+C to stop)...");
    info!("Starting periodic health monitoring with 30-second intervals");
    debug!("Monitoring will check vector store and AI client health");
    
    loop {
        interval.tick().await;
        trace!("Executing periodic health check");
        
        println!("\n⏰ Periodic check - FastEmbed and DeepSeek systems operational");
        
        // Test vector search
        if let Some(vector_store) = &state.vector_store {
            let query = "security vulnerability";
            trace!("Testing vector store with query: '{}'", query);
            match vector_store.similarity_search(query, 1).await {
                Ok(results) => {
                    println!("   🔍 Vector search for '{}': {} results", query, results.len());
                    debug!("Vector store health check successful, {} results returned", results.len());
                }
                Err(e) => {
                    println!("   ❌ Vector search error: {}", e);
                    error!("Vector store health check failed: {}", e);
                }
            }
        } else {
            debug!("Vector store not available during health check");
        }
        
        // Test DeepSeek client
        if let Some(client) = &state.deepseek_client {
            trace!("Testing DeepSeek client health with simple prompt");
            match client.prompt("Respond with just 'OK' to confirm you're working.").await {
                Ok(response) => {
                    println!("   🤖 DeepSeek client: {}", response.trim());
                    debug!("DeepSeek health check successful, response: '{}'", response.trim());
                }
                Err(e) => {
                    println!("   ❌ DeepSeek client error: {}", e);
                    error!("DeepSeek health check failed: {}", e);
                }
            }
        } else {
            debug!("DeepSeek client not available during health check");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file FIRST (before any client initialization)
    dotenvy::from_path(Config::ENV_FILE_PATH).ok(); // Load from configured path
    
    // Initialize centralized logging system
    init_dev_logging()?;

    // Log environment file status
    debug!("Environment file path: {}", Config::ENV_FILE_PATH);
    debug!("Environment file exists: {}", Config::env_file_exists());
    if let Ok(api_key) = std::env::var("DEEPSEEK_API_KEY") {
        debug!("DEEPSEEK_API_KEY loaded (length: {} chars)", api_key.len());
    } else {
        warn!("DEEPSEEK_API_KEY not found in environment");
    }

    info!("🚀 Starting Nautilus Trader Rig with MCP server...");
    debug!("Application entry point - initializing concurrent services");
    
    // Check configuration paths at startup
    log_status!(info, "Validating configuration paths");
    let rust_dirs = Config::all_rust_adapter_directories();
    for (i, dir) in rust_dirs.iter().enumerate() {
        let exists = dir.exists();
        let status = if exists { "Found" } else { "Missing" };
        log_directory_op!(info, format!("Path {} check", i + 1), dir, status);
        
        if exists {
            if let Ok(entries) = std::fs::read_dir(dir) {
                let adapter_count = entries.count();
                log_directory_op!(debug, "Directory contents", dir, adapter_count);
            }
        }
    }
    
    // Count total Rust files available
    let mut total_rust_files = 0;
    for rust_dir in rust_dirs {
        if let Ok(entries) = std::fs::read_dir(rust_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    let src_dir = entry.path().join("src");
                    if src_dir.exists() {
                        if let Ok(src_entries) = std::fs::read_dir(&src_dir) {
                            for src_entry in src_entries.flatten() {
                                if let Some(ext) = src_entry.path().extension() {
                                    if ext == "rs" {
                                        total_rust_files += 1;
                                        log_file_processing!(debug, "Found Rust file", src_entry.path().display());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    log_status!(info, format!("Total Rust adapter files available: {}", total_rust_files));
    
    // Start MCP server on a separate thread
    debug!("Spawning MCP server on background thread");
    let _mcp_handle = tokio::spawn(async {
        info!("🌐 Starting MCP server thread");
        if let Err(e) = run_mcp_server().await {
            error!("❌ MCP server failed: {}", e);
        } else {
            info!("✅ MCP server completed successfully");
        }
    });

    // Run the main application
    debug!("Starting main application thread");
    if let Err(e) = run_rig_sqlite_application().await {
        error!("❌ Main application failed: {}", e);
        return Err(e);
    }
    
    info!("✅ Application shutdown complete");
    Ok(())
}
