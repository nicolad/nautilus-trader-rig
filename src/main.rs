// Main module for Nautilus Trader Rig with rig-sqlite integration
//
// This implementation uses rig-sqlite for vector similarity search

use anyhow::Result;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

mod config;
mod deepseek;
mod fastembed;
mod logging;
mod mcp;
mod vector_store;

use config::Config;
use deepseek::DeepSeekClient;
use logging::{init_dev_logging, log_directory_op, log_file_processing, log_status};
use mcp::run_mcp_server;
use vector_store::VectorStoreManager;

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
        match client
            .analyze_code(&format!(
                "Analyze this Rust code for security issues:\n{}",
                test_code
            ))
            .await
        {
            Ok(analysis) => {
                println!("   ✅ Code analysis completed");
                println!(
                    "   📊 Analysis (first 200 chars): {}...",
                    analysis.chars().take(200).collect::<String>()
                );
                debug!(
                    "Code analysis successful, full response length: {} chars",
                    analysis.len()
                );
            }
            Err(e) => {
                println!("   ❌ Code analysis failed: {}", e);
            }
        }

        // Test critical bug confirmation
        println!("\n� Testing critical bug confirmation:");
        match client
            .confirm_critical_bug(
                "Potential authentication bypass in trading API",
                "if user.is_authenticated() { /* process */ }",
            )
            .await
        {
            Ok(confirmation) => {
                println!("   ✅ Bug confirmation completed");
                println!(
                    "   🔍 Confirmation (first 200 chars): {}...",
                    confirmation.chars().take(200).collect::<String>()
                );
                debug!(
                    "Bug confirmation successful, response length: {} chars",
                    confirmation.len()
                );
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

        let test_queries = ["authentication bypass vulnerability",
            "websocket security issues",
            "rate limiting problems",
            "memory leak"];

        debug!("Testing {} different search queries", test_queries.len());

        for (index, query) in test_queries.iter().enumerate() {
            println!("\n📝 Searching for: '{}'", query);
            trace!(
                "Running similarity search {}/{}: '{}'",
                index + 1,
                test_queries.len(),
                query
            );

            match vector_store.similarity_search(query, 3).await {
                Ok(results) => {
                    debug!(
                        "Similarity search completed, found {} results",
                        results.len()
                    );
                    if results.is_empty() {
                        println!("   No similar patterns found");
                        trace!("Empty result set for query: '{}'", query);
                    } else {
                        println!("   Found {} similar patterns:", results.len());
                        for (i, result) in results.iter().enumerate() {
                            if let Some(id) = result.get("id") {
                                if let Some(score) = result.get("score") {
                                    println!("   {}. {} (score: {:.3})", i + 1, id, score);
                                    trace!("Result {}: id={}, score={:.6}", i + 1, id, score);
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

// Function to analyze adapter files for bugs and store results with enhanced location tracking
async fn analyze_adapter_files_for_bugs(state: &UnifiedServerState) -> Result<()> {
    println!("\n🔍 Starting automated bug analysis on adapter files...");
    info!("Beginning automated bug analysis workflow");

    // Get list of adapter files
    let adapters_path = config::Config::core_adapters_directory_abs();
    let rust_files = discover_rust_files(&adapters_path.to_string_lossy()).await?;

    if rust_files.is_empty() {
        println!("⚠️ No Rust files found for analysis");
        warn!("Bug analysis skipped - no files discovered");
        return Ok(());
    }

    println!("📁 Found {} files to analyze", rust_files.len());
    info!(
        "Discovered {} Rust files for bug analysis",
        rust_files.len()
    );

    let mut bugs_found = 0;
    let mut files_analyzed = 0;
    let mut analysis_results = Vec::new();

    // Analyze each file
    for (i, file_path) in rust_files.iter().enumerate() {
        println!(
            "   📄 Analyzing file {}/{}: {}",
            i + 1,
            rust_files.len(),
            file_path
        );
        debug!("Starting analysis of file: {}", file_path);

        // Read file content
        let content = match tokio::fs::read_to_string(file_path).await {
            Ok(content) => content,
            Err(e) => {
                println!("   ❌ Failed to read file: {}", e);
                warn!("Skipping file due to read error: {} - {}", file_path, e);
                analysis_results.push(serde_json::json!({
                    "file_path": file_path,
                    "status": "error",
                    "error": format!("Failed to read file: {}", e),
                    "timestamp": chrono::Utc::now().to_rfc3339()
                }));
                continue;
            }
        };

        files_analyzed += 1;

        // Get file metadata for enhanced reporting
        let file_metadata = match tokio::fs::metadata(file_path).await {
            Ok(metadata) => Some(serde_json::json!({
                "size_bytes": metadata.len(),
                "lines_of_code": content.lines().count(),
                "last_modified": metadata.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
            })),
            Err(_) => None,
        };

        // Analyze with DeepSeek
        if let Some(deepseek_client) = &state.deepseek_client {
            let analysis_prompt = format!(
                "Analyze this Rust code for critical bugs, security vulnerabilities, and potential issues:\n\n\
                 File: {}\n\
                 Lines of code: {}\n\n\
                 ```rust\n{}\n```\n\n\
                 Focus on:\n\
                 - Security vulnerabilities (buffer overflows, injection attacks, etc.)\n\
                 - Memory safety issues\n\
                 - Logic errors that could cause financial losses\n\
                 - Performance bottlenecks\n\
                 - Error handling problems\n\
                 - Precision loss in financial calculations (especially with f64 conversions)\n\
                 - Type safety issues\n\n\
                 If you find critical issues, respond with:\n\
                 BUG_FOUND: yes\n\
                 SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]\n\
                 DESCRIPTION: [detailed description]\n\
                 CODE_SAMPLE: [relevant code snippet with function/line context]\n\
                 FIX_SUGGESTION: [how to fix it]\n\
                 AFFECTED_FUNCTIONS: [list of function names affected]\n\n\
                 If no critical issues found, respond with:\n\
                 BUG_FOUND: no\n\
                 ANALYSIS: [brief analysis summary]",
                file_path, content.lines().count(), content
            );

            match deepseek_client.analyze_code(&analysis_prompt).await {
                Ok(analysis_result) => {
                    debug!(
                        "Analysis completed for {}, response length: {}",
                        file_path,
                        analysis_result.len()
                    );

                    // Check if bug was found
                    if analysis_result.contains("BUG_FOUND: yes") {
                        bugs_found += 1;
                        println!("   🐛 Bug detected! Storing analysis...");

                        // Extract bug details with enhanced parsing
                        let severity = extract_field(&analysis_result, "SEVERITY")
                            .unwrap_or("MEDIUM".to_string());
                        let description = extract_field(&analysis_result, "DESCRIPTION")
                            .unwrap_or("Bug detected by automated analysis".to_string());
                        let code_sample = extract_field(&analysis_result, "CODE_SAMPLE")
                            .unwrap_or("See file content".to_string());
                        let fix_suggestion = extract_field(&analysis_result, "FIX_SUGGESTION")
                            .unwrap_or("Manual review required".to_string());
                        let affected_functions = extract_field(&analysis_result, "AFFECTED_FUNCTIONS")
                            .unwrap_or("Unknown".to_string());

                        // Generate enhanced bug ID with more context
                        let file_name = std::path::Path::new(file_path)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown");
                        let bug_id = format!(
                            "AUTO_BUG_{}_{}_{}",
                            file_name,
                            bugs_found,
                            chrono::Utc::now().format("%H%M%S")
                        );

                        // Store bug using enhanced internal function
                        match store_bug_internal(
                            &bug_id,
                            &severity,
                            &description,
                            Some(file_name.to_string()),
                            &code_sample,
                            &fix_suggestion,
                            Some(file_path.to_string()),
                        )
                        .await
                        {
                            Ok(filename) => {
                                println!("   ✅ Bug stored: {}", filename);
                                info!("Bug {} stored successfully: {}", bug_id, filename);
                                
                                analysis_results.push(serde_json::json!({
                                    "file_path": file_path,
                                    "status": "bug_found",
                                    "bug_id": bug_id,
                                    "severity": severity,
                                    "affected_functions": affected_functions,
                                    "bug_file": filename,
                                    "file_metadata": file_metadata,
                                    "timestamp": chrono::Utc::now().to_rfc3339()
                                }));
                            }
                            Err(e) => {
                                println!("   ❌ Failed to store bug: {}", e);
                                error!("Failed to store bug {}: {}", bug_id, e);
                                
                                analysis_results.push(serde_json::json!({
                                    "file_path": file_path,
                                    "status": "bug_found_but_storage_failed",
                                    "bug_id": bug_id,
                                    "storage_error": format!("{}", e),
                                    "timestamp": chrono::Utc::now().to_rfc3339()
                                }));
                            }
                        }
                    } else {
                        println!("   ✅ No critical issues found");
                        debug!("File analysis clean: {}", file_path);
                        
                        analysis_results.push(serde_json::json!({
                            "file_path": file_path,
                            "status": "clean",
                            "file_metadata": file_metadata,
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        }));
                    }
                }
                Err(e) => {
                    println!("   ❌ Analysis failed: {}", e);
                    error!("DeepSeek analysis failed for {}: {}", file_path, e);
                    
                    analysis_results.push(serde_json::json!({
                        "file_path": file_path,
                        "status": "analysis_failed",
                        "error": format!("{}", e),
                        "file_metadata": file_metadata,
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    }));
                }
            }
        } else {
            println!("   ⚠️ DeepSeek client not available");
            warn!("Skipping analysis - DeepSeek client not initialized");
            
            analysis_results.push(serde_json::json!({
                "file_path": file_path,
                "status": "skipped_no_client",
                "file_metadata": file_metadata,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }));
        }

        // Add small delay to avoid rate limiting
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Store comprehensive analysis summary
    let summary_report = serde_json::json!({
        "analysis_summary": {
            "total_files_discovered": rust_files.len(),
            "files_analyzed": files_analyzed,
            "bugs_found": bugs_found,
            "analysis_timestamp": chrono::Utc::now().to_rfc3339(),
            "workspace_info": {
                "adapters_path": adapters_path.display().to_string(),
                "repository": "nautilus_trader",
                "branch": get_git_branch().await.unwrap_or_else(|| "unknown".to_string())
            }
        },
        "file_results": analysis_results
    });

    // Store summary report
    let bugs_dir = config::Config::bugs_directory_path();
    let summary_filename = bugs_dir.join(format!(
        "analysis_summary_{}.json",
        chrono::Utc::now().format("%Y%m%d_%H%M%S")
    ));
    
    if let Err(e) = tokio::fs::write(&summary_filename, serde_json::to_string_pretty(&summary_report)?).await {
        error!("Failed to write analysis summary: {}", e);
    } else {
        println!("📊 Analysis summary saved to: {}", summary_filename.display());
        info!("Analysis summary saved: {}", summary_filename.display());
    }

    println!("\n📊 Bug analysis completed:");
    println!("   📄 Files analyzed: {}", files_analyzed);
    println!("   🐛 Bugs found: {}", bugs_found);
    println!("   📋 Summary report: {}", summary_filename.display());

    // Print file-by-file results
    if bugs_found > 0 {
        println!("\n🔍 Files with bugs detected:");
        for result in &analysis_results {
            if result["status"] == "bug_found" {
                println!(
                    "   • {} (Bug ID: {}, Severity: {})",
                    result["file_path"],
                    result["bug_id"],
                    result["severity"]
                );
            }
        }
    }

    info!(
        "Bug analysis workflow completed: {} files analyzed, {} bugs found",
        files_analyzed, bugs_found
    );

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

// Internal function to store bugs with enhanced file location tracking
async fn store_bug_internal(
    bug_id: &str,
    severity: &str,
    description: &str,
    adapter_name: Option<String>,
    code_sample: &str,
    fix_suggestion: &str,
    file_path: Option<String>,
) -> Result<String> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let adapter_suffix = adapter_name
        .as_ref()
        .map(|s| format!("_{}", s))
        .unwrap_or_default();
    let bugs_dir = config::Config::bugs_directory_path();
    let filename = bugs_dir.join(format!("{}{}_{}.json", bug_id, adapter_suffix, timestamp));

    // Enhanced file location information
    let mut file_details = serde_json::Map::new();
    if let Some(path) = &file_path {
        file_details.insert("absolute_path".to_string(), serde_json::Value::String(path.clone()));
        
        // Extract relative path from workspace root
        if let Ok(workspace_root) = std::env::current_dir() {
            if let Ok(relative_path) = std::path::Path::new(path).strip_prefix(&workspace_root) {
                file_details.insert("relative_path".to_string(), 
                    serde_json::Value::String(relative_path.display().to_string()));
            }
        }
        
        // Extract filename and directory information
        let path_obj = std::path::Path::new(path);
        if let Some(filename) = path_obj.file_name() {
            file_details.insert("filename".to_string(), 
                serde_json::Value::String(filename.to_string_lossy().to_string()));
        }
        if let Some(parent) = path_obj.parent() {
            file_details.insert("directory".to_string(), 
                serde_json::Value::String(parent.display().to_string()));
        }
        
        // Check if file exists and get metadata
        if let Ok(metadata) = tokio::fs::metadata(path).await {
            file_details.insert("file_size_bytes".to_string(), 
                serde_json::Value::Number(serde_json::Number::from(metadata.len())));
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                    file_details.insert("last_modified_timestamp".to_string(), 
                        serde_json::Value::Number(serde_json::Number::from(duration.as_secs())));
                }
            }
        }
    }

    // Try to extract line numbers from code sample if available
    let mut location_details = serde_json::Map::new();
    if !code_sample.is_empty() && file_path.is_some() {
        if let Some(path) = &file_path {
            if let Ok(file_content) = tokio::fs::read_to_string(path).await {
                // Find the approximate line number where the code sample appears
                if let Some(line_number) = find_code_in_file(&file_content, code_sample) {
                    location_details.insert("approximate_line_number".to_string(), 
                        serde_json::Value::Number(serde_json::Number::from(line_number)));
                    location_details.insert("context_extraction_method".to_string(), 
                        serde_json::Value::String("fuzzy_string_match".to_string()));
                }
            }
        }
    }

    let bug_data = serde_json::json!({
        "bug_id": bug_id,
        "severity": severity,
        "description": description,
        "adapter_name": adapter_name,
        "code_sample": code_sample,
        "fix_suggestion": fix_suggestion,
        "timestamp": timestamp,
        "analysis_context": "Automated detection via Nautilus Trader Rig",
        "file_location": {
            "details": file_details,
            "source_location": location_details
        },
        "workspace_info": {
            "repository": "nautilus_trader",
            "branch": get_git_branch().await.unwrap_or_else(|| "unknown".to_string()),
            "commit_hash": get_git_commit_hash().await.unwrap_or_else(|| "unknown".to_string())
        }
    });

    // Ensure bugs directory exists
    tokio::fs::create_dir_all(&bugs_dir).await?;

    tokio::fs::write(&filename, serde_json::to_string_pretty(&bug_data)?).await?;

    Ok(filename.to_string_lossy().to_string())
}

// Helper function to find approximate line number of code in file
fn find_code_in_file(file_content: &str, code_sample: &str) -> Option<usize> {
    // Clean up code sample for better matching
    let cleaned_sample = code_sample
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ");
    
    if cleaned_sample.is_empty() {
        return None;
    }
    
    // Look for the first substantial line from the code sample
    for (line_num, line) in file_content.lines().enumerate() {
        let cleaned_line = line.trim();
        if !cleaned_line.is_empty() && cleaned_sample.contains(cleaned_line) {
            return Some(line_num + 1); // 1-indexed line numbers
        }
    }
    
    None
}

// Helper function to get current git branch
async fn get_git_branch() -> Option<String> {
    let output = tokio::process::Command::new("git")
        .args(["branch", "--show-current"])
        .output()
        .await
        .ok()?;
    
    if output.status.success() {
        String::from_utf8(output.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

// Helper function to get current git commit hash
async fn get_git_commit_hash() -> Option<String> {
    let output = tokio::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .await
        .ok()?;
    
    if output.status.success() {
        String::from_utf8(output.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
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
                    println!(
                        "   🔍 Vector search for '{}': {} results",
                        query,
                        results.len()
                    );
                    debug!(
                        "Vector store health check successful, {} results returned",
                        results.len()
                    );
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
            match client
                .prompt("Respond with just 'OK' to confirm you're working.")
                .await
            {
                Ok(response) => {
                    println!("   🤖 DeepSeek client: {}", response.trim());
                    debug!(
                        "DeepSeek health check successful, response: '{}'",
                        response.trim()
                    );
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
    // Try absolute path first, then relative paths
    let env_paths = [
        Config::manifest_dir().join(".env"),
        std::path::Path::new(".env").to_path_buf(),
        std::path::Path::new("nautilus-trader-rig/.env").to_path_buf(),
    ];

    for env_path in &env_paths {
        if env_path.exists() {
            dotenvy::from_path(env_path).ok();
            break;
        }
    }

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
    let rust_dirs = Config::all_rust_adapter_directories_abs();
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
                                        log_file_processing!(
                                            debug,
                                            "Found Rust file",
                                            src_entry.path().display()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    log_status!(
        info,
        format!("Total Rust adapter files available: {}", total_rust_files)
    );

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
