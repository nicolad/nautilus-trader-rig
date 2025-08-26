// Main module for Nautilus Trader Rig with rig-sqlite integration
//
// This implementation uses rig-sqlite for vector similarity search

use anyhow::Result;
use std::fs;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

mod config;
mod deepseek;
mod false_positive_filter;
mod fastembed;
mod logging;
mod mcp;
pub mod patterns;
pub mod scanner;
mod vector_store;

use crate::vector_store::run_classification_demo;
use crate::false_positive_filter::{
    FalsePositiveFilter, SuggestedAction, ValidatedIssue, ValidationResult,
};
use config::Config;
use deepseek::DeepSeekClient;
use logging::{init_dev_logging, log_directory_op, log_file_processing};
use mcp::run_mcp_server;
use scanner::scan;
use vector_store::VectorStoreManager;

/// Scan repository directories for pattern matches
async fn scan_repository() -> Result<()> {
    info!("🔍 Scanning repository for pattern matches...");

    let repo_path = Config::rig_repo_path();
    if !repo_path.exists() {
        warn!("Repository path not found: {}", repo_path.display());
        return Ok(());
    }

    info!("Scanning repository: {}", repo_path.display());
    
    let mut total_issues = 0;
    let mut scanned_files = 0;

    for entry in walkdir::WalkDir::new(&repo_path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        
        // Skip hidden directories and common build/cache directories
        let path_str = path.to_string_lossy();
        if path_str.contains("/.") || 
           path_str.contains("/target/") || 
           path_str.contains("/node_modules/") || 
           path_str.contains("/__pycache__/") || 
           path_str.contains("/build/") || 
           path_str.contains("/dist/") ||
           path_str.contains("/.git/") ||
           path_str.ends_with("/target") ||
           path_str.ends_with("/node_modules") ||
           path_str.ends_with("/__pycache__") ||
           path_str.ends_with("/build") ||
           path_str.ends_with("/dist") ||
           path_str.ends_with("/.git") {
            continue;
        }
        
        if let Some(ext) = path.extension() {
            if Config::RUST_FILE_EXTENSIONS.contains(&ext.to_str().unwrap_or("")) {
                if let Ok(content) = fs::read_to_string(path) {
                    scanned_files += 1;
                    let issues = scan(&content);
                    if !issues.is_empty() {
                        let relative_path = pathdiff::diff_paths(path, &repo_path)
                            .unwrap_or_else(|| path.to_path_buf());

                        info!(
                            "Found {} issues in: {}",
                            issues.len(),
                            relative_path.display()
                        );
                        total_issues += issues.len();

                        // Store each issue as a bug report
                        for issue in issues {
                            let bug_data = serde_json::json!({
                                "bug_id": format!("SCAN_{}_{}_L{}", issue.pattern_id,
                                    relative_path.file_stem().unwrap_or_default().to_str().unwrap_or("unknown"),
                                    issue.line),
                                "adapter_name": relative_path.file_stem().unwrap_or_default().to_str().unwrap_or("unknown"),
                                "analysis_context": "Automated pattern detection",
                                "description": format!("{} detected: {}", issue.category, issue.name),
                                "severity": issue.severity,
                                "file_location": {
                                    "relative_path": relative_path.to_str().unwrap_or(""),
                                    "line": issue.line,
                                    "column": issue.col
                                },
                                "code_sample": issue.excerpt,
                                "pattern_id": issue.pattern_id,
                                "fix_suggestion": format!("Review {} pattern usage", issue.category.to_lowercase()),
                                "timestamp": chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string(),
                                "workspace_info": {
                                    "repository": "repository",
                                    "branch": "main"
                                }
                            });

                            // Store bug report
                            let bug_id = bug_data["bug_id"].as_str().unwrap_or("unknown");
                            let bugs_dir = Config::manifest_dir().join(Config::BUGS_DIRECTORY);
                            fs::create_dir_all(&bugs_dir)?;
                            let bug_file = bugs_dir.join(format!("{}.json", bug_id));
                            fs::write(&bug_file, serde_json::to_string_pretty(&bug_data)?)?;
                        }
                    }
                }
            }
        }
    }

    info!(
        "✅ Pattern scanning complete. Scanned {} Rust files, found {} total issues",
        scanned_files, total_issues
    );
    Ok(())
}

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

        let test_queries = [
            "authentication bypass vulnerability",
            "websocket security issues",
            "rate limiting problems",
            "memory leak",
        ];

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

        // First run pattern-based scanning
        println!("   🔍 Running pattern-based analysis...");
        let pattern_results = crate::scanner::scan(&content);

        // Initialize false positive filter
        let mut fp_filter = FalsePositiveFilter::new(state.deepseek_client.clone());
        let mut validated_issues = Vec::new();
        let mut real_issues = 0;

        if !pattern_results.is_empty() {
            println!(
                "   🔍 Validating {} pattern matches for false positives...",
                pattern_results.len()
            );

            for issue in pattern_results {
                match fp_filter.validate_issue(&issue, &content).await {
                    Ok(validation) => {
                        let validated_issue = ValidatedIssue::new(issue, validation);

                        if validated_issue.is_valid {
                            real_issues += 1;
                            debug!(
                                "Real issue: {} - {} (confidence: {:.2})",
                                validated_issue.issue.pattern_id,
                                validated_issue.issue.name,
                                validated_issue.confidence
                            );
                        } else {
                            debug!(
                                "False positive filtered: {} - {} (reason: {})",
                                validated_issue.issue.pattern_id,
                                validated_issue.issue.name,
                                validated_issue.ai_reasoning
                            );
                        }

                        validated_issues.push(validated_issue);
                    }
                    Err(e) => {
                        warn!("Failed to validate issue: {}", e);
                        // Include unvalidated issue with conservative approach
                        let validation = ValidationResult {
                            is_false_positive: false,
                            confidence: 0.5,
                            reasoning: format!("Validation failed: {}", e),
                            suggested_action: SuggestedAction::Review,
                        };
                        validated_issues.push(ValidatedIssue::new(issue, validation));
                        real_issues += 1;
                    }
                }
            }

            let (total_validations, false_positives) = fp_filter.get_validation_stats();
            println!(
                "   📊 Validation results: {} real issues, {} false positives filtered",
                real_issues,
                validated_issues.len() - real_issues
            );
            debug!(
                "False positive filter stats: {}/{} total validations, {} false positives",
                false_positives, total_validations, false_positives
            );
        } else {
            println!("   ✅ No pattern-based issues detected");
        }

        // Get file metadata for enhanced reporting
        let file_metadata = match tokio::fs::metadata(file_path).await {
            Ok(metadata) => Some(serde_json::json!({
                "size_bytes": metadata.len(),
                "lines_of_code": content.lines().count(),
                "last_modified": metadata.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
                "total_pattern_matches": validated_issues.len(),
                "real_issues_found": real_issues,
                "false_positives_filtered": validated_issues.len() - real_issues,
                "validated_issues": validated_issues.iter().map(|vi| serde_json::json!({
                    "pattern_id": vi.issue.pattern_id,
                    "severity": vi.issue.severity,
                    "category": vi.issue.category,
                    "name": vi.issue.name,
                    "line": vi.issue.line,
                    "excerpt": vi.issue.excerpt,
                    "is_false_positive": !vi.is_valid,
                    "confidence": vi.confidence,
                    "is_valid": vi.is_valid,
                    "reasoning": vi.ai_reasoning
                })).collect::<Vec<_>>()
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

                    // Check if bug was found (DeepSeek or validated pattern-based)
                    let deepseek_bug_found = analysis_result.contains("BUG_FOUND: yes");
                    let real_pattern_bugs =
                        validated_issues.iter().filter(|vi| vi.is_valid).count() > 0;

                    if deepseek_bug_found || real_pattern_bugs {
                        bugs_found += 1;
                        println!("   🐛 Bug detected! Storing analysis...");

                        // Extract bug details with enhanced parsing
                        let severity = if real_pattern_bugs {
                            // Use highest severity from real (non-false-positive) pattern results
                            validated_issues
                                .iter()
                                .filter(|vi| vi.is_valid)
                                .map(|vi| vi.issue.severity.clone())
                                .max_by_key(|s| match s.as_str() {
                                    "Critical" => 4,
                                    "High" => 3,
                                    "Medium" => 2,
                                    "Low" => 1,
                                    _ => 0,
                                })
                                .unwrap_or("MEDIUM".to_string())
                                .to_string()
                        } else {
                            extract_field(&analysis_result, "SEVERITY")
                                .unwrap_or("MEDIUM".to_string())
                        };

                        let description = if real_pattern_bugs {
                            let pattern_desc = validated_issues
                                .iter()
                                .filter(|vi| vi.is_valid)
                                .map(|vi| {
                                    format!(
                                        "[{}] {} (confidence: {:.2})",
                                        vi.issue.pattern_id, vi.issue.name, vi.confidence
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join("; ");
                            if deepseek_bug_found {
                                format!(
                                    "Validated Pattern Issues: {}; DeepSeek: {}",
                                    pattern_desc,
                                    extract_field(&analysis_result, "DESCRIPTION")
                                        .unwrap_or("Additional issues detected".to_string())
                                )
                            } else {
                                format!("Validated Pattern Issues: {}", pattern_desc)
                            }
                        } else {
                            extract_field(&analysis_result, "DESCRIPTION")
                                .unwrap_or("Bug detected by automated analysis".to_string())
                        };

                        let code_sample = extract_field(&analysis_result, "CODE_SAMPLE")
                            .unwrap_or("See file content".to_string());
                        let fix_suggestion = extract_field(&analysis_result, "FIX_SUGGESTION")
                            .unwrap_or("Manual review required".to_string());
                        let affected_functions =
                            extract_field(&analysis_result, "AFFECTED_FUNCTIONS")
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
            // Even without DeepSeek, check for validated pattern-based issues
            let real_issues_count = validated_issues.iter().filter(|vi| vi.is_valid).count();
            if real_issues_count > 0 {
                bugs_found += 1;
                println!("   🐛 Validated pattern-based bugs detected! Storing analysis...");

                // Use validated pattern-based bug information
                let severity = validated_issues
                    .iter()
                    .filter(|vi| vi.is_valid)
                    .map(|vi| vi.issue.severity.clone())
                    .max_by_key(|s| match s.as_str() {
                        "Critical" => 4,
                        "High" => 3,
                        "Medium" => 2,
                        "Low" => 1,
                        _ => 0,
                    })
                    .unwrap_or("MEDIUM".to_string())
                    .to_string();

                let description = validated_issues
                    .iter()
                    .filter(|vi| vi.is_valid)
                    .map(|vi| {
                        format!(
                            "[{}] {} (confidence: {:.2})",
                            vi.issue.pattern_id, vi.issue.name, vi.confidence
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");

                // Generate bug ID
                let file_name = std::path::Path::new(file_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");
                let bug_id = format!(
                    "PATTERN_BUG_{}_{}_{}",
                    file_name,
                    bugs_found,
                    chrono::Utc::now().format("%H%M%S")
                );

                // Store pattern-based bug
                match store_bug_internal(
                    &bug_id,
                    &severity,
                    &description,
                    Some(file_name.to_string()),
                    "Pattern-based detection",
                    "Review code patterns and apply fixes as needed",
                    Some(file_path.to_string()),
                )
                .await
                {
                    Ok(filename) => {
                        println!("   ✅ Pattern bug stored: {}", filename);
                        info!("Pattern bug {} stored successfully: {}", bug_id, filename);

                        analysis_results.push(serde_json::json!({
                            "file_path": file_path,
                            "status": "pattern_bug_found",
                            "bug_id": bug_id,
                            "severity": severity,
                            "bug_file": filename,
                            "file_metadata": file_metadata,
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        }));
                    }
                    Err(e) => {
                        println!("   ❌ Failed to store pattern bug: {}", e);
                        error!("Failed to store pattern bug {}: {}", bug_id, e);

                        analysis_results.push(serde_json::json!({
                            "file_path": file_path,
                            "status": "pattern_bug_found_but_storage_failed",
                            "bug_id": bug_id,
                            "storage_error": format!("{}", e),
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        }));
                    }
                }
            } else {
                println!("   ⚠️ DeepSeek client not available, no pattern issues found");
                warn!("Skipping analysis - DeepSeek client not initialized and no pattern issues");

                analysis_results.push(serde_json::json!({
                    "file_path": file_path,
                    "status": "skipped_no_client_no_patterns",
                    "file_metadata": file_metadata,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                }));
            }
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

    if let Err(e) = tokio::fs::write(
        &summary_filename,
        serde_json::to_string_pretty(&summary_report)?,
    )
    .await
    {
        error!("Failed to write analysis summary: {}", e);
    } else {
        println!(
            "📊 Analysis summary saved to: {}",
            summary_filename.display()
        );
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
                    result["file_path"], result["bug_id"], result["severity"]
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

    // Extract relative path from workspace root
    let file_location = if let Some(path) = &file_path {
        if let Ok(workspace_root) = std::env::current_dir() {
            if let Ok(relative_path) = std::path::Path::new(path).strip_prefix(&workspace_root) {
                relative_path.display().to_string()
            } else {
                path.clone()
            }
        } else {
            path.clone()
        }
    } else {
        "unknown".to_string()
    };

    let bug_data = serde_json::json!({
        "bug_id": bug_id,
        "severity": severity,
        "description": description,
        "adapter_name": adapter_name,
        "code_sample": code_sample,
        "fix_suggestion": fix_suggestion,
        "timestamp": timestamp,
        "analysis_context": "Automated detection via Nautilus Trader Rig",
        "relative_path": file_location,
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

    // Automatically scan repository for pattern matches
    if let Err(e) = scan_repository().await {
        error!("Failed to scan repository: {}", e);
    }

    // Log environment file status
    debug!("Environment file path: {}", Config::ENV_FILE_PATH);
    debug!("Environment file exists: {}", Config::env_file_exists());
    if let Ok(api_key) = std::env::var("DEEPSEEK_API_KEY") {
        debug!("DEEPSEEK_API_KEY loaded (length: {} chars)", api_key.len());
    } else {
        warn!("DEEPSEEK_API_KEY not found in environment");
    }

    // Log rig repository configuration
    if let Some(rig_path) = Config::rig_repo_path_env_value() {
        info!("REPO_PATH set to: {}", rig_path);
        debug!("Using rig repository from environment variable");
    } else {
        let default_path = Config::rig_repo_path();
        info!(
            "REPO_PATH not set, using default: {}",
            default_path.display()
        );
        debug!("Using default rig repository path");
    }

    info!("🚀 Starting Nautilus Trader Rig with MCP server...");
    debug!("Application entry point - initializing concurrent services");

    // Check configuration paths at startup
    info!("ℹ️ Validating configuration paths");
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
    info!(
        "ℹ️ Total Rust adapter files available: {}",
        total_rust_files
    );

    // Run classification demo if enabled
    if std::env::var("RUN_CLASSIFICATION_DEMO").is_ok() {
        info!("🧠 Running classification demo...");
        if let Err(e) = run_classification_demo().await {
            warn!("Classification demo failed: {}", e);
        }
    }

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
