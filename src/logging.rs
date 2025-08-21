// src/logging.rs
//
// Comprehensive logging module for the Nautilus Trader Autopatcher
//
// Provides both console and file-based logging with structured output
// for better debugging and monitoring of autopatcher activities.

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// File-based logger for detailed autopatcher activity
#[derive(Clone)]
pub struct FileLogger {
    log_file: Arc<Mutex<BufWriter<std::fs::File>>>,
    log_path: String,
}

impl FileLogger {
    /// Create a new file logger in the .logs directory
    pub fn new() -> Result<Self> {
        let log_dir = Path::new(".logs");
        fs::create_dir_all(log_dir)?;
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let log_path = log_dir.join(format!("autopatcher_{}.log", timestamp));
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("Failed to create log file: {}", log_path.display()))?;
        
        let log_file = Arc::new(Mutex::new(BufWriter::new(file)));
        
        println!("📁 Created log file: {}", log_path.display());
        
        Ok(Self { 
            log_file,
            log_path: log_path.to_string_lossy().to_string(),
        })
    }
    
    /// Log a message to the file with timestamp
    pub async fn log(&self, message: &str) -> Result<()> {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let formatted = format!("[{}] {}\n", timestamp, message);
        
        let mut writer = self.log_file.lock().await;
        writer.write_all(formatted.as_bytes())
            .with_context(|| "Failed to write to log file")?;
        writer.flush()
            .with_context(|| "Failed to flush log file")?;
        Ok(())
    }
    
    /// Log an info message
    pub async fn info(&self, message: &str) -> Result<()> {
        self.log(&format!("INFO: {}", message)).await
    }
    
    /// Log a warning message
    pub async fn warn(&self, message: &str) -> Result<()> {
        self.log(&format!("WARN: {}", message)).await
    }
    
    /// Log an error message
    pub async fn error(&self, message: &str) -> Result<()> {
        self.log(&format!("ERROR: {}", message)).await
    }
    
    /// Log a debug message
    pub async fn debug(&self, message: &str) -> Result<()> {
        self.log(&format!("DEBUG: {}", message)).await
    }
    
    /// Log the start of a major operation
    pub async fn operation_start(&self, operation: &str, details: &str) -> Result<()> {
        self.log(&format!("🚀 OPERATION START: {} - {}", operation, details)).await
    }
    
    /// Log the completion of a major operation
    pub async fn operation_complete(&self, operation: &str, duration_ms: u64, success: bool) -> Result<()> {
        let status = if success { "✅ SUCCESS" } else { "❌ FAILED" };
        self.log(&format!("{}: {} completed in {}ms", status, operation, duration_ms)).await
    }
    
    /// Log autopatcher iteration details
    pub async fn iteration(&self, iter: u32, max_iter: u32, action: &str) -> Result<()> {
        self.log(&format!("🔄 ITERATION {}/{}: {}", iter, max_iter, action)).await
    }
    
    /// Log AI interaction details
    pub async fn ai_interaction(&self, agent_name: &str, prompt_size: usize, response_size: usize, duration_ms: u64) -> Result<()> {
        self.log(&format!("🤖 AI: {} | Prompt: {} chars | Response: {} chars | Duration: {}ms", 
                         agent_name, prompt_size, response_size, duration_ms)).await
    }
    
    /// Log patch application details
    #[allow(dead_code)]
    pub async fn patch_applied(&self, patch_title: &str, file_count: usize, success: bool) -> Result<()> {
        let status = if success { "✅" } else { "❌" };
        self.log(&format!("{} PATCH: '{}' affecting {} files", status, patch_title, file_count)).await
    }
    
    /// Log git operations
    #[allow(dead_code)]
    pub async fn git_operation(&self, operation: &str, branch: Option<&str>, success: bool) -> Result<()> {
        let status = if success { "✅" } else { "❌" };
        let branch_info = branch.map(|b| format!(" [{}]", b)).unwrap_or_default();
        self.log(&format!("{} GIT: {}{}", status, operation, branch_info)).await
    }
    
    /// Get the path to the current log file
    pub fn log_path(&self) -> &str {
        &self.log_path
    }
}

/// Enhanced logging configuration and utilities
pub struct LoggingConfig {
    pub console_level: log::LevelFilter,
    pub file_enabled: bool,
    #[allow(dead_code)]
    pub structured_output: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            console_level: log::LevelFilter::Info,
            file_enabled: true,
            structured_output: true,
        }
    }
}

/// Initialize comprehensive logging for the autopatcher
pub async fn initialize_logging(config: LoggingConfig) -> Result<Option<FileLogger>> {
    println!("📋 Initializing enhanced logging system");
    
    // Initialize file logger if enabled
    let file_logger = if config.file_enabled {
        match FileLogger::new() {
            Ok(logger) => {
                println!("📁 File logging initialized successfully");
                logger.info("Autopatcher logging system initialized").await?;
                Some(logger)
            }
            Err(e) => {
                println!("⚠️  File logging failed to initialize: {}", e);
                None
            }
        }
    } else {
        None
    };
    
    // Initialize console logging
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
        println!("📋 Set RUST_LOG to info level");
    }

    match env_logger::Builder::from_default_env()
        .filter_level(config.console_level)
        .format_timestamp_secs()
        .try_init()
    {
        Ok(_) => {
            println!("📋 Console logging initialized successfully");
            if let Some(ref logger) = file_logger {
                logger.info("Console logging initialized").await?;
            }
        }
        Err(e) => {
            println!("📋 Console logging already initialized: {}", e);
        }
    }

    Ok(file_logger)
}

/// Structured logging helper for autopatcher operations
pub struct OperationLogger {
    file_logger: Option<FileLogger>,
    operation: String,
    start_time: std::time::Instant,
}

impl OperationLogger {
    pub async fn new(operation: &str, file_logger: Option<FileLogger>) -> Self {
        let start_time = std::time::Instant::now();
        
        if let Some(ref logger) = file_logger {
            let _ = logger.operation_start(operation, "Starting operation").await;
        }
        
        Self {
            file_logger,
            operation: operation.to_string(),
            start_time,
        }
    }
    
    pub async fn complete(self, success: bool) {
        let duration = self.start_time.elapsed().as_millis() as u64;
        
        if let Some(ref logger) = self.file_logger {
            let _ = logger.operation_complete(&self.operation, duration, success).await;
        }
    }
    
    #[allow(dead_code)]
    pub async fn log(&self, message: &str) {
        if let Some(ref logger) = self.file_logger {
            let _ = logger.log(&format!("[{}] {}", self.operation, message)).await;
        }
    }
}
