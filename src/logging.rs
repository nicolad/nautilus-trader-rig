//! Centralized logging configuration for Nautilus Trader Rig
//!
//! This module provides consistent logging setup across all components with:
//! - Structured logging with tracing
//! - Environment-based log levels
//! - Color-coded output for development
//! - File output for production
//! - Performance monitoring
//! - Component-specific logging levels

use crate::config::Config;
use anyhow::Result;
use std::path::Path;
use tracing::{debug, info, Level};
use tracing_subscriber::EnvFilter;

/// Log levels for different components
#[derive(Debug, Clone)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

/// Logging configuration for the application
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Base log level for the application
    pub level: LogLevel,
    /// Enable file logging
    pub file_logging: bool,
    /// Log file path (if file logging enabled)
    pub log_file: Option<String>,
    /// Enable colored output (for development)
    pub colored: bool,
    /// Include timestamps
    #[allow(dead_code)]
    pub timestamps: bool,
    /// Include source location (file:line)
    pub include_location: bool,
    /// Component-specific log levels
    pub component_levels: Vec<(String, LogLevel)>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file_logging: false,
            log_file: None,
            colored: true,
            timestamps: true,
            include_location: true,
            component_levels: vec![
                ("nautilus_trader_rig".to_string(), LogLevel::Info),
                ("ort".to_string(), LogLevel::Warn), // Reduce ONNX runtime noise
                ("hf_hub".to_string(), LogLevel::Info),
                ("rig".to_string(), LogLevel::Info),
                ("mcp".to_string(), LogLevel::Debug), // Detailed MCP logging
                ("config".to_string(), LogLevel::Debug),
                ("vector_store".to_string(), LogLevel::Info),
                ("deepseek".to_string(), LogLevel::Info),
            ],
        }
    }
}

impl LogConfig {
    /// Create a new log configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the base log level
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// Enable file logging with specified path
    pub fn with_file_logging<P: AsRef<Path>>(mut self, log_file: P) -> Self {
        self.file_logging = true;
        self.log_file = Some(log_file.as_ref().to_string_lossy().to_string());
        self
    }

    /// Set colored output (useful for development vs production)
    pub fn with_colored(mut self, colored: bool) -> Self {
        self.colored = colored;
        self
    }

    /// Include source code location in logs
    pub fn with_location(mut self, include_location: bool) -> Self {
        self.include_location = include_location;
        self
    }

    /// Add component-specific log level
    pub fn with_component_level(mut self, component: &str, level: LogLevel) -> Self {
        self.component_levels.push((component.to_string(), level));
        self
    }

    /// Initialize the global tracing subscriber with dual output (console + file)
    pub fn init(self) -> Result<()> {
        use tracing_subscriber::layer::SubscriberExt;

        // Build the environment filter
        let mut filter = EnvFilter::from_default_env().add_directive(
            format!(
                "{}={}",
                env!("CARGO_PKG_NAME").replace('-', "_"),
                self.level_string()
            )
            .parse()?,
        );

        // Add component-specific filters
        for (component, level) in &self.component_levels {
            filter =
                filter.add_directive(format!("{}={}", component, level_string(level)).parse()?);
        }

        // Create console layer (always enabled for development)
        let console_layer = tracing_subscriber::fmt::layer()
            .with_ansi(self.colored)
            .with_target(true)
            .with_file(self.include_location)
            .with_line_number(self.include_location)
            .compact();

        // Create the subscriber with console layer
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(console_layer);

        // Add file layer if file logging is enabled
        if self.file_logging {
            if let Some(log_file) = &self.log_file {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_file)
                {
                    Ok(file) => {
                        let file_layer = tracing_subscriber::fmt::layer()
                            .with_ansi(false) // No colors in file
                            .with_target(true)
                            .with_file(true)
                            .with_line_number(true)
                            .compact()
                            .with_writer(file);

                        let subscriber = subscriber.with(file_layer);
                        tracing::subscriber::set_global_default(subscriber)?;

                        info!("🚀 Logging system initialized with console and file output");
                        debug!("Log file: {}", log_file);
                    }
                    Err(e) => {
                        tracing::subscriber::set_global_default(subscriber)?;
                        info!("🚀 Logging system initialized with console output only");
                        eprintln!("❌ Failed to open log file '{}': {}", log_file, e);
                        eprintln!("Continuing with console logging only");
                    }
                }
            } else {
                tracing::subscriber::set_global_default(subscriber)?;
                info!("🚀 Logging system initialized with console output only");
            }
        } else {
            tracing::subscriber::set_global_default(subscriber)?;
            info!("🚀 Logging system initialized with console output only");
        }

        debug!("Log configuration: {:?}", self);

        Ok(())
    }

    fn level_string(&self) -> &'static str {
        level_string(&self.level)
    }
}

fn level_string(level: &LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

/// Initialize logging with default configuration
#[allow(dead_code)]
pub fn init_default_logging() -> Result<()> {
    LogConfig::default().init()
}

/// Initialize logging for development (verbose, colored, with file output)
pub fn init_dev_logging() -> Result<()> {
    // Create logs directory if it doesn't exist
    if !Config::logs_directory_exists() {
        std::fs::create_dir_all(Config::logs_directory())?;
        println!("📁 Created logs directory: {:?}", Config::logs_directory());
    }

    // Generate timestamped log file path
    let log_file = Config::generate_log_file_path();
    println!("📝 Log file will be created at: {:?}", log_file);

    // Test file creation to ensure path is writable
    if let Some(parent) = log_file.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            println!("📁 Created parent directories for log file");
        }
    }

    LogConfig::new()
        .with_level(LogLevel::Debug)
        .with_colored(true)
        .with_location(true)
        .with_file_logging(log_file)
        .with_component_level("nautilus_trader_rig", LogLevel::Debug)
        .with_component_level("mcp", LogLevel::Debug)
        .with_component_level("config", LogLevel::Debug)
        .init()
}

/// Initialize logging for production (concise, file-based)
#[allow(dead_code)]
pub fn init_prod_logging<P: AsRef<Path>>(log_file: P) -> Result<()> {
    LogConfig::new()
        .with_level(LogLevel::Info)
        .with_colored(false)
        .with_location(false)
        .with_file_logging(log_file)
        .with_component_level("ort", LogLevel::Error) // Minimize ONNX noise in prod
        .init()
}

// Structured logging macros for consistent formatting
/// Log file processing operations
macro_rules! log_file_processing {
    ($level:ident, $action:expr, $file:expr) => {
        tracing::$level!("📄 {} file: {}", $action, $file);
    };
    ($level:ident, $action:expr, $file:expr, $size:expr) => {
        tracing::$level!("📄 {} file: {} ({} bytes)", $action, $file, $size);
    };
}

/// Log directory operations  
macro_rules! log_directory_op {
    ($level:ident, $action:expr, $dir:expr) => {
        tracing::$level!("📁 {} directory: {:?}", $action, $dir);
    };
    ($level:ident, $action:expr, $dir:expr, $count:expr) => {
        tracing::$level!("📁 {} directory: {:?} ({} items)", $action, $dir, $count);
    };
}

/// Log configuration operations
#[allow(unused_macros)]
macro_rules! log_config_op {
    ($level:ident, $action:expr, $component:expr) => {
        tracing::$level!("🔧 {} {}", $action, $component);
    };
    ($level:ident, $action:expr, $component:expr, $value:expr) => {
        tracing::$level!("🔧 {} {}: {}", $action, $component, $value);
    };
}

/// Log network/MCP operations
macro_rules! log_mcp_op {
    ($level:ident, $action:expr, $details:expr) => {
        tracing::$level!("🌐 MCP {}: {}", $action, $details);
    };
    ($level:ident, $action:expr) => {
        tracing::$level!("🌐 MCP {}", $action);
    };
}

/// Log performance metrics
#[allow(unused_macros)]
macro_rules! log_performance {
    ($level:ident, $operation:expr, $duration:expr) => {
        tracing::$level!("⏱️ {} took: {:?}", $operation, $duration);
    };
    ($level:ident, $operation:expr, $duration:expr, $count:expr) => {
        tracing::$level!("⏱️ {} took: {:?} ({} items)", $operation, $duration, $count);
    };
}

// Re-export macros for use in other modules
pub(crate) use log_directory_op;
pub(crate) use log_file_processing;
pub(crate) use log_mcp_op;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_creation() {
        let config = LogConfig::new()
            .with_level(LogLevel::Debug)
            .with_colored(false)
            .with_location(true);

        assert!(matches!(config.level, LogLevel::Debug));
        assert!(!config.colored);
        assert!(config.include_location);
    }

    #[test]
    fn test_level_conversion() {
        assert_eq!(Level::from(LogLevel::Info), Level::INFO);
        assert_eq!(Level::from(LogLevel::Debug), Level::DEBUG);
        assert_eq!(Level::from(LogLevel::Error), Level::ERROR);
    }
}
