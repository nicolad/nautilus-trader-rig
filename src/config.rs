// Configuration module for Nautilus Trader Rig
//
// This module contains configuration constants and paths used throughout the application

use std::path::Path;

/// Application configuration constants
pub struct Config;

impl Config {
    /// Path to the environment file
    pub const ENV_FILE_PATH: &'static str = "nautilus-trader-rig/.env";
    
    /// Default MCP server port
    pub const DEFAULT_MCP_PORT: u16 = 3000;
    
    /// Default bugs directory
    pub const BUGS_DIRECTORY: &'static str = "bugs";
    
    /// Default logs directory
    pub const LOGS_DIRECTORY: &'static str = "logs";
    
    /// Nautilus Trader adapters directory (Python files)
    pub const ADAPTERS_DIRECTORY: &'static str = "../nautilus_trader/adapters";
    
    /// Core Rust adapters directory
    pub const CORE_ADAPTERS_DIRECTORY: &'static str = "./crates/adapters";
    
    /// Rust adapter file patterns
    pub const RUST_FILE_EXTENSIONS: &'static [&'static str] = &["*.rs"];
    
    /// Vector similarity search limit
    pub const DEFAULT_SEARCH_LIMIT: usize = 10;
    
    /// DeepSeek model name
    pub const DEEPSEEK_MODEL: &'static str = "deepseek-chat";
    
    /// FastEmbed model dimension
    pub const FASTEMBED_DIMENSION: usize = 384;
}

impl Config {
    /// Get the full path to the environment file
    pub fn env_file_path() -> &'static Path {
        Path::new(Self::ENV_FILE_PATH)
    }
    
    /// Get the full path to the bugs directory
    pub fn bugs_directory() -> &'static Path {
        Path::new(Self::BUGS_DIRECTORY)
    }
    
    /// Get the full path to the logs directory
    pub fn logs_directory() -> &'static Path {
        Path::new(Self::LOGS_DIRECTORY)
    }
    
    /// Check if environment file exists
    pub fn env_file_exists() -> bool {
        Self::env_file_path().exists()
    }
    
    /// Check if bugs directory exists
    pub fn bugs_directory_exists() -> bool {
        Self::bugs_directory().exists()
    }
    
    /// Check if logs directory exists
    pub fn logs_directory_exists() -> bool {
        Self::logs_directory().exists()
    }
    
    /// Generate a log file path with timestamp
    pub fn generate_log_file_path() -> std::path::PathBuf {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        Self::logs_directory().join(format!("nautilus_trader_rig_{}.log", timestamp))
    }
    
    /// Get the full path to the Rust adapters directory
    pub fn rust_adapters_directory() -> &'static Path {
        Path::new(Self::CORE_ADAPTERS_DIRECTORY)
    }
    
    /// Get the full path to the Rust core directory
    pub fn rust_core_directory() -> &'static Path {
        Path::new(Self::CORE_ADAPTERS_DIRECTORY)
    }
    
    /// Check if Rust adapters directory exists
    pub fn rust_adapters_directory_exists() -> bool {
        Self::rust_adapters_directory().exists()
    }
    
    /// Check if Rust core directory exists
    pub fn rust_core_directory_exists() -> bool {
        Self::rust_core_directory().exists()
    }
    
    /// Get all Rust adapter directories
    pub fn all_rust_adapter_directories() -> Vec<&'static Path> {
        vec![
            Self::rust_adapters_directory(),
            Self::rust_core_directory(),
        ]
    }
    
    /// Get list of supported Rust file extensions
    pub fn rust_extensions() -> &'static [&'static str] {
        Self::RUST_FILE_EXTENSIONS
    }
    
    /// Get Rust adapter directory path by name
    pub fn rust_adapter_path(adapter_name: &str) -> std::path::PathBuf {
        Path::new(Self::CORE_ADAPTERS_DIRECTORY).join(adapter_name)
    }
}