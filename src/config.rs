// Configuration module for Nautilus Trader Rig
//
// This module contains configuration constants and paths used throughout the application

use std::path::Path;

/// Application configuration constants
pub struct Config;

#[allow(dead_code)]
impl Config {
    /// Path to the environment file (relative to crate dir)
    pub const ENV_FILE_PATH: &'static str = ".env";
    
    /// Default MCP server port
    pub const DEFAULT_MCP_PORT: u16 = 3000;
    
    /// Default bugs directory (relative name; use bugs_directory_path() for absolute)
    pub const BUGS_DIRECTORY: &'static str = "bugs";
    
    /// Default logs directory
    pub const LOGS_DIRECTORY: &'static str = "logs";
    
    /// Nautilus Trader adapters directory (Python files)
    pub const ADAPTERS_DIRECTORY: &'static str = "../nautilus_trader/adapters";
    
    /// Core Rust adapters directory
    /// Note: This path is relative to the nautilus-trader-rig crate directory.
    /// The adapters live at the repo root under `crates/adapters`, so from
    /// within `nautilus-trader-rig/` we must go up one level.
    pub const CORE_ADAPTERS_DIRECTORY: &'static str = "../crates/adapters";
    
    /// Rust adapter file extensions (without leading dot)
    pub const RUST_FILE_EXTENSIONS: &'static [&'static str] = &["rs"];
    
    /// Vector similarity search limit
    pub const DEFAULT_SEARCH_LIMIT: usize = 10;
    
    /// DeepSeek model name
    pub const DEEPSEEK_MODEL: &'static str = "deepseek-chat";
    
    /// FastEmbed model dimension
    pub const FASTEMBED_DIMENSION: usize = 384;
}

#[allow(dead_code)]
impl Config {
    /// Absolute path to this crate's directory at compile time
    pub fn manifest_dir() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }
    
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
    
    /// Absolute bugs directory path, independent of current working directory
    pub fn bugs_directory_path() -> std::path::PathBuf {
        Self::manifest_dir().join("bugs")
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

    /// Absolute paths for Rust adapter directories (preferred for robust execution)
    pub fn all_rust_adapter_directories_abs() -> Vec<std::path::PathBuf> {
        let base = Self::manifest_dir();
        vec![
            base.join("../crates/adapters"),
            base.join("../crates/adapters"), // kept twice to mirror existing API semantics
        ]
    }
    
    /// Absolute path to core adapters directory
    pub fn core_adapters_directory_abs() -> std::path::PathBuf {
        Self::manifest_dir().join("../crates/adapters")
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