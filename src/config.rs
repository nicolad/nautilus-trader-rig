use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutopatcherConfig {
    /// The model to use for the autopatcher
    pub model: String,
    /// The maximum number of tokens to generate
    pub max_tokens: u32,
    /// The temperature for generation (0.0 to 1.0)
    pub temperature: f32,
    /// The number of iterations to run the autopatcher
    pub max_iterations: usize,
    /// Whether to enable streaming output
    pub enable_streaming: bool,
    /// Target directory to work on
    pub target: PathBuf,
    /// Number of candidates per iteration
    pub candidates: usize,
    /// Number of parallel jobs
    pub jobs: usize,
    /// Maximum files in snapshot
    pub snapshot_max_files: usize,
    /// Maximum bytes per file
    pub snapshot_max_bytes: usize,
}

impl Default for AutopatcherConfig {
    fn default() -> Self {
        Self {
            model: "deepseek-chat".to_string(),
            max_tokens: 4000,
            temperature: 0.1,
            max_iterations: 5,
            enable_streaming: true,
            target: PathBuf::from("."),
            candidates: 3,
            jobs: 3,
            snapshot_max_files: 40,
            snapshot_max_bytes: 8_192,
        }
    }
}

impl AutopatcherConfig {
    /// Load configuration from environment variables and defaults
    pub fn from_env() -> Self {
        Self {
            model: "deepseek-chat".to_string(),
            max_tokens: 4000,
            temperature: 0.1,
            max_iterations: 5,
            enable_streaming: true,
            target: PathBuf::from("."),
            candidates: 3,
            jobs: 3,
            snapshot_max_files: 40,
            snapshot_max_bytes: 8_192,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_tokens == 0 {
            return Err("max_tokens must be greater than 0".to_string());
        }

        if !(0.0..=2.0).contains(&self.temperature) {
            return Err("temperature must be between 0.0 and 2.0".to_string());
        }

        if self.max_iterations == 0 {
            return Err("max_iterations must be greater than 0".to_string());
        }

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = AutopatcherConfig::default();
        assert!(config.validate().is_ok(), "Default config should be valid");
    }

    #[test]
    fn test_autopatcher_config_validation_errors() {
        let mut config = AutopatcherConfig::default();
        
        // Test max_tokens validation
        config.max_tokens = 0;
        assert!(config.validate().is_err(), "max_tokens=0 should fail");
        
        // Test temperature validation
        config.max_tokens = 4000;
        config.temperature = 2.1;
        assert!(config.validate().is_err(), "temperature=2.1 should fail");
        
        config.temperature = -0.1;
        assert!(config.validate().is_err(), "temperature=-0.1 should fail");
        
        // Test max_iterations validation
        config.temperature = 0.1;
        config.max_iterations = 0;
        assert!(config.validate().is_err(), "max_iterations=0 should fail");
    }

    #[test]
    fn test_autopatcher_config_validation_edge_cases() {
        let mut config = AutopatcherConfig::default();
        
        // Test temperature bounds (0.0 and 2.0 should be valid)
        config.temperature = 0.0;
        assert!(config.validate().is_ok(), "temperature=0.0 should be valid");
        
        config.temperature = 2.0;
        assert!(config.validate().is_ok(), "temperature=2.0 should be valid");
        
        // Test minimum valid values
        config.temperature = 0.1;
        config.max_tokens = 1;
        config.max_iterations = 1;
        assert!(config.validate().is_ok(), "minimum valid values should pass");
    }

    #[test]
    fn test_config_from_env() {
        let config = AutopatcherConfig::from_env();
        assert!(config.validate().is_ok(), "Config from env should be valid");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPConfig {
    /// The MCP server name
    pub name: String,
    /// The version of the MCP server
    pub version: String,
    /// Whether to enable debug logging
    pub debug: bool,
}

impl Default for MCPConfig {
    fn default() -> Self {
        Self {
            name: "nautilus-autopatcher".to_string(),
            version: "1.0.0".to_string(),
            debug: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub autopatcher: AutopatcherConfig,
    pub mcp: MCPConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            autopatcher: AutopatcherConfig::default(),
            mcp: MCPConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            autopatcher: AutopatcherConfig::from_env(),
            mcp: MCPConfig::default(),
        }
    }

    /// Validate the entire configuration
    pub fn validate(&self) -> Result<(), String> {
        self.autopatcher.validate()?;
        Ok(())
    }
}
