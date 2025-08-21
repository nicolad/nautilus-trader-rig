use serde::{Deserialize, Serialize};
use std::path::PathBimpl Default for AutopatcherConfig {
    fn default() -> Self {
        Self {
            model: "deepseek-chat".to_string(),
            max_tokens: 8192,
            temperature: 0.3,
            max_iterations: 1000, // Increased to allow much longer runsderive(Debug, Clone, Serialize, Deserialize)]
pub struct CronConfig {
    /// Cron schedule expression (e.g., "0 */5 * * * *" for every 5 minutes)
    pub schedule: String,
}

impl Default for CronConfig {
    fn default() -> Self {
        Self {
            schedule: "0 */5 * * * *".to_string(), // Every 5 minutes
        }
    }
}

impl CronConfig {
    /// Validate cron configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.schedule.is_empty() {
            return Err("schedule cannot be empty".to_string());
        }
        Ok(())
    }
}

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
    /// Enable self-improvement checks
    pub enable_self_improvement: bool,
    /// Enable automatic PR creation
    pub enable_auto_pr: bool,
    /// Frequency of outcome checks (every N iterations)
    pub outcome_check_frequency: usize,
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
            enable_self_improvement: true,
            enable_auto_pr: true,
            outcome_check_frequency: 1, // Check every iteration
        }
    }
}

impl AutopatcherConfig {
    /// Load configuration from environment variables and defaults
    pub fn from_env() -> Self {
        Self::default()
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

        if self.outcome_check_frequency == 0 {
            return Err("outcome_check_frequency must be greater than 0".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// GitHub personal access token
    pub token: Option<String>,
    /// Target repository URL (e.g., "https://github.com/nicolad/nautilus_trader")
    pub target_repo_url: String,
    /// Whether to enable self-improvement
    pub enable_self_improvement: bool,
    /// Whether to enable automatic PR creation
    pub enable_auto_pr: bool,
    /// How often to check for self-improvements (every N iterations)
    pub self_improvement_frequency: usize,
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            token: None,
            target_repo_url: "https://github.com/nicolad/nautilus_trader".to_string(),
            enable_self_improvement: true,
            enable_auto_pr: true,
            self_improvement_frequency: 5,
        }
    }
}

impl GitHubConfig {
    /// Load from environment variables
    pub fn from_env() -> Self {
        Self {
            token: std::env::var("GITHUB_TOKEN").ok(),
            target_repo_url: std::env::var("TARGET_REPO_URL")
                .unwrap_or_else(|_| "https://github.com/nicolad/nautilus_trader".to_string()),
            enable_self_improvement: std::env::var("ENABLE_SELF_IMPROVEMENT")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            enable_auto_pr: std::env::var("ENABLE_AUTO_PR")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            self_improvement_frequency: std::env::var("SELF_IMPROVEMENT_FREQUENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
        }
    }

    /// Validate the GitHub configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.enable_auto_pr || self.enable_self_improvement {
            if self.token.is_none() {
                return Err(
                    "GITHUB_TOKEN is required when self-improvement or auto-PR is enabled"
                        .to_string(),
                );
            }
        }

        if self.target_repo_url.is_empty() {
            return Err("target_repo_url cannot be empty".to_string());
        }

        if self.self_improvement_frequency == 0 {
            return Err("self_improvement_frequency must be greater than 0".to_string());
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
        assert!(
            config.validate().is_ok(),
            "minimum valid values should pass"
        );
    }

    #[test]
    fn test_config_from_env() {
        let config = AutopatcherConfig::from_env();
        assert!(config.validate().is_ok(), "Config from env should be valid");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitConfig {
    /// Git user name for commits
    pub user_name: String,
    /// Git user email for commits
    pub user_email: String,
    /// Files to exclude from autopatcher (never touch these)
    pub excluded_files: Vec<String>,
    /// Remote repository URL (optional, uses current remote if not set)
    pub remote_url: Option<String>,
    /// Branch to push to (defaults to current branch)
    pub target_branch: Option<String>,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            user_name: "nicolad".to_string(),
            user_email: "nicolai.vadim@gmail.com".to_string(),
            excluded_files: vec![
                ".gitignore".to_string(),
                ".env".to_string(),
                "*.pem".to_string(),
                "*.key".to_string(),
            ],
            remote_url: None,
            target_branch: None,
        }
    }
}

impl GitConfig {
    /// Load Git configuration from environment
    pub fn from_env() -> Self {
        Self {
            user_name: "nicolad".to_string(),
            user_email: "nicolai.vadim@gmail.com".to_string(),
            excluded_files: vec![
                ".gitignore".to_string(),
                ".env".to_string(),
                "*.pem".to_string(),
                "*.key".to_string(),
            ],
            remote_url: std::env::var("https://github.com/nicolad/nautilus_trader_rig").ok(),
            target_branch: std::env::var("main").ok(),
        }
    }

    /// Validate Git configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.user_name.is_empty() {
            return Err("git user_name cannot be empty".to_string());
        }
        if self.user_email.is_empty() {
            return Err("git user_email cannot be empty".to_string());
        }
        Ok(())
    }

    /// Check if a file should be excluded from autopatcher
    pub fn is_excluded(&self, file_path: &str) -> bool {
        self.excluded_files.iter().any(|pattern| {
            if pattern.contains('*') {
                // Simple wildcard matching - just check if the pattern matches the end
                let pattern_without_star = pattern.replace("*", "");
                file_path.contains(&pattern_without_star)
            } else {
                file_path == pattern || file_path.ends_with(pattern)
            }
        })
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
    pub cron: CronConfig,
    pub git: GitConfig,
    pub github: GitHubConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            autopatcher: AutopatcherConfig::default(),
            mcp: MCPConfig::default(),
            cron: CronConfig::default(),
            git: GitConfig::default(),
            github: GitHubConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            autopatcher: AutopatcherConfig::from_env(),
            mcp: MCPConfig::default(),
            cron: CronConfig::default(),
            git: GitConfig::from_env(),
            github: GitHubConfig::from_env(),
        }
    }

    /// Validate the entire configuration
    pub fn validate(&self) -> Result<(), String> {
        self.autopatcher.validate()?;
        self.cron.validate()?;
        self.git.validate()?;
        self.github.validate()?;
        Ok(())
    }
}
