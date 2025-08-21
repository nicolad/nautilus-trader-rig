// src/pr.rs
//
// Pull Request module for creating and managing PRs against nautilus_trader repository
// Follows established commit patterns and contribution guidelines

use crate::DeepSeekClient;
use anyhow::{anyhow, Context, Result};
use octocrab::Octocrab;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrConfig {
    pub base_repo: String,   // "nicolad/nautilus_trader"
    pub fork_repo: String,   // User's fork
    pub base_branch: String, // "master" or "main"
    pub work_branch: String, // Feature branch name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrRequest {
    pub title: String,
    pub description: String,
    pub changes: Vec<FileChange>,
    pub category: PrCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub action: ChangeAction,
    pub content: Option<String>,
    pub diff: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeAction {
    Create,
    Modify,
    Delete,
}

impl std::fmt::Display for ChangeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeAction::Create => write!(f, "Create"),
            ChangeAction::Modify => write!(f, "Modify"),
            ChangeAction::Delete => write!(f, "Delete"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrCategory {
    Fix,
    Feature,
    Improvement,
    Refactor,
    Documentation,
    Test,
}

pub struct PrManager {
    client: DeepSeekClient,
    github: Octocrab,
    config: PrConfig,
}

impl PrManager {
    pub fn new(client: DeepSeekClient, github_token: &str, config: PrConfig) -> Result<Self> {
        let github = Octocrab::builder()
            .personal_token(github_token.to_string())
            .build()?;

        Ok(Self {
            client,
            github,
            config,
        })
    }

    /// Create a new pull request with automated optimization
    pub async fn create_pr(&self, mut request: PrRequest) -> Result<PrResult> {
        // Optimize the PR before creation
        request = self.optimize_pr(request).await?;

        // Create branch and apply changes
        let branch_name = self.create_branch(&request).await?;
        self.apply_changes(&request.changes).await?;

        // Generate commit message following nautilus_trader patterns
        let commit_msg = self.generate_commit_message(&request).await?;
        self.commit_changes(&commit_msg).await?;

        // Push to fork
        self.push_branch(&branch_name).await?;

        // Create GitHub PR
        let pr_url = self.create_github_pr(&request, &branch_name).await?;

        Ok(PrResult {
            pr_url,
            branch_name,
            commit_message: commit_msg,
            files_changed: request.changes.len(),
        })
    }

    /// Analyze existing codebase to suggest PR opportunities
    pub async fn suggest_pr_opportunities(&self, repo_path: &str) -> Result<Vec<PrOpportunity>> {
        let analysis = self.analyze_repository(repo_path).await?;
        let opportunities = self.identify_opportunities(&analysis).await?;

        Ok(opportunities)
    }

    /// Validate PR against repository standards
    pub async fn validate_pr(&self, request: &PrRequest) -> Result<ValidationResult> {
        let mut issues = Vec::new();

        // Check commit message format
        if !self.validate_title(&request.title) {
            issues.push(
                "Title doesn't follow pattern: <Action> <Component> <description>".to_string(),
            );
        }

        // Check file changes
        for change in &request.changes {
            if let Some(validation_issue) = self.validate_file_change(change).await? {
                issues.push(validation_issue);
            }
        }

        // Check description completeness
        if request.description.len() < 50 {
            issues.push("Description too short. Provide detailed explanation.".to_string());
        }

        Ok(ValidationResult {
            is_valid: issues.is_empty(),
            issues: issues.clone(),
            suggestions: self.generate_suggestions(&issues).await?,
        })
    }

    async fn optimize_pr(&self, mut request: PrRequest) -> Result<PrRequest> {
        // Optimize title
        request.title = self.optimize_title(&request.title).await?;

        // Enhance description
        request.description = self.enhance_description(&request).await?;

        // Optimize file changes
        for change in &mut request.changes {
            if let Some(content) = &change.content {
                change.content = Some(self.optimize_code(content).await?);
            }
        }

        Ok(request)
    }

    async fn create_branch(&self, request: &PrRequest) -> Result<String> {
        let branch_name = self.generate_branch_name(request).await?;

        // Create and checkout new branch
        let output = Command::new("git")
            .args(&["checkout", "-b", &branch_name])
            .output()
            .context("Failed to create git branch")?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to create branch: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(branch_name)
    }

    async fn apply_changes(&self, changes: &[FileChange]) -> Result<()> {
        for change in changes {
            match change.action {
                ChangeAction::Create | ChangeAction::Modify => {
                    if let Some(content) = &change.content {
                        std::fs::write(&change.path, content)
                            .context(format!("Failed to write file: {}", change.path))?;
                    }
                }
                ChangeAction::Delete => {
                    std::fs::remove_file(&change.path)
                        .context(format!("Failed to delete file: {}", change.path))?;
                }
            }
        }
        Ok(())
    }

    async fn generate_commit_message(&self, request: &PrRequest) -> Result<String> {
        let action = match request.category {
            PrCategory::Fix => "Fix",
            PrCategory::Feature => "Add",
            PrCategory::Improvement => "Improve",
            PrCategory::Refactor => "Refactor",
            PrCategory::Documentation => "Update",
            PrCategory::Test => "Add",
        };

        // Extract component from file paths
        let component = self.extract_component(&request.changes);

        let prompt = format!(
            "Generate a commit message following nautilus_trader pattern: '{} {} <description>'
            
            Changes:
            {}
            
            Pattern examples:
            - Fix BitMEX reconnection logic
            - Add OKX position reconciliation
            - Improve adapter error handling
            - Refactor execution engine
            
            Keep it concise and specific.",
            action,
            component,
            request
                .changes
                .iter()
                .map(|c| format!("- {}: {}", c.action, c.path))
                .collect::<Vec<_>>()
                .join("\n")
        );

        let response = self.client.prompt(&prompt).await?;
        Ok(response.trim().to_string())
    }

    async fn commit_changes(&self, message: &str) -> Result<()> {
        // Stage all changes
        Command::new("git")
            .args(&["add", "."])
            .output()
            .context("Failed to stage changes")?;

        // Commit with message
        let output = Command::new("git")
            .args(&["commit", "-m", message])
            .output()
            .context("Failed to commit changes")?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to commit: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    async fn push_branch(&self, branch_name: &str) -> Result<()> {
        let output = Command::new("git")
            .args(&["push", "origin", branch_name])
            .output()
            .context("Failed to push branch")?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to push: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    async fn create_github_pr(&self, request: &PrRequest, branch_name: &str) -> Result<String> {
        let parts: Vec<&str> = self.config.base_repo.split('/').collect();
        let owner = parts[0];
        let repo = parts[1];

        let pr = self
            .github
            .pulls(owner, repo)
            .create(
                &request.title,
                &format!("{}:{}", owner, branch_name),
                &self.config.base_branch,
            )
            .body(&request.description)
            .send()
            .await
            .context("Failed to create GitHub PR")?;

        Ok(pr.html_url.unwrap().to_string())
    }

    fn validate_title(&self, title: &str) -> bool {
        let pattern = regex::Regex::new(
            r"^(Fix|Add|Improve|Refine|Standardize|Remove|Update|Implement|Continue)\s+\w+\s+.+",
        )
        .unwrap();
        pattern.is_match(title)
    }

    async fn validate_file_change(&self, change: &FileChange) -> Result<Option<String>> {
        // Validate file patterns
        if change.path.contains("test")
            && !matches!(change.action, ChangeAction::Create | ChangeAction::Modify)
        {
            return Ok(Some("Avoid deleting test files".to_string()));
        }

        // Validate Rust code if applicable
        if change.path.ends_with(".rs") {
            if let Some(content) = &change.content {
                return self.validate_rust_code(content).await;
            }
        }

        Ok(None)
    }

    async fn validate_rust_code(&self, code: &str) -> Result<Option<String>> {
        // Basic validation - could be enhanced with rust analyzer
        if !code.contains("use ") && code.len() > 100 {
            return Ok(Some("Consider adding proper imports".to_string()));
        }

        Ok(None)
    }

    async fn generate_suggestions(&self, issues: &[String]) -> Result<Vec<String>> {
        if issues.is_empty() {
            return Ok(vec!["PR looks good!".to_string()]);
        }

        let prompt = format!(
            "Generate suggestions to fix these PR issues:
            {}
            
            Focus on nautilus_trader contribution guidelines.",
            issues.join("\n- ")
        );

        let response = self.client.prompt(&prompt).await?;
        Ok(response.lines().map(|s| s.trim().to_string()).collect())
    }

    async fn analyze_repository(&self, _repo_path: &str) -> Result<RepoAnalysis> {
        // Placeholder for repository analysis
        Ok(RepoAnalysis {
            total_files: 0,
            rust_files: 0,
            test_coverage: 0.0,
            issues: vec![],
        })
    }

    async fn identify_opportunities(&self, _analysis: &RepoAnalysis) -> Result<Vec<PrOpportunity>> {
        // Identify potential improvement opportunities
        Ok(vec![])
    }

    async fn optimize_title(&self, title: &str) -> Result<String> {
        if self.validate_title(title) {
            return Ok(title.to_string());
        }

        let prompt = format!(
            "Optimize this title to follow nautilus_trader pattern '<Action> <Component> <description>':
            Original: {}
            
            Use actions: Fix, Add, Improve, Refine, Standardize, Remove, Update, Implement, Continue
            Keep it concise and specific.",
            title
        );

        let response = self.client.prompt(&prompt).await?;
        Ok(response.trim().to_string())
    }

    async fn enhance_description(&self, request: &PrRequest) -> Result<String> {
        if request.description.len() > 200 {
            return Ok(request.description.clone());
        }

        let prompt = format!(
            "Enhance this PR description for nautilus_trader:
            
            Title: {}
            Current description: {}
            Changes: {} files
            
            Include:
            - What problem this solves
            - How it's implemented
            - Testing approach
            - Breaking changes (if any)
            
            Keep it professional and comprehensive.",
            request.title,
            request.description,
            request.changes.len()
        );

        let response = self.client.prompt(&prompt).await?;
        Ok(response.trim().to_string())
    }

    async fn optimize_code(&self, code: &str) -> Result<String> {
        // Basic code optimization - could be enhanced
        Ok(code.to_string())
    }

    async fn generate_branch_name(&self, request: &PrRequest) -> Result<String> {
        let category = match request.category {
            PrCategory::Fix => "fix",
            PrCategory::Feature => "feature",
            PrCategory::Improvement => "improve",
            PrCategory::Refactor => "refactor",
            PrCategory::Documentation => "docs",
            PrCategory::Test => "test",
        };

        let component = self.extract_component(&request.changes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(format!(
            "{}-{}-{}",
            category,
            component.to_lowercase(),
            timestamp
        ))
    }

    fn extract_component(&self, changes: &[FileChange]) -> String {
        // Extract component from file paths
        for change in changes {
            if change.path.contains("bitmex") {
                return "bitmex".to_string();
            }
            if change.path.contains("bybit") {
                return "bybit".to_string();
            }
            if change.path.contains("okx") {
                return "okx".to_string();
            }
            if change.path.contains("adapter") {
                return "adapters".to_string();
            }
            if change.path.contains("execution") {
                return "execution".to_string();
            }
            if change.path.contains("backtest") {
                return "backtest".to_string();
            }
            if change.path.contains("live") {
                return "live".to_string();
            }
        }
        "core".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrResult {
    pub pr_url: String,
    pub branch_name: String,
    pub commit_message: String,
    pub files_changed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub issues: Vec<String>,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrOpportunity {
    pub title: String,
    pub description: String,
    pub category: PrCategory,
    pub effort: Effort,
    pub impact: Impact,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoAnalysis {
    pub total_files: usize,
    pub rust_files: usize,
    pub test_coverage: f64,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effort {
    Low,    // 1-2 hours
    Medium, // 1-2 days
    High,   // 1+ weeks
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Impact {
    Low,    // Minor improvement
    Medium, // Noticeable improvement
    High,   // Significant improvement
}
