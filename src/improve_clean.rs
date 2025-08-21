// src/improve.rs
//
// Self-improvement module for analyzing and enhancing code quality
// Based on established patterns from nautilus_trader repository

use crate::{logging::FileLogger, DeepSeekClient};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAnalysis {
    pub file_path: String,
    pub issues: Vec<QualityIssue>,
    pub improvements: Vec<Improvement>,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityIssue {
    pub category: IssueCategory,
    pub severity: Severity,
    pub line: Option<u32>,
    pub description: String,
    pub suggestion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueCategory {
    Naming,
    ErrorHandling,
    Performance,
    Architecture,
    Testing,
    Documentation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Improvement {
    pub title: String,
    pub description: String,
    pub impact: Impact,
    pub effort: Effort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Impact {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effort {
    Low,
    Medium,
    High,
}

pub struct Improver {
    client: DeepSeekClient,
    patterns: PatternDatabase,
    logger: FileLogger,
    recent_commits: HashSet<String>,
}

pub struct PatternDatabase {
    pub naming_patterns: HashMap<String, String>,
    pub error_patterns: Vec<String>,
    pub architecture_patterns: Vec<String>,
}

impl Improver {
    pub fn new(client: DeepSeekClient, logger: FileLogger) -> Self {
        Self {
            client,
            patterns: PatternDatabase::default(),
            logger,
            recent_commits: HashSet::new(),
        }
    }

    /// Initialize recent commits cache to avoid duplicates
    pub async fn load_recent_commits(&mut self) -> Result<()> {
        self.logger
            .operation_start("LOAD_COMMITS", "Loading recent commits to avoid duplicates")
            .await?;

        let output = Command::new("git")
            .args(&["log", "--oneline", "-20", "--pretty=format:%s"])
            .output()?;

        if output.status.success() {
            let commits = String::from_utf8_lossy(&output.stdout);
            for line in commits.lines() {
                let commit_msg = line.trim();
                if !commit_msg.is_empty() {
                    self.recent_commits.insert(commit_msg.to_string());
                }
            }

            self.logger
                .info(&format!(
                    "Loaded {} recent commits to prevent duplicates",
                    self.recent_commits.len()
                ))
                .await?;
            self.logger
                .operation_complete("LOAD_COMMITS", 0, true)
                .await?;
        } else {
            self.logger
                .warn("Failed to load recent commits - duplicate detection disabled")
                .await?;
        }

        Ok(())
    }

    /// Check if a commit message would create a duplicate
    pub fn is_duplicate_commit(&self, commit_message: &str) -> bool {
        let normalized = self.normalize_commit_message(commit_message);
        self.recent_commits.contains(&normalized)
    }

    /// Add a commit message to the recent commits cache
    pub fn add_commit_to_cache(&mut self, commit_message: &str) {
        let normalized = self.normalize_commit_message(commit_message);
        self.recent_commits.insert(normalized);
    }

    /// Normalize commit message for duplicate detection
    fn normalize_commit_message(&self, message: &str) -> String {
        // Remove timestamps and normalize whitespace
        message
            .trim()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    }

    /// Generate unique commit message by adding suffix if needed
    pub async fn ensure_unique_commit(&mut self, base_message: &str) -> Result<String> {
        if !self.is_duplicate_commit(base_message) {
            self.add_commit_to_cache(base_message);
            return Ok(base_message.to_string());
        }

        self.logger
            .warn(&format!("Duplicate commit detected: {}", base_message))
            .await?;

        // Try adding a suffix to make it unique
        for i in 1..=10 {
            let candidate = format!("{} (v{})", base_message, i);
            if !self.is_duplicate_commit(&candidate) {
                self.logger
                    .info(&format!("Generated unique commit: {}", candidate))
                    .await?;
                self.add_commit_to_cache(&candidate);
                return Ok(candidate);
            }
        }

        // If we can't find a unique version, add timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let unique_message = format!("{} [{}]", base_message, timestamp);
        self.add_commit_to_cache(&unique_message);

        self.logger
            .info(&format!(
                "Generated timestamped unique commit: {}",
                unique_message
            ))
            .await?;
        Ok(unique_message)
    }

    /// Suggest alternative commit message to avoid duplication
    pub async fn suggest_alternative_commit(
        &self,
        base_message: &str,
        context: &str,
    ) -> Result<String> {
        if !self.is_duplicate_commit(base_message) {
            return Ok(base_message.to_string());
        }

        let recent_commits_list = self
            .recent_commits
            .iter()
            .take(10)
            .map(|s| format!("- {}", s))
            .collect::<Vec<_>>()
            .join("\n");

        let prompt = format!(
            "The commit message '{}' would be a duplicate.\n\nContext: {}\n\nRecent commits to avoid:\n{}\n\nGenerate an alternative commit message that:\n1. Describes the same change but with different wording\n2. Is more specific about what was changed\n3. Follows the pattern: <Action> <Component> <specific description>\n4. Avoids duplicating recent commits\n\nReturn only the alternative commit message.",
            base_message,
            context,
            recent_commits_list
        );

        let response = self.client.prompt(&prompt).await?;
        let alternative = response.trim().to_string();

        self.logger
            .info(&format!("AI suggested alternative commit: {}", alternative))
            .await?;
        Ok(alternative)
    }

    /// Analyze code quality and suggest improvements
    pub async fn analyze_code(&self, file_path: &str, content: &str) -> Result<CodeAnalysis> {
        let start_time = Instant::now();

        self.logger
            .operation_start("CODE_ANALYSIS", &format!("Analyzing file: {}", file_path))
            .await?;
        self.logger
            .debug(&format!(
                "File content length: {} characters",
                content.len()
            ))
            .await?;

        let prompt = format!(
            "Analyze this Rust code for quality issues and improvements:\n\nFile: {}\n\nCode:\n{}\n\nBased on nautilus_trader patterns:\n1. Use snake_case naming consistently\n2. Provide specific error messages\n3. Implement proper validation\n4. Follow standardized subscription methods\n5. Ensure consistent disconnect sequences\n\nReturn analysis as JSON with issues and improvements.",
            file_path, content
        );

        self.logger
            .debug(&format!(
                "Sending analysis prompt: {} characters",
                prompt.len()
            ))
            .await?;
        let ai_start = Instant::now();
        let response = self.client.prompt(&prompt).await?;
        let ai_duration = ai_start.elapsed().as_millis() as u64;

        self.logger
            .ai_interaction("Code-Analyzer", prompt.len(), response.len(), ai_duration)
            .await?;

        // Parse response and extract analysis
        let analysis = self.parse_analysis_response(&response, file_path)?;

        let duration = start_time.elapsed().as_millis() as u64;
        let issue_count = analysis.issues.len();
        let improvement_count = analysis.improvements.len();

        self.logger
            .operation_complete("CODE_ANALYSIS", duration, true)
            .await?;
        self.logger
            .info(&format!(
                "Analysis complete for {}: {} issues, {} improvements, score: {:.1}",
                file_path, issue_count, improvement_count, analysis.score
            ))
            .await?;

        // Log detailed findings
        for issue in &analysis.issues {
            self.logger
                .debug(&format!(
                    "Issue found: {:?} severity {:?} at line {:?}: {}",
                    issue.category, issue.severity, issue.line, issue.description
                ))
                .await?;
        }

        Ok(analysis)
    }

    /// Generate improvement plan for codebase
    pub async fn create_improvement_plan(
        &self,
        analyses: &[CodeAnalysis],
    ) -> Result<ImprovementPlan> {
        let start_time = Instant::now();

        self.logger
            .operation_start(
                "CREATE_PLAN",
                &format!("Creating plan for {} files", analyses.len()),
            )
            .await?;

        let total_issues = analyses.iter().map(|a| a.issues.len()).sum::<usize>();
        let avg_score = analyses.iter().map(|a| a.score).sum::<f64>() / analyses.len() as f64;

        let priorities = self.prioritize_improvements(analyses);
        let timeline = self.estimate_timeline(&priorities);

        let duration = start_time.elapsed().as_millis() as u64;
        self.logger
            .operation_complete("CREATE_PLAN", duration, true)
            .await?;
        self.logger
            .info(&format!(
                "Timeline: {} immediate, {} short-term, {} medium-term",
                timeline.immediate, timeline.short_term, timeline.medium_term
            ))
            .await?;

        Ok(ImprovementPlan {
            total_files: analyses.len(),
            total_issues,
            average_score: avg_score,
            priorities: priorities.clone(),
            timeline,
        })
    }

    /// Apply automated fixes to code
    pub async fn apply_fixes(&self, analysis: &CodeAnalysis, content: &str) -> Result<String> {
        let start_time = Instant::now();

        self.logger
            .operation_start(
                "APPLY_FIXES",
                &format!(
                    "Fixing {} issues in {}",
                    analysis.issues.len(),
                    analysis.file_path
                ),
            )
            .await?;

        let mut fixed_content = content.to_string();
        let mut fixes_applied = 0;
        let mut fixes_skipped = 0;

        for issue in &analysis.issues {
            if self.can_auto_fix(issue) {
                self.logger
                    .debug(&format!("Applying fix for: {}", issue.description))
                    .await?;
                match self.apply_fix(&fixed_content, issue).await {
                    Ok(new_content) => {
                        fixed_content = new_content;
                        fixes_applied += 1;
                        self.logger
                            .debug(&format!("Fix applied: {}", issue.description))
                            .await?;
                    }
                    Err(e) => {
                        self.logger
                            .warn(&format!("Fix failed for {}: {}", issue.description, e))
                            .await?;
                        fixes_skipped += 1;
                    }
                }
            } else {
                self.logger
                    .debug(&format!("Skipping manual fix: {}", issue.description))
                    .await?;
                fixes_skipped += 1;
            }
        }

        let duration = start_time.elapsed().as_millis() as u64;
        let success = fixes_applied > 0;

        self.logger
            .operation_complete("APPLY_FIXES", duration, success)
            .await?;
        self.logger
            .info(&format!(
                "Fixes applied: {}, skipped: {}, total issues: {}",
                fixes_applied,
                fixes_skipped,
                analysis.issues.len()
            ))
            .await?;

        Ok(fixed_content)
    }

    fn parse_analysis_response(&self, _response: &str, file_path: &str) -> Result<CodeAnalysis> {
        // Implementation to parse AI response into structured analysis
        // This would parse JSON response from the AI model

        Ok(CodeAnalysis {
            file_path: file_path.to_string(),
            issues: vec![],
            improvements: vec![],
            score: 85.0, // Placeholder
        })
    }

    fn prioritize_improvements(&self, analyses: &[CodeAnalysis]) -> Vec<PriorityItem> {
        let mut priorities = Vec::new();

        for analysis in analyses {
            for issue in &analysis.issues {
                let priority_score = self.calculate_priority_score(issue);
                priorities.push(PriorityItem {
                    file: analysis.file_path.clone(),
                    issue: issue.clone(),
                    priority_score,
                });
            }
        }

        priorities.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap());
        priorities
    }

    fn calculate_priority_score(&self, issue: &QualityIssue) -> f64 {
        let severity_weight = match issue.severity {
            Severity::Critical => 4.0,
            Severity::High => 3.0,
            Severity::Medium => 2.0,
            Severity::Low => 1.0,
        };

        let category_weight = match issue.category {
            IssueCategory::ErrorHandling => 1.5,
            IssueCategory::Performance => 1.3,
            IssueCategory::Architecture => 1.2,
            _ => 1.0,
        };

        severity_weight * category_weight
    }

    fn can_auto_fix(&self, issue: &QualityIssue) -> bool {
        matches!(
            issue.category,
            IssueCategory::Naming | IssueCategory::Documentation
        ) && matches!(issue.severity, Severity::Low | Severity::Medium)
    }

    async fn apply_fix(&self, content: &str, _issue: &QualityIssue) -> Result<String> {
        // Implementation for automated fixes
        // This would apply specific transformations based on issue type
        Ok(content.to_string())
    }

    fn estimate_timeline(&self, priorities: &[PriorityItem]) -> Timeline {
        let critical_count = priorities
            .iter()
            .filter(|p| matches!(p.issue.severity, Severity::Critical))
            .count();
        let high_count = priorities
            .iter()
            .filter(|p| matches!(p.issue.severity, Severity::High))
            .count();

        Timeline {
            immediate: critical_count,
            short_term: high_count,
            medium_term: priorities.len() - critical_count - high_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementPlan {
    pub total_files: usize,
    pub total_issues: usize,
    pub average_score: f64,
    pub priorities: Vec<PriorityItem>,
    pub timeline: Timeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityItem {
    pub file: String,
    pub issue: QualityIssue,
    pub priority_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub immediate: usize,   // Critical issues (0-1 week)
    pub short_term: usize,  // High priority (1-4 weeks)
    pub medium_term: usize, // Medium/Low priority (1-3 months)
}

impl Default for PatternDatabase {
    fn default() -> Self {
        let mut naming_patterns = HashMap::new();
        naming_patterns.insert("function".to_string(), "snake_case".to_string());
        naming_patterns.insert("variable".to_string(), "snake_case".to_string());
        naming_patterns.insert("struct".to_string(), "PascalCase".to_string());

        let error_patterns = vec![
            "provide specific error context".to_string(),
            "use anyhow::Context for error chaining".to_string(),
            "avoid generic error messages".to_string(),
        ];

        let architecture_patterns = vec![
            "use standardized subscription methods".to_string(),
            "implement consistent disconnect sequences".to_string(),
            "follow adapter pattern for integrations".to_string(),
        ];

        Self {
            naming_patterns,
            error_patterns,
            architecture_patterns,
        }
    }
}
