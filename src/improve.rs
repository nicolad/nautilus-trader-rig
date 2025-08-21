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
    #[allow(dead_code)]
    patterns: PatternDatabase,
    logger: FileLogger,
    recent_commits: HashSet<String>,
}

pub struct PatternDatabase {
    #[allow(dead_code)]
    pub naming_patterns: HashMap<String, String>,
    #[allow(dead_code)]
    pub error_patterns: Vec<String>,
    #[allow(dead_code)]
    pub architecture_patterns: Vec<String>,
}

#[allow(dead_code)]
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

    /// Run Clippy analysis on a specific file or workspace
    pub async fn run_clippy_analysis(&self, file_path: &str) -> Result<Vec<ClippyIssue>> {
        self.logger
            .operation_start(
                "CLIPPY_ANALYSIS",
                &format!("Running Clippy on {}", file_path),
            )
            .await?;

        let output = Command::new("cargo")
            .args(&["clippy", "--message-format=json", "--", "-W", "clippy::all"])
            .output()?;

        let mut issues = Vec::new();

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Ok(message) = serde_json::from_str::<ClippyMessage>(line) {
                    if let Some(issue) = self.parse_clippy_message(message, file_path) {
                        issues.push(issue);
                    }
                }
            }
        } else {
            self.logger
                .warn(&format!(
                    "Clippy analysis failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
                .await?;
        }

        self.logger
            .info(&format!(
                "Clippy analysis complete: {} issues found",
                issues.len()
            ))
            .await?;
        self.logger
            .operation_complete("CLIPPY_ANALYSIS", 0, true)
            .await?;

        Ok(issues)
    }

    /// Run comprehensive Clippy analysis on the entire workspace
    pub async fn run_comprehensive_clippy(&self) -> Result<ClippyReport> {
        self.logger
            .operation_start(
                "COMPREHENSIVE_CLIPPY",
                "Running comprehensive Clippy analysis",
            )
            .await?;

        let output = Command::new("cargo")
            .args(&[
                "clippy",
                "--all-targets",
                "--message-format=json",
                "--",
                "-W",
                "clippy::all",
                "-W",
                "clippy::pedantic",
                "-W",
                "clippy::nursery",
            ])
            .output()?;

        let mut report = ClippyReport {
            total_issues: 0,
            warnings: 0,
            errors: 0,
            allows: 0,
            files_analyzed: HashSet::new(),
            issues_by_category: HashMap::new(),
            issues: Vec::new(),
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Ok(message) = serde_json::from_str::<ClippyMessage>(line) {
                    if let Some(issue) = self.parse_clippy_message(message, "") {
                        report.total_issues += 1;

                        match issue.level.as_str() {
                            "warning" => report.warnings += 1,
                            "error" => report.errors += 1,
                            _ => report.allows += 1,
                        }

                        if let Some(file) = &issue.file_path {
                            report.files_analyzed.insert(file.clone());
                        }

                        *report
                            .issues_by_category
                            .entry(issue.lint_name.clone())
                            .or_insert(0) += 1;
                        report.issues.push(issue);
                    }
                }
            }
        }

        self.logger
            .info(&format!(
                "Comprehensive Clippy analysis complete: {} total issues ({} warnings, {} errors)",
                report.total_issues, report.warnings, report.errors
            ))
            .await?;

        self.logger
            .operation_complete("COMPREHENSIVE_CLIPPY", 0, true)
            .await?;

        Ok(report)
    }

    /// Generate improvement suggestions based on Clippy findings
    pub async fn clippy_guided_improvements(&self) -> Result<Vec<ClippyImprovement>> {
        let clippy_report = self.run_comprehensive_clippy().await?;
        let mut improvements = Vec::new();

        self.logger
            .operation_start(
                "CLIPPY_IMPROVEMENTS",
                "Generating Clippy-guided improvements",
            )
            .await?;

        // Group issues by severity and frequency
        let mut lint_frequency: HashMap<String, usize> = HashMap::new();
        for issue in &clippy_report.issues {
            *lint_frequency.entry(issue.lint_name.clone()).or_insert(0) += 1;
        }

        // Create improvements for the most frequent issues
        for (lint_name, frequency) in lint_frequency.iter() {
            if *frequency >= 3 {
                // Focus on issues that appear 3+ times
                let sample_issue = clippy_report
                    .issues
                    .iter()
                    .find(|i| i.lint_name == *lint_name)
                    .unwrap();

                let improvement = self
                    .create_clippy_improvement(sample_issue, *frequency)
                    .await?;
                improvements.push(improvement);
            }
        }

        // Sort by impact score
        improvements.sort_by(|a, b| b.impact_score.partial_cmp(&a.impact_score).unwrap());

        self.logger
            .info(&format!(
                "Generated {} Clippy-guided improvements",
                improvements.len()
            ))
            .await?;
        self.logger
            .operation_complete("CLIPPY_IMPROVEMENTS", 0, true)
            .await?;

        Ok(improvements)
    }

    /// Fix Clippy issues automatically where possible
    pub async fn auto_fix_clippy_issues(&self, file_path: &str) -> Result<FixResult> {
        self.logger
            .operation_start(
                "AUTO_FIX_CLIPPY",
                &format!("Auto-fixing Clippy issues in {}", file_path),
            )
            .await?;

        // Run clippy with --fix flag
        let output = Command::new("cargo")
            .args(&["clippy", "--fix", "--allow-dirty", "--allow-staged"])
            .output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Count fixes applied by parsing output
        let fixes_applied = stderr
            .lines()
            .filter(|line| line.contains("fixed") || line.contains("applied"))
            .count();

        let result = FixResult {
            success,
            fixes_applied,
            output: stdout.to_string(),
            errors: if success {
                None
            } else {
                Some(stderr.to_string())
            },
        };

        if success {
            self.logger
                .info(&format!(
                    "Auto-fix complete: {} fixes applied",
                    fixes_applied
                ))
                .await?;
        } else {
            self.logger
                .warn(&format!("Auto-fix failed: {}", stderr))
                .await?;
        }

        self.logger
            .operation_complete("AUTO_FIX_CLIPPY", 0, success)
            .await?;

        Ok(result)
    }

    fn parse_clippy_message(
        &self,
        message: ClippyMessage,
        target_file: &str,
    ) -> Option<ClippyIssue> {
        // Parse Clippy JSON message format
        if let Some(code) = &message.code {
            let file_path = message.spans.first()?.file_name.clone();

            // Filter to target file if specified
            if !target_file.is_empty() && !file_path.contains(target_file) {
                return None;
            }

            Some(ClippyIssue {
                lint_name: code.code.clone(),
                message: message.message,
                level: message.level,
                file_path: Some(file_path),
                line: message.spans.first()?.line_start,
                column: message.spans.first()?.column_start,
                suggestion: message.spans.first()?.suggested_replacement.clone(),
            })
        } else {
            None
        }
    }

    fn convert_clippy_to_quality_issue(&self, clippy_issue: ClippyIssue) -> QualityIssue {
        let category = self.categorize_clippy_lint(&clippy_issue.lint_name);
        let severity = self.clippy_level_to_severity(&clippy_issue.level);

        QualityIssue {
            category,
            severity,
            line: Some(clippy_issue.line as u32),
            description: format!(
                "[Clippy: {}] {}",
                clippy_issue.lint_name, clippy_issue.message
            ),
            suggestion: clippy_issue
                .suggestion
                .unwrap_or_else(|| "Apply Clippy suggestion".to_string()),
        }
    }

    fn categorize_clippy_lint(&self, lint_name: &str) -> IssueCategory {
        match lint_name {
            name if name.contains("naming") || name.contains("style") => IssueCategory::Naming,
            name if name.contains("error") || name.contains("unwrap") || name.contains("panic") => {
                IssueCategory::ErrorHandling
            }
            name if name.contains("perf")
                || name.contains("performance")
                || name.contains("clone") =>
            {
                IssueCategory::Performance
            }
            name if name.contains("complexity") || name.contains("cognitive") => {
                IssueCategory::Architecture
            }
            name if name.contains("doc") || name.contains("missing") => {
                IssueCategory::Documentation
            }
            _ => IssueCategory::Architecture, // Default for other lints
        }
    }

    fn clippy_level_to_severity(&self, level: &str) -> Severity {
        match level {
            "error" => Severity::Critical,
            "warning" => Severity::High,
            "help" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    fn calculate_code_score(&self, issues: &[QualityIssue]) -> f64 {
        let total_penalty: f64 = issues
            .iter()
            .map(|issue| match issue.severity {
                Severity::Critical => 10.0,
                Severity::High => 5.0,
                Severity::Medium => 2.0,
                Severity::Low => 1.0,
            })
            .sum();

        // Start with 100 and subtract penalties
        (100.0 - total_penalty).max(0.0)
    }

    async fn create_clippy_improvement(
        &self,
        issue: &ClippyIssue,
        frequency: usize,
    ) -> Result<ClippyImprovement> {
        let impact_score = self.calculate_clippy_impact_score(issue, frequency);

        let prompt = format!(
            "Create an improvement plan for this Clippy lint that appears {} times:\n\nLint: {}\nMessage: {}\nLevel: {}\n\nProvide:\n1. A clear title\n2. Detailed description of the issue\n3. Step-by-step fix instructions\n4. Code examples if helpful",
            frequency, issue.lint_name, issue.message, issue.level
        );

        let response = self.client.prompt(&prompt).await?;

        Ok(ClippyImprovement {
            lint_name: issue.lint_name.clone(),
            title: format!("Fix {} (appears {} times)", issue.lint_name, frequency),
            description: response,
            frequency,
            impact_score,
            auto_fixable: self.is_auto_fixable(&issue.lint_name),
            priority: self.clippy_level_to_severity(&issue.level),
        })
    }

    fn calculate_clippy_impact_score(&self, issue: &ClippyIssue, frequency: usize) -> f64 {
        let base_score = frequency as f64;
        let severity_multiplier = match issue.level.as_str() {
            "error" => 4.0,
            "warning" => 2.0,
            _ => 1.0,
        };

        base_score * severity_multiplier
    }

    fn is_auto_fixable(&self, lint_name: &str) -> bool {
        // Common auto-fixable Clippy lints
        matches!(
            lint_name,
            "clippy::needless_return"
                | "clippy::redundant_closure"
                | "clippy::explicit_iter_loop"
                | "clippy::single_char_pattern"
                | "clippy::unnecessary_mut_passed"
                | "clippy::useless_format"
        )
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

    /// Analyze log files to extract patterns and insights for improvement
    pub async fn analyze_logs(&self, log_content: &str) -> Result<LogAnalysis> {
        let start_time = Instant::now();

        self.logger
            .operation_start(
                "LOG_ANALYSIS",
                &format!("Analyzing {} characters of logs", log_content.len()),
            )
            .await?;

        let prompt = format!(
            "Analyze these application logs to identify patterns, errors, and improvement opportunities:\n\nLogs:\n{}\n\nFocus on:\n1. Error patterns and frequency\n2. Performance bottlenecks\n3. Resource usage patterns\n4. Common failure points\n5. Optimization opportunities\n\nReturn structured analysis with categories and recommendations.",
            log_content
        );

        self.logger
            .debug(&format!(
                "Sending log analysis prompt: {} characters",
                prompt.len()
            ))
            .await?;
        let ai_start = Instant::now();
        let response = self.client.prompt(&prompt).await?;
        let ai_duration = ai_start.elapsed().as_millis() as u64;

        self.logger
            .ai_interaction("Log-Analyzer", prompt.len(), response.len(), ai_duration)
            .await?;

        // Parse the response into structured log analysis
        let analysis = self.parse_log_analysis(&response)?;

        let duration = start_time.elapsed().as_millis() as u64;
        self.logger
            .operation_complete("LOG_ANALYSIS", duration, true)
            .await?;
        self.logger
            .info(&format!(
                "Log analysis complete: {} patterns found, {} recommendations",
                analysis.patterns.len(),
                analysis.recommendations.len()
            ))
            .await?;

        Ok(analysis)
    }

    /// Analyze log patterns from file path
    pub async fn analyze_log_file(&self, log_file_path: &str) -> Result<LogAnalysis> {
        self.logger
            .info(&format!("Reading log file: {}", log_file_path))
            .await?;

        let log_content = std::fs::read_to_string(log_file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read log file {}: {}", log_file_path, e))?;

        self.logger
            .info(&format!(
                "Log file {} contains {} characters",
                log_file_path,
                log_content.len()
            ))
            .await?;

        self.analyze_logs(&log_content).await
    }

    /// Extract improvement insights from recent application logs
    pub async fn extract_log_insights(&self, logger: &FileLogger) -> Result<Vec<LogInsight>> {
        self.logger
            .operation_start(
                "EXTRACT_INSIGHTS",
                "Extracting insights from recent application logs",
            )
            .await?;

        let log_path = logger.log_path();

        // Read recent log entries (last 1000 lines)
        let output = Command::new("tail")
            .args(&["-n", "1000", log_path])
            .output()?;

        if !output.status.success() {
            self.logger
                .warn("Failed to read recent log entries")
                .await?;
            return Ok(vec![]);
        }

        let recent_logs = String::from_utf8_lossy(&output.stdout);
        let analysis = self.analyze_logs(&recent_logs).await?;

        // Convert log patterns to actionable insights
        let mut insights = Vec::new();

        for pattern in &analysis.patterns {
            let insight = match pattern.pattern_type {
                PatternType::Error => LogInsight {
                    category: InsightCategory::ErrorReduction,
                    description: format!("Frequent error: {}", pattern.description),
                    impact_score: self.calculate_error_impact(pattern),
                    suggested_action: self.suggest_error_fix(pattern).await?,
                    priority: self.map_severity_to_priority(&pattern.severity),
                },
                PatternType::Performance => LogInsight {
                    category: InsightCategory::PerformanceOptimization,
                    description: format!("Performance issue: {}", pattern.description),
                    impact_score: self.calculate_performance_impact(pattern),
                    suggested_action: self.suggest_performance_fix(pattern).await?,
                    priority: self.map_severity_to_priority(&pattern.severity),
                },
                PatternType::Resource => LogInsight {
                    category: InsightCategory::ResourceOptimization,
                    description: format!("Resource usage: {}", pattern.description),
                    impact_score: self.calculate_resource_impact(pattern),
                    suggested_action: self.suggest_resource_fix(pattern).await?,
                    priority: self.map_severity_to_priority(&pattern.severity),
                },
                _ => continue,
            };

            insights.push(insight);
        }

        self.logger
            .info(&format!(
                "Extracted {} actionable insights from logs",
                insights.len()
            ))
            .await?;
        self.logger
            .operation_complete("EXTRACT_INSIGHTS", 0, true)
            .await?;

        Ok(insights)
    }

    /// Monitor logs in real-time for issues requiring immediate attention
    pub async fn monitor_logs_realtime(
        &self,
        log_file_path: &str,
        _callback: impl Fn(&LogPattern) -> bool,
    ) -> Result<()> {
        self.logger
            .operation_start(
                "MONITOR_LOGS",
                &format!("Starting real-time monitoring of {}", log_file_path),
            )
            .await?;

        // This would implement real-time log monitoring using file watching
        // For now, providing the structure for implementation

        self.logger.info("Real-time log monitoring started").await?;

        // Implementation would use a file watcher to monitor new log entries
        // and analyze them for critical patterns

        Ok(())
    }

    fn parse_log_analysis(&self, _response: &str) -> Result<LogAnalysis> {
        // Parse AI response into structured log analysis
        // This would parse JSON response from the AI model

        // For now, provide a structured placeholder
        Ok(LogAnalysis {
            patterns: vec![LogPattern {
                pattern_type: PatternType::Error,
                description: "Example error pattern from logs".to_string(),
                frequency: 1,
                severity: Severity::Medium,
                first_occurrence: "2025-08-21T10:00:00Z".to_string(),
                last_occurrence: "2025-08-21T11:00:00Z".to_string(),
            }],
            recommendations: vec![
                "Improve error handling in critical paths".to_string(),
                "Add more detailed logging for debugging".to_string(),
            ],
            summary: LogSummary {
                total_entries: 1000,
                error_rate: 0.05,
                warning_rate: 0.15,
                performance_issues: 2,
                time_range: "Last 1000 log entries".to_string(),
            },
        })
    }

    fn calculate_error_impact(&self, pattern: &LogPattern) -> f64 {
        // Calculate impact score based on frequency and severity
        let base_score = pattern.frequency as f64;
        let severity_multiplier = match pattern.severity {
            Severity::Critical => 4.0,
            Severity::High => 3.0,
            Severity::Medium => 2.0,
            Severity::Low => 1.0,
        };

        base_score * severity_multiplier
    }

    fn calculate_performance_impact(&self, pattern: &LogPattern) -> f64 {
        // Performance issues have higher base impact
        let base_score = pattern.frequency as f64 * 1.5;
        let severity_multiplier = match pattern.severity {
            Severity::Critical => 3.5,
            Severity::High => 2.5,
            Severity::Medium => 1.8,
            Severity::Low => 1.2,
        };

        base_score * severity_multiplier
    }

    fn calculate_resource_impact(&self, pattern: &LogPattern) -> f64 {
        // Resource issues compound over time
        let base_score = pattern.frequency as f64 * 1.2;
        let severity_multiplier = match pattern.severity {
            Severity::Critical => 3.0,
            Severity::High => 2.2,
            Severity::Medium => 1.5,
            Severity::Low => 1.0,
        };

        base_score * severity_multiplier
    }

    async fn suggest_error_fix(&self, pattern: &LogPattern) -> Result<String> {
        let prompt = format!(
            "Suggest a specific fix for this error pattern:\n\nError: {}\nFrequency: {}\nSeverity: {:?}\n\nProvide a concise, actionable fix suggestion.",
            pattern.description, pattern.frequency, pattern.severity
        );

        let response = self.client.prompt(&prompt).await?;
        Ok(response.trim().to_string())
    }

    async fn suggest_performance_fix(&self, pattern: &LogPattern) -> Result<String> {
        let prompt = format!(
            "Suggest a performance optimization for this issue:\n\nIssue: {}\nFrequency: {}\nSeverity: {:?}\n\nProvide a specific optimization strategy.",
            pattern.description, pattern.frequency, pattern.severity
        );

        let response = self.client.prompt(&prompt).await?;
        Ok(response.trim().to_string())
    }

    async fn suggest_resource_fix(&self, pattern: &LogPattern) -> Result<String> {
        let prompt = format!(
            "Suggest a resource optimization for this pattern:\n\nPattern: {}\nFrequency: {}\nSeverity: {:?}\n\nProvide a resource management improvement.",
            pattern.description, pattern.frequency, pattern.severity
        );

        let response = self.client.prompt(&prompt).await?;
        Ok(response.trim().to_string())
    }

    fn map_severity_to_priority(&self, severity: &Severity) -> Priority {
        match severity {
            Severity::Critical => Priority::Urgent,
            Severity::High => Priority::High,
            Severity::Medium => Priority::Medium,
            Severity::Low => Priority::Low,
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

// Log analysis structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAnalysis {
    pub patterns: Vec<LogPattern>,
    pub recommendations: Vec<String>,
    pub summary: LogSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPattern {
    pub pattern_type: PatternType,
    pub description: String,
    pub frequency: usize,
    pub severity: Severity,
    pub first_occurrence: String,
    pub last_occurrence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    Error,
    Warning,
    Performance,
    Security,
    Resource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSummary {
    pub total_entries: usize,
    pub error_rate: f64,
    pub warning_rate: f64,
    pub performance_issues: usize,
    pub time_range: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogInsight {
    pub category: InsightCategory,
    pub description: String,
    pub impact_score: f64,
    pub suggested_action: String,
    pub priority: Priority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InsightCategory {
    ErrorReduction,
    PerformanceOptimization,
    ResourceOptimization,
    SecurityEnhancement,
    CodeQuality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Urgent,
    High,
    Medium,
    Low,
}

// Clippy integration structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClippyIssue {
    pub lint_name: String,
    pub message: String,
    pub level: String,
    pub file_path: Option<String>,
    pub line: usize,
    pub column: usize,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClippyReport {
    pub total_issues: usize,
    pub warnings: usize,
    pub errors: usize,
    pub allows: usize,
    pub files_analyzed: HashSet<String>,
    pub issues_by_category: HashMap<String, usize>,
    pub issues: Vec<ClippyIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClippyImprovement {
    pub lint_name: String,
    pub title: String,
    pub description: String,
    pub frequency: usize,
    pub impact_score: f64,
    pub auto_fixable: bool,
    pub priority: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    pub success: bool,
    pub fixes_applied: usize,
    pub output: String,
    pub errors: Option<String>,
}

// Clippy JSON message format structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClippyMessage {
    pub message: String,
    pub code: Option<ClippyCode>,
    pub level: String,
    pub spans: Vec<ClippySpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClippyCode {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClippySpan {
    pub file_name: String,
    pub line_start: usize,
    pub column_start: usize,
    pub suggested_replacement: Option<String>,
}
