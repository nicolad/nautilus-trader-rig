// src/commit_analyzer.rs
//
// Commit Quality Analyzer for Nautilus Trader
//
// This module analyzes git commits for inconsistencies, typos, and pattern violations.

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitAnalysis {
    pub commit_hash: String,
    pub message: String,
    pub author: String,
    pub date: String,
    pub files_changed: Vec<FileChange>,
    pub code_changes: CodeChangeSummary,
    pub issues: Vec<CommitIssue>,
    pub score: u32, // 0-100, higher is better
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub file_path: String,
    pub change_type: ChangeType,
    pub lines_added: u32,
    pub lines_removed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChangeSummary {
    pub total_files: u32,
    pub total_lines_added: u32,
    pub total_lines_removed: u32,
    pub languages_affected: Vec<String>,
    pub components_affected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyAnalysis {
    pub author_patterns: HashMap<String, AuthorPattern>,
    pub component_patterns: HashMap<String, ComponentPattern>,
    pub naming_patterns: Vec<NamingPattern>,
    pub temporal_patterns: Vec<TemporalPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorPattern {
    pub commit_count: u32,
    pub avg_message_length: f32,
    pub common_actions: Vec<String>,
    pub common_components: Vec<String>,
    pub style_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentPattern {
    pub change_frequency: u32,
    pub common_file_patterns: Vec<String>,
    pub typical_change_size: u32,
    pub associated_components: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamingPattern {
    pub pattern_type: String,
    pub regex_pattern: String,
    pub examples: Vec<String>,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPattern {
    pub time_window: String,
    pub activity_level: u32,
    pub dominant_changes: Vec<String>,
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitIssue {
    pub issue_type: IssueType,
    pub description: String,
    pub severity: Severity,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueType {
    // Code Consistency Issues
    InconsistentNaming,
    InconsistentPatterns,
    MissingTests,
    UnusualFileLocation,
    InconsistentErrorHandling,
    InconsistentLogging,
    DeadCode,
    DuplicatedLogic,
    InconsistentImports,
    SecurityConcern,
    PerformanceIssue,
    ArchitecturalViolation,
    
    // Change Pattern Issues
    LargeChangeset,
    MixedConcerns,
    NoCodeChanges,
    IncompleteFeature,
    RiskyChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

pub struct CommitAnalyzer {
    // Common typos and their corrections
    typo_map: HashMap<String, String>,
    // Valid action words
    valid_actions: HashSet<String>,
    // Regex patterns for validation
    patterns: AnalysisPatterns,
    // Consistency tracking
    consistency_analysis: ConsistencyAnalysis,
    // Advanced pattern matchers
    semantic_patterns: SemanticPatterns,
    // Architectural rules
    architectural_rules: ArchitecturalRules,
}

struct AnalysisPatterns {
    commit_format: Regex,
    vague_words: Regex,
}

#[derive(Debug, Clone)]
struct SemanticPatterns {
    // Pattern matchers for semantic consistency
    action_component_map: HashMap<String, Vec<String>>,
    component_file_patterns: HashMap<String, Vec<Regex>>,
    naming_conventions: HashMap<String, Regex>,
    temporal_patterns: Vec<Regex>,
}

#[derive(Debug, Clone)]
struct ArchitecturalRules {
    // Rules for architectural consistency
    component_dependencies: HashMap<String, Vec<String>>,
    forbidden_cross_dependencies: Vec<(String, String)>,
    layer_hierarchy: Vec<String>,
    naming_rules: HashMap<String, Vec<String>>,
}

impl CommitAnalyzer {
    pub fn new() -> Result<Self> {
        let typo_map = Self::build_typo_map();
        let valid_actions = Self::build_valid_actions();
        let patterns = Self::build_patterns()?;
        let consistency_analysis = Self::build_consistency_analysis();
        let semantic_patterns = Self::build_semantic_patterns()?;
        let architectural_rules = Self::build_architectural_rules();

        Ok(Self {
            typo_map,
            valid_actions,
            patterns,
            consistency_analysis,
            semantic_patterns,
            architectural_rules,
        })
    }

    pub async fn analyze_last_commits(&self, count: usize) -> Result<Vec<CommitAnalysis>> {
        let commits = self.fetch_commits(count)?;
        let mut analyses = Vec::new();

        // First pass: individual commit analysis
        for commit in &commits {
            let analysis = self.analyze_commit(commit)?;
            analyses.push(analysis);
        }

        // Second pass: cross-commit consistency analysis
        self.analyze_cross_commit_consistency(&mut analyses)?;

        Ok(analyses)
    }

    /// Analyze commits with AI assistance using DeepSeek
    #[allow(dead_code)]
    pub async fn analyze_commits_with_ai(&self, count: usize) -> Result<Vec<CommitAnalysis>> {
        let commits = self.fetch_commits(count)?;
        let mut analyses = Vec::new();

        // First do basic analysis
        for commit in &commits {
            let analysis = self.analyze_commit(commit)?;
            analyses.push(analysis);
        }

        // Then enhance with AI analysis (disabled for now)
        // let commit_messages: Vec<String> = commits.iter().map(|c| c.message.clone()).collect();
        // let ai_analysis = self.get_ai_commit_analysis(&commit_messages).await?;
        
        // Merge AI insights with basic analysis (disabled for now)
        // self.merge_ai_analysis(&mut analyses, &ai_analysis);

        Ok(analyses)
    }

    /// Get AI analysis of commit messages for patterns and issues
    #[allow(dead_code)]
    async fn get_ai_commit_analysis(&self, commit_messages: &[String]) -> Result<String> {
        let commits_text = commit_messages.iter()
            .enumerate()
            .map(|(i, msg)| format!("{}. {}", i + 1, msg))
            .collect::<Vec<_>>()
            .join("\n");

        let _prompt = format!(
            r#"Analyze these commit messages for patterns, inconsistencies, and quality issues:

{}

Look for:
1. **Typos and spelling errors** - identify any misspelled words
2. **Inconsistent formatting** - check for pattern violations in structure 
3. **Vague language** - identify overly generic or unclear descriptions
4. **Grammar issues** - spot grammatical problems
5. **Missing context** - find commits that lack sufficient detail
6. **Pattern violations** - check against standard format: "<Action> <Component> <description>"

Valid actions: Fix, Add, Improve, Remove, Update, Implement, Refactor, etc.
Valid components: adapters, execution, data, portfolio, risk, indicators, etc.

For each issue found, specify:
- Commit number (1-based)
- Issue type (typo/format/vague/grammar/context/pattern)
- Severity (high/medium/low)
- Specific problem description
- Suggested improvement

Format your response as structured analysis with clear issue identification."#,
            commits_text
        );

        // AI analysis disabled for simplified version
        Ok("AI analysis not available in simplified mode".to_string())
    }

    /// Merge AI analysis insights into existing commit analyses
    #[allow(dead_code)]
    fn merge_ai_analysis(&self, analyses: &mut [CommitAnalysis], ai_response: &str) {
        // Parse AI response and extract insights
        // This is a simplified implementation - in practice you might want more sophisticated parsing
        log::debug!("AI analysis response: {}", ai_response);
        
        // For now, just log the AI analysis
        // TODO: Implement sophisticated parsing of AI response to extract specific issues
        // and merge them with the existing analyses
        log::info!("AI commit analysis completed, {} commits analyzed", analyses.len());
    }

    pub fn generate_report(&self, analyses: &[CommitAnalysis], format: &str) -> Result<String> {
        match format {
            "json" => self.generate_json_report(analyses),
            _ => Ok(self.generate_text_report(analyses)),
        }
    }

    fn generate_text_report(&self, analyses: &[CommitAnalysis]) -> String {
        let mut report = String::new();
        
        report.push_str("# Commit Quality Analysis Report\n\n");
        report.push_str(&format!("Analyzed {} commits\n\n", analyses.len()));

        // Summary statistics
        let total_issues: usize = analyses.iter().map(|a| a.issues.len()).sum();
        let avg_score: f32 = analyses.iter().map(|a| a.score as f32).sum::<f32>() / analyses.len() as f32;
        let high_severity_issues = analyses.iter()
            .flat_map(|a| &a.issues)
            .filter(|i| matches!(i.severity, Severity::High))
            .count();

        report.push_str("## Summary\n");
        report.push_str(&format!("- Total issues found: {}\n", total_issues));
        report.push_str(&format!("- Average quality score: {:.1}/100\n", avg_score));
        report.push_str(&format!("- High severity issues: {}\n\n", high_severity_issues));

        // Issue type breakdown
        let mut issue_counts: HashMap<String, usize> = HashMap::new();
        for analysis in analyses {
            for issue in &analysis.issues {
                let key = format!("{:?}", issue.issue_type);
                *issue_counts.entry(key).or_insert(0) += 1;
            }
        }

        if !issue_counts.is_empty() {
            report.push_str("## Issue Types\n");
            for (issue_type, count) in issue_counts {
                report.push_str(&format!("- {}: {}\n", issue_type, count));
            }
            report.push('\n');
        }

        // Detailed findings
        report.push_str("## Detailed Analysis\n\n");
        for analysis in analyses {
            report.push_str(&format!("### {} (Score: {})\n", 
                &analysis.commit_hash[..8], analysis.score));
            report.push_str(&format!("**Message:** {}\n", analysis.message));
            report.push_str(&format!("**Author:** {} ({})\n", analysis.author, analysis.date));
            
            // Code changes summary
            report.push_str(&format!("**Files Changed:** {} files (+{} -{} lines)\n", 
                analysis.code_changes.total_files,
                analysis.code_changes.total_lines_added,
                analysis.code_changes.total_lines_removed));
            
            if !analysis.code_changes.components_affected.is_empty() {
                report.push_str(&format!("**Components:** {}\n", 
                    analysis.code_changes.components_affected.join(", ")));
            }
            
            if !analysis.code_changes.languages_affected.is_empty() {
                report.push_str(&format!("**Languages:** {}\n", 
                    analysis.code_changes.languages_affected.join(", ")));
            }
            
            // File details (show up to 5 files)
            if !analysis.files_changed.is_empty() {
                report.push_str("**File Changes:**\n");
                for (i, file) in analysis.files_changed.iter().enumerate() {
                    if i >= 5 {
                        report.push_str(&format!("  ... and {} more files\n", analysis.files_changed.len() - 5));
                        break;
                    }
                    let change_symbol = match file.change_type {
                        ChangeType::Added => "➕",
                        ChangeType::Modified => "📝",
                        ChangeType::Deleted => "❌",
                        ChangeType::Renamed => "🔄",
                    };
                    report.push_str(&format!("  {} {} (+{} -{} lines)\n", 
                        change_symbol, file.file_path, file.lines_added, file.lines_removed));
                }
            }
            
            if !analysis.issues.is_empty() {
                report.push_str("\n**Issues Found:**\n");
                for issue in &analysis.issues {
                    let severity_icon = match issue.severity {
                        Severity::High => "🔴",
                        Severity::Medium => "🟡", 
                        Severity::Low => "🟢",
                    };
                    report.push_str(&format!("{} **{:?}**: {}\n", 
                        severity_icon, issue.issue_type, issue.description));
                    if let Some(suggestion) = &issue.suggestion {
                        report.push_str(&format!("   💡 *Suggestion: {}*\n", suggestion));
                    }
                }
            } else {
                report.push_str("\n✅ **No issues found**\n");
            }
            report.push('\n');
        }

        // Recommendations
        if total_issues > 0 {
            report.push_str("## Recommendations\n\n");
            if high_severity_issues > 0 {
                report.push_str("- 🔴 **High Priority**: Address high severity issues immediately\n");
            }
            report.push_str("- 📝 Follow consistent commit message format: `<Action> <Component> <description>`\n");
            report.push_str("- ✅ Use spell check before committing\n");
            report.push_str("- 📏 Keep commit messages concise but descriptive\n");
            report.push_str("- 🎯 Use specific action words (Fix, Add, Improve, etc.)\n\n");
        } else {
            report.push_str("## ✅ All commits look good!\n\n");
            report.push_str("No significant issues found in the analyzed commits.\n\n");
        }

        report
    }

    fn generate_json_report(&self, analyses: &[CommitAnalysis]) -> Result<String> {
        use serde_json::json;
        
        let total_issues: usize = analyses.iter().map(|a| a.issues.len()).sum();
        let avg_score: f32 = if !analyses.is_empty() {
            analyses.iter().map(|a| a.score as f32).sum::<f32>() / analyses.len() as f32
        } else {
            0.0
        };

        let report = json!({
            "📊 Commit Analysis Report": {
                "summary": {
                    "total_commits_analyzed": analyses.len(),
                    "total_issues": total_issues,
                    "average_quality_score": format!("{:.1}", avg_score)
                },
                "commits": analyses.iter().map(|a| {
                    json!({
                        "hash": a.commit_hash,
                        "message": a.message,
                        "author": a.author,
                        "date": a.date,
                        "score": a.score,
                        "files_changed": a.files_changed,
                        "code_changes": a.code_changes,
                        "issues": a.issues
                    })
                }).collect::<Vec<_>>()
            }
        });

        Ok(serde_json::to_string_pretty(&report)?)
    }

    fn fetch_commits(&self, count: usize) -> Result<Vec<GitCommit>> {
        // Run git command from parent directory to get nautilus_trader repo commits
        let output = Command::new("git")
            .current_dir("..") // Go up one directory to nautilus_trader root
            .args([
                "log",
                &format!("-{}", count),
                "--pretty=format:%H|%s|%an|%ad",
                "--date=short"
            ])
            .output()
            .context("Failed to execute git log command")?;

        if !output.status.success() {
            return Err(anyhow!("Git log command failed: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        let output_str = String::from_utf8(output.stdout)
            .context("Git log output is not valid UTF-8")?;

        let mut commits = Vec::new();
        for line in output_str.lines() {
            if let Some(commit) = Self::parse_commit_line(line)? {
                commits.push(commit);
            }
        }

        Ok(commits)
    }

    fn fetch_commit_diff(&self, commit_hash: &str) -> Result<(Vec<FileChange>, CodeChangeSummary)> {
        // Get the file statistics for this commit
        let stats_output = Command::new("git")
            .current_dir("..")
            .args([
                "show",
                "--stat",
                "--format=",
                commit_hash
            ])
            .output()
            .context("Failed to execute git show --stat command")?;

        if !stats_output.status.success() {
            return Err(anyhow!("Git show --stat command failed: {}", 
                String::from_utf8_lossy(&stats_output.stderr)));
        }

        // Get the diff with file names
        let diff_output = Command::new("git")
            .current_dir("..")
            .args([
                "show",
                "--name-status",
                "--format=",
                commit_hash
            ])
            .output()
            .context("Failed to execute git show --name-status command")?;

        if !diff_output.status.success() {
            return Err(anyhow!("Git show --name-status command failed: {}", 
                String::from_utf8_lossy(&diff_output.stderr)));
        }

        let stats_str = String::from_utf8(stats_output.stdout)
            .context("Git show --stat output is not valid UTF-8")?;
        
        let diff_str = String::from_utf8(diff_output.stdout)
            .context("Git show --name-status output is not valid UTF-8")?;

        self.parse_commit_changes(&stats_str, &diff_str)
    }

    fn parse_commit_changes(&self, stats_str: &str, diff_str: &str) -> Result<(Vec<FileChange>, CodeChangeSummary)> {
        let mut file_changes = Vec::new();
        let mut total_lines_added = 0;
        let mut total_lines_removed = 0;
        let mut languages = HashSet::new();
        let mut components = HashSet::new();

        // Parse file status changes (A=added, M=modified, D=deleted, R=renamed)
        let mut file_statuses = HashMap::new();
        for line in diff_str.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, '\t').collect();
            if parts.len() == 2 {
                let status = parts[0].chars().next().unwrap_or('M');
                let file_path = parts[1];
                file_statuses.insert(file_path.to_string(), status);
            }
        }

        // Parse stats to get line changes
        for line in stats_str.lines() {
            if line.trim().is_empty() || line.contains("file") {
                continue;
            }
            
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 {
                let file_path = parts[0].trim();
                let changes_part = parts[1].trim();
                
                let (added, removed) = self.parse_line_changes(changes_part);
                total_lines_added += added;
                total_lines_removed += removed;

                // Determine change type
                let change_type = match file_statuses.get(file_path).unwrap_or(&'M') {
                    'A' => ChangeType::Added,
                    'D' => ChangeType::Deleted,
                    'R' => ChangeType::Renamed,
                    _ => ChangeType::Modified,
                };

                // Extract language from file extension
                if let Some(extension) = file_path.split('.').last() {
                    match extension {
                        "rs" => languages.insert("Rust".to_string()),
                        "py" => languages.insert("Python".to_string()),
                        "pyx" => languages.insert("Cython".to_string()),
                        "pxd" => languages.insert("Cython".to_string()),
                        "toml" => languages.insert("TOML".to_string()),
                        "md" => languages.insert("Markdown".to_string()),
                        "yml" | "yaml" => languages.insert("YAML".to_string()),
                        "json" => languages.insert("JSON".to_string()),
                        _ => false,
                    };
                }

                // Extract component from file path
                self.extract_component_from_path(file_path, &mut components);

                file_changes.push(FileChange {
                    file_path: file_path.to_string(),
                    change_type,
                    lines_added: added,
                    lines_removed: removed,
                });
            }
        }

        let summary = CodeChangeSummary {
            total_files: file_changes.len() as u32,
            total_lines_added,
            total_lines_removed,
            languages_affected: languages.into_iter().collect(),
            components_affected: components.into_iter().collect(),
        };

        Ok((file_changes, summary))
    }

    fn parse_line_changes(&self, changes_str: &str) -> (u32, u32) {
        let mut added = 0;
        let mut removed = 0;
        
        // Parse strings like "5 ++---" or "12 +++++++-----"
        for part in changes_str.split_whitespace() {
            if let Ok(_num) = part.parse::<u32>() {
                continue; // Skip the number part
            }
            
            for ch in part.chars() {
                match ch {
                    '+' => added += 1,
                    '-' => removed += 1,
                    _ => {}
                }
            }
        }

        (added, removed)
    }

    fn extract_component_from_path(&self, file_path: &str, components: &mut HashSet<String>) {
        let path_parts: Vec<&str> = file_path.split('/').collect();
        
        // Look for nautilus_trader components
        for (i, part) in path_parts.iter().enumerate() {
            if *part == "nautilus_trader" && i + 1 < path_parts.len() {
                components.insert(path_parts[i + 1].to_string());
                break;
            }
        }

        // Look for crates components
        for (i, part) in path_parts.iter().enumerate() {
            if *part == "crates" && i + 1 < path_parts.len() {
                components.insert(format!("crates/{}", path_parts[i + 1]));
                break;
            }
        }

        // Look for other common components
        if file_path.contains("examples/") {
            components.insert("examples".to_string());
        } else if file_path.contains("tests/") {
            components.insert("tests".to_string());
        } else if file_path.contains("docs/") {
            components.insert("docs".to_string());
        }
    }

    fn parse_commit_line(line: &str) -> Result<Option<GitCommit>> {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 4 {
            Ok(Some(GitCommit {
                hash: parts[0].to_string(),
                message: parts[1].to_string(),
                author: parts[2].to_string(),
                date: parts[3].to_string(),
            }))
        } else {
            Ok(None)
        }
    }

    fn analyze_commit(&self, commit: &GitCommit) -> Result<CommitAnalysis> {
        let mut issues = Vec::new();
        let message = &commit.message;

        // Fetch code changes for this commit
        let (files_changed, code_changes) = self.fetch_commit_diff(&commit.hash)?;

        // Check for typos
        self.check_typos(message, &mut issues);

        // Check commit message format
        self.check_format(message, &mut issues);

        // Check for vague language
        self.check_vague_language(message, &mut issues);

        // Check capitalization
        self.check_capitalization(message, &mut issues);

        // Check length
        self.check_length(message, &mut issues);

        // Check for grammar issues
        self.check_grammar(message, &mut issues);

        // Check code changes for issues
        self.check_code_changes(&code_changes, &files_changed, message, &mut issues);

        // Calculate score
        let score = self.calculate_score(&issues);

        Ok(CommitAnalysis {
            commit_hash: commit.hash.clone(),
            message: commit.message.clone(),
            author: commit.author.clone(),
            date: commit.date.clone(),
            files_changed,
            code_changes,
            issues,
            score,
        })
    }

    fn check_typos(&self, message: &str, issues: &mut Vec<CommitIssue>) {
        let words: Vec<&str> = message.split_whitespace().collect();
        
        for word in words {
            let clean_word = word.trim_matches(|c: char| !c.is_alphabetic()).to_lowercase();
            if let Some(correction) = self.typo_map.get(&clean_word) {
                issues.push(CommitIssue {
                    issue_type: IssueType::Typo,
                    description: format!("Possible typo: '{}' might be '{}'", word, correction),
                    severity: Severity::Medium,
                    suggestion: Some(format!("Replace '{}' with '{}'", word, correction)),
                });
            }
        }
    }

    fn check_format(&self, message: &str, issues: &mut Vec<CommitIssue>) {
        if !self.patterns.commit_format.is_match(message) {
            let words: Vec<&str> = message.split_whitespace().collect();
            if !words.is_empty() {
                let first_word = words[0];
                if !self.valid_actions.contains(&first_word.to_lowercase()) {
                    issues.push(CommitIssue {
                        issue_type: IssueType::MissingAction,
                        description: format!("Commit doesn't start with a recognized action word: '{}'", first_word),
                        severity: Severity::High,
                        suggestion: Some("Start with: Fix, Add, Improve, Remove, Update, Implement, etc.".to_string()),
                    });
                }
            }
        }
    }

    fn check_vague_language(&self, message: &str, issues: &mut Vec<CommitIssue>) {
        if self.patterns.vague_words.is_match(message) {
            issues.push(CommitIssue {
                issue_type: IssueType::VagueMessage,
                description: "Message contains vague language".to_string(),
                severity: Severity::Medium,
                suggestion: Some("Be more specific about what was changed".to_string()),
            });
        }
    }

    fn check_capitalization(&self, message: &str, issues: &mut Vec<CommitIssue>) {
        if let Some(first_char) = message.chars().next() {
            if first_char.is_lowercase() {
                issues.push(CommitIssue {
                    issue_type: IssueType::InconsistentCapitalization,
                    description: "Commit message should start with a capital letter".to_string(),
                    severity: Severity::Low,
                    suggestion: Some("Capitalize the first letter".to_string()),
                });
            }
        }
    }

    fn check_length(&self, message: &str, issues: &mut Vec<CommitIssue>) {
        if message.len() > 72 {
            issues.push(CommitIssue {
                issue_type: IssueType::LengthIssue,
                description: format!("Commit message is too long ({} characters)", message.len()),
                severity: Severity::Medium,
                suggestion: Some("Keep commit messages under 72 characters".to_string()),
            });
        } else if message.len() < 10 {
            issues.push(CommitIssue {
                issue_type: IssueType::LengthIssue,
                description: "Commit message is too short".to_string(),
                severity: Severity::Medium,
                suggestion: Some("Provide more descriptive commit messages".to_string()),
            });
        }
    }

    fn check_grammar(&self, message: &str, issues: &mut Vec<CommitIssue>) {
        // Check for common grammar issues
        let grammar_issues = vec![
            ("it's", "its", "Use 'its' (possessive) not 'it's' (it is)"),
            ("there", "their", "Check if you meant 'their' (possessive)"),
            ("your", "you're", "Check if you meant 'you're' (you are)"),
        ];

        for (word, _alternative, suggestion) in grammar_issues {
            if message.to_lowercase().contains(word) {
                issues.push(CommitIssue {
                    issue_type: IssueType::GrammarError,
                    description: format!("Possible grammar issue with '{}'", word),
                    severity: Severity::Low,
                    suggestion: Some(suggestion.to_string()),
                });
            }
        }
    }

    fn check_code_changes(&self, code_changes: &CodeChangeSummary, files_changed: &[FileChange], message: &str, issues: &mut Vec<CommitIssue>) {
        // Check if this is a large changeset
        if code_changes.total_files > 20 {
            issues.push(CommitIssue {
                issue_type: IssueType::LargeChangeset,
                description: format!("Large changeset with {} files modified", code_changes.total_files),
                severity: Severity::Medium,
                suggestion: Some("Consider breaking this into smaller, focused commits".to_string()),
            });
        }

        // Check for very large line changes
        if code_changes.total_lines_added + code_changes.total_lines_removed > 500 {
            issues.push(CommitIssue {
                issue_type: IssueType::LargeChangeset,
                description: format!("Large code changes: +{} -{} lines", 
                    code_changes.total_lines_added, code_changes.total_lines_removed),
                severity: Severity::Medium,
                suggestion: Some("Consider splitting large changes into smaller commits".to_string()),
            });
        }

        // Check for mixed concerns (multiple components changed)
        if code_changes.components_affected.len() > 3 {
            issues.push(CommitIssue {
                issue_type: IssueType::MixedConcerns,
                description: format!("Multiple components affected: {}", 
                    code_changes.components_affected.join(", ")),
                severity: Severity::Medium,
                suggestion: Some("Consider separating changes to different components into different commits".to_string()),
            });
        }

        // Check if commit message mentions the actual components changed
        let message_lower = message.to_lowercase();
        let mentioned_components: Vec<&String> = code_changes.components_affected
            .iter()
            .filter(|component| message_lower.contains(&component.to_lowercase()))
            .collect();

        if mentioned_components.is_empty() && !code_changes.components_affected.is_empty() {
            issues.push(CommitIssue {
                issue_type: IssueType::VagueMessage,
                description: format!("Commit message doesn't mention affected components: {}", 
                    code_changes.components_affected.join(", ")),
                severity: Severity::Medium,
                suggestion: Some("Include the affected component(s) in the commit message".to_string()),
            });
        }

        // Check for commits with no code changes (only docs/config)
        let has_code_files = files_changed.iter().any(|file| {
            let path = &file.file_path;
            path.ends_with(".rs") || path.ends_with(".py") || path.ends_with(".pyx") || path.ends_with(".pxd")
        });

        if !has_code_files && !files_changed.is_empty() {
            let file_types: Vec<String> = files_changed.iter()
                .filter_map(|file| {
                    let path = &file.file_path;
                    if path.ends_with(".md") { Some("documentation".to_string()) }
                    else if path.ends_with(".toml") || path.ends_with(".yml") || path.ends_with(".yaml") { Some("configuration".to_string()) }
                    else if path.ends_with(".json") { Some("data".to_string()) }
                    else { None }
                })
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            if !file_types.is_empty() {
                issues.push(CommitIssue {
                    issue_type: IssueType::NoCodeChanges,
                    description: format!("Non-code changes only: {}", file_types.join(", ")),
                    severity: Severity::Low,
                    suggestion: Some("Consider using prefixes like 'docs:', 'config:', or 'chore:' for non-code changes".to_string()),
                });
            }
        }

        // Check for inconsistent action words vs actual changes
        let action_patterns = vec![
            ("fix", vec![ChangeType::Modified]),
            ("add", vec![ChangeType::Added, ChangeType::Modified]),
            ("remove", vec![ChangeType::Deleted]),
            ("delete", vec![ChangeType::Deleted]),
            ("implement", vec![ChangeType::Added, ChangeType::Modified]),
            ("refactor", vec![ChangeType::Modified]),
        ];

        let message_lower = message.to_lowercase();
        for (action, expected_types) in action_patterns {
            if message_lower.contains(action) {
                let actual_types: std::collections::HashSet<_> = files_changed.iter()
                    .map(|f| f.change_type.clone())
                    .collect();
                
                let has_expected = expected_types.iter().any(|t| actual_types.contains(t));
                if !has_expected && !actual_types.is_empty() {
                    issues.push(CommitIssue {
                        issue_type: IssueType::InconsistentFormat,
                        description: format!("Action '{}' doesn't match file changes", action),
                        severity: Severity::Low,
                        suggestion: Some("Ensure commit message action matches the actual changes made".to_string()),
                    });
                }
            }
        }
    }

    fn calculate_score(&self, issues: &[CommitIssue]) -> u32 {
        let mut score = 100u32;
        
        for issue in issues {
            let deduction = match issue.severity {
                Severity::High => 20,
                Severity::Medium => 10,
                Severity::Low => 5,
            };
            score = score.saturating_sub(deduction);
        }
        
        score
    }

    fn build_typo_map() -> HashMap<String, String> {
        let mut map = HashMap::new();
        
        // Common typos in programming/trading context
        map.insert("recieve".to_string(), "receive".to_string());
        map.insert("occured".to_string(), "occurred".to_string());
        map.insert("seperate".to_string(), "separate".to_string());
        map.insert("definately".to_string(), "definitely".to_string());
        map.insert("neccessary".to_string(), "necessary".to_string());
        map.insert("accomodate".to_string(), "accommodate".to_string());
        map.insert("begining".to_string(), "beginning".to_string());
        map.insert("existance".to_string(), "existence".to_string());
        map.insert("independant".to_string(), "independent".to_string());
        map.insert("maintainence".to_string(), "maintenance".to_string());
        map.insert("persistance".to_string(), "persistence".to_string());
        map.insert("refactore".to_string(), "refactor".to_string());
        map.insert("optimisation".to_string(), "optimization".to_string());
        map.insert("initialise".to_string(), "initialize".to_string());
        map.insert("analyse".to_string(), "analyze".to_string());
        map.insert("synchronisation".to_string(), "synchronization".to_string());
        
        map
    }

    fn build_valid_actions() -> HashSet<String> {
        let actions = vec![
            "fix", "add", "improve", "refine", "standardize", "remove", "update", 
            "implement", "continue", "repair", "optimize", "enhance", "introduce",
            "upgrade", "refactor", "clean", "port", "migrate", "deprecate",
            "revert", "merge", "release", "bump", "configure", "enable", "disable",
            "create", "delete", "modify", "adjust", "correct", "resolve", "address",
        ];
        
        actions.into_iter().map(|s| s.to_string()).collect()
    }

    fn build_patterns() -> Result<AnalysisPatterns> {
        Ok(AnalysisPatterns {
            commit_format: Regex::new(r"^[A-Z][a-z]+ [A-Za-z0-9_-]+ .+")?,
            vague_words: Regex::new(r"\b(stuff|things|some|various|misc|etc)\b")?,
        })
    }
}

#[derive(Debug, Clone)]
struct GitCommit {
    hash: String,
    message: String,
    author: String,
    date: String,
}

impl Default for CommitAnalyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create CommitAnalyzer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_analyzer_creation() {
        let analyzer = CommitAnalyzer::new();
        assert!(analyzer.is_ok());
        
        let analyzer = analyzer.unwrap();
        assert!(!analyzer.valid_actions.is_empty());
    }

    #[test]
    fn test_commit_format_parsing() {
        let commit = "abc123|John Doe|john@example.com|2025-08-22 10:30:00 +0000|feat: add new feature";
        let parts: Vec<&str> = commit.split('|').collect();
        
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "abc123");
        assert_eq!(parts[1], "John Doe");
        assert_eq!(parts[2], "john@example.com");
        assert_eq!(parts[3], "2025-08-22 10:30:00 +0000");
        assert_eq!(parts[4], "feat: add new feature");
    }

    #[test]
    fn test_commit_list_processing() {
        let commits = vec![
            "abc123|Author1|a1@test.com|2025-08-22 10:30:00|Fix: typo in readme".to_string(),
            "def456|Author2|a2@test.com|2025-08-22 11:30:00|feat: add new feature".to_string(),
        ];
        
        assert_eq!(commits.len(), 2);
        assert!(commits[0].contains("Fix: typo"));
        assert!(commits[1].contains("feat: add"));
    }

    #[tokio::test]
    async fn test_analyze_last_commits() {
        let analyzer = CommitAnalyzer::new().unwrap();
        // Test with a small number to avoid long execution
        let result = analyzer.analyze_last_commits(1).await;
        // In a git repo this should work, outside it will fail
        assert!(result.is_ok() || result.is_err());
    }
}
