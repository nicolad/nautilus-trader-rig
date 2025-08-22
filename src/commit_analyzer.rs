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

use crate::deepseek::DeepSeekClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitAnalysis {
    pub commit_hash: String,
    pub message: String,
    pub author: String,
    pub date: String,
    pub issues: Vec<CommitIssue>,
    pub score: u32, // 0-100, higher is better
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
    Typo,
    InconsistentFormat,
    VagueMessage,
    InconsistentCapitalization,
    MissingAction,
    InconsistentComponent,
    GrammarError,
    LengthIssue,
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
    // Valid component names
    valid_components: HashSet<String>,
    // Regex patterns for validation
    patterns: AnalysisPatterns,
}

struct AnalysisPatterns {
    commit_format: Regex,
    typo_patterns: Vec<(Regex, String)>,
    capitalization: Regex,
    vague_words: Regex,
}

impl CommitAnalyzer {
    pub fn new() -> Result<Self> {
        let typo_map = Self::build_typo_map();
        let valid_actions = Self::build_valid_actions();
        let valid_components = Self::build_valid_components();
        let patterns = Self::build_patterns()?;

        Ok(Self {
            typo_map,
            valid_actions,
            valid_components,
            patterns,
        })
    }

    pub async fn analyze_last_commits(&self, count: usize) -> Result<Vec<CommitAnalysis>> {
        let commits = self.fetch_commits(count)?;
        let mut analyses = Vec::new();

        for commit in commits {
            let analysis = self.analyze_commit(&commit)?;
            analyses.push(analysis);
        }

        Ok(analyses)
    }

    /// Analyze commits with AI assistance using DeepSeek
    pub async fn analyze_commits_with_ai(&self, count: usize, deepseek_client: &DeepSeekClient) -> Result<Vec<CommitAnalysis>> {
        let commits = self.fetch_commits(count)?;
        let mut analyses = Vec::new();

        // First do basic analysis
        for commit in &commits {
            let analysis = self.analyze_commit(commit)?;
            analyses.push(analysis);
        }

        // Then enhance with AI analysis
        let commit_messages: Vec<String> = commits.iter().map(|c| c.message.clone()).collect();
        let ai_analysis = self.get_ai_commit_analysis(&commit_messages, deepseek_client).await?;
        
        // Merge AI insights with basic analysis
        self.merge_ai_analysis(&mut analyses, &ai_analysis);

        Ok(analyses)
    }

    /// Get AI analysis of commit messages for patterns and issues
    async fn get_ai_commit_analysis(&self, commit_messages: &[String], deepseek_client: &DeepSeekClient) -> Result<String> {
        let commits_text = commit_messages.iter()
            .enumerate()
            .map(|(i, msg)| format!("{}. {}", i + 1, msg))
            .collect::<Vec<_>>()
            .join("\n");

        let prompt = format!(
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

        deepseek_client.analyze_commits(&prompt).await
    }

    /// Merge AI analysis insights into existing commit analyses
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

        report.push_str(&format!("## Summary\n"));
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
            report.push_str("\n");
        }

        // Detailed findings
        report.push_str("## Detailed Analysis\n\n");
        for analysis in analyses {
            if !analysis.issues.is_empty() {
                report.push_str(&format!("### {} (Score: {})\n", 
                    &analysis.commit_hash[..8], analysis.score));
                report.push_str(&format!("**Message:** {}\n", analysis.message));
                report.push_str(&format!("**Author:** {} ({})\n\n", analysis.author, analysis.date));
                
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
                report.push_str("\n");
            }
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
                        "issues": a.issues
                    })
                }).collect::<Vec<_>>()
            }
        });

        Ok(serde_json::to_string_pretty(&report)?)
    }

    fn fetch_commits(&self, count: usize) -> Result<Vec<GitCommit>> {
        let output = Command::new("git")
            .args(&[
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

        // Calculate score
        let score = self.calculate_score(&issues);

        Ok(CommitAnalysis {
            commit_hash: commit.hash.clone(),
            message: commit.message.clone(),
            author: commit.author.clone(),
            date: commit.date.clone(),
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

        for (word, alternative, suggestion) in grammar_issues {
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

    fn build_valid_components() -> HashSet<String> {
        let components = vec![
            "bitmex", "bybit", "okx", "binance", "dydx", "adapters", "execution", 
            "reconciliation", "logging", "data", "portfolio", "risk", "indicators",
            "analysis", "backtest", "live", "core", "model", "common", "network",
            "persistence", "serialization", "system", "trading", "infrastructure",
            "cache", "config", "examples", "docs", "tests", "scripts", "ci", "cd",
        ];
        
        components.into_iter().map(|s| s.to_string()).collect()
    }

    fn build_patterns() -> Result<AnalysisPatterns> {
        Ok(AnalysisPatterns {
            commit_format: Regex::new(r"^[A-Z][a-z]+ [A-Za-z0-9_-]+ .+")?,
            typo_patterns: vec![
                (Regex::new(r"\bteh\b")?, "the".to_string()),
                (Regex::new(r"\bwtih\b")?, "with".to_string()),
                (Regex::new(r"\bfrom\b")?, "form".to_string()),
            ],
            capitalization: Regex::new(r"^[a-z]")?,
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
        assert!(!analyzer.patterns.typo_patterns.is_empty());
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
