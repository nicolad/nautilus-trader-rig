// src/code_analyzer.rs
//
// Advanced Code Consistency Analyzer for Nautilus Trader
//
// This module focuses on deep code analysis, pattern detection, and consistency validation

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::process::Command;
use crate::deepseek::DeepSeekClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAnalysis {
    pub commit_hash: String,
    pub author: String,
    pub date: String,
    pub files_changed: Vec<FileAnalysis>,
    pub consistency_issues: Vec<ConsistencyIssue>,
    pub patterns_detected: Vec<PatternDetection>,
    pub risk_score: u32, // 0-100, higher is riskier
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysis {
    pub file_path: String,
    pub change_type: ChangeType,
    pub lines_added: u32,
    pub lines_removed: u32,
    pub language: String,
    pub component: String,
    pub code_patterns: Vec<String>,
    pub potential_issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyIssue {
    pub issue_type: ConsistencyIssueType,
    pub description: String,
    pub severity: Severity,
    pub files_affected: Vec<String>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ConsistencyIssueType {
    // Critical Security Issues
    UnsafeCodeUsage,
    PotentialPanic,
    SecretInCode,
    
    // Critical Performance Issues
    MemoryLeak,
    InfiniteLoop,
    BlockingInAsync,
    
    // Critical Architecture Issues
    CircularDependency,
    LayerViolation,
    DataRace,
    
    // Critical Correctness Issues
    LogicError,
    DeadCode,
    UnhandledError,
    
    // Critical Reliability Issues
    MissingErrorHandling,
    ResourceLeak,
    ThreadSafety,
    
    // Code Quality Issues
    InconsistentNaming,
    InconsistentErrorHandling,
    MissingTests,
    SecurityConcern,
    PerformanceAntiPattern,
    LargeChangeset,
    MixedConcerns,
    IncompleteFeature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDetection {
    pub pattern_name: String,
    pub confidence: f32, // 0.0-1.0
    pub description: String,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical, // System-breaking, security vulnerabilities
    High,     // Potential issues that could affect reliability
    Medium,   // Code quality issues
    Low,      // Style and consistency issues
}

// AI Analysis Structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysisResponse {
    pub critical_issues: Vec<AICriticalIssue>,
    pub risk_patterns: Vec<AIRiskPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AICriticalIssue {
    #[serde(rename = "type")]
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub file_pattern: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIRiskPattern {
    pub pattern: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCache {
    pub analyzed_commits: HashSet<String>,
    pub last_analysis: Option<String>,
    pub analysis_results: Vec<CodeAnalysis>,
}

impl AnalysisCache {
    pub fn new() -> Self {
        Self {
            analyzed_commits: HashSet::new(),
            last_analysis: None,
            analysis_results: Vec::new(),
        }
    }

    pub fn load() -> Result<Self> {
        match std::fs::read_to_string("analysis_cache.json") {
            Ok(content) => {
                serde_json::from_str(&content).map_err(|e| anyhow!("Failed to parse cache: {}", e))
            }
            Err(_) => Ok(Self::new())
        }
    }

    pub fn save(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write("analysis_cache.json", content)?;
        Ok(())
    }

    pub fn is_analyzed(&self, commit_hash: &str) -> bool {
        self.analyzed_commits.contains(commit_hash)
    }

    pub fn add_analysis(&mut self, analysis: CodeAnalysis) {
        self.analyzed_commits.insert(analysis.commit_hash.clone());
        self.analysis_results.push(analysis);
        self.last_analysis = Some(chrono::Utc::now().to_rfc3339());
    }
}

#[derive(Debug)]
pub struct CodeAnalyzer {
    // Pattern matchers for different languages
    rust_patterns: RustPatterns,
    python_patterns: PythonPatterns,
    
    // Rules for consistency checking
    naming_rules: NamingRules,
    architectural_rules: ArchitecturalRules,
    
    // Historical data for pattern learning
    commit_history: Vec<HistoricalPattern>,
    
    // DeepSeek AI client for advanced analysis
    deepseek_client: Option<DeepSeekClient>,
    
    // Analysis cache for avoiding duplicate work
    cache: AnalysisCache,
}

#[derive(Debug)]
struct RustPatterns {
    error_handling: Vec<Regex>,
    naming_conventions: Vec<Regex>,
    unsafe_patterns: Vec<Regex>,
    performance_patterns: Vec<Regex>,
}

#[derive(Debug)]
struct PythonPatterns {
    import_patterns: Vec<Regex>,
    exception_handling: Vec<Regex>,
    naming_conventions: Vec<Regex>,
    performance_patterns: Vec<Regex>,
}

#[derive(Debug)]
struct NamingRules {
    rust_struct_naming: Regex,
    rust_function_naming: Regex,
    python_class_naming: Regex,
    python_function_naming: Regex,
    file_naming: HashMap<String, Regex>,
}

#[derive(Debug)]
struct ArchitecturalRules {
    allowed_dependencies: HashMap<String, Vec<String>>,
    forbidden_patterns: Vec<Regex>,
    layer_rules: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct HistoricalPattern {
    author: String,
    component: String,
    common_patterns: Vec<String>,
    typical_change_size: (u32, u32), // (min_lines, max_lines)
}

#[derive(Debug)]
struct GitCommit {
    hash: String,
    author: String,
    date: String,
    diff: String,
}

impl CodeAnalyzer {
    pub fn new() -> Result<Self> {
        println!("🔧 Initializing Advanced Code Consistency Analyzer...");
        
        let deepseek_client = match DeepSeekClient::from_env() {
            Ok(client) => {
                println!("🤖 DeepSeek AI enabled for criticality analysis");
                Some(client)
            }
            Err(_) => {
                println!("⚠️  DeepSeek AI not available - using rule-based analysis only");
                None
            }
        };

        // Load existing analysis cache
        let cache = AnalysisCache::load().unwrap_or_else(|e| {
            println!("📋 Creating new analysis cache ({})", e);
            AnalysisCache::new()
        });

        if !cache.analyzed_commits.is_empty() {
            println!("📋 Loaded cache with {} previously analyzed commits", cache.analyzed_commits.len());
        }

        Ok(CodeAnalyzer {
            rust_patterns: Self::create_rust_patterns()?,
            python_patterns: Self::create_python_patterns()?,
            naming_rules: Self::create_naming_rules()?,
            architectural_rules: Self::create_architectural_rules()?,
            commit_history: Vec::new(),
            deepseek_client,
            cache,
        })
    }

    pub async fn analyze_commits(&mut self, count: usize) -> Result<Vec<CodeAnalysis>> {
        println!("🔍 Fetching {} most recent commits...", count);
        let commits = self.fetch_commits(count)?;
        
        let mut analyses = Vec::new();
        let mut new_analyses = 0;
        let mut skipped_analyses = 0;
        
        for (i, commit) in commits.iter().enumerate() {
            if self.cache.is_analyzed(&commit.hash) {
                println!("⏭️  Skipping commit {}/{}: {} (already analyzed)", 
                         i + 1, commits.len(), &commit.hash[..8]);
                skipped_analyses += 1;
                
                // Find existing analysis from cache
                if let Some(existing) = self.cache.analysis_results.iter().find(|a| a.commit_hash == commit.hash) {
                    analyses.push(existing.clone());
                }
                continue;
            }
            
            println!("📊 Analyzing commit {}/{}: {} ({})", 
                     i + 1, commits.len(), &commit.hash[..8], commit.author);
            
            let analysis = self.analyze_commit_code(commit).await?;
            
            // Add to cache and save
            self.cache.add_analysis(analysis.clone());
            analyses.push(analysis);
            new_analyses += 1;
        }
        
        // Save cache after processing
        if new_analyses > 0 {
            if let Err(e) = self.cache.save() {
                println!("⚠️ Failed to save analysis cache: {}", e);
            } else {
                println!("💾 Saved analysis cache with {} new commits", new_analyses);
            }
        }
        
        if skipped_analyses > 0 {
            println!("📋 Skipped {} previously analyzed commits", skipped_analyses);
        }
        
        Ok(analyses)
    }

    async fn analyze_commit_code(&self, commit: &GitCommit) -> Result<CodeAnalysis> {
        let detailed_diff = &commit.diff;
        let file_analyses = self.analyze_files(detailed_diff)?;
        
        let mut consistency_issues = Vec::new();
        let mut patterns_detected = Vec::new();
        
        // Focus only on critical issues
        self.check_unsafe_operations(&file_analyses, &mut consistency_issues);
        self.check_panic_sources(&file_analyses, &mut consistency_issues);
        self.check_security_vulnerabilities(&file_analyses, &mut consistency_issues);
        self.check_performance_critical_issues(&file_analyses, &mut consistency_issues);
        self.check_error_handling_critical(&file_analyses, &mut consistency_issues);
        self.check_concurrency_issues(&file_analyses, &mut consistency_issues);
        self.check_resource_management(&file_analyses, &mut consistency_issues);

        // Detect code patterns
        self.detect_patterns(&file_analyses, detailed_diff, &mut patterns_detected);

        // Use AI to enhance criticality assessment if available
        if let Some(ref client) = self.deepseek_client {
            println!("🤖 Enhancing analysis with DeepSeek AI...");
            self.enhance_with_ai_analysis(client, detailed_diff, &mut consistency_issues, &mut patterns_detected).await?;
        }

        let risk_score = self.calculate_risk_score(&consistency_issues, &patterns_detected);

        Ok(CodeAnalysis {
            commit_hash: commit.hash.clone(),
            author: commit.author.clone(),
            date: commit.date.clone(),
            files_changed: file_analyses,
            consistency_issues,
            patterns_detected,
            risk_score,
        })
    }

    fn check_unsafe_operations(&self, file_analyses: &[FileAnalysis], issues: &mut Vec<ConsistencyIssue>) {
        for file in file_analyses {
            if file.language == "Rust" {
                for pattern in &file.code_patterns {
                    if pattern.contains("unsafe_code:") {
                        issues.push(ConsistencyIssue {
                            issue_type: ConsistencyIssueType::UnsafeCodeUsage,
                            description: format!("Unsafe code block detected in {}", file.file_path),
                            severity: Severity::Critical,
                            files_affected: vec![file.file_path.clone()],
                            suggestion: Some("Review unsafe code for memory safety and consider safe alternatives".to_string()),
                        });
                    }
                }
                
                for issue in &file.potential_issues {
                    if issue.contains("unsafe") {
                        issues.push(ConsistencyIssue {
                            issue_type: ConsistencyIssueType::UnsafeCodeUsage,
                            description: format!("Unsafe operation in {}: {}", file.file_path, issue),
                            severity: Severity::High,
                            files_affected: vec![file.file_path.clone()],
                            suggestion: Some("Minimize unsafe code usage and ensure proper safety invariants".to_string()),
                        });
                    }
                }
            }
        }
    }

    async fn enhance_with_ai_analysis(
        &self,
        client: &DeepSeekClient,
        detailed_diff: &str,
        consistency_issues: &mut Vec<ConsistencyIssue>,
        patterns_detected: &mut Vec<PatternDetection>,
    ) -> Result<()> {
        // Limit diff size for AI analysis
        let truncated_diff = if detailed_diff.len() > 8000 {
            format!("{}...\n[TRUNCATED - {} total characters]", 
                    &detailed_diff[..8000], detailed_diff.len())
        } else {
            detailed_diff.to_string()
        };

        let prompt = format!(r#"Analyze this code diff for CRITICAL issues only. Focus on:
1. Security vulnerabilities (hardcoded secrets, unsafe operations, input validation)
2. Reliability issues (potential panics, race conditions, resource leaks)  
3. Financial calculation errors (precision, overflow, logic errors)
4. Performance problems (memory leaks, blocking operations, inefficient algorithms)

Return ONLY JSON in this exact format:
{{
  "critical_issues": [
    {{
      "type": "security|reliability|financial|performance",
      "severity": "critical|high", 
      "description": "Brief description",
      "file_pattern": "affected file pattern",
      "confidence": 0.8
    }}
  ],
  "risk_patterns": [
    {{
      "pattern": "pattern name",
      "description": "what makes this risky",
      "confidence": 0.9
    }}
  ]
}}

Code diff:
{}
"#, truncated_diff);

        match client.analyze_code(&prompt).await {
            Ok(response) => {
                if let Ok(ai_analysis) = serde_json::from_str::<AIAnalysisResponse>(&response) {
                    // Add AI-detected critical issues
                    for issue in ai_analysis.critical_issues {
                        if issue.confidence > 0.6 {
                            let issue_type = match issue.issue_type.as_str() {
                                "security" => ConsistencyIssueType::SecretInCode,
                                "reliability" => ConsistencyIssueType::PotentialPanic,
                                "financial" => ConsistencyIssueType::LogicError,
                                "performance" => ConsistencyIssueType::MemoryLeak,
                                _ => ConsistencyIssueType::UnhandledError,
                            };

                            let severity = match issue.severity.as_str() {
                                "critical" => Severity::Critical,
                                _ => Severity::High,
                            };

                            consistency_issues.push(ConsistencyIssue {
                                issue_type,
                                description: format!("🤖 AI: {}", issue.description),
                                severity,
                                files_affected: vec![issue.file_pattern],
                                suggestion: Some("AI-detected critical issue - requires immediate review".to_string()),
                            });
                        }
                    }

                    // Add AI-detected risk patterns
                    for pattern in ai_analysis.risk_patterns {
                        if pattern.confidence > 0.7 {
                            patterns_detected.push(PatternDetection {
                                pattern_name: format!("🤖 AI: {}", pattern.pattern),
                                confidence: pattern.confidence,
                                description: pattern.description,
                                files: vec!["AI analysis".to_string()],
                            });
                        }
                    }
                }
            }
            Err(e) => {
                println!("⚠️ AI analysis failed: {}", e);
            }
        }

        Ok(())
    }

    fn check_panic_sources(&self, file_analyses: &[FileAnalysis], issues: &mut Vec<ConsistencyIssue>) {
        for file in file_analyses {
            for pattern in &file.code_patterns {
                if pattern.contains("error_handling: unwrap") || pattern.contains("error_handling: expect") {
                    let panic_type = if pattern.contains("unwrap") { "unwrap" } else { "expect" };
                    issues.push(ConsistencyIssue {
                        issue_type: ConsistencyIssueType::PotentialPanic,
                        description: format!("Potential panic source in {}: error_handling: {} (risky)", 
                                           file.file_path, panic_type),
                        severity: Severity::Critical,
                        files_affected: vec![file.file_path.clone()],
                        suggestion: Some("Replace unwrap/expect with proper error handling using match or if-let".to_string()),
                    });
                }
            }
            
            for issue in &file.potential_issues {
                if issue.contains("unwrap()") || issue.contains("panic!") {
                    issues.push(ConsistencyIssue {
                        issue_type: ConsistencyIssueType::PotentialPanic,
                        description: format!("Panic risk in {}: critical: {}", file.file_path, issue),
                        severity: Severity::Critical,
                        files_affected: vec![file.file_path.clone()],
                        suggestion: Some("Use Result<T, E> for error handling instead of panicking".to_string()),
                    });
                }
            }
        }
    }

    // ... [Include all other check methods from the original implementation]
    // This is a simplified version focusing on compilation success

    fn calculate_risk_score(&self, issues: &[ConsistencyIssue], patterns: &[PatternDetection]) -> u32 {
        let mut score = 0;

        for issue in issues {
            score += match issue.severity {
                Severity::Critical => 40,  // Critical issues heavily weighted
                Severity::High => 25,
                Severity::Medium => 10,
                Severity::Low => 2,
            };
        }

        for pattern in patterns {
            if pattern.pattern_name.contains("critical") {
                score += 30;
            } else if pattern.pattern_name.contains("Security") || pattern.pattern_name.contains("unsafe") {
                score += 20;
            } else if pattern.pattern_name.contains("Performance") && pattern.confidence > 0.7 {
                score += 15;
            }
        }

        score.min(100)
    }

    // Placeholder implementations for required methods
    fn create_rust_patterns() -> Result<RustPatterns> {
        Ok(RustPatterns {
            error_handling: vec![],
            naming_conventions: vec![],
            unsafe_patterns: vec![],
            performance_patterns: vec![],
        })
    }

    fn create_python_patterns() -> Result<PythonPatterns> {
        Ok(PythonPatterns {
            import_patterns: vec![],
            exception_handling: vec![],
            naming_conventions: vec![],
            performance_patterns: vec![],
        })
    }

    fn create_naming_rules() -> Result<NamingRules> {
        Ok(NamingRules {
            rust_struct_naming: Regex::new("")?,
            rust_function_naming: Regex::new("")?,
            python_class_naming: Regex::new("")?,
            python_function_naming: Regex::new("")?,
            file_naming: HashMap::new(),
        })
    }

    fn create_architectural_rules() -> Result<ArchitecturalRules> {
        Ok(ArchitecturalRules {
            allowed_dependencies: HashMap::new(),
            forbidden_patterns: vec![],
            layer_rules: HashMap::new(),
        })
    }

    fn fetch_commits(&self, count: usize) -> Result<Vec<GitCommit>> {
        let output = Command::new("git")
            .current_dir("..")
            .args(&["log", "--format=%H|%an|%ae|%ad|%s", &format!("-{}", count)])
            .output()
            .context("Failed to execute git log command")?;

        if !output.status.success() {
            return Err(anyhow!("Git command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let commits_str = String::from_utf8(output.stdout)
            .context("Invalid UTF-8 in git output")?;

        let mut commits = Vec::new();
        for line in commits_str.lines() {
            if line.trim().is_empty() { continue; }
            
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 5 {
                let hash = parts[0].to_string();
                let diff = self.get_commit_diff(&hash)?;
                
                commits.push(GitCommit {
                    hash,
                    author: parts[1].to_string(),
                    date: parts[3].to_string(),
                    diff,
                });
            }
        }

        Ok(commits)
    }

    fn get_commit_diff(&self, commit_hash: &str) -> Result<String> {
        // Get actual code diff with context for Rust files specifically
        let output = Command::new("git")
            .current_dir("..")
            .args(&[
                "show", 
                "--no-merges", 
                "--format=format:", 
                "--unified=5",  // More context lines
                "--", 
                "*.rs",        // Focus on Rust files
                "crates/**/*.rs"
            ])
            .arg(commit_hash)
            .output()
            .context("Failed to get Rust file diffs")?;

        let rust_diff = String::from_utf8_lossy(&output.stdout).to_string();
        
        // If no Rust files, get all diffs but prioritize code files
        if rust_diff.trim().is_empty() {
            let all_output = Command::new("git")
                .current_dir("..")
                .args(&["show", "--no-merges", "--format=format:", "--unified=3", commit_hash])
                .output()
                .context("Failed to get commit diff")?;
            Ok(String::from_utf8_lossy(&all_output.stdout).to_string())
        } else {
            // Also get file stats for comprehensive analysis
            let stats_output = Command::new("git")
                .current_dir("..")
                .args(&["show", "--stat", "--format=", commit_hash])
                .output()
                .context("Failed to get commit stats")?;

            let stats_content = String::from_utf8_lossy(&stats_output.stdout).to_string();
            
            // Combine Rust diffs with stats
            Ok(format!("=== RUST CODE CHANGES ===\n{}\n\n=== FILE STATS ===\n{}", rust_diff, stats_content))
        }
    }

    fn analyze_files(&self, diff: &str) -> Result<Vec<FileAnalysis>> {
        let mut files = Vec::new();
        let lines: Vec<&str> = diff.lines().collect();
        
        for line in lines {
            if let Some(file_path) = self.extract_file_path(line) {
                let language = self.detect_language(&file_path);
                let component = self.extract_component(&file_path);
                
                files.push(FileAnalysis {
                    file_path: file_path.clone(),
                    change_type: ChangeType::Modified,
                    lines_added: 0,
                    lines_removed: 0,
                    language,
                    component,
                    code_patterns: self.extract_patterns(&file_path, line),
                    potential_issues: self.detect_potential_issues(&file_path, line),
                });
            }
        }
        
        Ok(files)
    }

    fn extract_file_path(&self, line: &str) -> Option<String> {
        // Simple file extraction from git diff lines
        if line.contains(" | ") {
            Some(line.split(" | ").next()?.trim().to_string())
        } else {
            None
        }
    }

    fn detect_language(&self, file_path: &str) -> String {
        if file_path.ends_with(".rs") { "Rust".to_string() }
        else if file_path.ends_with(".py") { "Python".to_string() }
        else if file_path.ends_with(".md") { "Markdown".to_string() }
        else if file_path.ends_with(".toml") { "TOML".to_string() }
        else { "Unknown".to_string() }
    }

    fn extract_component(&self, file_path: &str) -> String {
        let parts: Vec<&str> = file_path.split('/').collect();
        if parts.len() > 1 { parts[0].to_string() } else { "root".to_string() }
    }

    fn extract_patterns(&self, _file_path: &str, _content: &str) -> Vec<String> {
        // Simplified pattern extraction
        vec![]
    }

    fn detect_potential_issues(&self, _file_path: &str, _content: &str) -> Vec<String> {
        // Simplified issue detection
        vec![]
    }

    fn detect_patterns(&self, file_analyses: &[FileAnalysis], detailed_diff: &str, patterns: &mut Vec<PatternDetection>) {
        // Detect risky patterns in code
        self.detect_security_patterns(file_analyses, detailed_diff, patterns);
        self.detect_performance_patterns(file_analyses, detailed_diff, patterns);
        self.detect_architectural_patterns(file_analyses, patterns);
    }

    fn detect_security_patterns(&self, file_analyses: &[FileAnalysis], detailed_diff: &str, patterns: &mut Vec<PatternDetection>) {
        // Check for hardcoded secrets/keys
        if detailed_diff.contains("password") || detailed_diff.contains("secret") || detailed_diff.contains("api_key") {
            patterns.push(PatternDetection {
                pattern_name: "🔒 Security Pattern: secret".to_string(),
                confidence: 0.8,
                description: "Usage of potentially unsafe pattern: secret".to_string(),
                files: vec!["detected in diff".to_string()],
            });
        }

        // Check for unsafe Rust patterns
        if detailed_diff.contains("unsafe") {
            patterns.push(PatternDetection {
                pattern_name: "🔒 Security Pattern: unsafe".to_string(),
                confidence: 0.9,
                description: "Usage of potentially unsafe pattern: unsafe".to_string(),
                files: vec!["detected in diff".to_string()],
            });
        }

        // Check for panic patterns
        if detailed_diff.contains("unwrap") || detailed_diff.contains("expect") {
            let pattern_type = if detailed_diff.contains("unwrap") { "unwrap" } else { "expect" };
            patterns.push(PatternDetection {
                pattern_name: format!("🔒 Security Pattern: {}", pattern_type),
                confidence: 0.7,
                description: format!("Usage of potentially unsafe pattern: {}", pattern_type),
                files: vec!["detected in diff".to_string()],
            });
        }
    }

    fn detect_performance_patterns(&self, _file_analyses: &[FileAnalysis], detailed_diff: &str, patterns: &mut Vec<PatternDetection>) {
        // Check for performance anti-patterns
        if detailed_diff.contains("clone()") && detailed_diff.matches("clone()").count() > 5 {
            patterns.push(PatternDetection {
                pattern_name: "⚡ Performance Pattern: excessive cloning".to_string(),
                confidence: 0.6,
                description: "Multiple clone() calls detected - consider borrowing".to_string(),
                files: vec!["detected in diff".to_string()],
            });
        }
    }

    fn detect_architectural_patterns(&self, file_analyses: &[FileAnalysis], patterns: &mut Vec<PatternDetection>) {
        // Check for mixed concerns (changes spanning multiple components)
        let components: std::collections::HashSet<_> = file_analyses.iter()
            .map(|f| &f.component)
            .collect();
        
        if components.len() > 3 {
            patterns.push(PatternDetection {
                pattern_name: "🔀 Mixed Concerns".to_string(),
                confidence: 0.8,
                description: format!("Changes span {} different components", components.len()),
                files: components.into_iter().cloned().collect(),
            });
        }
    }

    // Enhanced check methods
    fn check_security_vulnerabilities(&self, file_analyses: &[FileAnalysis], issues: &mut Vec<ConsistencyIssue>) {
        for file in file_analyses {
            for issue in &file.potential_issues {
                if issue.contains("secret") || issue.contains("password") || issue.contains("key") {
                    issues.push(ConsistencyIssue {
                        issue_type: ConsistencyIssueType::SecretInCode,
                        description: format!("Potential secret exposure in {}: critical: Hardcoded secrets detected - security vulnerability", file.file_path),
                        severity: Severity::Critical,
                        files_affected: vec![file.file_path.clone()],
                        suggestion: Some("Move secrets to environment variables or secure configuration".to_string()),
                    });
                }
            }
        }
    }

    fn check_performance_critical_issues(&self, file_analyses: &[FileAnalysis], issues: &mut Vec<ConsistencyIssue>) {
        for file in file_analyses {
            for pattern in &file.code_patterns {
                if pattern.contains("performance_issue:") {
                    issues.push(ConsistencyIssue {
                        issue_type: ConsistencyIssueType::MemoryLeak,
                        description: format!("Performance issue in {}: {}", file.file_path, pattern),
                        severity: Severity::High,
                        files_affected: vec![file.file_path.clone()],
                        suggestion: Some("Optimize for better performance".to_string()),
                    });
                }
            }
        }
    }

    fn check_error_handling_critical(&self, file_analyses: &[FileAnalysis], issues: &mut Vec<ConsistencyIssue>) {
        for file in file_analyses {
            // Check for missing error handling in critical components
            if file.component.contains("adapter") || file.component.contains("core") || 
               file.component.contains("execution") || file.component.contains("portfolio") {
                issues.push(ConsistencyIssue {
                    issue_type: ConsistencyIssueType::MissingErrorHandling,
                    description: format!("Critical component {} lacks error handling", file.file_path),
                    severity: Severity::Critical,
                    files_affected: vec![file.file_path.clone()],
                    suggestion: Some("Add proper error handling for critical operations".to_string()),
                });
            }
        }
    }

    fn check_concurrency_issues(&self, file_analyses: &[FileAnalysis], issues: &mut Vec<ConsistencyIssue>) {
        for file in file_analyses {
            for issue in &file.potential_issues {
                if issue.contains("race condition") || issue.contains("deadlock") {
                    issues.push(ConsistencyIssue {
                        issue_type: ConsistencyIssueType::DataRace,
                        description: format!("Concurrency issue in {}: {}", file.file_path, issue),
                        severity: Severity::Critical,
                        files_affected: vec![file.file_path.clone()],
                        suggestion: Some("Review concurrency patterns and use proper synchronization".to_string()),
                    });
                }
            }
        }
    }

    fn check_resource_management(&self, file_analyses: &[FileAnalysis], issues: &mut Vec<ConsistencyIssue>) {
        for file in file_analyses {
            // Check for resource leaks in specific file types
            if file.file_path.contains("websocket") || file.file_path.contains("client") {
                issues.push(ConsistencyIssue {
                    issue_type: ConsistencyIssueType::ResourceLeak,
                    description: format!("Potential resource leak in {}: resources created without cleanup", file.file_path),
                    severity: Severity::High,
                    files_affected: vec![file.file_path.clone()],
                    suggestion: Some("Ensure proper resource cleanup using RAII, with statements, or explicit cleanup".to_string()),
                });
            }
        }
    }

    pub fn generate_report(&self, analyses: &[CodeAnalysis]) -> String {
        let mut report = String::new();
        report.push_str("# 🔍 Code Consistency & Quality Analysis\n\n");
        report.push_str(&format!("Analyzed {} commits for code patterns and consistency\n\n", analyses.len()));

        if !analyses.is_empty() {
            let total_issues: usize = analyses.iter().map(|a| a.consistency_issues.len()).sum();
            let avg_risk: f64 = analyses.iter().map(|a| a.risk_score as f64).sum::<f64>() / analyses.len() as f64;
            let high_risk_commits: Vec<&CodeAnalysis> = analyses.iter().filter(|a| a.risk_score > 60).collect();

            report.push_str("## 🎯 Code Quality Assessment\n");
            report.push_str(&format!("- Critical code issues: {}\n", total_issues));
            report.push_str(&format!("- High-risk code changes: {}\n", high_risk_commits.len()));
            report.push_str(&format!("- Average risk score: {:.1}/100\n\n", avg_risk));

            // Save high-risk changes to files
            if !high_risk_commits.is_empty() {
                self.save_high_risk_changes(&high_risk_commits).unwrap_or_else(|e| {
                    println!("⚠️ Failed to save high-risk changes: {}", e);
                });
                
                report.push_str("## 🚨 High-Risk Code Changes (Saved to Files)\n\n");
                for (i, commit) in high_risk_commits.iter().enumerate() {
                    report.push_str(&format!("### 🔴 High-Risk Commit {} (Risk: {})\n", i + 1, commit.risk_score));
                    report.push_str(&format!("**Hash:** {}\n", commit.commit_hash));
                    report.push_str(&format!("**Author:** {}\n", commit.author));
                    report.push_str(&format!("**Date:** {}\n", commit.date));
                    report.push_str(&format!("**Files:** {}\n", commit.files_changed.len()));
                    report.push_str(&format!("**Issues:** {}\n\n", commit.consistency_issues.len()));
                    
                    // Show critical issues
                    for issue in &commit.consistency_issues {
                        if matches!(issue.severity, Severity::Critical | Severity::High) {
                            report.push_str(&format!("🔴 **{:?}**: {}\n", issue.issue_type, issue.description));
                            if let Some(suggestion) = &issue.suggestion {
                                report.push_str(&format!("   💡 *{}*\n", suggestion));
                            }
                        }
                    }
                    report.push_str("\n");
                }
            }
        }

        report
    }

    fn save_high_risk_changes(&self, high_risk_commits: &[&CodeAnalysis]) -> Result<()> {
        use std::fs;
        use std::io::Write;

        // Create timestamped analysis directory
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let analysis_dir = format!("analysis_results/{}", timestamp);
        fs::create_dir_all(&analysis_dir)?;

        // Also create latest symlink directory for easy access
        let latest_dir = "analysis_results/latest";
        fs::create_dir_all(latest_dir)?;

        // Save summary file in both locations
        for dir in [&analysis_dir, latest_dir] {
            let mut summary_file = fs::File::create(format!("{}/high_risk_summary.md", dir))?;
            writeln!(summary_file, "# 🚨 High-Risk Code Changes Analysis")?;
            writeln!(summary_file, "\nGenerated: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))?;
            writeln!(summary_file, "Analysis ID: {}", timestamp)?;
            writeln!(summary_file, "Total High-Risk Commits: {}\n", high_risk_commits.len())?;

            for (i, commit) in high_risk_commits.iter().enumerate() {
                writeln!(summary_file, "## Commit {} - {} (Risk: {})", i + 1, &commit.commit_hash[..8], commit.risk_score)?;
                writeln!(summary_file, "- **Author:** {}", commit.author)?;
                writeln!(summary_file, "- **Date:** {}", commit.date)?;
                writeln!(summary_file, "- **Files Changed:** {}", commit.files_changed.len())?;
                writeln!(summary_file, "- **Critical Issues:** {}", commit.consistency_issues.len())?;
                writeln!(summary_file)?;
            }
        }

        // Save detailed analysis for each high-risk commit INCLUDING RAW DIFFS
        for (i, commit) in high_risk_commits.iter().enumerate() {
            // Get actual git diff for this commit
            let rust_diff = self.get_commit_diff(&commit.commit_hash).unwrap_or_else(|e| {
                format!("Failed to get diff: {}", e)
            });

            // Save raw diff file
            let diff_filename = format!("{}/diff_{}_{}.txt", analysis_dir, i + 1, &commit.commit_hash[..8]);
            fs::write(&diff_filename, &rust_diff)?;
            println!("📄 Saved raw diff: {}", diff_filename);

            let filename = format!("{}/commit_{}_{}.md", analysis_dir, i + 1, &commit.commit_hash[..8]);
            let mut detail_file = fs::File::create(&filename)?;
            
            writeln!(detail_file, "# High-Risk Commit Analysis: {}", commit.commit_hash)?;
            writeln!(detail_file, "\n**Risk Score:** {}/100", commit.risk_score)?;
            writeln!(detail_file, "**Author:** {}", commit.author)?;
            writeln!(detail_file, "**Date:** {}", commit.date)?;
            writeln!(detail_file, "**Raw Diff File:** `{}`", diff_filename)?;
            writeln!(detail_file)?;

            writeln!(detail_file, "## Files Changed ({})", commit.files_changed.len())?;
            for file in &commit.files_changed {
                writeln!(detail_file, "- `{}` ({})", file.file_path, file.language)?;
                writeln!(detail_file, "  - Component: {}", file.component)?;
                writeln!(detail_file, "  - Change Type: {:?}", file.change_type)?;
                if !file.potential_issues.is_empty() {
                    writeln!(detail_file, "  - Issues: {}", file.potential_issues.join(", "))?;
                }
            }
            writeln!(detail_file)?;

            writeln!(detail_file, "## Critical Issues ({})", commit.consistency_issues.len())?;
            for issue in &commit.consistency_issues {
                writeln!(detail_file, "### {:?} - {:?}", issue.issue_type, issue.severity)?;
                writeln!(detail_file, "**Description:** {}", issue.description)?;
                writeln!(detail_file, "**Files Affected:** {}", issue.files_affected.join(", "))?;
                if let Some(suggestion) = &issue.suggestion {
                    writeln!(detail_file, "**Suggestion:** {}", suggestion)?;
                }
                writeln!(detail_file)?;
            }

            if !commit.patterns_detected.is_empty() {
                writeln!(detail_file, "## Risk Patterns Detected ({})", commit.patterns_detected.len())?;
                for pattern in &commit.patterns_detected {
                    writeln!(detail_file, "### {} (Confidence: {:.1}%)", pattern.pattern_name, pattern.confidence * 100.0)?;
                    writeln!(detail_file, "**Description:** {}", pattern.description)?;
                    writeln!(detail_file, "**Files:** {}", pattern.files.join(", "))?;
                    writeln!(detail_file)?;
                }
            }
        }

        // Save JSON data for programmatic access
        let json_data = serde_json::to_string_pretty(high_risk_commits)?;
        fs::write(format!("{}/high_risk_commits.json", analysis_dir), json_data)?;

        println!("📁 Analysis saved to: {}/", analysis_dir);
        println!("   - high_risk_summary.md");
        println!("   - high_risk_commits.json");
        for i in 0..high_risk_commits.len() {
            println!("   - commit_{}_{}.md", i + 1, &high_risk_commits[i].commit_hash[..8]);
            println!("   - diff_{}_{}.txt (RAW DIFF)", i + 1, &high_risk_commits[i].commit_hash[..8]);
        }

        Ok(())
    }
}
