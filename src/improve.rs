// src/improve.rs
//
// Self-improvement module for analyzing and enhancing code quality
// Based on established patterns from nautilus_trader repository

use anyhow::{anyhow, Context, Result};
use rig::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use crate::DeepSeekClient;

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
}

pub struct PatternDatabase {
    pub naming_patterns: HashMap<String, String>,
    pub error_patterns: Vec<String>,
    pub architecture_patterns: Vec<String>,
}

impl Improver {
    pub fn new(client: DeepSeekClient) -> Self {
        Self {
            client,
            patterns: PatternDatabase::default(),
        }
    }

    /// Analyze code quality and suggest improvements
    pub async fn analyze_code(&self, file_path: &str, content: &str) -> Result<CodeAnalysis> {
        let prompt = format!(
            r#"Analyze this Rust code for quality issues and improvements:

File: {}

Code:
```rust
{}
```

Based on nautilus_trader patterns:
1. Use snake_case naming consistently
2. Provide specific error messages
3. Implement proper validation
4. Follow standardized subscription methods
5. Ensure consistent disconnect sequences

Return analysis as JSON with issues and improvements."#,
            file_path, content
        );

        let response = self.client.prompt(&prompt).await?;
        
        // Parse response and extract analysis
        self.parse_analysis_response(&response, file_path)
    }

    /// Generate improvement plan for codebase
    pub async fn create_improvement_plan(&self, analyses: &[CodeAnalysis]) -> Result<ImprovementPlan> {
        let total_issues = analyses.iter().map(|a| a.issues.len()).sum::<usize>();
        let avg_score = analyses.iter().map(|a| a.score).sum::<f64>() / analyses.len() as f64;

        let priorities = self.prioritize_improvements(analyses);
        
        Ok(ImprovementPlan {
            total_files: analyses.len(),
            total_issues,
            average_score: avg_score,
            priorities: priorities.clone(),
            timeline: self.estimate_timeline(&priorities),
        })
    }

    /// Apply automated fixes to code
    pub async fn apply_fixes(&self, analysis: &CodeAnalysis, content: &str) -> Result<String> {
        let mut fixed_content = content.to_string();
        
        for issue in &analysis.issues {
            if self.can_auto_fix(issue) {
                fixed_content = self.apply_fix(&fixed_content, issue).await?;
            }
        }
        
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
        let critical_count = priorities.iter().filter(|p| matches!(p.issue.severity, Severity::Critical)).count();
        let high_count = priorities.iter().filter(|p| matches!(p.issue.severity, Severity::High)).count();
        
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
    pub immediate: usize,    // Critical issues (0-1 week)
    pub short_term: usize,   // High priority (1-4 weeks)
    pub medium_term: usize,  // Medium/Low priority (1-3 months)
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
