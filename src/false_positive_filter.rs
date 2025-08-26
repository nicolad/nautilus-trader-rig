// False Positive Detection System
//
// This module uses DeepSeek AI to validate pattern matches and filter out false positives
// by analyzing the context and semantics of detected issues.

use crate::deepseek::DeepSeekClient;
use crate::scanner::Issue;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_false_positive: bool,
    pub confidence: f32, // 0.0 to 1.0
    pub reasoning: String,
    pub suggested_action: SuggestedAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuggestedAction {
    Ignore,
    Review,
    FixImmediately,
    MonitorForPatterns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositivePattern {
    pub pattern_id: String,
    pub context_keywords: Vec<String>,
    pub common_false_positives: Vec<String>,
    pub confidence_threshold: f32,
}

pub struct FalsePositiveFilter {
    deepseek_client: Option<DeepSeekClient>,
    known_patterns: HashMap<String, FalsePositivePattern>,
    validation_cache: HashMap<String, ValidationResult>,
}

impl FalsePositiveFilter {
    pub fn new(deepseek_client: Option<DeepSeekClient>) -> Self {
        let mut filter = Self {
            deepseek_client,
            known_patterns: HashMap::new(),
            validation_cache: HashMap::new(),
        };

        filter.initialize_known_patterns();
        filter
    }

    fn initialize_known_patterns(&mut self) {
        // R005: assert_eq! in tests
        self.known_patterns.insert(
            "R005".to_string(),
            FalsePositivePattern {
                pattern_id: "R005".to_string(),
                context_keywords: vec![
                    "#[test]".to_string(),
                    "#[cfg(test)]".to_string(),
                    "mod tests".to_string(),
                ],
                common_false_positives: vec!["assert_eq!".to_string(), "assert_ne!".to_string()],
                confidence_threshold: 0.8,
            },
        );

        // R085: let _ = for non-Result types
        self.known_patterns.insert(
            "R085".to_string(),
            FalsePositivePattern {
                pattern_id: "R085".to_string(),
                context_keywords: vec![
                    "tuple".to_string(),
                    "struct".to_string(),
                    "len()".to_string(),
                ],
                common_false_positives: ["let _ = (", "let _ = struct", "let _ = x.len()"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                confidence_threshold: 0.7,
            },
        );

        // R001: panic! in test code
        self.known_patterns.insert(
            "R001".to_string(),
            FalsePositivePattern {
                pattern_id: "R001".to_string(),
                context_keywords: vec![
                    "#[test]".to_string(),
                    "#[should_panic]".to_string(),
                    "test_".to_string(),
                ],
                common_false_positives: vec![
                    "panic!(\"test".to_string(),
                    "panic!(\"Test".to_string(),
                ],
                confidence_threshold: 0.9,
            },
        );

        // R030: TODO comments in development
        self.known_patterns.insert(
            "R030".to_string(),
            FalsePositivePattern {
                pattern_id: "R030".to_string(),
                context_keywords: vec!["// TODO:".to_string(), "/* TODO".to_string()],
                common_false_positives: vec![
                    "TODO: implement".to_string(),
                    "TODO: add tests".to_string(),
                ],
                confidence_threshold: 0.6,
            },
        );
    }

    pub async fn validate_issue(
        &mut self,
        issue: &Issue,
        file_content: &str,
    ) -> Result<ValidationResult> {
        let cache_key = format!("{}:{}:{}", issue.pattern_id, issue.line, issue.excerpt);

        // Check cache first
        if let Some(cached_result) = self.validation_cache.get(&cache_key) {
            debug!("Using cached validation result for {}", issue.pattern_id);
            return Ok(cached_result.clone());
        }

        // Quick heuristic check
        if let Some(quick_result) = self.quick_heuristic_check(issue, file_content) {
            self.validation_cache
                .insert(cache_key.clone(), quick_result.clone());
            return Ok(quick_result);
        }

        // DeepSeek validation
        let validation_result = if let Some(deepseek) = &self.deepseek_client {
            self.deepseek_validation(issue, file_content, deepseek)
                .await?
        } else {
            // Fallback to pattern-based validation
            self.pattern_based_validation(issue, file_content)
        };

        // Cache the result
        self.validation_cache
            .insert(cache_key, validation_result.clone());
        Ok(validation_result)
    }

    fn quick_heuristic_check(&self, issue: &Issue, file_content: &str) -> Option<ValidationResult> {
        if let Some(pattern) = self.known_patterns.get(issue.pattern_id) {
            let issue_line = file_content.lines().nth(issue.line.saturating_sub(1))?;
            let context_lines: Vec<&str> = file_content
                .lines()
                .skip(issue.line.saturating_sub(6))
                .take(10)
                .collect();

            let context_text = context_lines.join("\n");

            // Check for test context
            let is_in_test_context = pattern
                .context_keywords
                .iter()
                .any(|keyword| context_text.contains(keyword) || issue_line.contains(keyword));

            // Check for known false positive patterns
            let matches_false_positive = pattern.common_false_positives.iter().any(|fp_pattern| {
                issue.excerpt.contains(fp_pattern) || issue_line.contains(fp_pattern)
            });

            if is_in_test_context && matches_false_positive {
                return Some(ValidationResult {
                    is_false_positive: true,
                    confidence: pattern.confidence_threshold,
                    reasoning: format!(
                        "Detected {} in test context with known false positive pattern",
                        issue.pattern_id
                    ),
                    suggested_action: SuggestedAction::Ignore,
                });
            }

            // Special case for R085: check if it's actually discarding a Result
            if issue.pattern_id == "R085"
                && !issue_line.contains("Result<")
                && !context_text.contains("-> Result<")
            {
                return Some(ValidationResult {
                    is_false_positive: true,
                    confidence: 0.8,
                    reasoning: "let _ = pattern not applied to Result type".to_string(),
                    suggested_action: SuggestedAction::Ignore,
                });
            }
        }

        None
    }

    async fn deepseek_validation(
        &self,
        issue: &Issue,
        file_content: &str,
        deepseek: &DeepSeekClient,
    ) -> Result<ValidationResult> {
        let context_lines: Vec<&str> = file_content
            .lines()
            .skip(issue.line.saturating_sub(10))
            .take(20)
            .collect();

        let context = context_lines.join("\n");

        let validation_prompt = format!(
            r#"Analyze this Rust code pattern detection result for false positives:

Pattern ID: {}
Pattern Name: {}
Detected Issue: {}
Line {}: {}

Code Context:
```rust
{}
```

Please analyze if this is a FALSE POSITIVE by considering:
1. Is this in test code where the pattern might be acceptable?
2. Is the pattern being used safely in this context?
3. Is this a common development practice that's generally safe?
4. Does the surrounding code provide proper error handling?

Respond in this exact format:
FALSE_POSITIVE: [yes|no]
CONFIDENCE: [0.0-1.0]
REASONING: [detailed explanation]
ACTION: [IGNORE|REVIEW|FIX_IMMEDIATELY|MONITOR]

Be conservative - only mark as false positive if you're confident it's safe."#,
            issue.pattern_id,
            issue.name,
            issue.excerpt,
            issue.line,
            file_content
                .lines()
                .nth(issue.line.saturating_sub(1))
                .unwrap_or(""),
            context
        );

        match deepseek.analyze_code(&validation_prompt).await {
            Ok(response) => {
                debug!("DeepSeek validation response: {}", response);
                self.parse_deepseek_response(&response)
            }
            Err(e) => {
                warn!("DeepSeek validation failed: {}", e);
                // Fallback to conservative validation
                Ok(ValidationResult {
                    is_false_positive: false,
                    confidence: 0.5,
                    reasoning: format!("Could not validate with DeepSeek: {}", e),
                    suggested_action: SuggestedAction::Review,
                })
            }
        }
    }

    fn parse_deepseek_response(&self, response: &str) -> Result<ValidationResult> {
        let is_false_positive = response
            .lines()
            .find(|line| line.starts_with("FALSE_POSITIVE:"))
            .and_then(|line| line.split(':').nth(1))
            .map(|s| s.trim().to_lowercase() == "yes")
            .unwrap_or(false);

        let confidence = response
            .lines()
            .find(|line| line.starts_with("CONFIDENCE:"))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|s| s.trim().parse::<f32>().ok())
            .unwrap_or(0.5);

        let reasoning = response
            .lines()
            .find(|line| line.starts_with("REASONING:"))
            .map(|line| {
                line.split(':')
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join(":")
                    .trim()
                    .to_string()
            })
            .unwrap_or_else(|| "No reasoning provided".to_string());

        let suggested_action = response
            .lines()
            .find(|line| line.starts_with("ACTION:"))
            .and_then(|line| line.split(':').nth(1))
            .map(|s| match s.trim().to_uppercase().as_str() {
                "IGNORE" => SuggestedAction::Ignore,
                "FIX_IMMEDIATELY" => SuggestedAction::FixImmediately,
                "MONITOR" => SuggestedAction::MonitorForPatterns,
                _ => SuggestedAction::Review,
            })
            .unwrap_or(SuggestedAction::Review);

        Ok(ValidationResult {
            is_false_positive,
            confidence,
            reasoning,
            suggested_action,
        })
    }

    fn pattern_based_validation(&self, issue: &Issue, file_content: &str) -> ValidationResult {
        // Fallback pattern-based validation when DeepSeek is not available
        match issue.pattern_id {
            "R005" | "R006" | "R007" | "R008" => {
                // Assert patterns in test context
                let context = file_content
                    .lines()
                    .skip(issue.line.saturating_sub(20))
                    .take(40)
                    .collect::<Vec<_>>()
                    .join("\n");

                if context.contains("#[test]")
                    || context.contains("#[cfg(test)]")
                    || context.contains("mod tests")
                {
                    ValidationResult {
                        is_false_positive: true,
                        confidence: 0.8,
                        reasoning: "Assert pattern detected in test context".to_string(),
                        suggested_action: SuggestedAction::Ignore,
                    }
                } else {
                    ValidationResult {
                        is_false_positive: false,
                        confidence: 0.7,
                        reasoning: "Assert pattern outside test context".to_string(),
                        suggested_action: SuggestedAction::Review,
                    }
                }
            }
            "R085" => {
                // let _ = pattern validation
                let line = file_content
                    .lines()
                    .nth(issue.line.saturating_sub(1))
                    .unwrap_or("");
                if line.contains("Result<") || line.contains("()") {
                    ValidationResult {
                        is_false_positive: false,
                        confidence: 0.8,
                        reasoning: "Potentially discarding Result type".to_string(),
                        suggested_action: SuggestedAction::Review,
                    }
                } else {
                    ValidationResult {
                        is_false_positive: true,
                        confidence: 0.7,
                        reasoning: "let _ = used with non-Result type".to_string(),
                        suggested_action: SuggestedAction::Ignore,
                    }
                }
            }
            _ => ValidationResult {
                is_false_positive: false,
                confidence: 0.5,
                reasoning: "No specific validation rule available".to_string(),
                suggested_action: SuggestedAction::Review,
            },
        }
    }

    pub fn get_validation_stats(&self) -> (usize, usize) {
        let total = self.validation_cache.len();
        let false_positives = self
            .validation_cache
            .values()
            .filter(|v| v.is_false_positive)
            .count();
        (total, false_positives)
    }
}

// Serializable version of Issue that owns its strings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableIssue {
    pub pattern_id: String,
    pub name: String,
    pub severity: String,
    pub category: String,
    pub line: usize,
    pub col: usize,
    pub excerpt: String,
}

impl From<Issue> for SerializableIssue {
    fn from(issue: Issue) -> Self {
        Self {
            pattern_id: issue.pattern_id.to_string(),
            name: issue.name.to_string(),
            severity: issue.severity.to_string(),
            category: issue.category.to_string(),
            line: issue.line,
            col: issue.col,
            excerpt: issue.excerpt,
        }
    }
}

// Enhanced Issue with validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedIssue {
    pub issue: SerializableIssue,
    pub is_valid: bool,
    pub confidence: f32,
    pub ai_reasoning: String,
    pub validation_method: String,
}

impl ValidatedIssue {
    pub fn new(issue: Issue, validation: ValidationResult) -> Self {
        let is_valid = !validation.is_false_positive;
        let confidence = validation.confidence;

        Self {
            issue: issue.into(),
            is_valid,
            confidence,
            ai_reasoning: validation.reasoning,
            validation_method: format!("{:?}", validation.suggested_action),
        }
    }
}
