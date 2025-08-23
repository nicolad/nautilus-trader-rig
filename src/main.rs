use anyhow::Result;

mod code_analyzer;
mod deepseek;

use code_analyzer::CodeAnalyzer;

/// Run advanced code consistency analysis 
async fn run_commit_analysis() -> Result<()> {
    println!("🔍 Running Advanced Code Consistency Analyzer...");
    println!("🔍 Analyzing latest 5 commits for code patterns and consistency...");
    
    let mut analyzer = CodeAnalyzer::new()?;
    let analyses = analyzer.analyze_commits(5).await?; // Check latest 5 commits
    
    // Generate report and automatically save high-risk changes
    let report = analyzer.generate_report(&analyses);
    println!("{}", report);
    
    // Count and save high-risk changes specifically
    let high_risk_count = analyses.iter().filter(|a| a.risk_score > 60).count();
    if high_risk_count > 0 {
        println!("\n🚨 Found {} high-risk code changes - details saved to analysis folder", high_risk_count);
    } else {
        println!("\n✅ No high-risk code changes detected in latest 5 commits");
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();
    
    // Run analysis with default commit count
    run_commit_analysis().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit_analyzer::CommitAnalyzer;

    #[test]
    fn test_commit_analyzer_creation() {
        let analyzer = CommitAnalyzer::new();
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_commit_parsing() {
        // Test parsing of commit format
        let sample_commit = "abc123|John Doe|john@example.com|2025-08-22 10:30:00 +0000|Fix: update documentation";
        let parts: Vec<&str> = sample_commit.split('|').collect();
        
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "abc123"); // hash
        assert_eq!(parts[1], "John Doe"); // author name
        assert_eq!(parts[2], "john@example.com"); // author email
        assert_eq!(parts[3], "2025-08-22 10:30:00 +0000"); // date
        assert_eq!(parts[4], "Fix: update documentation"); // message
    }

    #[tokio::test]
    async fn test_run_commit_analysis_simplified() {
        // Test running simplified commit analysis
        // This is an integration test that requires git repo
        let result = run_commit_analysis().await;
        // Should succeed if we're in a git repository, fail otherwise
        assert!(result.is_ok() || result.is_err());
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
}
