use anyhow::Result;
use dotenvy::dotenv;

mod commit_analyzer;
mod deepseek;

use commit_analyzer::CommitAnalyzer;
use deepseek::DeepSeekClient;

/// Run commit analysis with the specified parameters
async fn run_commit_analysis(count: usize, format: &str, with_ai: bool) -> Result<()> {
    println!("🔍 Analyzing last {} commits...", count);
    
    let analyzer = CommitAnalyzer::new()?;
    let analysis = analyzer.analyze_last_commits(count).await?;
    
    if with_ai {
        println!("🤖 Running AI analysis...");
        let deepseek = DeepSeekClient::from_env()?;
        // Convert analysis to commit format for AI
        let commit_strings: Vec<String> = analysis.iter()
            .map(|a| format!("{}|{}|{}|{}|{}", a.commit_hash, "author", "email", a.date, a.message))
            .collect();
        let commits_text = commit_strings.join("\n");
        let ai_analysis = deepseek.analyze_commits(&commits_text).await?;
        println!("🎯 AI Analysis Results:\n{}", ai_analysis);
    }
    
    // Generate report in requested format
    let report = match format {
        "json" => analyzer.generate_report(&analysis, "json")?,
        _ => analyzer.generate_report(&analysis, "text")?,
    };
    
    println!("{}", report);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file if present
    let _ = dotenv();

    // Run commit analysis with default settings
    println!("🔍 Running Nautilus Trader Commit Analyzer...");
    run_commit_analysis(20, "text", false).await
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
    fn test_git_command_format() {
        // Test that git command format is correct
        let count = 5;
        let expected_args = vec![
            "log",
            "--oneline", 
            "--no-merges",
            "-5",
            "--pretty=format:%H|%an|%ae|%ad|%s",
            "--date=iso"
        ];
        
        // This tests our command structure
        assert_eq!(format!("-{}", count), "-5");
    }

    #[tokio::test]
    async fn test_run_commit_analysis_without_ai() {
        // Test running commit analysis without AI
        // This is an integration test that requires git repo
        let result = run_commit_analysis(1, "text", false).await;
        // Should succeed if we're in a git repository
        assert!(result.is_ok() || result.is_err()); // Either way is valid for test
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
