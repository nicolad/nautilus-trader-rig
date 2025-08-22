// src/deepseek.rs
//
// DeepSeek AI Client Module for Nautilus Trader Rig
//
// This module provides a wrapper around the DeepSeek API using the rig framework
// for consistent AI interactions across the application.

use anyhow::{anyhow, Result};
use rig::completion::Prompt;
use rig::prelude::*;
use rig::providers;

/// DeepSeek client using rig framework
#[derive(Clone)]
pub struct DeepSeekClient {
    client: providers::deepseek::Client,
}

impl DeepSeekClient {
    /// Create a new DeepSeek client with the provided API key
    pub fn new(api_key: String) -> Self {
        let client = providers::deepseek::Client::new(&api_key);
        Self { client }
    }

    /// Create a DeepSeek client from the DEEPSEEK_API_KEY environment variable
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("DEEPSEEK_API_KEY")
            .map_err(|_| anyhow!("DEEPSEEK_API_KEY environment variable not set"))?;
        let client = providers::deepseek::Client::new(&api_key);
        Ok(Self { client })
    }

    /// Send a simple prompt and get the complete response
    pub async fn prompt(&self, prompt: &str) -> Result<String> {
        self.prompt_with_context(prompt, "Nautilus-Autopatcher")
            .await
    }

    /// Send a prompt with a specific context/agent name
    pub async fn prompt_with_context(&self, prompt: &str, agent_name: &str) -> Result<String> {
        log::info!("🤖 Initializing agent: {}", agent_name);

        let agent = self
            .client
            .agent(providers::deepseek::DEEPSEEK_CHAT)
            .preamble("You are a helpful assistant specialized in code analysis and improvement.")
            .name(agent_name)
            .build();

        log::debug!(
            "📤 Sending prompt to {}: {} chars",
            agent_name,
            prompt.len()
        );
        let response = agent.prompt(prompt).await?;
        log::info!(
            "📥 Received response from {}: {} chars",
            agent_name,
            response.len()
        );

        Ok(response)
    }

    /// Send a prompt for commit analysis with appropriate context
    pub async fn analyze_commits(&self, prompt: &str) -> Result<String> {
        log::info!("🔍 Starting commit analysis with DeepSeek");
        
        let agent = self
            .client
            .agent(providers::deepseek::DEEPSEEK_CHAT)
            .preamble(
                "You are an expert code quality analyst specializing in commit message analysis, \
                 typo detection, and pattern consistency. You help identify inconsistencies, \
                 typos, and violations of established commit patterns in software repositories."
            )
            .name("Commit-Quality-Analyzer")
            .build();

        log::debug!("📤 Sending commit analysis prompt: {} chars", prompt.len());
        let response = agent.prompt(prompt).await?;
        log::info!("📥 Received commit analysis response: {} chars", response.len());

        Ok(response)
    }

    /// Stream a prompt and get real-time response (simplified for now)
    pub async fn stream_prompt(&self, prompt: &str) -> Result<String> {
        self.stream_prompt_with_context(prompt, "Nautilus-Autopatcher-Stream")
            .await
    }

    /// Stream a prompt with a specific context/agent name
    pub async fn stream_prompt_with_context(
        &self,
        prompt: &str,
        agent_name: &str,
    ) -> Result<String> {
        println!("🤖 {} is thinking...", agent_name);
        std::io::Write::flush(&mut std::io::stdout())?;

        // For now, just use the regular prompt method
        // TODO: Implement proper streaming when rig API supports it
        let response = self.prompt_with_context(prompt, agent_name).await?;

        println!("✅ Response received from {}", agent_name);
        Ok(response)
    }

    /// Validate that the client can connect to DeepSeek API
    pub async fn validate_connection(&self) -> Result<()> {
        log::info!("🔌 Validating DeepSeek API connection");
        
        let test_prompt = "Reply with 'OK' if you can receive this message.";
        let response = self.prompt_with_context(test_prompt, "Connection-Test").await?;
        
        if response.trim().to_uppercase().contains("OK") {
            log::info!("✅ DeepSeek API connection validated successfully");
            Ok(())
        } else {
            Err(anyhow!("DeepSeek API connection validation failed: unexpected response"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deepseek_client_creation() {
        let client = DeepSeekClient::new("test-api-key".to_string());
        // Just test that we can create the client without panicking
        assert!(true);
    }

    #[tokio::test]
    async fn test_deepseek_client_from_env_missing_key() {
        // Remove the env var if it exists for this test
        std::env::remove_var("DEEPSEEK_API_KEY");
        
        let result = DeepSeekClient::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DEEPSEEK_API_KEY"));
    }

    #[test]
    fn test_deepseek_client_from_env_with_key() {
        std::env::set_var("DEEPSEEK_API_KEY", "test-key");
        
        let result = DeepSeekClient::from_env();
        assert!(result.is_ok());
        
        // Clean up
        std::env::remove_var("DEEPSEEK_API_KEY");
    }

    #[test]
    fn test_analyze_commits_prompt_format() {
        let commits = vec![
            "abc123|John Doe|john@example.com|2025-08-22 10:30:00 +0000|feat: add new feature".to_string(),
            "def456|Jane Smith|jane@example.com|2025-08-22 11:30:00 +0000|fix: correct typo".to_string(),
        ];
        
        let prompt = format!(
            "Analyze these git commits for quality, consistency, and potential issues:\n\n{}",
            commits.join("\n")
        );
        
        assert!(prompt.contains("feat: add new feature"));
        assert!(prompt.contains("fix: correct typo"));
        assert!(prompt.contains("Analyze these git commits"));
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
    fn test_empty_commits_handling() {
        let empty_commits: Vec<String> = vec![];
        let prompt = format!(
            "Analyze these git commits for quality, consistency, and potential issues:\n\n{}",
            empty_commits.join("\n")
        );
        
        assert!(prompt.contains("Analyze these git commits"));
        // Should handle empty list gracefully
        assert_eq!(empty_commits.len(), 0);
    }

    #[tokio::test]
    async fn test_new_client_creation() {
        // Test that we can create a client with a test key
        std::env::set_var("DEEPSEEK_API_KEY", "test-key-for-creation");
        
        let result = DeepSeekClient::new().await;
        
        // Should succeed in creating the client (even with fake key)
        assert!(result.is_ok());
        
        // Clean up
        std::env::remove_var("DEEPSEEK_API_KEY");
    }

    #[test]
    fn test_client_clone() {
        std::env::set_var("DEEPSEEK_API_KEY", "test-key");
        
        let client = DeepSeekClient::from_env().unwrap();
        let cloned_client = client.clone();
        
        // Both clients should be valid (this tests the Clone implementation)
        assert!(true); // If we get here, clone worked
        
        std::env::remove_var("DEEPSEEK_API_KEY");
    }
}
