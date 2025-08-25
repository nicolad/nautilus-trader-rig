//! Vector Store Manager for bug pattern similarity search using FastEmbed
//! 
//! This module uses FastEmbed for local embeddings (no API key required) with in-memory or SQLite storage.
//! Embeddings are generated locally using the AllMiniLML6V2 model.

use anyhow::Result;
use std::path::Path;
use tracing::{debug, info, trace};
use serde::{Deserialize, Serialize};

use fastembed::{
    EmbeddingModel as FastembedModel, Pooling, TextEmbedding as FastembedTextEmbedding,
    TokenizerFiles, UserDefinedEmbeddingModel, read_file_to_bytes,
};
use rig::{
    Embed,
    embeddings::EmbeddingsBuilder,
    vector_store::{
        VectorStoreIndex, in_memory_store::InMemoryVectorStore, request::VectorSearchRequest,
    },
};
use rig_fastembed::EmbeddingModel;

// Bug pattern document that will be embedded and searched
#[derive(Embed, Clone, Deserialize, Debug, Serialize, Eq, PartialEq, Default)]
pub struct BugPatternDocument {
    pub id: String,
    pub category: String,
    pub severity: u8,
    // The content field will be used to generate embeddings
    #[embed]
    pub content: String,
}

pub struct VectorStoreManager {
    pub vector_store: InMemoryVectorStore<BugPatternDocument>,
    pub embedding_model: EmbeddingModel,
    pub documents: Vec<BugPatternDocument>,
}

impl VectorStoreManager {
    /// Initialize vector store with FastEmbed local embeddings
    pub async fn new() -> Result<Self> {
        info!("🔧 Initializing vector store with FastEmbed local embeddings...");
        debug!("Starting vector store initialization process");

        // Try to use pre-downloaded model first, fall back to automatic download
        trace!("Creating FastEmbed embedding model");
        let embedding_model = Self::create_embedding_model().await?;
        info!("✅ FastEmbed embedding model created successfully");

        debug!("Initializing in-memory vector store");
        let mut manager = Self {
            vector_store: InMemoryVectorStore::default(),
            embedding_model,
            documents: Vec::new(),
        };

        // Initialize with default patterns
        debug!("Loading default bug patterns into vector store");
        manager.initialize_default_patterns().await?;

        info!("✅ Vector store initialized successfully with FastEmbed");
        debug!("Vector store ready with {} patterns loaded", manager.documents.len());
        Ok(manager)
    }

    /// Create embedding model - try local files first, then auto-download
    async fn create_embedding_model() -> Result<EmbeddingModel> {
        let model_dir = Path::new("./models/Qdrant--all-MiniLM-L6-v2-onnx/snapshots");
        
        if model_dir.exists() {
            info!("Loading FastEmbed model from local directory: {model_dir:?}");
            Self::load_local_model(model_dir).await
        } else {
            info!("Local model not found, using automatic download");
            Self::load_auto_model().await
        }
    }

    /// Load model from local files
    async fn load_local_model(model_dir: &Path) -> Result<EmbeddingModel> {
        // Get model info
        let test_model_info = FastembedTextEmbedding::get_model_info(&FastembedModel::AllMiniLML6V2)?;

        // Load model files
        let onnx_file = read_file_to_bytes(&model_dir.join("model.onnx"))?;

        let tokenizer_files = TokenizerFiles {
            tokenizer_file: read_file_to_bytes(&model_dir.join("tokenizer.json"))?,
            config_file: read_file_to_bytes(&model_dir.join("config.json"))?,
            special_tokens_map_file: read_file_to_bytes(&model_dir.join("special_tokens_map.json"))?,
            tokenizer_config_file: read_file_to_bytes(&model_dir.join("tokenizer_config.json"))?,
        };

        // Create embedding model
        let user_defined_model = UserDefinedEmbeddingModel::new(onnx_file, tokenizer_files)
            .with_pooling(Pooling::Mean);

        let embedding_model = EmbeddingModel::new_from_user_defined(
            user_defined_model, 
            384, // Dimension for AllMiniLML6V2
            test_model_info
        );

        Ok(embedding_model)
    }

    /// Load model with automatic download
    async fn load_auto_model() -> Result<EmbeddingModel> {
        // Create init options for the FastEmbed model
        let init_options = fastembed::InitOptions::new(FastembedModel::AllMiniLML6V2);
        
        // First create the FastEmbed model instance  
        let _fastembed_model = FastembedTextEmbedding::try_new(init_options)?;
        
        // Get the model info 
        let model_info = FastembedTextEmbedding::get_model_info(&FastembedModel::AllMiniLML6V2)?;
        
        // Create the rig embedding model - use reference to the model enum, not the instance
        let embedding_model = EmbeddingModel::new(&FastembedModel::AllMiniLML6V2, model_info.dim);
        Ok(embedding_model)
    }

    /// Initialize with default bug patterns
    async fn initialize_default_patterns(&mut self) -> Result<()> {
        let default_patterns = vec![
            BugPatternDocument {
                id: "auth_bypass_001".to_string(),
                category: "AUTHENTICATION".to_string(),
                severity: 9,
                content: "Authentication bypass vulnerability in trading adapters: API key validation missing, weak token verification, credential exposure in logs, unauthorized access to trading functions".to_string(),
            },
            BugPatternDocument {
                id: "rate_limit_bypass_001".to_string(),
                category: "RATE_LIMITING".to_string(),
                severity: 8,
                content: "Rate limiting bypass in exchange adapters: Multiple connection exploitation, request queue overflow, throttling mechanism failure, DoS attack vectors".to_string(),
            },
            BugPatternDocument {
                id: "websocket_security_001".to_string(),
                category: "WEBSOCKET".to_string(),
                severity: 7,
                content: "WebSocket security vulnerabilities: Unvalidated message injection, connection hijacking, authentication after connect, message replay attacks".to_string(),
            },
            BugPatternDocument {
                id: "order_execution_race_001".to_string(),
                category: "EXECUTION".to_string(),
                severity: 9,
                content: "Order execution race conditions: Concurrent order processing, double execution vulnerability, state synchronization issues, atomic operation failures".to_string(),
            },
            BugPatternDocument {
                id: "data_validation_001".to_string(),
                category: "VALIDATION".to_string(),
                severity: 6,
                content: "Market data validation failures: Unvalidated price feeds, malformed data processing, type conversion vulnerabilities, data integrity checks missing".to_string(),
            },
            BugPatternDocument {
                id: "connection_pool_001".to_string(),
                category: "CONNECTION".to_string(),
                severity: 5,
                content: "Connection pool issues: Pool exhaustion, resource leaks, timeout handling, connection state management, cleanup failures".to_string(),
            },
            BugPatternDocument {
                id: "memory_leak_001".to_string(),
                category: "MEMORY".to_string(),
                severity: 7,
                content: "Memory management issues: Memory leaks in adapters, resource cleanup failures, garbage collection problems, buffer overflows".to_string(),
            },
            BugPatternDocument {
                id: "performance_degradation_001".to_string(),
                category: "PERFORMANCE".to_string(),
                severity: 6,
                content: "Performance issues: Slow response times, high latency, CPU bottlenecks, inefficient algorithms, blocking operations".to_string(),
            },
            BugPatternDocument {
                id: "error_handling_001".to_string(),
                category: "ERROR_HANDLING".to_string(),
                severity: 8,
                content: "Error handling problems: Unhandled exceptions, silent failures, improper error propagation, missing error logging".to_string(),
            },
            BugPatternDocument {
                id: "configuration_001".to_string(),
                category: "CONFIGURATION".to_string(),
                severity: 7,
                content: "Configuration vulnerabilities: Hardcoded secrets, missing environment variables, insecure defaults, configuration injection".to_string(),
            },
        ];

        // Create embeddings using EmbeddingsBuilder
        let embeddings = EmbeddingsBuilder::new(self.embedding_model.clone())
            .documents(default_patterns.clone())?
            .build()
            .await?;

        // Create vector store from documents
        self.vector_store = InMemoryVectorStore::from_documents_with_id_f(
            embeddings, 
            |doc| doc.id.clone()
        );

        self.documents = default_patterns;
        
        info!("Added {} default bug patterns to vector store with FastEmbed", self.documents.len());
        Ok(())
    }

    /// Perform similarity search using FastEmbed
    pub async fn similarity_search(&self, query: &str, limit: usize) -> Result<Vec<serde_json::Value>> {
        debug!("Performing similarity search for: '{}'", query);

        // Create index for searching
        let index = self.vector_store.clone().index(self.embedding_model.clone());

        let req = VectorSearchRequest::builder()
            .query(query)
            .samples(limit as u64)
            .build()?;

        // Query the index
        let results = index
            .top_n::<BugPatternDocument>(req)
            .await?
            .into_iter()
            .map(|(score, _id, doc)| {
                serde_json::json!({
                    "id": doc.id,
                    "content": doc.content,
                    "category": doc.category,
                    "severity": doc.severity,
                    "score": score
                })
            })
            .collect::<Vec<_>>();

        debug!("Found {} similar patterns", results.len());
        Ok(results)
    }

    /// Add a new bug pattern to the vector store using FastEmbed
    pub async fn add_pattern(&mut self, pattern: BugPatternDocument) -> Result<()> {
        // Create embeddings for the new pattern
        let embeddings = EmbeddingsBuilder::new(self.embedding_model.clone())
            .documents(vec![pattern.clone()])?
            .build()
            .await?;

        // Add to vector store
        self.vector_store.add_documents_with_id_f(embeddings, |doc| doc.id.clone());
        self.documents.push(pattern);
        
        Ok(())
    }

    /// Get pattern by ID
    pub async fn get_pattern_by_id(&self, pattern_id: &str) -> Result<Option<BugPatternDocument>> {
        Ok(self.documents.iter().find(|p| p.id == pattern_id).cloned())
    }

    /// Get all patterns in a specific category
    pub async fn get_patterns_by_category(&self, category: &str) -> Result<Vec<BugPatternDocument>> {
        Ok(self.documents.iter()
            .filter(|p| p.category == category)
            .cloned()
            .collect())
    }

    /// Get patterns by severity level
    pub async fn get_patterns_by_severity(&self, min_severity: u8) -> Result<Vec<BugPatternDocument>> {
        Ok(self.documents.iter()
            .filter(|p| p.severity >= min_severity)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vector_store_creation() {
        // FastEmbed doesn't require API keys - runs locally
        let manager = VectorStoreManager::new().await.unwrap();
        let results = manager.similarity_search("authentication", 3).await.unwrap();
        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_add_pattern() {
        // FastEmbed doesn't require API keys - runs locally
        let mut manager = VectorStoreManager::new().await.unwrap();
        
        let new_pattern = BugPatternDocument {
            id: "test_pattern_001".to_string(),
            category: "TEST".to_string(),
            severity: 5,
            content: "Test pattern for unit testing: This is a test vulnerability pattern".to_string(),
        };

        manager.add_pattern(new_pattern).await.unwrap();
    }

    #[tokio::test]
    async fn test_similarity_search() {
        let manager = VectorStoreManager::new().await.unwrap();
        
        // Test searching for authentication-related issues
        let results = manager.similarity_search("API key security authentication", 3).await.unwrap();
        assert!(!results.is_empty());
        
        // The first result should be related to authentication
        let first_result = &results[0];
        assert!(first_result["category"].as_str().unwrap_or("").contains("AUTHENTICATION") || 
                first_result["content"].as_str().unwrap_or("").to_lowercase().contains("authentication"));
    }

    #[tokio::test]
    async fn test_category_filtering() {
        let manager = VectorStoreManager::new().await.unwrap();
        let auth_patterns = manager.get_patterns_by_category("AUTHENTICATION").await.unwrap();
        assert!(!auth_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_severity_filtering() {
        let manager = VectorStoreManager::new().await.unwrap();
        let critical_patterns = manager.get_patterns_by_severity(8).await.unwrap();
        assert!(!critical_patterns.is_empty());
    }
}
