//! FastEmbed implementation for testing and reference
//! 
//! This module provides FastEmbed integration with local model files
//! and implements the embedding and vector search workflow.

use anyhow::Result;
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
use serde::{Deserialize, Serialize};
use std::path::Path;

// Shape of data that needs to be RAG'ed.
// The definition field will be used to generate embeddings.
#[derive(Embed, Clone, Deserialize, Debug, Serialize, Eq, PartialEq, Default)]
struct WordDefinition {
    id: String,
    word: String,
    #[embed]
    definitions: Vec<String>,
}

pub async fn run_fastembed_test() -> Result<()> {
    // Get model info
    let test_model_info =
        FastembedTextEmbedding::get_model_info(&FastembedModel::AllMiniLML6V2).unwrap();

    // Set up model directory
    let model_dir = Path::new("./models/Qdrant--all-MiniLM-L6-v2-onnx/snapshots");
    println!("Loading model from: {model_dir:?}");

    let embedding_model = if model_dir.exists() {
        // Load model files
        let onnx_file =
            read_file_to_bytes(&model_dir.join("model.onnx")).expect("Could not read model.onnx file");

        let tokenizer_files = TokenizerFiles {
            tokenizer_file: read_file_to_bytes(&model_dir.join("tokenizer.json"))
                .expect("Could not read tokenizer.json"),
            config_file: read_file_to_bytes(&model_dir.join("config.json"))
                .expect("Could not read config.json"),
            special_tokens_map_file: read_file_to_bytes(&model_dir.join("special_tokens_map.json"))
                .expect("Could not read special_tokens_map.json"),
            tokenizer_config_file: read_file_to_bytes(&model_dir.join("tokenizer_config.json"))
                .expect("Could not read tokenizer_config.json"),
        };

        // Create embedding model
        let user_defined_model =
            UserDefinedEmbeddingModel::new(onnx_file, tokenizer_files).with_pooling(Pooling::Mean);

        EmbeddingModel::new_from_user_defined(user_defined_model, 384, test_model_info)
    } else {
        println!("Model directory not found, using automatic download");
        // Create init options for the FastEmbed model
        let init_options = fastembed::InitOptions::new(FastembedModel::AllMiniLML6V2);
        
        // First create the FastEmbed model instance
        let _fastembed_model = FastembedTextEmbedding::try_new(init_options)?;
        
        // Get the model info 
        let model_info = FastembedTextEmbedding::get_model_info(&FastembedModel::AllMiniLML6V2)?;
        
        // Create the rig embedding model - use reference to the model enum, not the instance
        EmbeddingModel::new(&FastembedModel::AllMiniLML6V2, model_info.dim)
    };

    // Create documents
    let documents = vec![
        WordDefinition {
            id: "doc0".to_string(),
            word: "flurbo".to_string(),
            definitions: vec![
                "A green alien that lives on cold planets.".to_string(),
                "A fictional digital currency that originated in the animated series Rick and Morty.".to_string()
            ]
        },
        WordDefinition {
            id: "doc1".to_string(),
            word: "glarb-glarb".to_string(),
            definitions: vec![
                "An ancient tool used by the ancestors of the inhabitants of planet Jiro to farm the land.".to_string(),
                "A fictional creature found in the distant, swampy marshlands of the planet Glibbo in the Andromeda galaxy.".to_string()
            ]
        },
        WordDefinition {
            id: "doc2".to_string(),
            word: "linglingdong".to_string(),
            definitions: vec![
                "A term used by inhabitants of the sombrero galaxy to describe humans.".to_string(),
                "A rare, mystical instrument crafted by the ancient monks of the Nebulon Mountain Ranges on the planet Quarm.".to_string()
            ]
        },
    ];

    // Create embeddings using EmbeddingsBuilder
    let embeddings = EmbeddingsBuilder::new(embedding_model.clone())
        .documents(documents)?
        .build()
        .await?;

    // Create vector store
    let vector_store =
        InMemoryVectorStore::from_documents_with_id_f(embeddings, |doc| doc.id.clone());
    let index = vector_store.index(embedding_model);

    let query =
        "I need to buy something in a fictional universe. What type of money can I use for this?";

    let req = VectorSearchRequest::builder()
        .query(query)
        .samples(1)
        .build()?;

    let results = index
        .top_n::<WordDefinition>(req)
        .await?
        .into_iter()
        .map(|(score, id, doc)| (score, id, doc.word))
        .collect::<Vec<_>>();

    println!("Results: {results:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fastembed_integration() {
        run_fastembed_test().await.unwrap();
    }
}
