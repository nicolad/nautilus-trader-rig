// Nautilus Trader Rig Library
//
// Enhanced with 220+ pattern-based Rust bug detection and AI validation

pub mod config;
pub mod deepseek;
pub mod false_positive_filter;
pub mod fastembed;
pub mod logging;
pub mod mcp;
pub mod patterns;
pub mod scanner;
pub mod vector_store;

pub use config::Config;
pub use deepseek::DeepSeekClient;
pub use logging::init_dev_logging;
pub use vector_store::VectorStoreManager;

// Re-export bug detection API
pub use false_positive_filter::{
    FalsePositiveFilter, SerializableIssue, ValidatedIssue, ValidationResult,
};
pub use patterns::{all_patterns, Category, PatternDef, Severity};
pub use scanner::{scan, Issue};
