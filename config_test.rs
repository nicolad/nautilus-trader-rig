mod config;

use config::Config;

fn main() {
    println!("🔍 Testing Config paths:");
    println!("Current working directory: {:?}", std::env::current_dir().unwrap());
    
    println!("\n�� Rust adapters directory:");
    let rust_adapters = Config::rust_adapters_directory();
    println!("Path: {:?}", rust_adapters);
    println!("Exists: {}", Config::rust_adapters_directory_exists());
    
    println!("\n📁 Rust core directory:");
    let rust_core = Config::rust_core_directory();
    println!("Path: {:?}", rust_core);
    println!("Exists: {}", Config::rust_core_directory_exists());
    
    println!("\n📋 All rust adapter directories:");
    for (i, dir) in Config::all_rust_adapter_directories().iter().enumerate() {
        println!("  {}. {:?} - Exists: {}", i + 1, dir, dir.exists());
    }
    
    println!("\n🗂️ Rust extensions:");
    for ext in Config::rust_extensions() {
        println!("  - {}", ext);
    }
}
