use std::path::Path;

fn main() {
    println!("Current working directory: {:?}", std::env::current_dir().unwrap());
    
    // Test the paths from config
    let adapters_path = "../nautilus_trader/adapters";
    let core_adapters_path = "../crates/adapters";
    
    println!("Testing path: {}", adapters_path);
    println!("Exists: {}", Path::new(adapters_path).exists());
    
    println!("Testing path: {}", core_adapters_path);
    println!("Exists: {}", Path::new(core_adapters_path).exists());
    
    // List some directories
    if Path::new(core_adapters_path).exists() {
        println!("Contents of {}:", core_adapters_path);
        if let Ok(entries) = std::fs::read_dir(core_adapters_path) {
            for entry in entries.take(5) {
                if let Ok(entry) = entry {
                    println!("  - {}", entry.file_name().to_string_lossy());
                }
            }
        }
    }
}
