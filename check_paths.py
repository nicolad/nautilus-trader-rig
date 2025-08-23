#!/usr/bin/env python3
import os
from pathlib import Path

print("🔍 Path Existence Check for Nautilus Trader Rig Config")
print("=" * 60)

# Get current working directory 
cwd = Path.cwd()
print(f"Current working directory: {cwd}")

# Test paths from config.rs
paths_to_test = [
    "../nautilus_trader/adapters",
    "../crates/adapters", 
    "bugs",
    "../nautilus_trader",
    "../crates"
]

print("\n📁 Testing configured paths:")
for path_str in paths_to_test:
    path = Path(path_str)
    exists = path.exists()
    icon = "✅" if exists else "❌"
    print(f"  {icon} {path_str} -> {path.absolute()}")
    
    if exists and path.is_dir():
        try:
            # List first few entries
            entries = list(path.iterdir())[:5]
            if entries:
                print(f"      Contents (first 5): {[e.name for e in entries]}")
        except PermissionError:
            print(f"      (Permission denied)")

print("\n🧪 Testing Rust adapter paths specifically:")
adapters_path = Path("../crates/adapters")
if adapters_path.exists():
    rust_files = []
    for adapter_dir in sorted(adapters_path.iterdir()):
        if adapter_dir.is_dir():
            src_dir = adapter_dir / "src"
            if src_dir.exists():
                rs_files = list(src_dir.glob("*.rs"))
                rust_files.extend(rs_files)
                print(f"  📦 {adapter_dir.name}/src: {len(rs_files)} .rs files")
                
                # Show individual files
                for rs_file in sorted(rs_files):
                    file_size = rs_file.stat().st_size
                    print(f"      📄 {rs_file.name} ({file_size:,} bytes)")
    
    print(f"\n🔍 Total .rs files found: {len(rust_files)}")
