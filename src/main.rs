//! # Nautilus Trader MCP with Tiny-Change Protocol
//!
//! This application demonstrates a "tiny-change" protocol for code modifications using
//! Model Context Protocol (MCP) with git operations. The tiny-change protocol enforces
//! strict limits on patch sizes to ensure surgical, minimal code changes.
//!
//! ## Tiny-Change Protocol Rules:
//! - Maximum 1 file per patch
//! - Maximum 2 hunks per patch  
//! - Maximum 20 total changed lines (additions + deletions)
//! - No refactors, renames, or formatting-only changes
//! - Preserve existing style and public APIs
//!
//! ## Functions:
//! - `patch_metrics()`: Analyzes unified diff to count files, hunks, and changed lines
//! - `enforce_patch_limits()`: Validates patches against tiny-change constraints
//! - `apply_patch_with_limits()`: Guards patch application with size enforcement
//! - `build_tiny_change_prompt()`: Generates Claude prompts with protocol rules
//! - `run_test_command()`: Executes test commands for feedback loops
//!
//! ## Usage:
//! ```bash
//! cargo run
//! ```
//!
//! This will demonstrate:
//! 1. MCP connection to git server
//! 2. Repository status checking
//! 3. Tiny-change protocol enforcement examples
//! 4. Valid patch acceptance
//! 5. Oversized patch rejection

use anyhow::Result;
use rmcp::{
    model::CallToolRequestParam,
    service::ServiceExt,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use tokio::process::Command;

/// Metrics for patch analysis
#[derive(Debug, Default, Clone, Copy)]
struct PatchMetrics {
    files: usize,
    hunks: usize,
    added: usize,
    removed: usize,
    changed: usize, // added + removed
}

/// Count files, hunks, and changed lines in a unified diff.
fn patch_metrics(diff: &str) -> PatchMetrics {
    let mut m = PatchMetrics::default();
    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            m.files += 1;
        } else if line.starts_with("@@") {
            m.hunks += 1;
        } else if line.starts_with('+') && !line.starts_with("+++") {
            m.added += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            m.removed += 1;
        }
    }
    m.changed = m.added + m.removed;
    m
}

/// Enforce tiny-change limits. Return metrics or an error message explaining the violation.
fn enforce_patch_limits(
    diff: &str,
    max_files: usize,
    max_hunks: usize,
    max_changed_lines: usize,
) -> Result<PatchMetrics, String> {
    let m = patch_metrics(diff);
    if m.files == 0 {
        return Err("no files found in diff".into());
    }
    if m.files > max_files {
        return Err(format!("too many files: {} > {}", m.files, max_files));
    }
    if m.hunks > max_hunks {
        return Err(format!("too many hunks: {} > {}", m.hunks, max_hunks));
    }
    if m.changed > max_changed_lines {
        return Err(format!(
            "too many changed lines: {} > {}",
            m.changed, max_changed_lines
        ));
    }
    Ok(m)
}

/// Run test command and return output for analysis
async fn run_test_command(repo_path: &str, test_cmd: &str) -> Result<(i32, String)> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(test_cmd).current_dir(repo_path);

    let output = cmd.output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    let exit_code = output.status.code().unwrap_or(-1);
    Ok((exit_code, combined))
}

/// Apply patch with tiny-change enforcement
fn apply_patch_with_limits(diff: &str) -> Result<bool> {
    // Tiny-change guard: ≤1 file, ≤2 hunks, ≤20 changed lines.
    match enforce_patch_limits(diff, 1, 2, 20) {
        Ok(metrics) => {
            println!(
                "[worker] patch accepted (files={}, hunks={}, +{}, -{}, total={})",
                metrics.files, metrics.hunks, metrics.added, metrics.removed, metrics.changed
            );
            Ok(true)
        }
        Err(reason) => {
            eprintln!("[worker] rejecting patch: {}", reason);
            Ok(false)
        }
    }
}

/// Generate tiny-change guidance prompt
fn build_tiny_change_prompt(
    repo_path: &str,
    test_cmd: &str,
    exit_code: i32,
    test_output: &str,
) -> String {
    let trimmed_output = test_output.chars().take(9000).collect::<String>();
    format!(
        "Repo path: {}\n\
         \n\
         Goal: Fix the failing test(s) with the smallest safe change.\n\
         \n\
         Rules:\n\
         - Make the smallest change that plausibly fixes the immediate issue.\n\
         - Touch at most 1 file and at most 2 hunks per response.\n\
         - Change at most 20 lines total (additions + deletions).\n\
         - No refactors, no formatting-only edits, no renames/moves.\n\
         - Preserve existing style and public APIs.\n\
         - If a fix is uncertain, add a guarded check or TODO and keep the change minimal.\n\
         \n\
         Output contract:\n\
         - Return exactly one unified diff inside a single code fence with the language tag `diff`.\n\
         - No prose before or after the fence. No extra fences.\n\
         - The diff must apply from repo root and use `diff --git a/... b/...` headers.\n\
         \n\
         Signals:\n\
         - Test command: {}\n\
         - Exit code: {}\n\
         - Test output (trimmed):\n{}\n\
         \n\
         Return: exactly one unified diff inside one ```diff fence (no extra text). If no compliant fix: NO CHANGE.\n",
        repo_path, test_cmd, exit_code, trimmed_output
    )
}

/// Contract
/// - Input: none (hardcodes repo URL for demo)
/// - Behavior: clones nautilus_trader if not exists, then connects to mcp-server-git and demonstrates tiny-change protocol
/// - Output: prints server info, tools list, git_status, and demonstrates patch enforcement
#[tokio::main]
async fn main() -> Result<()> {
    // Target repo
    let repo_url = "https://github.com/nautechsystems/nautilus_trader";
    let repo_dir = std::path::PathBuf::from("./nautilus_trader");

    // Ensure we have a local clone; use `git` directly for the initial fetch
    if !repo_dir.exists() {
        println!("Cloning {repo_url} to {:?}...", repo_dir);
        let status = tokio::process::Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg(repo_url)
            .arg(&repo_dir)
            .status()
            .await?;
        if !status.success() {
            anyhow::bail!("git clone failed with status {status}");
        }
    }

    // Connect to mcp-server-git via uvx
    let service = ()
        .serve(TokioChildProcess::new(Command::new("uvx").configure(
            |cmd| {
                cmd.arg("mcp-server-git");
            },
        ))?)
        .await?;

    // Server info
    let server_info = service.peer_info();
    println!("Connected to server: {server_info:#?}");

    // List tools
    let tools = service.list_tools(Default::default()).await?;
    println!("Available tools: {tools:#?}");

    // Call git_status on the cloned repo
    let repo_path = repo_dir.canonicalize()?.to_string_lossy().to_string();
    let result = service
        .call_tool(CallToolRequestParam {
            name: "git_status".into(),
            arguments: serde_json::json!({
                "repo_path": &repo_path,
            })
            .as_object()
            .cloned(),
        })
        .await?;
    println!("git_status: {result:#?}");

    // Demonstrate tiny-change protocol
    println!("\n=== Demonstrating Tiny-Change Protocol ===");

    // Example test command (this would come from user input in real usage)
    let test_cmd = "python -m pytest tests/unit_tests/test_example.py -v";

    // Simulate running test and getting failure
    println!("Simulating test run...");
    let (exit_code, test_output) = run_test_command(&repo_path, test_cmd).await?;
    println!("Test exit code: {}", exit_code);

    // Generate guidance prompt using tiny-change protocol
    let guidance = build_tiny_change_prompt(&repo_path, test_cmd, exit_code, &test_output);
    println!("\nGenerated guidance prompt:\n{}", guidance);

    // Demonstrate patch enforcement with examples
    println!("\n=== Demonstrating Patch Enforcement ===");

    // Example 1: Valid tiny patch
    let valid_patch = r#"diff --git a/example.py b/example.py
index 1234567..abcdefg 100644
--- a/example.py
+++ b/example.py
@@ -10,7 +10,7 @@ def calculate():
     x = 5
     y = 10
-    return x + y
+    return x * y
     
 def main():
     result = calculate()
"#;

    println!("Testing valid tiny patch:");
    match apply_patch_with_limits(valid_patch) {
        Ok(true) => println!("✓ Patch would be accepted"),
        Ok(false) => println!("✗ Patch was rejected"),
        Err(e) => println!("Error: {}", e),
    }

    // Example 2: Invalid large patch
    let large_patch = r#"diff --git a/file1.py b/file1.py
index 1234567..abcdefg 100644
--- a/file1.py
+++ b/file1.py
@@ -1,10 +1,15 @@
+# New header comment
+# Another comment
+# Yet another comment
 def function1():
-    pass
+    # Refactored implementation
+    x = calculate_something()
+    y = calculate_something_else()
+    z = combine_results(x, y)
+    return process_final(z)

diff --git a/file2.py b/file2.py  
index 2345678..bcdefgh 100644
--- a/file2.py
+++ b/file2.py
@@ -5,8 +5,12 @@ class Example:
     def __init__(self):
-        self.value = 0
+        # New initialization
+        self.value = initialize_value()
+        self.state = setup_state()
+        self.config = load_config()
"#;

    println!("\nTesting oversized patch (should be rejected):");
    match apply_patch_with_limits(large_patch) {
        Ok(true) => println!("✓ Patch would be accepted"),
        Ok(false) => println!("✗ Patch was rejected (as expected)"),
        Err(e) => println!("Error: {}", e),
    }

    // Close
    service.cancel().await?;

    Ok(())
}
