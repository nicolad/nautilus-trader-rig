// src/main.rs
//
// Self-improving Rust autopatcher with streaming support that:
// - uses rig + DeepSeek to propose tiny code edits (incl. tiny deterministic tests),
// - provides real-time streaming feedback during LLM generation,
// - evaluates candidates in parallel in temp copies,
// - applies a candidate to the real repo and commits ONLY if `cargo check` AND `cargo test` pass,
// - avoids file corruption with transactional, atomic writes + backups + rollback.

use anyhow::{anyhow, Context, Result};
use dotenvy::dotenv;
use fs_extra::dir::{copy as copy_dir, CopyOptions};
use rayon::prelude::*;
use rig::prelude::*;
use rig::{completion::Prompt, providers};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use walkdir::WalkDir;

mod config;
use config::{AutopatcherConfig, Config};

/// DeepSeek client using rig framework
pub struct DeepSeekClient {
    client: providers::deepseek::Client,
}

impl DeepSeekClient {
    pub fn new(api_key: String) -> Self {
        let client = providers::deepseek::Client::new(&api_key);
        Self { client }
    }

    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("DEEPSEEK_API_KEY")
            .context("DEEPSEEK_API_KEY environment variable not set")?;
        let client = providers::deepseek::Client::new(&api_key);
        Ok(Self { client })
    }

    /// Send a simple prompt and get the complete response
    pub async fn prompt(&self, prompt: &str) -> Result<String> {
        let agent = self
            .client
            .agent(providers::deepseek::DEEPSEEK_CHAT)
            .preamble("You are a helpful assistant specialized in code analysis and improvement.")
            .build();

        let response = agent.prompt(prompt).await?;
        Ok(response)
    }

    /// Stream a prompt and get real-time response (simplified for now)
    pub async fn stream_prompt(&self, prompt: &str) -> Result<String> {
        println!("🤖 DeepSeek is thinking...");
        std::io::Write::flush(&mut std::io::stdout())?;

        // For now, just use the regular prompt method
        // TODO: Implement proper streaming when rig API supports it
        let response = self.prompt(prompt).await?;

        println!("✅ Response received");
        Ok(response)
    }
}

/// A small, conservative patch set that the model proposes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct PatchSet {
    /// Short title used as the commit summary.
    title: String,
    /// Human rationale (used in commit body).
    rationale: String,
    /// Concrete file edits.
    edits: Vec<Edit>,
}

/// Minimal, safe edit primitives.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
enum Edit {
    /// Replace a file entirely (for new tiny tests/docs/small modules).
    ReplaceFile { path: String, content: String },

    /// Bounded search/replace (occurrences defaults to 1). Fails if `search` not found.
    SearchReplace {
        path: String,
        search: String,
        replace: String,
        occurrences: Option<usize>,
    },

    /// Insert before first `anchor`. Fails if `anchor` not found.
    InsertBefore {
        path: String,
        anchor: String,
        insert: String,
    },

    /// Insert after first `anchor`. Fails if `anchor` not found.
    InsertAfter {
        path: String,
        anchor: String,
        insert: String,
    },
}

/// Input we give the LLM: snapshot + last build log + desired candidate count.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlanningInput {
    policy: String,
    instructions: Option<String>,
    files: BTreeMap<String, String>,
    last_build_output: Option<String>,
    candidates: usize,
}

fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenv().ok();

    // Initialize logging with detailed output
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_secs()
        .init();

    // Load configuration
    let config = Config::from_env();

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Configuration error: {}", e);
        std::process::exit(1);
    }

    println!("🚀 Starting Rust Autopatcher with DeepSeek");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Simple config for backward compatibility
    let cfg = &config.autopatcher;

    println!("⚙️  Configuration:");
    println!("   Target directory: {}", cfg.target.display());
    println!("   Candidates per iteration: {}", cfg.candidates);
    println!("   Max iterations: {}", cfg.max_iterations);
    println!("   Model: {}", cfg.model);
    println!("   Max tokens: {}", cfg.max_tokens);
    println!("   Temperature: {}", cfg.temperature);
    println!("   Streaming enabled: {}", cfg.enable_streaming);
    println!("   Parallel jobs: {}", cfg.jobs);
    println!("   Max files in snapshot: {}", cfg.snapshot_max_files);
    println!("   Max bytes per file: {}", cfg.snapshot_max_bytes);
    println!();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cfg))
}

async fn run(cfg: &AutopatcherConfig) -> Result<()> {
    println!("🔍 Checking prerequisites...");

    ensure_command_exists("git").context("`git` is required in PATH")?;
    println!("   ✅ git found");

    ensure_command_exists("cargo").context("`cargo` is required (install Rust toolchain)")?;
    println!("   ✅ cargo found");

    println!("🤖 Initializing DeepSeek client...");
    let client = DeepSeekClient::from_env()?;
    println!("   ✅ DeepSeek client ready");

    let mut last_build_output: Option<String> = None;

    for iter in 1..=cfg.max_iterations {
        println!("\n🔄 === Iteration {iter}/{} ===", cfg.max_iterations);
        println!("📸 Taking codebase snapshot...");

        let files = snapshot_codebase(&cfg.target, cfg.snapshot_max_files, cfg.snapshot_max_bytes)?;
        println!("   📝 Captured {} files", files.len());
        for (path, content) in &files {
            println!("      {} ({} bytes)", path, content.len());
        }

        // Read instructions from INSTRUCTIONS.md if available
        let instructions = read_instructions(&cfg.target);

        let input = PlanningInput {
            policy: POLICY_TEXT.to_string(),
            instructions,
            files,
            last_build_output: last_build_output.clone(),
            candidates: cfg.candidates,
        };

        if let Some(ref build_output) = input.last_build_output {
            println!(
                "📋 Including previous build output ({} chars)",
                build_output.len()
            );
        }

        println!("🧠 Requesting patch proposals from DeepSeek...");
        let plan_json = serde_json::to_string_pretty(&input)?;
        println!("   📤 Sending prompt ({} chars)", plan_json.len());
        let prompt = format!(
            r#"
Return **ONLY** valid JSON of the form:
{{
  "patches": PatchSet[]
}}

Where `PatchSet` matches this JSON Schema:
{patch_schema}

Your constraints:
- Prefer tiny, deterministic tests (≤ ~30 lines each) when helpful:
  * Put new tests under `tests/` as `tests/smoke_*.rs` or inside an existing module as `#[cfg(test)] mod tests {{ ... }}`
  * No network, filesystem, randomness, time sleeps, threads, or flakiness.
  * Tests must compile and run in < 2s.
- Keep code edits conservative and localized (≤ ~200 changed lines per patch set).
- If last build output shows an error, fix it minimally and add a focused test if it makes sense.
- NEVER change Cargo features in ways that break builds.
- Target stable Rust (1.75+).

Input:
{plan}
"#,
            patch_schema = serde_json::to_string_pretty(&schemars::schema_for!(PatchSet))?,
            plan = plan_json
        );

        let raw = client.prompt(&prompt).await.context("LLM call failed")?;
        println!("   📥 Received response ({} chars)", raw.len());

        println!("🔍 Parsing patch proposals...");
        let parsed = parse_patches(&raw)?;
        if parsed.is_empty() {
            println!("❌ Model returned no patches; stopping.");
            break;
        }

        println!("   ✅ Found {} patch proposals:", parsed.len());
        for (i, ps) in parsed.iter().enumerate() {
            println!("      {} - {} ({} edits)", i + 1, ps.title, ps.edits.len());
            for edit in &ps.edits {
                match edit {
                    Edit::ReplaceFile { path, content } => {
                        println!(
                            "         📝 ReplaceFile: {} ({} bytes)",
                            path,
                            content.len()
                        );
                    }
                    Edit::SearchReplace {
                        path,
                        search,
                        replace,
                        ..
                    } => {
                        println!(
                            "         🔄 SearchReplace: {} ({}→{})",
                            path,
                            search.chars().take(20).collect::<String>(),
                            replace.chars().take(20).collect::<String>()
                        );
                    }
                    Edit::InsertBefore {
                        path,
                        anchor,
                        insert,
                    } => {
                        println!(
                            "         ⬆️ InsertBefore: {} before {} ({} chars)",
                            path,
                            anchor.chars().take(20).collect::<String>(),
                            insert.len()
                        );
                    }
                    Edit::InsertAfter {
                        path,
                        anchor,
                        insert,
                    } => {
                        println!(
                            "         ⬇️ InsertAfter: {} after {} ({} chars)",
                            path,
                            anchor.chars().take(20).collect::<String>(),
                            insert.len()
                        );
                    }
                }
            }
        }

        println!(
            "🔧 Evaluating candidates in parallel ({} jobs)...",
            cfg.jobs
        );
        rayon::ThreadPoolBuilder::new()
            .num_threads(cfg.jobs)
            .build_global()
            .ok();

        let evals: Vec<_> = parsed
            .par_iter()
            .enumerate()
            .map(|(i, ps)| {
                println!("   🚀 Starting evaluation of candidate {}", i + 1);
                (i, try_build_and_test_in_temp(&cfg, ps))
            })
            .collect();

        println!("📊 Evaluation results:");
        for (i, result) in &evals {
            match result {
                Ok(eval) => {
                    let check_status = if eval.check_ok { "✅" } else { "❌" };
                    let test_status = if eval.tests_ok { "✅" } else { "❌" };
                    println!(
                        "   Candidate {}: {} check, {} tests",
                        i + 1,
                        check_status,
                        test_status
                    );
                    if !eval.build_stderr.is_empty() && (!eval.check_ok || !eval.tests_ok) {
                        println!(
                            "      Error preview: {}",
                            eval.build_stderr
                                .lines()
                                .take(3)
                                .collect::<Vec<_>>()
                                .join(" | ")
                        );
                    }
                }
                Err(e) => {
                    println!("   Candidate {}: ❌ evaluation failed: {}", i + 1, e);
                }
            }
        }

        // Winner = first candidate where check & tests both pass.
        if let Some((i, Ok(_ce))) = evals.into_iter().find(|(_, r)| {
            if let Ok(eval) = r {
                eval.check_ok && eval.tests_ok
            } else {
                false
            }
        }) {
            let ps = &parsed[i];
            println!("🏆 WINNER: Candidate {} - {}", i + 1, ps.title);
            println!("   📋 Rationale: {}", ps.rationale);

            println!("🔄 Applying patch to real repository...");
            apply_patchset_transactional(&cfg.target, ps)
                .context("Failed to apply patchset transactionally to real repo")?;
            println!("   ✅ Patch applied successfully");

            println!("📝 Committing changes...");
            ensure_git_repo(&cfg.target)?;
            git_add_all(&cfg.target)?;
            let commit_msg = format!("{} [autopatch]\n\n{}", ps.title.trim(), ps.rationale.trim());
            git_commit(&cfg.target, &commit_msg)?;
            println!("🎉 Committed successfully!");
            println!("   💾 Commit message: {}", ps.title.trim());

            println!("📤 Pushing changes...");
            git_push(&cfg.target)?;
            println!("🚀 Pushed successfully!");

            last_build_output = None;
        } else {
            println!("💔 No candidate passed both build and tests.");
            println!("📝 Capturing build output for next iteration...");

            // Capture a failing build log to feed back next time (best-effort on first candidate).
            last_build_output = Some(
                parsed
                    .first()
                    .and_then(|p| try_build_and_test_in_temp(&cfg, p).ok())
                    .map(|ce| ce.build_stderr)
                    .unwrap_or_default(),
            );

            if let Some(ref output) = last_build_output {
                println!("   📋 Captured {} chars of build output", output.len());
            }
            break;
        }
    }

    println!("\n🏁 Autopatcher completed!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    Ok(())
}

/// Policy the model receives inside the input blob.
const POLICY_TEXT: &str = r#"
Output strictly valid JSON for { "patches": PatchSet[] }.
Use only the provided edit kinds. Avoid broad matches in search/replace.
Prefer adding tests under `tests/` as `smoke_*` or minimal `#[cfg(test)]` modules.
Pay attention to any instructions provided - they contain guidance for what improvements to focus on.
"#;

/// Read the INSTRUCTIONS.md file if it exists.
fn read_instructions(target_dir: &Path) -> Option<String> {
    let instructions_path = target_dir.join("INSTRUCTIONS.md");
    if instructions_path.exists() {
        match fs::read_to_string(&instructions_path) {
            Ok(content) => {
                println!("📋 Read instructions from {}", instructions_path.display());
                Some(content.trim().to_string())
            }
            Err(e) => {
                println!("⚠️  Failed to read {}: {}", instructions_path.display(), e);
                None
            }
        }
    } else {
        println!("📋 No INSTRUCTIONS.md found");
        None
    }
}

/// Candidate result from temp evaluation.
#[derive(Default)]
struct CandidateEval {
    check_ok: bool,
    tests_ok: bool,
    build_stderr: String,
}

/// Evaluate a candidate in a fresh temp copy of the project:
/// 1) apply edits (atomic writes),
/// 2) cargo check,
/// 3) cargo test.
fn try_build_and_test_in_temp(cfg: &AutopatcherConfig, ps: &PatchSet) -> Result<CandidateEval> {
    println!("      🗂️ Creating temp directory...");
    let tmp = TempDir::new()?;
    let td = tmp.path().to_path_buf();
    println!("         📁 {}", td.display());

    println!("      📋 Copying project to temp...");
    let mut cp = CopyOptions::new();
    cp.copy_inside = true;
    cp.overwrite = true;
    copy_dir(&cfg.target, &td, &cp).with_context(|| "Failed to copy target into temp dir")?;
    println!("         ✅ Project copied");

    println!("      ⚡ Applying patches...");
    apply_patchset_atomic_only(&td, ps)?;
    println!("         ✅ Patches applied");

    println!("      🔍 Running cargo check...");
    let check_out = run_cargo_capture(&td, &["check"])?;
    let check_ok = check_out.status.success();
    let mut build_stderr = String::from_utf8_lossy(&check_out.stderr).to_string();
    println!(
        "         {} cargo check",
        if check_ok { "✅" } else { "❌" }
    );

    let tests_ok = if check_ok {
        println!("      🧪 Running cargo test...");
        let test_out = run_cargo_capture(&td, &["test"])?;
        if !test_out.status.success() {
            build_stderr.push_str(&String::from_utf8_lossy(&test_out.stderr));
        }
        let success = test_out.status.success();
        println!("         {} cargo test", if success { "✅" } else { "❌" });
        success
    } else {
        println!("         ⏭️ Skipping tests (check failed)");
        false
    };

    println!("      🧹 Cleaning up temp directory...");

    Ok(CandidateEval {
        check_ok,
        tests_ok,
        build_stderr,
    })
}

/// Transactionally apply a patch set to the real repo:
/// - Pre-validate all edits (anchors/search exist) & compute new contents in-memory.
/// - Create a single backup directory for all touched files.
/// - Write each file via atomic tempfile+persist (same dir) and fsync best-effort.
/// - If ANY write fails, roll back from backups.
/// - Run `cargo check` and `cargo test`; if either fails, roll back entirely.
/// - On success, delete the backup directory.
fn apply_patchset_transactional(root: &Path, ps: &PatchSet) -> Result<()> {
    let plan = plan_edits(root, ps)
        .with_context(|| format!("Pre-validation failed for patch '{}'", ps.title))?;

    let backup_dir = make_backup_dir(root)?;
    // Create backups up-front so we can roll back on any error.
    for f in &plan.files_to_write {
        if f.existed_before {
            let src = root.join(&f.rel_path);
            let dst = backup_dir.join(&f.rel_path);
            if let Some(dir) = dst.parent() {
                fs::create_dir_all(dir)?;
            }
            fs::copy(&src, &dst).with_context(|| format!("Failed to backup {}", f.rel_path))?;
        }
    }

    // Attempt writes atomically per file.
    if let Err(e) = write_all_atomically(root, &plan) {
        eprintln!("❌ Write failure: {e}. Rolling back…");
        rollback_from_backups(root, &backup_dir, &plan)?;
        return Err(e);
    }

    // Gate: check + test.
    if let Err(e) = run_cargo(root, &["check"]) {
        eprintln!("❌ `cargo check` failed after apply: {e}. Rolling back…");
        rollback_from_backups(root, &backup_dir, &plan)?;
        return Err(anyhow!("post-apply cargo check failed"));
    }
    if let Err(e) = run_cargo(root, &["test"]) {
        eprintln!("❌ `cargo test` failed after apply: {e}. Rolling back…");
        rollback_from_backups(root, &backup_dir, &plan)?;
        return Err(anyhow!("post-apply cargo test failed"));
    }

    // Success: cleanup backups.
    let _ = fs::remove_dir_all(&backup_dir);
    Ok(())
}

/// Apply patchset using only atomic writes (no backups/rollback). Used in temp dirs.
fn apply_patchset_atomic_only(root: &Path, ps: &PatchSet) -> Result<()> {
    let plan = plan_edits(root, ps)?;
    write_all_atomically(root, &plan)
}

/// Pre-validated, computed outputs for a patch.
struct PlannedEdits {
    files_to_write: Vec<FileWritePlan>,
}

/// One file that will be rewritten atomically.
struct FileWritePlan {
    rel_path: String,
    new_content: String,
    existed_before: bool,
}

/// Build a deterministic plan: validate anchors/search and compute final contents in-memory.
/// No files are touched in this phase.
fn plan_edits(root: &Path, ps: &PatchSet) -> Result<PlannedEdits> {
    // Map of rel_path -> current content (lazy-read).
    let mut cache: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut writes: Vec<FileWritePlan> = Vec::new();

    for edit in &ps.edits {
        match edit {
            Edit::ReplaceFile { path, content } => {
                let rel = path.clone();
                let existed = root.join(&rel).exists();
                writes.push(FileWritePlan {
                    rel_path: rel,
                    new_content: content.clone(),
                    existed_before: existed,
                });
            }
            Edit::SearchReplace {
                path,
                search,
                replace,
                occurrences,
            } => {
                let rel = path.clone();
                let old = read_cached(root, &mut cache, &rel)?;
                let occ = occurrences.unwrap_or(1).max(1);
                if !old.contains(search) {
                    return Err(anyhow!("Search string not found in {}", rel));
                }
                let new = old.replacen(search, replace, occ);
                writes.push(FileWritePlan {
                    rel_path: rel,
                    new_content: new,
                    existed_before: true,
                });
            }
            Edit::InsertBefore {
                path,
                anchor,
                insert,
            } => {
                let rel = path.clone();
                let mut old = read_cached(root, &mut cache, &rel)?;
                if let Some(pos) = old.find(anchor) {
                    old.insert_str(pos, insert);
                    writes.push(FileWritePlan {
                        rel_path: rel,
                        new_content: old,
                        existed_before: true,
                    });
                } else {
                    return Err(anyhow!("Anchor not found in {}", path));
                }
            }
            Edit::InsertAfter {
                path,
                anchor,
                insert,
            } => {
                let rel = path.clone();
                let mut old = read_cached(root, &mut cache, &rel)?;
                if let Some(pos) = old.find(anchor) {
                    let new_pos = pos + anchor.len();
                    old.insert_str(new_pos, insert);
                    writes.push(FileWritePlan {
                        rel_path: rel,
                        new_content: old,
                        existed_before: true,
                    });
                } else {
                    return Err(anyhow!("Anchor not found in {}", path));
                }
            }
        }
    }

    Ok(PlannedEdits {
        files_to_write: writes,
    })
}

fn read_cached(
    root: &Path,
    cache: &mut BTreeMap<String, Option<String>>,
    rel: &str,
) -> Result<String> {
    if !cache.contains_key(rel) {
        let p = root.join(rel);
        cache.insert(
            rel.to_string(),
            Some(fs::read_to_string(&p).with_context(|| format!("Cannot read file: {}", rel))?),
        );
    }
    Ok(cache.get(rel).and_then(|o| o.clone()).unwrap())
}

/// Write all planned files atomically. If any write fails, caller must roll back using backups.
fn write_all_atomically(root: &Path, plan: &PlannedEdits) -> Result<()> {
    for f in &plan.files_to_write {
        let dst = root.join(&f.rel_path);
        atomic_write(&dst, &f.new_content)
            .with_context(|| format!("Atomic write failed for {}", f.rel_path))?;
    }
    Ok(())
}

/// Perform atomic write to `path`:
/// - create parent dir,
/// - write to a tempfile in the same directory,
/// - flush file, persist (atomic rename),
/// - best-effort fsync of the directory.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".autopatch.")
            .tempfile_in(dir)?;
        tmp.as_file_mut().write_all(content.as_bytes())?;
        tmp.as_file_mut().sync_all()?; // flush file

        // Persist atomically over the destination.
        tmp.persist(path)
            .map_err(|e| anyhow!("persist failed for {}: {}", path.display(), e))?;

        // Best-effort: sync directory metadata.
        if let Ok(df) = fs::File::open(dir) {
            let _ = df.sync_all();
        }
        Ok(())
    } else {
        Err(anyhow!("No parent directory for {}", path.display()))
    }
}

/// Create a unique backup directory under `<root>/.autopatch_backups/<ts>-<pid>/`
fn make_backup_dir(root: &Path) -> Result<PathBuf> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let pid = std::process::id();
    let dir = root
        .join(".autopatch_backups")
        .join(format!("{}-{}", ts, pid));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Roll back all touched files from backups. Removes newly created files (that had no backup).
fn rollback_from_backups(root: &Path, backup_dir: &Path, plan: &PlannedEdits) -> Result<()> {
    for f in &plan.files_to_write {
        let dst = root.join(&f.rel_path);
        let bak = backup_dir.join(&f.rel_path);
        if bak.exists() {
            // Restore via atomic write from backup content.
            let mut buf = String::new();
            fs::File::open(&bak)?.read_to_string(&mut buf)?;
            atomic_write(&dst, &buf)?;
        } else {
            // File did not exist before; remove it if present.
            let _ = fs::remove_file(&dst);
        }
    }
    Ok(())
}

/// Snapshot a bounded view of the codebase for the model context.
fn snapshot_codebase(
    root: &Path,
    max_files: usize,
    max_bytes: usize,
) -> Result<BTreeMap<String, String>> {
    let mut files: Vec<PathBuf> = vec![];
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| include_in_snapshot(e.path()))
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file() && is_rust_source(p) {
            files.push(p.to_path_buf());
        }
    }

    files.sort();
    files.truncate(max_files);

    let mut map = BTreeMap::new();
    for p in files {
        let rel = path_relative(root, &p);
        let mut content = fs::read_to_string(&p).unwrap_or_default();
        if content.len() > max_bytes {
            content.truncate(max_bytes);
            content.push_str("\n/* … truncated … */\n");
        }
        map.insert(rel, content);
    }
    Ok(map)
}

fn include_in_snapshot(path: &Path) -> bool {
    let bad = [
        "target",
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".autopatch_backups",
    ];
    if path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        bad.iter().any(|b| s == *b)
    }) {
        return false;
    }
    true
}

fn is_rust_source(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("rs")) || path.file_name() == Some(OsStr::new("Cargo.toml"))
}

fn path_relative(root: &Path, p: &Path) -> String {
    pathdiff::diff_paths(p, root)
        .unwrap_or_else(|| p.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn run_cargo(root: &Path, args: &[&str]) -> Result<()> {
    let st = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .status()?;
    if !st.success() {
        return Err(anyhow!("cargo {:?} failed", args));
    }
    Ok(())
}

fn run_cargo_capture(root: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new("cargo")
        .args(args)
        .current_dir(root)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()?)
}

fn ensure_git_repo(root: &Path) -> Result<()> {
    let inside = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if inside {
        return Ok(());
    }

    Command::new("git").arg("init").current_dir(root).status()?;
    git_add_all(root)?;
    git_commit(root, "chore: initial commit [autopatch]")?;
    Ok(())
}

fn git_add_all(root: &Path) -> Result<()> {
    let ok = Command::new("git")
        .args(["add", "-A"])
        .current_dir(root)
        .status()?
        .success();
    if !ok {
        return Err(anyhow!("git add -A failed"));
    }
    Ok(())
}

fn git_commit(root: &Path, msg: &str) -> Result<()> {
    let ok = Command::new("git")
        .args(["commit", "-m", msg])
        .current_dir(root)
        .status()?
        .success();
    if !ok {
        return Err(anyhow!("git commit failed"));
    }
    Ok(())
}

fn git_push(root: &Path) -> Result<()> {
    let ok = Command::new("git")
        .args(["push"])
        .current_dir(root)
        .status()?
        .success();
    if !ok {
        return Err(anyhow!("git push failed"));
    }
    Ok(())
}

fn ensure_command_exists(name: &str) -> Result<()> {
    which::which(name)
        .map(|_| ())
        .with_context(|| format!("Command `{name}` not found in PATH"))
}

/// Parse the JSON response from the LLM to extract patch sets.
fn parse_patches(raw: &str) -> Result<Vec<PatchSet>> {
    // Find JSON in the response (model might include explanations)
    let start_idx = raw.find('{').unwrap_or(0);
    let end_idx = raw.rfind('}').map(|i| i + 1).unwrap_or(raw.len());
    let json_part = &raw[start_idx..end_idx];

    #[derive(Deserialize)]
    struct Response {
        patches: Vec<PatchSet>,
    }

    let response: Response =
        serde_json::from_str(json_part).context("Failed to parse LLM response as JSON")?;

    Ok(response.patches)
}

// Minimal pathdiff impl (to avoid an extra dependency).
mod pathdiff {
    use std::path::{Component, Path, PathBuf};

    pub fn diff_paths(path: &Path, base: &Path) -> Option<PathBuf> {
        let mut ita = base.components();
        let mut itb = path.components();

        let mut comps_a = vec![];
        let mut comps_b = vec![];

        loop {
            match (ita.next(), itb.next()) {
                (Some(a), Some(b)) if comp_eq(a, b) => continue,
                (a, b) => {
                    if let Some(c) = a {
                        comps_a.push(c);
                        for c in ita {
                            comps_a.push(c);
                        }
                    }
                    if let Some(c) = b {
                        comps_b.push(c);
                        for c in itb {
                            comps_b.push(c);
                        }
                    }
                    break;
                }
            }
        }

        let mut out = PathBuf::new();
        for _ in comps_a.iter().filter(|c| !is_cur_dir(c)) {
            out.push("..");
        }
        for c in comps_b {
            out.push(c.as_os_str());
        }
        Some(out)
    }

    fn comp_eq(a: Component, b: Component) -> bool {
        a.as_os_str() == b.as_os_str()
    }
    fn is_cur_dir(c: &Component) -> bool {
        matches!(c, Component::CurDir)
    }
}
