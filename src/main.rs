use anyhow::Result;
use rmcp::{
    model::CallToolRequestParam,
    service::ServiceExt,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use tokio::process::Command;

/// Contract
/// - Input: none (hardcodes repo URL for demo)
/// - Behavior: clones nautilus_trader if not exists, then connects to mcp-server-git and runs git_status
/// - Output: prints server info, tools list, and git_status result
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
    let result = service
        .call_tool(CallToolRequestParam {
            name: "git_status".into(),
            arguments: serde_json::json!({
                "repo_path": repo_dir.canonicalize()?.to_string_lossy(),
            })
            .as_object()
            .cloned(),
        })
        .await?;
    println!("git_status: {result:#?}");

    // Close
    service.cancel().await?;

    Ok(())
}
