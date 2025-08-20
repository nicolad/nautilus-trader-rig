//! Rig agent wrapper for Nautilus MCP tools.
//! - Default: works with rmcp=0.6 using a manual ToolDyn adapter.
//! - Optional: enable `--features rig,rig_mcp_tool` and pin rmcp=0.5 to use Rig's built-in McpTool.

use anyhow::{Context, Result};
use rmcp::{service::ServiceExt, transport::TokioChildProcess};
use std::env;
use tokio::process::Command;

use rig::completion::Prompt;
use rig::{
    agent::Agent,
    client::{CompletionClient, ProviderClient},
    completion::ToolDefinition,
    providers,
    tool::{ToolDyn, ToolError, ToolSet},
};

async fn run_with_agent<M: rig::completion::CompletionModel>(
    mut agent: Agent<M>,
    toolset: ToolSet,
) {
    agent.tools = toolset;
    let demo = r#"
You can call tools. Goal: quickly diagnose a Nautilus repo and propose safe fixes.
- Run scan_repo (write report to .lhf/report.json).
- Dry-run: apply_autofixes only if allow_actions includes 'safe'.
- Then load_sample_data, catalog_doctor, run_canary (short window, entry_threshold ~ 2e-5).
Return a concise, actionable summary.
"#;
    match agent.prompt(demo).await {
        Ok(out) => println!("--- Agent Output ---\n{out}\n"),
        Err(e) => eprintln!("Agent error: {e:?}"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Minimal logging without external deps
    if env::var("RUST_LOG").is_ok() {
        eprintln!("nautilus-rig-agent: starting (RUST_LOG set)");
    }

    // Launch command: override via NAUTILUS_MCP_CMD; default to `nautilus-mcp-doctor`.
    let server_cmd =
        env::var("NAUTILUS_MCP_CMD").unwrap_or_else(|_| "nautilus-mcp-doctor".to_string());

    let transport = if server_cmd.contains(' ') {
        let mut parts = server_cmd.split_whitespace();
        let head = parts.next().expect("NAUTILUS_MCP_CMD cannot be empty");
        let mut c = Command::new(head);
        for a in parts {
            c.arg(a);
        }
        TokioChildProcess::new(c)?
    } else {
        TokioChildProcess::new(Command::new(server_cmd))?
    };

    // Connect over stdio
    let service = ().serve(transport).await.context("start/connect MCP child")?;
    println!(
        "Connected to Nautilus MCP server; peer: {:?}",
        service.peer_info()
    );

    // Discover tools
    let tools_res = service.list_tools(Default::default()).await?;
    let tools = tools_res.tools.clone();
    if tools.is_empty() {
        eprintln!("Warning: No MCP tools found on the server");
    }

    // Build Rig toolset using the manual adapter (rmcp=0.6)
    let toolset = {
        let mut builder = ToolSet::builder();
        let peer = service.peer().clone();
        for t in tools.clone() {
            builder = builder.static_tool(ManualMcpDyn::new(t, peer.clone()));
        }
        builder.build()
    };

    // Run agent if provider configured, else just list tools
    if env::var("DEEPSEEK_API_KEY").is_ok() {
        let client = providers::deepseek::Client::from_env();
        let model = env::var("DEEPSEEK_MODEL").unwrap_or_else(|_| "deepseek-chat".to_string());
        let agent = client
            .agent(&model)
            .preamble("You are a cautious SRE for live trading. Prefer dry-runs unless explicitly allowed.")
            .temperature(0.1)
            .build();
        run_with_agent(agent, toolset).await;
    } else if env::var("OPENAI_API_KEY").is_ok() {
        let client = providers::openai::Client::from_env();
        let model = env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());
        let agent = client
            .agent(&model)
            .preamble("You are a cautious SRE for live trading. Prefer dry-runs unless explicitly allowed.")
            .temperature(0.1)
            .build();
        run_with_agent(agent, toolset).await;
    } else {
        println!(
            "Exposed {} MCP tools to Rig (no provider configured):",
            tools.len()
        );
        for t in tools {
            println!("  - {}", t.name);
        }
    }

    let _ = service.cancel().await;
    Ok(())
}

struct ManualMcpDyn {
    name: String,
    description: String,
    params_schema: serde_json::Value,
    peer: rmcp::service::Peer<rmcp::service::RoleClient>,
}

impl ManualMcpDyn {
    fn new(def: rmcp::model::Tool, peer: rmcp::service::Peer<rmcp::service::RoleClient>) -> Self {
        Self {
            name: def.name.to_string(),
            description: def.description.map(|c| c.to_string()).unwrap_or_default(),
            // Schema shapes differ across rmcp versions; keep it simple and permissive.
            params_schema: serde_json::json!({"type": "object"}),
            peer,
        }
    }
}

impl ToolDyn for ManualMcpDyn {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn definition(
        &self,
        _prompt: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ToolDefinition> + Send + Sync>> {
        let name = self.name.clone();
        let desc = self.description.clone();
        let params = self.params_schema.clone();
        Box::pin(async move {
            ToolDefinition {
                name,
                description: desc,
                parameters: params,
            }
        })
    }

    fn call(
        &self,
        args: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, ToolError>> + Send + Sync>>
    {
        let name = self.name.clone();
        let peer = self.peer.clone();
        Box::pin(async move {
            let arguments = match serde_json::from_str::<serde_json::Value>(&args) {
                Ok(serde_json::Value::Object(map)) => Some(map),
                Ok(serde_json::Value::Null) => None,
                Ok(other) => Some(
                    serde_json::json!({ "value": other })
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
                Err(_) => None,
            };
            let req = rmcp::model::CallToolRequestParam {
                name: name.into(),
                arguments,
            };
            let res = peer.call_tool(req).await.map_err(|e| {
                ToolError::from(Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            })?;
            Ok(serde_json::to_string(&res).unwrap_or_else(|_| "{\"ok\":true}".to_string()))
        })
    }
}
