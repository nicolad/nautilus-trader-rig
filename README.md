# nautilus_trader_rig_mcp

Small Rust client that:

- Clones <https://github.com/nautechsystems/nautilus_trader> locally (if missing)
- Connects to the MCP Git server (`uvx mcp-server-git`) using the rmcp Rust SDK
- Lists tools and runs `git_status` against the cloned repo

## Requirements

- macOS with git
- [uv / uvx](https://docs.astral.sh/uv/getting-started/installation/) available on PATH
- Rust toolchain (cargo)

## Run

```
cargo run
```

This will:

1. Clone `nautilus_trader` into `./nautilus_trader` if not already present
2. Start `mcp-server-git` as a child process via uvx
3. Print server info, available tools, and `git_status` result

## Notes

- Uses rmcp 0.6 client API.
- For more advanced MCP usage and tool orchestration, see the rust-sdk `examples/rig-integration`.
