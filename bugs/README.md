# Bugs Directory

This directory stores bugs detected by the Nautilus Trader Rig analysis system.

## Structure

Bugs are stored as JSON files with the following naming convention:

- `{bug_id}_{adapter_name}_{timestamp}.json`

## Bug File Format

Each bug file contains:

- `bug_id`: Unique identifier for the bug
- `severity`: Bug severity (Critical, High, Medium, Low)
- `description`: Detailed description of the bug
- `adapter_name`: Name of the adapter where the bug was found
- `code_sample`: Code sample showing the bug
- `fix_suggestion`: Suggested fix for the bug
- `timestamp`: When the bug was detected
- `analysis_context`: Additional analysis context

## Integration

Bugs are automatically stored here when detected via:

1. RMCP (Remote Model Context Protocol) adapter analysis
2. Vector similarity search matches
3. DeepSeek AI code analysis
4. Manual bug reports through the MCP server

## Access

Bugs can be accessed via the MCP server tools:

- `store_bug`: Store a new bug
- `list_bugs`: List all stored bugs
- `search_bugs`: Search bugs by criteria
