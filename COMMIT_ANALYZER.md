# Nautilus Trader Rig - Commit Analyzer

This tool analyzes git commits for inconsistencies, typos, and pattern violations to help maintain high code quality standards.

## Features

- **Pattern Analysis**: Checks commits against established patterns like `<Action> <Component> <description>`
- **Typo Detection**: Identifies common misspellings in commit messages
- **Grammar Checking**: Spots basic grammar issues
- **Format Validation**: Ensures consistent capitalization and length
- **AI Enhancement**: Optional AI-powered analysis using DeepSeek for advanced pattern recognition
- **Multiple Formats**: Output in text or JSON format

## Usage

### Basic Analysis

Analyze the last 20 commits (default):
```bash
cargo run -- analyze-commits
```

Analyze a specific number of commits:
```bash
cargo run -- analyze-commits --count 10
```

### AI-Enhanced Analysis

For enhanced analysis using AI (requires DEEPSEEK_API_KEY environment variable):
```bash
cargo run -- analyze-commits --count 20 --with-ai
```

### Output Formats

Text format (default):
```bash
cargo run -- analyze-commits --format text
```

JSON format for programmatic use:
```bash
cargo run -- analyze-commits --format json
```

## Environment Variables

- `DEEPSEEK_API_KEY`: Required for AI-enhanced analysis. Get your API key from [DeepSeek](https://platform.deepseek.com/)

## Analysis Categories

The analyzer checks for:

### 1. Pattern Violations
- Missing action words (Fix, Add, Improve, etc.)
- Inconsistent component naming
- Vague or unclear descriptions

### 2. Text Quality Issues
- Common typos and misspellings
- Grammar errors
- Inconsistent capitalization
- Message length issues (too short/long)

### 3. Format Issues
- Missing required structure elements
- Inconsistent formatting patterns

## Scoring System

Each commit receives a score from 0-100:
- **90-100**: Excellent quality
- **70-89**: Good quality with minor issues
- **50-69**: Acceptable but needs improvement
- **Below 50**: Significant issues requiring attention

## Issue Severity Levels

- 🔴 **High**: Critical issues that should be addressed immediately
- 🟡 **Medium**: Important issues that affect readability
- 🟢 **Low**: Minor issues or style preferences

## Example Output

```
# Commit Quality Analysis Report

Analyzed 5 commits

## Summary
- Total issues found: 3
- Average quality score: 85.0/100
- High severity issues: 1

## Issue Types
- MissingAction: 1
- Typo: 1
- LengthIssue: 1

## Detailed Analysis

### a1b2c3d4 (Score: 70)
**Message:** fix smal bug in parser
**Author:** developer (2025-08-22)

🔴 **MissingAction**: Commit doesn't start with a recognized action word: 'fix'
   💡 *Suggestion: Start with: Fix, Add, Improve, Remove, Update, Implement, etc.*
🟡 **Typo**: Possible typo: 'smal' might be 'small'
   💡 *Suggestion: Replace 'smal' with 'small'*
```

## Integration with CI/CD

You can integrate this tool into your CI/CD pipeline to automatically check commit quality:

```yaml
# GitHub Actions example
- name: Analyze Commits
  run: |
    cd nautilus-trader-rig
    cargo run -- analyze-commits --count 10 --format json > commit-analysis.json
    # Process the JSON output as needed
```

## Contributing

When adding new analysis rules:

1. Add patterns to `CommitAnalyzer::build_typo_map()` for typos
2. Update `CommitAnalyzer::build_valid_actions()` for new action words
3. Modify validation methods for new checking logic
4. Add tests in the `tests` module

## Configuration

The analyzer uses built-in patterns based on Nautilus Trader conventions:

- **Valid Actions**: Fix, Add, Improve, Refactor, Remove, Update, Implement, etc.
- **Valid Components**: adapters, execution, data, portfolio, risk, indicators, etc.
- **Expected Format**: `<Action> <Component> <description>`

These can be extended by modifying the respective builder methods in `CommitAnalyzer`.
