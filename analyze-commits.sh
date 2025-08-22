#!/bin/bash
# analyze-commits.sh - Simple wrapper for the Nautilus Trader commit analyzer

# Default values
COUNT=20
FORMAT="text"
WITH_AI=false
HELP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--count)
            COUNT="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        --with-ai)
            WITH_AI=true
            shift
            ;;
        -h|--help)
            HELP=true
            shift
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Show help
if [ "$HELP" = true ]; then
    echo "Nautilus Trader Commit Analyzer"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  -c, --count COUNT     Number of commits to analyze (default: 20)"
    echo "  -f, --format FORMAT   Output format: text or json (default: text)"
    echo "  --with-ai            Use AI assistance for enhanced analysis"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "ENVIRONMENT VARIABLES:"
    echo "  DEEPSEEK_API_KEY     API key for AI-enhanced analysis"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                              # Analyze last 20 commits"
    echo "  $0 --count 10                   # Analyze last 10 commits"
    echo "  $0 --with-ai                    # Use AI enhancement"
    echo "  $0 --format json                # Output as JSON"
    exit 0
fi

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build the cargo command
CARGO_CMD="cargo run --"
CARGO_CMD="$CARGO_CMD analyze-commits"
CARGO_CMD="$CARGO_CMD --count $COUNT"
CARGO_CMD="$CARGO_CMD --format $FORMAT"

if [ "$WITH_AI" = true ]; then
    CARGO_CMD="$CARGO_CMD --with-ai"
fi

# Check if we need to build first
if [ ! -f "$SCRIPT_DIR/target/debug/nautilus_trader_rig" ]; then
    echo "🔨 Building nautilus_trader_rig..."
    cd "$SCRIPT_DIR" && cargo build
fi

# Run the analyzer
echo "🔍 Running commit analysis..."
cd "$SCRIPT_DIR" && eval $CARGO_CMD
