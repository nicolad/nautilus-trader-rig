#!/bin/bash

echo "🎯 Starting Nautilus Trader Autopatcher locally..."

# Load environment variables from .env if it exists
if [ -f .env ]; then
    echo "📋 Loading environment variables from .env"
    export $(cat .env | grep -v '^#' | xargs)
fi

# Run the application
cargo run
