#!/bin/bash
# shuttle_setup_container.sh - Sets up the runtime container

echo "🔧 Shuttle container setup: Installing runtime dependencies..."

# Install git (needed for the autopatcher to function)
apt update
apt install -y git

# Configure git with basic settings
git config --global user.name "nautilus-autopatcher"
git config --global user.email "autopatcher@shuttle.app"
git config --global init.defaultBranch main

# Verify git installation
echo "📋 Git version: $(git --version)"
echo "📋 Git config user.name: $(git config --global user.name)"
echo "📋 Git config user.email: $(git config --global user.email)"

echo "✅ Container setup complete"
