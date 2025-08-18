#!/bin/bash

# RHOAI Security Dashboard Launcher Script
# Quick start script for the Streamlit dashboard using uv package manager

set -e

echo "🛡️  RHOAI Security Dashboard Launcher"
echo "======================================"

# Check if uv is available
if ! command -v uv &> /dev/null; then
    echo "❌ Error: uv package manager is not installed or not in PATH"
    echo "   Install uv from: https://docs.astral.sh/uv/getting-started/installation/"
    echo "   Quick install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo "✅ Found uv package manager"

# Check if required files exist
if [ ! -f "rhoai_security_dashboard.py" ]; then
    echo "❌ Error: rhoai_security_dashboard.py not found in current directory"
    exit 1
fi

if [ ! -f "rhoai_security_pyxis.py" ]; then
    echo "⚠️  Warning: rhoai_security_pyxis.py not found. You won't be able to generate fresh data."
fi

# Check if virtual environment exists, create if needed
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment with uv..."
    uv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Install dependencies using uv
if [ -f "requirements.txt" ]; then
    echo "📦 Installing dependencies with uv..."
    uv pip install -r requirements.txt
else
    echo "⚠️  Warning: requirements.txt not found. Installing core dependencies..."
    uv pip install streamlit pandas plotly requests
fi

echo "✅ Dependencies installed successfully"

# Check for existing data files
echo "📊 Checking for existing data files..."
data_files=$(ls rhoai_security_*.json 2>/dev/null | grep -v rhoai_images.json || true)

if [ -n "$data_files" ]; then
    echo "✅ Found existing data files:"
    echo "$data_files" | while read -r file; do
        echo "   - $file"
    done
else
    echo "ℹ️  No existing security data files found."
    echo "   You can generate data using the dashboard or run:"
    echo "   uv run python ./rhoai_security_pyxis.py --release v2.22 --format json"
fi

echo ""
echo "🚀 Starting RHOAI Security Dashboard..."
echo "   Dashboard will be available at: http://localhost:8501"
echo "   Press Ctrl+C to stop the dashboard"
echo ""

# Launch Streamlit using uv run
uv run streamlit run rhoai_security_dashboard.py --server.port 8501 --server.address localhost