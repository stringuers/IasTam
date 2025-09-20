#!/bin/bash
set -e

echo "🛡️ Installing DefenSys Security Scanner..."

# Check Python version
python_version=$(python3 --version 2>&1 | grep -o "[0-9]\+\.[0-9]\+")
required_version="3.9"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python $required_version or higher is required. Found: $python_version"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
echo "⬇️ Installing dependencies..."
pip install -r requirements.txt

# Install DefenSys
echo "🔧 Installing DefenSys..."
pip install -e .

# Verify installation
echo "✅ Verifying installation..."
defensys --version

echo "🎉 DefenSys installed successfully!"
echo ""
echo "🚀 Quick start:"
echo "  source venv/bin/activate"
echo "  defensys ./your-project -r"
echo ""
echo "📚 Documentation: https://docs.defensys.ai"
