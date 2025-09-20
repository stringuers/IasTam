#!/bin/bash
set -e

echo "🔨 Building DefenSys..."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build/
rm -rf dist/
rm -rf *.egg-info/

# Install build dependencies
echo "📦 Installing build dependencies..."
pip install build wheel twine

# Run tests
echo "🧪 Running tests..."
python -m pytest tests/ -v

# Build package
echo "📦 Building package..."
python -m build

# Check package
echo "🔍 Checking package..."
twine check dist/*

echo "✅ Build completed successfully!"
echo "📦 Package files created in dist/"
echo "🚀 Ready for distribution!"
