# DefenSys Installation Guide

This guide will help you install and set up DefenSys on your system.

## 📋 Prerequisites

### System Requirements
- **Python**: 3.9 or higher
- **Memory**: 4GB RAM minimum (8GB recommended)
- **Storage**: 2GB free space
- **OS**: Linux, macOS, or Windows

### Dependencies
- Git (for cloning the repository)
- pip (Python package manager)
- Virtual environment (recommended)

## 🚀 Installation Methods

### Method 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/defensys/scanner.git
cd scanner

# Run the installation script
chmod +x scripts/install.sh
./scripts/install.sh
```

### Method 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/defensys/scanner.git
cd scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install DefenSys
pip install -e .
```

### Method 3: Docker Installation

```bash
# Clone the repository
git clone https://github.com/defensys/scanner.git
cd scanner

# Build Docker image
docker build -t defensys:latest .

# Run DefenSys
docker run -it --rm -v $(pwd):/app defensys:latest defensys --help
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in your project root:

```bash
# DefenSys Configuration
DEFENSYS_ENV=development
LOG_LEVEL=info

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET=your-jwt-secret-here

# ML Configuration
MODEL_PATH=./data/models/
TRAINING_DATA_PATH=./data/training_data/
```

### Configuration File

Create a `config.json` file:

```json
{
  "scan": {
    "max_file_size_mb": 50,
    "timeout_seconds": 300,
    "parallel_scans": 4,
    "deep_analysis": false
  },
  "report": {
    "output_dir": "./scan_results/",
    "include_poc": true,
    "generate_attack_chains": true
  },
  "ml": {
    "model_path": "./data/models/",
    "confidence_threshold": 0.7
  }
}
```

## ✅ Verification

Test your installation:

```bash
# Check version
defensys --version

# Run a test scan
defensys ./tests/fixtures/vulnerable_samples/ -r

# Start API server
defensys --api --port 8000
```

## 🐳 Docker Compose Setup

For production deployment:

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f defensys-api
```

## 🔧 Development Setup

For contributing to DefenSys:

```bash
# Clone repository
git clone https://github.com/defensys/scanner.git
cd scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install DefenSys in development mode
pip install -e .

# Run tests
pytest tests/ -v

# Run linting
black src/ tests/
flake8 src/ tests/
```

## 🚨 Troubleshooting

### Common Issues

#### Python Version Error
```bash
# Check Python version
python3 --version

# If version is too old, install Python 3.9+
# On Ubuntu/Debian:
sudo apt update
sudo apt install python3.9 python3.9-venv

# On macOS with Homebrew:
brew install python@3.9
```

#### Permission Denied
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Or run with bash
bash scripts/install.sh
```

#### Module Not Found
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall DefenSys
pip install -e .
```

#### Docker Issues
```bash
# Check Docker is running
docker --version
docker-compose --version

# Rebuild image
docker build --no-cache -t defensys:latest .
```

### Getting Help

- **Documentation**: [docs.defensys.ai](https://docs.defensys.ai)
- **GitHub Issues**: [github.com/defensys/scanner/issues](https://github.com/defensys/scanner/issues)
- **Discord**: [discord.gg/defensys](https://discord.gg/defensys)
- **Email**: support@defensys.ai

## 🎉 Next Steps

After installation, check out:

1. [Quick Start Guide](usage.md) - Run your first scan
2. [Configuration Guide](configuration.md) - Customize DefenSys
3. [API Reference](api_reference.md) - Use the REST API
4. [Examples](examples/) - See DefenSys in action

---

*Installation guide last updated: 2024-01-01*
