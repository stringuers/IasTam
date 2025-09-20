FROM python:3.9-slim

LABEL maintainer="DefenSys Team"
LABEL version="1.0.0"
LABEL description="AI-powered cybersecurity scanner"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY tests/ ./tests/
COPY setup.py .
COPY README.md .

# Install the package
RUN pip install -e .

# Create non-root user for security
RUN useradd -m -u 1000 defensys && chown -R defensys:defensys /app
USER defensys

# Create necessary directories
RUN mkdir -p scan_results projects

# Set environment variables
ENV PYTHONPATH=/app/src
ENV DEFENSYS_ENV=production

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["python", "src/defensys_cli_api_enhanced.py", "--api", "--port", "8000"]
