#!/bin/bash
set -e

echo "🚀 Deploying DefenSys..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required for deployment"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is required for deployment"
    exit 1
fi

# Build Docker image
echo "🐳 Building Docker image..."
docker build -t defensys:latest .

# Start services
echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check health
echo "🏥 Checking service health..."
curl -f http://localhost:8000/health || {
    echo "❌ Service health check failed"
    exit 1
}

echo "✅ DefenSys deployed successfully!"
echo "🌐 API available at: http://localhost:8000"
echo "📚 API docs at: http://localhost:8000/docs"
echo ""
echo "🛠️ Management commands:"
echo "  docker-compose logs -f defensys-api  # View logs"
echo "  docker-compose restart defensys-api  # Restart service"
echo "  docker-compose down                  # Stop services"
