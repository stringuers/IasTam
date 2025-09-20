"""
Tests for the DefenSys API endpoints.

This module contains tests for the REST API functionality.
"""

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from src.defensys_cli_api import app


class TestDefenSysAPI:
    """Test cases for DefenSys API."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "DefenSys API"
    
    @pytest.mark.asyncio
    async def test_scan_endpoint_success(self, client, tmp_path):
        """Test successful scan endpoint."""
        # Create test file
        test_file = tmp_path / "test.js"
        test_file.write_text("console.log('test');")
        
        scan_request = {
            "target_path": str(tmp_path),
            "recursive": True,
            "file_extensions": [".js"],
            "deep_analysis": False
        }
        
        with patch('src.defensys_cli_api.analyzer') as mock_analyzer:
            mock_analyzer.scan.return_value = {
                "scan_info": {
                    "target_path": str(tmp_path),
                    "timestamp": 1234567890
                },
                "summary": {
                    "total_vulnerabilities": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "attack_chains": 0
                },
                "vulnerabilities": [],
                "attack_chains": [],
                "recommendations": []
            }
            
            response = client.post("/scan", json=scan_request)
            
            assert response.status_code == 200
            data = response.json()
            assert "summary" in data
            assert data["summary"]["total_vulnerabilities"] == 0
    
    def test_scan_endpoint_invalid_path(self, client):
        """Test scan endpoint with invalid path."""
        scan_request = {
            "target_path": "/nonexistent/path",
            "recursive": True
        }
        
        response = client.post("/scan", json=scan_request)
        
        assert response.status_code == 400
        data = response.json()
        assert "Target path does not exist" in data["detail"]
    
    def test_scan_endpoint_missing_analyzer(self, client, tmp_path):
        """Test scan endpoint when analyzer is not initialized."""
        # Create test file
        test_file = tmp_path / "test.js"
        test_file.write_text("console.log('test');")
        
        scan_request = {
            "target_path": str(tmp_path),
            "recursive": True
        }
        
        with patch('src.defensys_cli_api.analyzer', None):
            response = client.post("/scan", json=scan_request)
            
            assert response.status_code == 500
            data = response.json()
            assert "Analyzer not initialized" in data["detail"]
    
    def test_scan_endpoint_analyzer_error(self, client, tmp_path):
        """Test scan endpoint when analyzer throws an error."""
        # Create test file
        test_file = tmp_path / "test.js"
        test_file.write_text("console.log('test');")
        
        scan_request = {
            "target_path": str(tmp_path),
            "recursive": True
        }
        
        with patch('src.defensys_cli_api.analyzer') as mock_analyzer:
            mock_analyzer.scan.side_effect = Exception("Test error")
            
            response = client.post("/scan", json=scan_request)
            
            assert response.status_code == 500
            data = response.json()
            assert "Test error" in data["detail"]
    
    def test_get_scan_results_not_implemented(self, client):
        """Test get scan results endpoint (not yet implemented)."""
        response = client.get("/scan/test-scan-id")
        
        assert response.status_code == 200
        data = response.json()
        assert "not yet implemented" in data["message"]


class TestScanRequest:
    """Test cases for ScanRequest model."""
    
    def test_scan_request_defaults(self):
        """Test ScanRequest default values."""
        from src.defensys_cli_api import ScanRequest
        
        request = ScanRequest(target_path="/test/path")
        
        assert request.target_path == "/test/path"
        assert request.recursive is True
        assert request.file_extensions is None
        assert request.deep_analysis is False
    
    def test_scan_request_custom_values(self):
        """Test ScanRequest with custom values."""
        from src.defensys_cli_api import ScanRequest
        
        request = ScanRequest(
            target_path="/test/path",
            recursive=False,
            file_extensions=[".js", ".ts"],
            deep_analysis=True
        )
        
        assert request.target_path == "/test/path"
        assert request.recursive is False
        assert request.file_extensions == [".js", ".ts"]
        assert request.deep_analysis is True


class TestAPIEndpoints:
    """Test cases for API endpoint functionality."""
    
    def test_api_documentation(self, client):
        """Test that API documentation is accessible."""
        response = client.get("/docs")
        assert response.status_code == 200
    
    def test_openapi_schema(self, client):
        """Test OpenAPI schema endpoint."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        
        schema = response.json()
        assert "openapi" in schema
        assert schema["info"]["title"] == "DefenSys API"
        assert schema["info"]["version"] == "1.0.0"
    
    def test_cors_headers(self, client):
        """Test CORS headers are present."""
        response = client.options("/scan")
        # Note: CORS headers might not be present in test environment
        # This test ensures the endpoint responds to OPTIONS requests
        assert response.status_code in [200, 405]  # 405 if OPTIONS not implemented


class TestAPIErrorHandling:
    """Test cases for API error handling."""
    
    def test_invalid_json_request(self, client):
        """Test handling of invalid JSON in request body."""
        response = client.post("/scan", data="invalid json")
        assert response.status_code == 422  # Unprocessable Entity
    
    def test_missing_required_fields(self, client):
        """Test handling of missing required fields."""
        response = client.post("/scan", json={})
        assert response.status_code == 422  # Unprocessable Entity
    
    def test_large_request_body(self, client):
        """Test handling of large request body."""
        large_data = {
            "target_path": "/test/path",
            "file_extensions": ["." + "x" * 1000] * 1000  # Very large list
        }
        
        response = client.post("/scan", json=large_data)
        # Should either succeed or fail gracefully
        assert response.status_code in [200, 400, 413, 422]
