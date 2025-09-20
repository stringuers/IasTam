"""
Tests for the core DefenSys analyzer.

This module contains unit tests for the main analyzer functionality.
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from src.defensys_analyzer import DefenSysAnalyzer, ScanConfig
from src.models.vulnerability import Vulnerability, Severity, VulnerabilityType
from src.utils.config import Config


class TestDefenSysAnalyzer:
    """Test cases for DefenSysAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance for testing."""
        config = Config()
        return DefenSysAnalyzer(config)
    
    @pytest.fixture
    def scan_config(self, tmp_path):
        """Create scan configuration for testing."""
        # Create a test file
        test_file = tmp_path / "test.js"
        test_file.write_text("console.log('test');")
        
        return ScanConfig(
            target_path=tmp_path,
            recursive=True,
            file_extensions=['.js'],
            deep_analysis=False
        )
    
    @pytest.mark.asyncio
    async def test_analyzer_initialization(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer is not None
        assert analyzer.vulnerabilities == []
        assert analyzer.attack_chains == []
    
    @pytest.mark.asyncio
    async def test_scan_with_no_vulnerabilities(self, analyzer, scan_config):
        """Test scan with no vulnerabilities found."""
        with patch.object(analyzer.recon_agent, 'discover_attack_surface') as mock_recon:
            with patch.object(analyzer.vuln_agent, 'analyze_vulnerabilities') as mock_vuln:
                with patch.object(analyzer.exploit_agent, 'analyze_attack_chains') as mock_exploit:
                    # Mock empty results
                    mock_recon.return_value = Mock(entry_points=[], api_endpoints=[], file_uploads=[], 
                                                 authentication_points=[], database_connections=[], 
                                                 external_dependencies=[], configuration_files=[], 
                                                 static_assets=[])
                    mock_vuln.return_value = []
                    mock_exploit.return_value = []
                    
                    results = await analyzer.scan(scan_config)
                    
                    assert results['summary']['total_vulnerabilities'] == 0
                    assert len(results['vulnerabilities']) == 0
                    assert len(results['attack_chains']) == 0
    
    @pytest.mark.asyncio
    async def test_scan_with_vulnerabilities(self, analyzer, scan_config):
        """Test scan with vulnerabilities found."""
        # Create mock vulnerability
        mock_vuln = Vulnerability(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="Test SQL Injection",
            description="Test vulnerability",
            location=Mock(file_path="test.js", line_number=1, column_number=0)
        )
        
        with patch.object(analyzer.recon_agent, 'discover_attack_surface') as mock_recon:
            with patch.object(analyzer.vuln_agent, 'analyze_vulnerabilities') as mock_vuln:
                with patch.object(analyzer.exploit_agent, 'analyze_attack_chains') as mock_exploit:
                    # Mock results with vulnerability
                    mock_recon.return_value = Mock(entry_points=[], api_endpoints=[], file_uploads=[], 
                                                 authentication_points=[], database_connections=[], 
                                                 external_dependencies=[], configuration_files=[], 
                                                 static_assets=[])
                    mock_vuln.return_value = [mock_vuln]
                    mock_exploit.return_value = []
                    
                    results = await analyzer.scan(scan_config)
                    
                    assert results['summary']['total_vulnerabilities'] == 1
                    assert results['summary']['high_count'] == 1
                    assert len(results['vulnerabilities']) == 1
                    assert results['vulnerabilities'][0]['title'] == "Test SQL Injection"
    
    @pytest.mark.asyncio
    async def test_scan_with_attack_chains(self, analyzer, scan_config):
        """Test scan with attack chains found."""
        mock_chain = {
            "chain_id": "test_chain",
            "description": "Test attack chain",
            "total_risk_score": 8.5,
            "steps": []
        }
        
        with patch.object(analyzer.recon_agent, 'discover_attack_surface') as mock_recon:
            with patch.object(analyzer.vuln_agent, 'analyze_vulnerabilities') as mock_vuln:
                with patch.object(analyzer.exploit_agent, 'analyze_attack_chains') as mock_exploit:
                    # Mock results with attack chain
                    mock_recon.return_value = Mock(entry_points=[], api_endpoints=[], file_uploads=[], 
                                                 authentication_points=[], database_connections=[], 
                                                 external_dependencies=[], configuration_files=[], 
                                                 static_assets=[])
                    mock_vuln.return_value = []
                    mock_exploit.return_value = [mock_chain]
                    
                    results = await analyzer.scan(scan_config)
                    
                    assert results['summary']['attack_chains'] == 1
                    assert len(results['attack_chains']) == 1
                    assert results['attack_chains'][0]['chain_id'] == "test_chain"
    
    def test_generate_recommendations_no_vulnerabilities(self, analyzer):
        """Test recommendation generation with no vulnerabilities."""
        recommendations = analyzer._generate_recommendations()
        
        assert len(recommendations) == 1
        assert recommendations[0]['type'] == 'success'
        assert 'No vulnerabilities detected' in recommendations[0]['message']
    
    def test_generate_recommendations_with_vulnerabilities(self, analyzer):
        """Test recommendation generation with vulnerabilities."""
        # Add mock vulnerabilities
        vuln1 = Vulnerability(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Test SQL injection",
            location=Mock(file_path="test.js", line_number=1, column_number=0)
        )
        
        vuln2 = Vulnerability(
            vulnerability_type=VulnerabilityType.XSS,
            severity=Severity.MEDIUM,
            title="XSS",
            description="Test XSS",
            location=Mock(file_path="test.js", line_number=2, column_number=0)
        )
        
        analyzer.vulnerabilities = [vuln1, vuln2]
        
        recommendations = analyzer._generate_recommendations()
        
        assert len(recommendations) == 2  # One for each vulnerability type
        assert any(rec['category'] == 'sql_injection' for rec in recommendations)
        assert any(rec['category'] == 'cross_site_scripting' for rec in recommendations)


class TestScanConfig:
    """Test cases for ScanConfig."""
    
    def test_scan_config_defaults(self, tmp_path):
        """Test ScanConfig default values."""
        config = ScanConfig(target_path=tmp_path)
        
        assert config.target_path == tmp_path
        assert config.recursive is True
        assert config.max_file_size_mb == 50
        assert config.timeout_seconds == 300
        assert config.parallel_scans == 4
        assert config.deep_analysis is False
        assert '.js' in config.file_extensions
        assert '.py' in config.file_extensions
    
    def test_scan_config_custom_values(self, tmp_path):
        """Test ScanConfig with custom values."""
        config = ScanConfig(
            target_path=tmp_path,
            recursive=False,
            file_extensions=['.js', '.ts'],
            max_file_size_mb=100,
            timeout_seconds=600,
            parallel_scans=8,
            deep_analysis=True
        )
        
        assert config.recursive is False
        assert config.file_extensions == ['.js', '.ts']
        assert config.max_file_size_mb == 100
        assert config.timeout_seconds == 600
        assert config.parallel_scans == 8
        assert config.deep_analysis is True
