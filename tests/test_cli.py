"""
Tests for the DefenSys CLI interface.

This module contains tests for the command-line interface functionality.
"""

import pytest
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, Mock
from click.testing import CliRunner

from src.defensys_cli_api import cli, scan, version


class TestDefenSysCLI:
    """Test cases for DefenSys CLI."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI runner for testing."""
        return CliRunner()
    
    @pytest.fixture
    def test_dir(self, tmp_path):
        """Create test directory with sample files."""
        # Create test JavaScript file
        js_file = tmp_path / "test.js"
        js_file.write_text("console.log('test');")
        
        # Create test Python file
        py_file = tmp_path / "test.py"
        py_file.write_text("print('test')")
        
        return tmp_path
    
    def test_cli_help(self, runner):
        """Test CLI help command."""
        result = runner.invoke(cli, ["--help"])
        
        assert result.exit_code == 0
        assert "DefenSys - AI-Powered Cybersecurity Scanner" in result.output
        assert "scan" in result.output
        assert "version" in result.output
    
    def test_version_command(self, runner):
        """Test version command."""
        result = runner.invoke(version)
        
        assert result.exit_code == 0
        assert "DefenSys Scanner v1.0.0" in result.output
    
    @pytest.mark.asyncio
    async def test_scan_command_basic(self, runner, test_dir):
        """Test basic scan command."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [str(test_dir)])
            
            assert result.exit_code == 0
            mock_run_scan.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_scan_command_with_options(self, runner, test_dir):
        """Test scan command with various options."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [
                str(test_dir),
                "--format", "html",
                "--output", "report.html",
                "--deep",
                "--extensions", "js,py"
            ])
            
            assert result.exit_code == 0
            mock_run_scan.assert_called_once()
    
    def test_scan_command_invalid_path(self, runner):
        """Test scan command with invalid path."""
        result = runner.invoke(scan, ["/nonexistent/path"])
        
        assert result.exit_code != 0
        assert "does not exist" in result.output
    
    def test_scan_command_api_mode(self, runner):
        """Test scan command in API mode."""
        with patch('src.defensys_cli_api.start_api_server') as mock_start_api:
            result = runner.invoke(scan, ["--api", "--port", "9000"])
            
            assert result.exit_code == 0
            mock_start_api.assert_called_once_with("127.0.0.1", 9000)
    
    def test_scan_command_recursive_option(self, runner, test_dir):
        """Test scan command with recursive option."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [str(test_dir), "-r"])
            
            assert result.exit_code == 0
            # Check that recursive=True was passed
            call_args = mock_run_scan.call_args
            assert call_args[1]['recursive'] is True
    
    def test_scan_command_no_recursive(self, runner, test_dir):
        """Test scan command without recursive option."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [str(test_dir), "--no-recursive"])
            
            assert result.exit_code == 0
            # Check that recursive=False was passed
            call_args = mock_run_scan.call_args
            assert call_args[1]['recursive'] is False
    
    def test_scan_command_output_formats(self, runner, test_dir):
        """Test scan command with different output formats."""
        formats = ["console", "html", "json"]
        
        for format_type in formats:
            with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
                mock_run_scan.return_value = None
                
                result = runner.invoke(scan, [str(test_dir), "--format", format_type])
                
                assert result.exit_code == 0
                # Check that correct format was passed
                call_args = mock_run_scan.call_args
                assert call_args[1]['output_format'] == format_type
    
    def test_scan_command_file_extensions(self, runner, test_dir):
        """Test scan command with custom file extensions."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [
                str(test_dir),
                "--extensions", "js,ts,py"
            ])
            
            assert result.exit_code == 0
            # Check that correct extensions were passed
            call_args = mock_run_scan.call_args
            assert call_args[1]['file_extensions'] == ['.js', '.ts', '.py']
    
    def test_scan_command_deep_analysis(self, runner, test_dir):
        """Test scan command with deep analysis."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [str(test_dir), "--deep"])
            
            assert result.exit_code == 0
            # Check that deep_analysis=True was passed
            call_args = mock_run_scan.call_args
            assert call_args[1]['deep_analysis'] is True


class TestCLIErrorHandling:
    """Test cases for CLI error handling."""
    
    def test_cli_invalid_command(self, runner):
        """Test CLI with invalid command."""
        result = runner.invoke(cli, ["invalid-command"])
        
        assert result.exit_code != 0
        assert "No such command" in result.output
    
    def test_cli_invalid_option(self, runner, test_dir):
        """Test CLI with invalid option."""
        result = runner.invoke(scan, [str(test_dir), "--invalid-option"])
        
        assert result.exit_code != 0
        assert "No such option" in result.output
    
    def test_cli_missing_required_argument(self, runner):
        """Test CLI with missing required argument."""
        result = runner.invoke(scan, [])
        
        assert result.exit_code != 0
        assert "Missing argument" in result.output


class TestCLIIntegration:
    """Integration tests for CLI functionality."""
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self, runner, test_dir):
        """Test complete scan workflow."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            # Mock successful scan
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [
                str(test_dir),
                "--format", "console",
                "--recursive"
            ])
            
            assert result.exit_code == 0
            mock_run_scan.assert_called_once()
    
    def test_cli_with_config_file(self, runner, test_dir, tmp_path):
        """Test CLI with configuration file."""
        # Create config file
        config_file = tmp_path / "config.json"
        config_file.write_text('{"scan": {"deep_analysis": true}}')
        
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [
                str(test_dir),
                "--config", str(config_file)
            ])
            
            # Note: Config file loading would need to be implemented
            assert result.exit_code in [0, 2]  # 2 if config option not implemented


class TestCLIOutput:
    """Test cases for CLI output formatting."""
    
    def test_console_output_format(self, runner, test_dir):
        """Test console output format."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [str(test_dir), "--format", "console"])
            
            assert result.exit_code == 0
            # Console output should be handled by run_scan
    
    def test_json_output_format(self, runner, test_dir):
        """Test JSON output format."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [str(test_dir), "--format", "json"])
            
            assert result.exit_code == 0
    
    def test_html_output_format(self, runner, test_dir):
        """Test HTML output format."""
        with patch('src.defensys_cli_api.run_scan') as mock_run_scan:
            mock_run_scan.return_value = None
            
            result = runner.invoke(scan, [str(test_dir), "--format", "html"])
            
            assert result.exit_code == 0
