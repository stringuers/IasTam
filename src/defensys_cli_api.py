"""
CLI tool and REST API for DefenSys.

This module provides both command-line interface and REST API endpoints
for the DefenSys vulnerability scanner.
"""

import asyncio
import click
import uvicorn
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .defensys_analyzer import DefenSysAnalyzer, ScanConfig
from .utils.logger import setup_logger
from .utils.config import Config
from .reports.console_formatter import ConsoleFormatter
from .reports.html_generator import HTMLGenerator
from .reports.json_exporter import JSONExporter


# FastAPI app instance
app = FastAPI(
    title="DefenSys API",
    description="AI-Powered Cybersecurity Vulnerability Scanner",
    version="1.0.0"
)

# Global analyzer instance
analyzer: Optional[DefenSysAnalyzer] = None


class ScanRequest(BaseModel):
    """Request model for scan API endpoint."""
    target_path: str
    recursive: bool = True
    file_extensions: list = None
    deep_analysis: bool = False


@app.on_event("startup")
async def startup_event():
    """Initialize the analyzer on startup."""
    global analyzer
    config = Config()
    analyzer = DefenSysAnalyzer(config)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "DefenSys API"}


@app.post("/scan")
async def scan_endpoint(request: ScanRequest):
    """Scan endpoint for vulnerability detection."""
    if not analyzer:
        raise HTTPException(status_code=500, detail="Analyzer not initialized")
    
    try:
        target_path = Path(request.target_path)
        if not target_path.exists():
            raise HTTPException(status_code=400, detail="Target path does not exist")
        
        scan_config = ScanConfig(
            target_path=target_path,
            recursive=request.recursive,
            file_extensions=request.file_extensions,
            deep_analysis=request.deep_analysis
        )
        
        results = await analyzer.scan(scan_config)
        return JSONResponse(content=results)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get results for a specific scan."""
    # TODO: Implement scan result storage and retrieval
    return {"message": "Scan result retrieval not yet implemented"}


@click.group()
def cli():
    """DefenSys - AI-Powered Cybersecurity Scanner"""
    pass


@cli.command()
@click.argument('target_path', type=click.Path(exists=True, path_type=Path))
@click.option('-r', '--recursive', is_flag=True, default=True, help='Scan recursively')
@click.option('-f', '--format', 'output_format', 
              type=click.Choice(['console', 'html', 'json']), 
              default='console', help='Output format')
@click.option('-o', '--output', type=click.Path(), help='Output file path')
@click.option('--deep', is_flag=True, help='Enable deep analysis')
@click.option('--extensions', help='File extensions to scan (comma-separated)')
@click.option('--api', is_flag=True, help='Start API server instead of scanning')
@click.option('--port', default=8000, help='API server port')
@click.option('--host', default='127.0.0.1', help='API server host')
def scan(target_path, recursive, output_format, output, deep, extensions, api, port, host):
    """Scan a directory for vulnerabilities."""
    if api:
        start_api_server(host, port)
        return
    
    # Parse file extensions
    file_extensions = None
    if extensions:
        file_extensions = [f".{ext.strip()}" for ext in extensions.split(',')]
    
    # Run scan
    asyncio.run(run_scan(
        target_path=target_path,
        recursive=recursive,
        output_format=output_format,
        output_file=output,
        deep_analysis=deep,
        file_extensions=file_extensions
    ))


async def run_scan(target_path: Path, recursive: bool, output_format: str, 
                  output_file: Optional[Path], deep_analysis: bool, 
                  file_extensions: Optional[list]):
    """Run the vulnerability scan."""
    config = Config()
    analyzer = DefenSysAnalyzer(config)
    
    scan_config = ScanConfig(
        target_path=target_path,
        recursive=recursive,
        file_extensions=file_extensions,
        deep_analysis=deep_analysis
    )
    
    try:
        results = await analyzer.scan(scan_config)
        
        # Generate output
        if output_format == 'console':
            formatter = ConsoleFormatter()
            output_text = formatter.format_results(results)
            if output_file:
                output_file.write_text(output_text)
            else:
                click.echo(output_text)
        
        elif output_format == 'html':
            generator = HTMLGenerator()
            html_content = generator.generate_report(results)
            if output_file:
                output_file.write_text(html_content)
            else:
                click.echo("HTML report generated")
        
        elif output_format == 'json':
            exporter = JSONExporter()
            json_content = exporter.export_results(results)
            if output_file:
                output_file.write_text(json_content)
            else:
                click.echo(json_content)
    
    except Exception as e:
        click.echo(f"Error during scan: {str(e)}", err=True)
        raise click.Abort()


def start_api_server(host: str, port: int):
    """Start the API server."""
    click.echo(f"Starting DefenSys API server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


@cli.command()
def version():
    """Show version information."""
    click.echo("DefenSys Scanner v1.0.0")
    click.echo("AI-Powered Cybersecurity Platform")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
