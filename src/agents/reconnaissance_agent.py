"""
Reconnaissance Agent for DefenSys.

This agent is responsible for discovering the attack surface of applications
by analyzing file structures, dependencies, and identifying potential entry points.
"""

import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
import json
import re

from ..utils.file_handler import FileHandler
from ..utils.logger import setup_logger


@dataclass
class AttackSurface:
    """Represents the discovered attack surface of an application."""
    entry_points: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    file_uploads: List[Dict[str, Any]]
    authentication_points: List[Dict[str, Any]]
    database_connections: List[Dict[str, Any]]
    external_dependencies: List[Dict[str, Any]]
    configuration_files: List[Dict[str, Any]]
    static_assets: List[Dict[str, Any]]


class ReconnaissanceAgent:
    """
    Agent responsible for discovering attack surfaces and entry points.
    
    This agent analyzes the codebase to identify potential attack vectors
    and security-relevant components.
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = setup_logger(__name__)
        self.file_handler = FileHandler()
        
        # Patterns for identifying different types of entry points
        self.api_patterns = [
            r'@app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'express\.Router\(\)\.(get|post|put|delete|patch)',
            r'fastapi\.FastAPI\(\)\.(get|post|put|delete|patch)',
            r'@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping'
        ]
        
        self.file_upload_patterns = [
            r'multer|multer\(\)',
            r'upload\.single|upload\.array|upload\.fields',
            r'FormData|multipart/form-data',
            r'file.*upload|upload.*file',
            r'@RequestParam.*MultipartFile'
        ]
        
        self.auth_patterns = [
            r'passport|passport\.authenticate',
            r'jwt|jsonwebtoken',
            r'session|express-session',
            r'oauth|oauth2',
            r'@PreAuthorize|@Secured',
            r'login|authenticate|authorize'
        ]
        
        self.db_patterns = [
            r'mysql|mysql2|pg|postgresql',
            r'mongodb|mongoose',
            r'sequelize|typeorm|prisma',
            r'@Entity|@Table|@Repository',
            r'connection\.query|db\.query'
        ]
    
    async def discover_attack_surface(self, target_path: Path, 
                                    recursive: bool = True,
                                    file_extensions: List[str] = None) -> AttackSurface:
        """
        Discover the attack surface of the target application.
        
        Args:
            target_path: Path to the target directory
            recursive: Whether to scan recursively
            file_extensions: List of file extensions to scan
            
        Returns:
            AttackSurface object containing discovered components
        """
        self.logger.info(f"Starting reconnaissance of {target_path}")
        
        if file_extensions is None:
            file_extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php']
        
        # Get all relevant files
        files = await self._get_relevant_files(target_path, recursive, file_extensions)
        
        # Analyze files for different attack surface components
        tasks = [
            self._find_api_endpoints(files),
            self._find_file_uploads(files),
            self._find_authentication_points(files),
            self._find_database_connections(files),
            self._find_external_dependencies(files),
            self._find_configuration_files(files),
            self._find_static_assets(target_path)
        ]
        
        results = await asyncio.gather(*tasks)
        
        attack_surface = AttackSurface(
            entry_points=[],
            api_endpoints=results[0],
            file_uploads=results[1],
            authentication_points=results[2],
            database_connections=results[3],
            external_dependencies=results[4],
            configuration_files=results[5],
            static_assets=results[6]
        )
        
        # Generate entry points summary
        attack_surface.entry_points = self._generate_entry_points_summary(attack_surface)
        
        self.logger.info(f"Reconnaissance complete. Found {len(attack_surface.entry_points)} entry points")
        return attack_surface
    
    async def _get_relevant_files(self, target_path: Path, recursive: bool, 
                                file_extensions: List[str]) -> List[Path]:
        """Get all relevant files for analysis."""
        files = []
        
        if recursive:
            for ext in file_extensions:
                pattern = f"**/*{ext}"
                files.extend(target_path.glob(pattern))
        else:
            for ext in file_extensions:
                pattern = f"*{ext}"
                files.extend(target_path.glob(pattern))
        
        # Filter out common non-application files
        filtered_files = []
        for file_path in files:
            if self._is_relevant_file(file_path):
                filtered_files.append(file_path)
        
        return filtered_files
    
    def _is_relevant_file(self, file_path: Path) -> bool:
        """Check if a file is relevant for security analysis."""
        # Skip common non-application directories
        skip_dirs = {'node_modules', '.git', 'dist', 'build', 'coverage', 'test', 'tests'}
        
        for part in file_path.parts:
            if part in skip_dirs:
                return False
        
        # Skip very large files
        try:
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                return False
        except OSError:
            return False
        
        return True
    
    async def _find_api_endpoints(self, files: List[Path]) -> List[Dict[str, Any]]:
        """Find API endpoints in the codebase."""
        endpoints = []
        
        for file_path in files:
            try:
                content = await self.file_handler.read_file(file_path)
                file_endpoints = self._extract_endpoints_from_content(content, file_path)
                endpoints.extend(file_endpoints)
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {e}")
        
        return endpoints
    
    def _extract_endpoints_from_content(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Extract API endpoints from file content."""
        endpoints = []
        
        for pattern in self.api_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                endpoint = {
                    "file_path": str(file_path),
                    "line_number": content[:match.start()].count('\n') + 1,
                    "method": match.group(1).upper() if len(match.groups()) > 0 else "UNKNOWN",
                    "path": match.group(2) if len(match.groups()) > 1 else match.group(0),
                    "full_match": match.group(0),
                    "type": "api_endpoint"
                }
                endpoints.append(endpoint)
        
        return endpoints
    
    async def _find_file_uploads(self, files: List[Path]) -> List[Dict[str, Any]]:
        """Find file upload functionality."""
        uploads = []
        
        for file_path in files:
            try:
                content = await self.file_handler.read_file(file_path)
                file_uploads = self._extract_uploads_from_content(content, file_path)
                uploads.extend(file_uploads)
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {e}")
        
        return uploads
    
    def _extract_uploads_from_content(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Extract file upload functionality from content."""
        uploads = []
        
        for pattern in self.file_upload_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                upload = {
                    "file_path": str(file_path),
                    "line_number": content[:match.start()].count('\n') + 1,
                    "pattern": pattern,
                    "match": match.group(0),
                    "type": "file_upload"
                }
                uploads.append(upload)
        
        return uploads
    
    async def _find_authentication_points(self, files: List[Path]) -> List[Dict[str, Any]]:
        """Find authentication and authorization points."""
        auth_points = []
        
        for file_path in files:
            try:
                content = await self.file_handler.read_file(file_path)
                file_auth = self._extract_auth_from_content(content, file_path)
                auth_points.extend(file_auth)
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {e}")
        
        return auth_points
    
    def _extract_auth_from_content(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Extract authentication points from content."""
        auth_points = []
        
        for pattern in self.auth_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                auth_point = {
                    "file_path": str(file_path),
                    "line_number": content[:match.start()].count('\n') + 1,
                    "pattern": pattern,
                    "match": match.group(0),
                    "type": "authentication"
                }
                auth_points.append(auth_point)
        
        return auth_points
    
    async def _find_database_connections(self, files: List[Path]) -> List[Dict[str, Any]]:
        """Find database connections and queries."""
        db_connections = []
        
        for file_path in files:
            try:
                content = await self.file_handler.read_file(file_path)
                file_db = self._extract_db_from_content(content, file_path)
                db_connections.extend(file_db)
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {e}")
        
        return db_connections
    
    def _extract_db_from_content(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Extract database connections from content."""
        db_connections = []
        
        for pattern in self.db_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                db_conn = {
                    "file_path": str(file_path),
                    "line_number": content[:match.start()].count('\n') + 1,
                    "pattern": pattern,
                    "match": match.group(0),
                    "type": "database_connection"
                }
                db_connections.append(db_conn)
        
        return db_connections
    
    async def _find_external_dependencies(self, files: List[Path]) -> List[Dict[str, Any]]:
        """Find external dependencies and third-party libraries."""
        dependencies = []
        
        # Look for package.json, requirements.txt, etc.
        package_files = ['package.json', 'requirements.txt', 'composer.json', 'pom.xml']
        
        for file_path in files:
            if file_path.name in package_files:
                try:
                    content = await self.file_handler.read_file(file_path)
                    deps = self._extract_dependencies_from_package_file(content, file_path)
                    dependencies.extend(deps)
                except Exception as e:
                    self.logger.warning(f"Error reading {file_path}: {e}")
        
        return dependencies
    
    def _extract_dependencies_from_package_file(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Extract dependencies from package files."""
        dependencies = []
        
        try:
            if file_path.name == 'package.json':
                data = json.loads(content)
                deps = data.get('dependencies', {})
                dev_deps = data.get('devDependencies', {})
                
                for name, version in {**deps, **dev_deps}.items():
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "file_path": str(file_path),
                        "type": "npm_dependency"
                    })
            
            elif file_path.name == 'requirements.txt':
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('==')
                        if len(parts) == 2:
                            dependencies.append({
                                "name": parts[0],
                                "version": parts[1],
                                "file_path": str(file_path),
                                "type": "python_dependency"
                            })
        
        except Exception as e:
            self.logger.warning(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    async def _find_configuration_files(self, files: List[Path]) -> List[Dict[str, Any]]:
        """Find configuration files that might contain sensitive data."""
        config_files = []
        config_patterns = ['.env', 'config', 'settings', 'secrets', 'credentials']
        
        for file_path in files:
            if any(pattern in file_path.name.lower() for pattern in config_patterns):
                config_files.append({
                    "file_path": str(file_path),
                    "type": "configuration_file",
                    "sensitive": True
                })
        
        return config_files
    
    async def _find_static_assets(self, target_path: Path) -> List[Dict[str, Any]]:
        """Find static assets that might be security-relevant."""
        static_assets = []
        asset_extensions = ['.html', '.css', '.js', '.json', '.xml']
        
        for ext in asset_extensions:
            for file_path in target_path.rglob(f"*{ext}"):
                if self._is_relevant_file(file_path):
                    static_assets.append({
                        "file_path": str(file_path),
                        "type": "static_asset",
                        "extension": ext
                    })
        
        return static_assets
    
    def _generate_entry_points_summary(self, attack_surface: AttackSurface) -> List[Dict[str, Any]]:
        """Generate a summary of all entry points."""
        entry_points = []
        
        # Add API endpoints
        for endpoint in attack_surface.api_endpoints:
            entry_points.append({
                "type": "API Endpoint",
                "description": f"{endpoint['method']} {endpoint['path']}",
                "file": endpoint['file_path'],
                "line": endpoint['line_number'],
                "risk_level": "high"
            })
        
        # Add file uploads
        for upload in attack_surface.file_uploads:
            entry_points.append({
                "type": "File Upload",
                "description": "File upload functionality detected",
                "file": upload['file_path'],
                "line": upload['line_number'],
                "risk_level": "high"
            })
        
        # Add authentication points
        for auth in attack_surface.authentication_points:
            entry_points.append({
                "type": "Authentication",
                "description": "Authentication/authorization logic",
                "file": auth['file_path'],
                "line": auth['line_number'],
                "risk_level": "critical"
            })
        
        return entry_points
