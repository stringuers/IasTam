"""
File handling utilities for DefenSys.

This module provides file operations and utilities for reading,
writing, and managing files during security scans.
"""

import asyncio
import aiofiles
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class FileInfo:
    """Information about a file."""
    path: Path
    size: int
    extension: str
    language: Optional[str] = None
    encoding: str = 'utf-8'
    is_binary: bool = False


class FileHandler:
    """
    File handling utilities for DefenSys.
    
    This class provides async file operations and utilities for
    reading and managing files during security scans.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.max_file_size = 50 * 1024 * 1024  # 50MB
        self.supported_extensions = {
            '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.cs', '.go', '.rb',
            '.html', '.htm', '.css', '.json', '.xml', '.yaml', '.yml', '.sql'
        }
        self.binary_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz',
            '.exe', '.dll', '.so', '.dylib', '.bin'
        }
    
    async def read_file(self, file_path: Path, encoding: str = 'utf-8') -> str:
        """
        Read a file asynchronously.
        
        Args:
            file_path: Path to the file
            encoding: File encoding (default: utf-8)
            
        Returns:
            File content as string
            
        Raises:
            FileNotFoundError: If file doesn't exist
            UnicodeDecodeError: If file can't be decoded
            OSError: If file can't be read
        """
        try:
            # Check if file exists
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                raise ValueError(f"File too large: {file_path} ({file_size} bytes)")
            
            # Check if it's a binary file
            if self._is_binary_file(file_path):
                raise ValueError(f"Binary file not supported: {file_path}")
            
            # Read file content
            async with aiofiles.open(file_path, 'r', encoding=encoding) as f:
                content = await f.read()
            
            self.logger.debug(f"Read file: {file_path} ({len(content)} characters)")
            return content
            
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            raise
    
    async def read_file_safe(self, file_path: Path, encoding: str = 'utf-8') -> Optional[str]:
        """
        Safely read a file, returning None if it can't be read.
        
        Args:
            file_path: Path to the file
            encoding: File encoding
            
        Returns:
            File content or None if error
        """
        try:
            return await self.read_file(file_path, encoding)
        except Exception:
            return None
    
    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if a file is binary."""
        # Check by extension first
        if file_path.suffix.lower() in self.binary_extensions:
            return True
        
        # Check by reading first few bytes
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' in chunk
        except Exception:
            return True
    
    async def get_file_info(self, file_path: Path) -> FileInfo:
        """
        Get information about a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            FileInfo object
        """
        try:
            stat = file_path.stat()
            extension = file_path.suffix.lower()
            language = self._detect_language(extension)
            
            return FileInfo(
                path=file_path,
                size=stat.st_size,
                extension=extension,
                language=language,
                encoding='utf-8',
                is_binary=self._is_binary_file(file_path)
            )
        except Exception as e:
            self.logger.error(f"Error getting file info for {file_path}: {e}")
            raise
    
    def _detect_language(self, extension: str) -> Optional[str]:
        """Detect programming language from file extension."""
        language_map = {
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.py': 'python',
            '.java': 'java',
            '.php': 'php',
            '.cs': 'csharp',
            '.go': 'go',
            '.rb': 'ruby',
            '.html': 'html',
            '.htm': 'html',
            '.css': 'css',
            '.json': 'json',
            '.xml': 'xml',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.sql': 'sql'
        }
        
        return language_map.get(extension)
    
    async def find_files(self, directory: Path, pattern: str = "*", 
                        recursive: bool = True) -> List[Path]:
        """
        Find files matching a pattern in a directory.
        
        Args:
            directory: Directory to search
            pattern: File pattern to match
            recursive: Whether to search recursively
            
        Returns:
            List of matching file paths
        """
        try:
            if recursive:
                files = list(directory.rglob(pattern))
            else:
                files = list(directory.glob(pattern))
            
            # Filter out directories and unsupported files
            filtered_files = []
            for file_path in files:
                if file_path.is_file() and self._is_supported_file(file_path):
                    filtered_files.append(file_path)
            
            self.logger.debug(f"Found {len(filtered_files)} files in {directory}")
            return filtered_files
            
        except Exception as e:
            self.logger.error(f"Error finding files in {directory}: {e}")
            return []
    
    def _is_supported_file(self, file_path: Path) -> bool:
        """Check if a file is supported for analysis."""
        extension = file_path.suffix.lower()
        
        # Check if it's a supported extension
        if extension not in self.supported_extensions:
            return False
        
        # Check if it's not a binary file
        if self._is_binary_file(file_path):
            return False
        
        # Check file size
        try:
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return False
        except OSError:
            return False
        
        return True
    
    async def read_multiple_files(self, file_paths: List[Path]) -> Dict[Path, str]:
        """
        Read multiple files asynchronously.
        
        Args:
            file_paths: List of file paths to read
            
        Returns:
            Dictionary mapping file paths to their content
        """
        tasks = []
        for file_path in file_paths:
            task = self.read_file_safe(file_path)
            tasks.append((file_path, task))
        
        results = {}
        for file_path, task in tasks:
            content = await task
            if content is not None:
                results[file_path] = content
        
        return results
    
    async def write_file(self, file_path: Path, content: str, 
                        encoding: str = 'utf-8') -> None:
        """
        Write content to a file asynchronously.
        
        Args:
            file_path: Path to write to
            content: Content to write
            encoding: File encoding
        """
        try:
            # Create directory if it doesn't exist
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(file_path, 'w', encoding=encoding) as f:
                await f.write(content)
            
            self.logger.debug(f"Wrote file: {file_path} ({len(content)} characters)")
            
        except Exception as e:
            self.logger.error(f"Error writing file {file_path}: {e}")
            raise
    
    async def copy_file(self, source: Path, destination: Path) -> None:
        """
        Copy a file asynchronously.
        
        Args:
            source: Source file path
            destination: Destination file path
        """
        try:
            # Create destination directory if it doesn't exist
            destination.parent.mkdir(parents=True, exist_ok=True)
            
            # Read source file
            content = await self.read_file(source)
            
            # Write to destination
            await self.write_file(destination, content)
            
            self.logger.debug(f"Copied file: {source} -> {destination}")
            
        except Exception as e:
            self.logger.error(f"Error copying file {source} to {destination}: {e}")
            raise
    
    def get_file_stats(self, directory: Path) -> Dict[str, Any]:
        """
        Get statistics about files in a directory.
        
        Args:
            directory: Directory to analyze
            
        Returns:
            Dictionary with file statistics
        """
        try:
            total_files = 0
            total_size = 0
            language_counts = {}
            extension_counts = {}
            
            for file_path in directory.rglob("*"):
                if file_path.is_file() and self._is_supported_file(file_path):
                    total_files += 1
                    total_size += file_path.stat().st_size
                    
                    extension = file_path.suffix.lower()
                    extension_counts[extension] = extension_counts.get(extension, 0) + 1
                    
                    language = self._detect_language(extension)
                    if language:
                        language_counts[language] = language_counts.get(language, 0) + 1
            
            return {
                "total_files": total_files,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "language_counts": language_counts,
                "extension_counts": extension_counts
            }
            
        except Exception as e:
            self.logger.error(f"Error getting file stats for {directory}: {e}")
            return {}
    
    async def cleanup_temp_files(self, temp_dir: Path) -> None:
        """
        Clean up temporary files.
        
        Args:
            temp_dir: Temporary directory to clean
        """
        try:
            if temp_dir.exists():
                import shutil
                shutil.rmtree(temp_dir)
                self.logger.debug(f"Cleaned up temp directory: {temp_dir}")
        except Exception as e:
            self.logger.error(f"Error cleaning up temp directory {temp_dir}: {e}")
