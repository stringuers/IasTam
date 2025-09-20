"""
Configuration management for DefenSys.

This module provides configuration loading and management for the
DefenSys application, including environment variables and config files.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from dotenv import load_dotenv


@dataclass
class ScanConfig:
    """Configuration for vulnerability scans."""
    max_file_size_mb: int = 50
    timeout_seconds: int = 300
    parallel_scans: int = 4
    deep_analysis: bool = False
    recursive: bool = True
    file_extensions: List[str] = field(default_factory=lambda: ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php'])
    exclude_patterns: List[str] = field(default_factory=lambda: ['node_modules', '.git', 'dist', 'build', 'coverage'])


@dataclass
class MLConfig:
    """Configuration for machine learning models."""
    model_path: str = "./data/models/"
    training_data_path: str = "./data/training_data/"
    confidence_threshold: float = 0.7
    use_gpu: bool = False
    batch_size: int = 32


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_dir: str = "./scan_results/"
    html_template_path: str = "./src/reports/templates/"
    include_poc: bool = True
    include_fix_suggestions: bool = True
    generate_attack_chains: bool = True
    export_formats: List[str] = field(default_factory=lambda: ["html", "json", "console"])


@dataclass
class APIConfig:
    """Configuration for API server."""
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    rate_limit: int = 100  # requests per minute


@dataclass
class DatabaseConfig:
    """Configuration for database connections."""
    url: str = "sqlite:///defensys.db"
    redis_url: str = "redis://localhost:6379"
    pool_size: int = 10
    max_overflow: int = 20


@dataclass
class SecurityConfig:
    """Security-related configuration."""
    secret_key: str = "your-secret-key-here"
    jwt_secret: str = "your-jwt-secret-here"
    encryption_key: str = "your-encryption-key-here"
    session_timeout: int = 3600  # seconds


@dataclass
class LoggingConfig:
    """Configuration for logging."""
    level: str = "INFO"
    log_dir: str = "./logs/"
    colored: bool = True
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5


class Config:
    """
    Main configuration class for DefenSys.
    
    This class manages all configuration settings for the application,
    including loading from environment variables and config files.
    """
    
    def __init__(self, config_file: Optional[Path] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to configuration file
        """
        # Load environment variables
        load_dotenv()
        
        # Initialize configuration sections
        self.scan = ScanConfig()
        self.ml = MLConfig()
        self.report = ReportConfig()
        self.api = APIConfig()
        self.database = DatabaseConfig()
        self.security = SecurityConfig()
        self.logging = LoggingConfig()
        
        # Load from config file if provided
        if config_file and config_file.exists():
            self.load_from_file(config_file)
        
        # Override with environment variables
        self._load_from_env()
    
    def load_from_file(self, config_file: Path) -> None:
        """
        Load configuration from a JSON file.
        
        Args:
            config_file: Path to configuration file
        """
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Update scan config
            if 'scan' in config_data:
                scan_data = config_data['scan']
                self.scan.max_file_size_mb = scan_data.get('max_file_size_mb', self.scan.max_file_size_mb)
                self.scan.timeout_seconds = scan_data.get('timeout_seconds', self.scan.timeout_seconds)
                self.scan.parallel_scans = scan_data.get('parallel_scans', self.scan.parallel_scans)
                self.scan.deep_analysis = scan_data.get('deep_analysis', self.scan.deep_analysis)
                self.scan.recursive = scan_data.get('recursive', self.scan.recursive)
                self.scan.file_extensions = scan_data.get('file_extensions', self.scan.file_extensions)
                self.scan.exclude_patterns = scan_data.get('exclude_patterns', self.scan.exclude_patterns)
            
            # Update ML config
            if 'ml' in config_data:
                ml_data = config_data['ml']
                self.ml.model_path = ml_data.get('model_path', self.ml.model_path)
                self.ml.training_data_path = ml_data.get('training_data_path', self.ml.training_data_path)
                self.ml.confidence_threshold = ml_data.get('confidence_threshold', self.ml.confidence_threshold)
                self.ml.use_gpu = ml_data.get('use_gpu', self.ml.use_gpu)
                self.ml.batch_size = ml_data.get('batch_size', self.ml.batch_size)
            
            # Update report config
            if 'report' in config_data:
                report_data = config_data['report']
                self.report.output_dir = report_data.get('output_dir', self.report.output_dir)
                self.report.html_template_path = report_data.get('html_template_path', self.report.html_template_path)
                self.report.include_poc = report_data.get('include_poc', self.report.include_poc)
                self.report.include_fix_suggestions = report_data.get('include_fix_suggestions', self.report.include_fix_suggestions)
                self.report.generate_attack_chains = report_data.get('generate_attack_chains', self.report.generate_attack_chains)
                self.report.export_formats = report_data.get('export_formats', self.report.export_formats)
            
            # Update API config
            if 'api' in config_data:
                api_data = config_data['api']
                self.api.host = api_data.get('host', self.api.host)
                self.api.port = api_data.get('port', self.api.port)
                self.api.workers = api_data.get('workers', self.api.workers)
                self.api.cors_origins = api_data.get('cors_origins', self.api.cors_origins)
                self.api.rate_limit = api_data.get('rate_limit', self.api.rate_limit)
            
            # Update database config
            if 'database' in config_data:
                db_data = config_data['database']
                self.database.url = db_data.get('url', self.database.url)
                self.database.redis_url = db_data.get('redis_url', self.database.redis_url)
                self.database.pool_size = db_data.get('pool_size', self.database.pool_size)
                self.database.max_overflow = db_data.get('max_overflow', self.database.max_overflow)
            
            # Update security config
            if 'security' in config_data:
                security_data = config_data['security']
                self.security.secret_key = security_data.get('secret_key', self.security.secret_key)
                self.security.jwt_secret = security_data.get('jwt_secret', self.security.jwt_secret)
                self.security.encryption_key = security_data.get('encryption_key', self.security.encryption_key)
                self.security.session_timeout = security_data.get('session_timeout', self.security.session_timeout)
            
            # Update logging config
            if 'logging' in config_data:
                logging_data = config_data['logging']
                self.logging.level = logging_data.get('level', self.logging.level)
                self.logging.log_dir = logging_data.get('log_dir', self.logging.log_dir)
                self.logging.colored = logging_data.get('colored', self.logging.colored)
                self.logging.max_file_size = logging_data.get('max_file_size', self.logging.max_file_size)
                self.logging.backup_count = logging_data.get('backup_count', self.logging.backup_count)
        
        except Exception as e:
            print(f"Error loading config file {config_file}: {e}")
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Scan configuration
        self.scan.max_file_size_mb = int(os.getenv('DEFENSYS_MAX_FILE_SIZE_MB', self.scan.max_file_size_mb))
        self.scan.timeout_seconds = int(os.getenv('DEFENSYS_SCAN_TIMEOUT_SECONDS', self.scan.timeout_seconds))
        self.scan.parallel_scans = int(os.getenv('DEFENSYS_PARALLEL_SCANS', self.scan.parallel_scans))
        self.scan.deep_analysis = os.getenv('DEFENSYS_DEEP_ANALYSIS', 'false').lower() == 'true'
        
        # ML configuration
        self.ml.model_path = os.getenv('DEFENSYS_MODEL_PATH', self.ml.model_path)
        self.ml.training_data_path = os.getenv('DEFENSYS_TRAINING_DATA_PATH', self.ml.training_data_path)
        self.ml.confidence_threshold = float(os.getenv('DEFENSYS_CONFIDENCE_THRESHOLD', self.ml.confidence_threshold))
        self.ml.use_gpu = os.getenv('DEFENSYS_USE_GPU', 'false').lower() == 'true'
        
        # Report configuration
        self.report.output_dir = os.getenv('DEFENSYS_REPORT_OUTPUT_DIR', self.report.output_dir)
        self.report.html_template_path = os.getenv('DEFENSYS_HTML_TEMPLATE_PATH', self.report.html_template_path)
        
        # API configuration
        self.api.host = os.getenv('DEFENSYS_API_HOST', self.api.host)
        self.api.port = int(os.getenv('DEFENSYS_API_PORT', self.api.port))
        self.api.workers = int(os.getenv('DEFENSYS_API_WORKERS', self.api.workers))
        
        # Database configuration
        self.database.url = os.getenv('DEFENSYS_DATABASE_URL', self.database.url)
        self.database.redis_url = os.getenv('DEFENSYS_REDIS_URL', self.database.redis_url)
        
        # Security configuration
        self.security.secret_key = os.getenv('DEFENSYS_SECRET_KEY', self.security.secret_key)
        self.security.jwt_secret = os.getenv('DEFENSYS_JWT_SECRET', self.security.jwt_secret)
        self.security.encryption_key = os.getenv('DEFENSYS_ENCRYPTION_KEY', self.security.encryption_key)
        
        # Logging configuration
        self.logging.level = os.getenv('DEFENSYS_LOG_LEVEL', self.logging.level)
        self.logging.log_dir = os.getenv('DEFENSYS_LOG_DIR', self.logging.log_dir)
        self.logging.colored = os.getenv('DEFENSYS_COLORED_LOGS', 'true').lower() == 'true'
    
    def save_to_file(self, config_file: Path) -> None:
        """
        Save current configuration to a JSON file.
        
        Args:
            config_file: Path to save configuration file
        """
        config_data = {
            'scan': {
                'max_file_size_mb': self.scan.max_file_size_mb,
                'timeout_seconds': self.scan.timeout_seconds,
                'parallel_scans': self.scan.parallel_scans,
                'deep_analysis': self.scan.deep_analysis,
                'recursive': self.scan.recursive,
                'file_extensions': self.scan.file_extensions,
                'exclude_patterns': self.scan.exclude_patterns
            },
            'ml': {
                'model_path': self.ml.model_path,
                'training_data_path': self.ml.training_data_path,
                'confidence_threshold': self.ml.confidence_threshold,
                'use_gpu': self.ml.use_gpu,
                'batch_size': self.ml.batch_size
            },
            'report': {
                'output_dir': self.report.output_dir,
                'html_template_path': self.report.html_template_path,
                'include_poc': self.report.include_poc,
                'include_fix_suggestions': self.report.include_fix_suggestions,
                'generate_attack_chains': self.report.generate_attack_chains,
                'export_formats': self.report.export_formats
            },
            'api': {
                'host': self.api.host,
                'port': self.api.port,
                'workers': self.api.workers,
                'cors_origins': self.api.cors_origins,
                'rate_limit': self.api.rate_limit
            },
            'database': {
                'url': self.database.url,
                'redis_url': self.database.redis_url,
                'pool_size': self.database.pool_size,
                'max_overflow': self.database.max_overflow
            },
            'security': {
                'secret_key': self.security.secret_key,
                'jwt_secret': self.security.jwt_secret,
                'encryption_key': self.security.encryption_key,
                'session_timeout': self.security.session_timeout
            },
            'logging': {
                'level': self.logging.level,
                'log_dir': self.logging.log_dir,
                'colored': self.logging.colored,
                'max_file_size': self.logging.max_file_size,
                'backup_count': self.logging.backup_count
            }
        }
        
        try:
            # Create directory if it doesn't exist
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)
        
        except Exception as e:
            print(f"Error saving config file {config_file}: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'scan': self.scan.__dict__,
            'ml': self.ml.__dict__,
            'report': self.report.__dict__,
            'api': self.api.__dict__,
            'database': self.database.__dict__,
            'security': self.security.__dict__,
            'logging': self.logging.__dict__
        }
    
    def validate(self) -> List[str]:
        """
        Validate configuration and return any errors.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Validate scan config
        if self.scan.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")
        
        if self.scan.timeout_seconds <= 0:
            errors.append("timeout_seconds must be positive")
        
        if self.scan.parallel_scans <= 0:
            errors.append("parallel_scans must be positive")
        
        # Validate ML config
        if not 0 <= self.ml.confidence_threshold <= 1:
            errors.append("confidence_threshold must be between 0 and 1")
        
        if self.ml.batch_size <= 0:
            errors.append("batch_size must be positive")
        
        # Validate API config
        if not 1 <= self.api.port <= 65535:
            errors.append("API port must be between 1 and 65535")
        
        if self.api.workers <= 0:
            errors.append("API workers must be positive")
        
        # Validate security config
        if len(self.security.secret_key) < 32:
            errors.append("secret_key should be at least 32 characters")
        
        if len(self.security.jwt_secret) < 32:
            errors.append("jwt_secret should be at least 32 characters")
        
        return errors
