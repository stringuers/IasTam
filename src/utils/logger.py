"""
Logging configuration for DefenSys.

This module provides centralized logging configuration and utilities
for the DefenSys application.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


def setup_logger(name: str = "defensys", level: str = "INFO", 
                log_file: Optional[Path] = None) -> logging.Logger:
    """
    Set up a logger with consistent configuration.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Set logging level
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        # Create log directory if it doesn't exist
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent duplicate logs
    logger.propagate = False
    
    return logger


def get_logger(name: str = "defensys") -> logging.Logger:
    """
    Get an existing logger or create a new one.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output."""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_colored_logger(name: str = "defensys", level: str = "INFO") -> logging.Logger:
    """
    Set up a logger with colored console output.
    
    Args:
        name: Logger name
        level: Logging level
        
    Returns:
        Configured logger with colored output
    """
    logger = logging.getLogger(name)
    logger.handlers.clear()
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Colored console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(console_handler)
    
    logger.propagate = False
    return logger


class ScanLogger:
    """Specialized logger for scan operations."""
    
    def __init__(self, scan_id: str, log_file: Optional[Path] = None):
        self.scan_id = scan_id
        self.logger = setup_logger(f"defensys.scan.{scan_id}", log_file=log_file)
        self.start_time = datetime.now()
    
    def log_scan_start(self, target_path: str):
        """Log scan start."""
        self.logger.info(f"Starting DefenSys scan of {target_path}")
        self.logger.info(f"Scan ID: {self.scan_id}")
    
    def log_scan_phase(self, phase: str, details: str = ""):
        """Log scan phase."""
        self.logger.info(f"Phase: {phase} - {details}")
    
    def log_vulnerability_found(self, vuln_type: str, file_path: str, line: int):
        """Log vulnerability found."""
        self.logger.warning(f"Vulnerability found: {vuln_type} in {file_path}:{line}")
    
    def log_attack_chain_found(self, chain_description: str, risk_score: float):
        """Log attack chain found."""
        self.logger.warning(f"Attack chain detected: {chain_description} (Risk: {risk_score:.1f})")
    
    def log_scan_complete(self, total_vulns: int, duration: float):
        """Log scan completion."""
        self.logger.info(f"Scan completed: {total_vulns} vulnerabilities found in {duration:.2f}s")
    
    def log_error(self, error: str, exception: Optional[Exception] = None):
        """Log error."""
        if exception:
            self.logger.error(f"Error: {error} - {str(exception)}", exc_info=True)
        else:
            self.logger.error(f"Error: {error}")


class PerformanceLogger:
    """Logger for performance monitoring."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.timings = {}
    
    def start_timer(self, operation: str):
        """Start timing an operation."""
        self.timings[operation] = datetime.now()
        self.logger.debug(f"Starting {operation}")
    
    def end_timer(self, operation: str):
        """End timing an operation."""
        if operation in self.timings:
            duration = (datetime.now() - self.timings[operation]).total_seconds()
            self.logger.info(f"{operation} completed in {duration:.2f}s")
            del self.timings[operation]
    
    def log_memory_usage(self):
        """Log current memory usage."""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            self.logger.debug(f"Memory usage: {memory_mb:.2f} MB")
        except ImportError:
            pass  # psutil not available


def configure_logging(level: str = "INFO", log_dir: Optional[Path] = None, 
                     colored: bool = True) -> None:
    """
    Configure global logging for DefenSys.
    
    Args:
        level: Logging level
        log_dir: Directory for log files
        colored: Whether to use colored output
    """
    # Set up main logger
    if colored:
        main_logger = setup_colored_logger("defensys", level)
    else:
        main_logger = setup_logger("defensys", level)
    
    # Set up file logging if directory provided
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"defensys_{datetime.now().strftime('%Y%m%d')}.log"
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        main_logger.addHandler(file_handler)
    
    # Configure third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("transformers").setLevel(logging.WARNING)
    
    main_logger.info("DefenSys logging configured")
