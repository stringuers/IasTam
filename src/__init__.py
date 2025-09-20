"""
DefenSys - AI-Powered Cybersecurity Platform

A comprehensive vulnerability scanner that uses AI to detect security issues
in web applications and provide actionable remediation guidance.
"""

__version__ = "1.0.0"
__author__ = "DefenSys Team"
__email__ = "contact@defensys.ai"

from .defensys_analyzer import DefenSysAnalyzer
from .defensys_cli_api import main

__all__ = ["DefenSysAnalyzer", "main"]
