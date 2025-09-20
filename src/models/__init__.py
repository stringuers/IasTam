"""
Data models for DefenSys.

This module contains all the data models used throughout the application,
including vulnerability definitions and ML model interfaces.
"""

from .vulnerability import Vulnerability, Severity, VulnerabilityType
from .ml_models import MLModel, VulnerabilityClassifier

__all__ = [
    "Vulnerability",
    "Severity", 
    "VulnerabilityType",
    "MLModel",
    "VulnerabilityClassifier"
]
