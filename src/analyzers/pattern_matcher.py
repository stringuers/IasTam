"""
Pattern-based vulnerability detection for DefenSys.

This module uses regex patterns and rule-based detection to identify
common security vulnerabilities in code.
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Pattern
from dataclasses import dataclass

from ..models.vulnerability import Vulnerability, Severity, VulnerabilityType, CodeLocation, FixSuggestion
from ..utils.logger import setup_logger


@dataclass
class DetectionPattern:
    """Represents a pattern for detecting vulnerabilities."""
    name: str
    pattern: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    description: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    fix_suggestion: Optional[str] = None
    confidence: float = 0.8


class PatternMatcher:
    """
    Pattern-based vulnerability detector.
    
    This class uses regex patterns and rule-based detection to identify
    common security vulnerabilities in source code.
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = setup_logger(__name__)
        self.patterns = self._load_detection_patterns()
    
    def _load_detection_patterns(self) -> List[DetectionPattern]:
        """Load vulnerability detection patterns."""
        patterns = []
        
        # SQL Injection patterns
        patterns.extend([
            DetectionPattern(
                name="SQL Injection - String Concatenation",
                pattern=r'["\'].*?\+.*?["\']|["\'].*?\$\{.*?\}.*?["\']',
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                description="SQL query uses string concatenation with user input",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                fix_suggestion="Use parameterized queries or prepared statements",
                confidence=0.9
            ),
            DetectionPattern(
                name="SQL Injection - Template Literals",
                pattern=r'`.*?\$\{.*?\}.*?`',
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                description="SQL query uses template literals with user input",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                fix_suggestion="Use parameterized queries or prepared statements",
                confidence=0.8
            )
        ])
        
        # XSS patterns
        patterns.extend([
            DetectionPattern(
                name="XSS - innerHTML Assignment",
                pattern=r'\.innerHTML\s*=\s*[^;]+',
                vulnerability_type=VulnerabilityType.XSS,
                severity=Severity.HIGH,
                description="Direct assignment to innerHTML with potentially unsafe content",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                fix_suggestion="Use textContent or sanitize HTML content",
                confidence=0.7
            ),
            DetectionPattern(
                name="XSS - document.write",
                pattern=r'document\.write\s*\([^)]+\)',
                vulnerability_type=VulnerabilityType.XSS,
                severity=Severity.HIGH,
                description="Use of document.write with potentially unsafe content",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                fix_suggestion="Avoid document.write, use safer DOM manipulation",
                confidence=0.8
            )
        ])
        
        # Authentication patterns
        patterns.extend([
            DetectionPattern(
                name="Hardcoded Secret",
                pattern=r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']',
                vulnerability_type=VulnerabilityType.AUTHENTICATION,
                severity=Severity.CRITICAL,
                description="Hardcoded secret or password found",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                fix_suggestion="Use environment variables or secure configuration",
                confidence=0.9
            ),
            DetectionPattern(
                name="Weak Password Policy",
                pattern=r'password.*length.*[0-5]|password.*min.*[0-5]',
                vulnerability_type=VulnerabilityType.AUTHENTICATION,
                severity=Severity.MEDIUM,
                description="Weak password length requirement",
                cwe_id="CWE-521",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                fix_suggestion="Implement stronger password requirements (minimum 8 characters)",
                confidence=0.6
            )
        ])
        
        # File Upload patterns
        patterns.extend([
            DetectionPattern(
                name="Missing File Type Validation",
                pattern=r'upload.*file|file.*upload',
                vulnerability_type=VulnerabilityType.FILE_UPLOAD,
                severity=Severity.HIGH,
                description="File upload without type validation",
                cwe_id="CWE-434",
                owasp_category="A01:2021 - Broken Access Control",
                fix_suggestion="Implement file type and content validation",
                confidence=0.5
            )
        ])
        
        # Cryptographic patterns
        patterns.extend([
            DetectionPattern(
                name="Weak Encryption Algorithm",
                pattern=r'(MD5|SHA1|DES|RC4)',
                vulnerability_type=VulnerabilityType.CRYPTOGRAPHIC,
                severity=Severity.MEDIUM,
                description="Use of weak cryptographic algorithm",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                fix_suggestion="Use stronger algorithms like SHA-256 or AES-256",
                confidence=0.8
            )
        ])
        
        # Input Validation patterns
        patterns.extend([
            DetectionPattern(
                name="Missing Input Validation",
                pattern=r'req\.(body|params|query)\.\w+',
                vulnerability_type=VulnerabilityType.INPUT_VALIDATION,
                severity=Severity.MEDIUM,
                description="Direct use of request data without validation",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                fix_suggestion="Implement input validation and sanitization",
                confidence=0.4
            )
        ])
        
        return patterns
    
    async def analyze_endpoint(self, endpoint: Dict[str, Any], context) -> List[Vulnerability]:
        """Analyze an API endpoint for vulnerabilities using patterns."""
        vulnerabilities = []
        
        try:
            # Read the file content around the endpoint
            file_path = Path(endpoint['file_path'])
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Get context around the endpoint line
            lines = content.split('\n')
            start_line = max(0, endpoint['line_number'] - 20)
            end_line = min(len(lines), endpoint['line_number'] + 20)
            context_content = '\n'.join(lines[start_line:end_line])
            
            # Apply all patterns
            for pattern in self.patterns:
                matches = re.finditer(pattern.pattern, context_content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Calculate line number relative to context
                    relative_line = context_content[:match.start()].count('\n')
                    absolute_line = start_line + relative_line
                    
                    vuln = Vulnerability(
                        vulnerability_type=pattern.vulnerability_type,
                        severity=pattern.severity,
                        title=pattern.name,
                        description=pattern.description,
                        location=CodeLocation(
                            file_path=endpoint['file_path'],
                            line_number=absolute_line,
                            column_number=match.start() - context_content[:match.start()].rfind('\n') - 1
                        ),
                        cwe_id=pattern.cwe_id,
                        owasp_category=pattern.owasp_category,
                        detection_method="pattern_matching",
                        confidence=pattern.confidence,
                        code_snippet=match.group(0),
                        fix_suggestions=[
                            FixSuggestion(
                                description=pattern.fix_suggestion or "Review and fix the identified issue",
                                confidence=0.8
                            )
                        ] if pattern.fix_suggestion else []
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.error(f"Error analyzing endpoint {endpoint['file_path']}: {e}")
        
        return vulnerabilities
    
    async def analyze_file(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Analyze a file for vulnerabilities using patterns."""
        vulnerabilities = []
        
        try:
            for pattern in self.patterns:
                matches = re.finditer(pattern.pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    column_number = match.start() - content[:match.start()].rfind('\n') - 1
                    
                    vuln = Vulnerability(
                        vulnerability_type=pattern.vulnerability_type,
                        severity=pattern.severity,
                        title=pattern.name,
                        description=pattern.description,
                        location=CodeLocation(
                            file_path=str(file_path),
                            line_number=line_number,
                            column_number=column_number
                        ),
                        cwe_id=pattern.cwe_id,
                        owasp_category=pattern.owasp_category,
                        detection_method="pattern_matching",
                        confidence=pattern.confidence,
                        code_snippet=match.group(0),
                        fix_suggestions=[
                            FixSuggestion(
                                description=pattern.fix_suggestion or "Review and fix the identified issue",
                                confidence=0.8
                            )
                        ] if pattern.fix_suggestion else []
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
        
        return vulnerabilities
    
    def add_custom_pattern(self, pattern: DetectionPattern) -> None:
        """Add a custom detection pattern."""
        self.patterns.append(pattern)
        self.logger.info(f"Added custom pattern: {pattern.name}")
    
    def load_patterns_from_file(self, file_path: Path) -> None:
        """Load patterns from a JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                pattern_data = json.load(f)
            
            for pattern_dict in pattern_data:
                pattern = DetectionPattern(
                    name=pattern_dict['name'],
                    pattern=pattern_dict['pattern'],
                    vulnerability_type=VulnerabilityType(pattern_dict['vulnerability_type']),
                    severity=Severity(pattern_dict['severity']),
                    description=pattern_dict['description'],
                    cwe_id=pattern_dict.get('cwe_id'),
                    owasp_category=pattern_dict.get('owasp_category'),
                    fix_suggestion=pattern_dict.get('fix_suggestion'),
                    confidence=pattern_dict.get('confidence', 0.8)
                )
                self.patterns.append(pattern)
            
            self.logger.info(f"Loaded {len(pattern_data)} patterns from {file_path}")
        
        except Exception as e:
            self.logger.error(f"Error loading patterns from {file_path}: {e}")
    
    def get_patterns_by_type(self, vulnerability_type: VulnerabilityType) -> List[DetectionPattern]:
        """Get all patterns for a specific vulnerability type."""
        return [p for p in self.patterns if p.vulnerability_type == vulnerability_type]
    
    def get_patterns_by_severity(self, severity: Severity) -> List[DetectionPattern]:
        """Get all patterns for a specific severity level."""
        return [p for p in self.patterns if p.severity == severity]
