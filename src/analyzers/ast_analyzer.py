"""
AST-based vulnerability analysis for DefenSys.

This module uses Abstract Syntax Tree analysis to detect complex
security vulnerabilities that pattern matching might miss.
"""

import ast
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass

from ..models.vulnerability import Vulnerability, Severity, VulnerabilityType, CodeLocation, FixSuggestion
from ..utils.logger import setup_logger


@dataclass
class ASTNode:
    """Represents a node in the Abstract Syntax Tree."""
    node_type: str
    line_number: int
    column_number: int
    content: str
    children: List['ASTNode'] = None
    
    def __post_init__(self):
        if self.children is None:
            self.children = []


class ASTAnalyzer:
    """
    AST-based vulnerability analyzer.
    
    This class analyzes code using Abstract Syntax Trees to detect
    complex security vulnerabilities.
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = setup_logger(__name__)
        self.supported_languages = ['python', 'javascript']
    
    async def analyze_file(self, context) -> List[Vulnerability]:
        """
        Analyze a file using AST-based detection.
        
        Args:
            context: AnalysisContext containing file information
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        if context.language not in self.supported_languages:
            self.logger.warning(f"AST analysis not supported for {context.language}")
            return vulnerabilities
        
        try:
            if context.language == 'python':
                vulnerabilities = await self._analyze_python_ast(context)
            elif context.language == 'javascript':
                vulnerabilities = await self._analyze_javascript_ast(context)
        
        except Exception as e:
            self.logger.error(f"Error in AST analysis: {e}")
        
        return vulnerabilities
    
    async def _analyze_python_ast(self, context) -> List[Vulnerability]:
        """Analyze Python code using AST."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(context.content, filename=str(context.file_path))
            
            # Walk through the AST
            for node in ast.walk(tree):
                vulns = await self._analyze_python_node(node, context)
                vulnerabilities.extend(vulns)
        
        except SyntaxError as e:
            self.logger.warning(f"Syntax error in {context.file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing Python AST: {e}")
        
        return vulnerabilities
    
    async def _analyze_python_node(self, node: ast.AST, context) -> List[Vulnerability]:
        """Analyze a Python AST node for vulnerabilities."""
        vulnerabilities = []
        
        # Check for SQL injection in function calls
        if isinstance(node, ast.Call):
            vulns = await self._check_python_sql_injection(node, context)
            vulnerabilities.extend(vulns)
        
        # Check for hardcoded secrets
        if isinstance(node, ast.Assign):
            vulns = await self._check_python_hardcoded_secrets(node, context)
            vulnerabilities.extend(vulns)
        
        # Check for weak cryptography
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            vulns = await self._check_python_crypto_imports(node, context)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _check_python_sql_injection(self, node: ast.Call, context) -> List[Vulnerability]:
        """Check for SQL injection in Python function calls."""
        vulnerabilities = []
        
        # Check if it's a database query function
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if func_name in ['execute', 'query', 'cursor']:
                # Check if arguments contain string formatting
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                        # String formatting with % operator
                        vuln = Vulnerability(
                            vulnerability_type=VulnerabilityType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            title="SQL Injection - String Formatting",
                            description="Database query uses string formatting which can lead to SQL injection",
                            location=CodeLocation(
                                file_path=str(context.file_path),
                                line_number=node.lineno,
                                column_number=node.col_offset
                            ),
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            detection_method="ast_analysis",
                            confidence=0.9,
                            fix_suggestions=[
                                FixSuggestion(
                                    description="Use parameterized queries or prepared statements",
                                    code_example="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                                    confidence=0.9
                                )
                            ]
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _check_python_hardcoded_secrets(self, node: ast.Assign, context) -> List[Vulnerability]:
        """Check for hardcoded secrets in Python assignments."""
        vulnerabilities = []
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(secret in var_name for secret in ['password', 'secret', 'key', 'token']):
                    if isinstance(node.value, ast.Str):
                        vuln = Vulnerability(
                            vulnerability_type=VulnerabilityType.AUTHENTICATION,
                            severity=Severity.CRITICAL,
                            title="Hardcoded Secret",
                            description=f"Hardcoded secret found in variable '{target.id}'",
                            location=CodeLocation(
                                file_path=str(context.file_path),
                                line_number=node.lineno,
                                column_number=node.col_offset
                            ),
                            cwe_id="CWE-798",
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            detection_method="ast_analysis",
                            confidence=0.9,
                            fix_suggestions=[
                                FixSuggestion(
                                    description="Use environment variables for secrets",
                                    code_example="import os\nsecret = os.getenv('SECRET_KEY')",
                                    confidence=0.9
                                )
                            ]
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _check_python_crypto_imports(self, node: Union[ast.Import, ast.ImportFrom], context) -> List[Vulnerability]:
        """Check for weak cryptographic imports."""
        vulnerabilities = []
        
        weak_algorithms = ['md5', 'sha1', 'des', 'rc4']
        
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(weak in alias.name.lower() for weak in weak_algorithms):
                    vuln = Vulnerability(
                        vulnerability_type=VulnerabilityType.CRYPTOGRAPHIC,
                        severity=Severity.MEDIUM,
                        title="Weak Cryptographic Algorithm",
                        description=f"Import of weak cryptographic algorithm: {alias.name}",
                        location=CodeLocation(
                            file_path=str(context.file_path),
                            line_number=node.lineno,
                            column_number=node.col_offset
                        ),
                        cwe_id="CWE-327",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        detection_method="ast_analysis",
                        confidence=0.8,
                        fix_suggestions=[
                            FixSuggestion(
                                description="Use stronger cryptographic algorithms",
                                code_example="import hashlib\nhashlib.sha256()",
                                confidence=0.9
                            )
                        ]
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _analyze_javascript_ast(self, context) -> List[Vulnerability]:
        """Analyze JavaScript code using AST."""
        vulnerabilities = []
        
        try:
            # For JavaScript, we would use a JavaScript parser like esprima
            # This is a simplified version
            vulns = await self._check_javascript_patterns(context)
            vulnerabilities.extend(vulns)
        
        except Exception as e:
            self.logger.error(f"Error parsing JavaScript AST: {e}")
        
        return vulnerabilities
    
    async def _check_javascript_patterns(self, context) -> List[Vulnerability]:
        """Check for JavaScript-specific vulnerabilities using pattern matching."""
        vulnerabilities = []
        
        # This is a simplified approach - in production, use a proper JS parser
        lines = context.content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for eval usage
            if 'eval(' in line:
                vuln = Vulnerability(
                    vulnerability_type=VulnerabilityType.INPUT_VALIDATION,
                    severity=Severity.HIGH,
                    title="Use of eval()",
                    description="Use of eval() function can lead to code injection",
                    location=CodeLocation(
                        file_path=str(context.file_path),
                        line_number=i,
                        column_number=0
                    ),
                    cwe_id="CWE-95",
                    owasp_category="A03:2021 - Injection",
                    detection_method="ast_analysis",
                    confidence=0.8,
                    fix_suggestions=[
                        FixSuggestion(
                            description="Avoid eval() and use safer alternatives",
                            code_example="// Instead of eval(expression)\n// Use JSON.parse() or other safe methods",
                            confidence=0.9
                        )
                    ]
                )
                vulnerabilities.append(vuln)
            
            # Check for innerHTML usage
            if '.innerHTML' in line and '=' in line:
                vuln = Vulnerability(
                    vulnerability_type=VulnerabilityType.XSS,
                    severity=Severity.HIGH,
                    title="innerHTML Assignment",
                    description="Direct assignment to innerHTML can lead to XSS",
                    location=CodeLocation(
                        file_path=str(context.file_path),
                        line_number=i,
                        column_number=0
                    ),
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 - Injection",
                    detection_method="ast_analysis",
                    confidence=0.7,
                    fix_suggestions=[
                        FixSuggestion(
                            description="Use textContent or sanitize HTML content",
                            code_example="element.textContent = userInput; // or sanitize HTML",
                            confidence=0.8
                        )
                    ]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_node_content(self, node: ast.AST, source: str) -> str:
        """Extract the source content for an AST node."""
        try:
            lines = source.split('\n')
            if hasattr(node, 'lineno') and hasattr(node, 'col_offset'):
                line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                return line.strip()
        except Exception:
            pass
        return ""
