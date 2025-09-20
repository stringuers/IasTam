"""
DefenSys Enhanced Core Vulnerability Analyzer
AI-powered static code analysis for JavaScript/TypeScript security vulnerabilities
"""

import ast
import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import esprima
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    INSECURE_DIRECT_OBJECT_REF = "Insecure Direct Object Reference"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    BROKEN_AUTHENTICATION = "Broken Authentication"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    INJECTION = "Injection"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    KNOWN_VULNERABILITIES = "Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class Vulnerability:
    id: str
    type: VulnerabilityType
    severity: Severity
    line: int
    column: int
    description: str
    code_snippet: str
    fix_suggestion: str
    proof_of_concept: str
    confidence: float
    attack_vector: str
    cwe_id: str = ""
    owasp_category: str = ""

class VulnerabilityDetector:
    def __init__(self):
        self.sql_injection_patterns = [
            r'query\s*\(\s*["\'].*?\+.*?["\']',  # String concatenation in queries
            r'execute\s*\(\s*["\'].*?\+.*?["\']',
            r'mysql\.query\s*\(\s*.*?\+.*?\)',
            r'db\.query\s*\(\s*.*?\+.*?\)',
            r'SELECT.*?\+.*?FROM',
            r'INSERT.*?\+.*?VALUES',
            r'UPDATE.*?\+.*?SET',
            r'DELETE.*?\+.*?WHERE'
        ]
        
        self.xss_patterns = [
            r'innerHTML\s*=\s*.*?\+',
            r'document\.write\s*\(\s*.*?\+',
            r'eval\s*\(\s*.*?\+',
            r'setTimeout\s*\(\s*["\'].*?\+',
            r'setInterval\s*\(\s*["\'].*?\+',
            r'dangerouslySetInnerHTML.*?__html\s*:',
            r'v-html\s*=\s*["\'].*?\+',
            r'\$\{.*?\}.*?innerHTML'
        ]
        
        self.auth_patterns = [
            r'password\s*===?\s*["\'].*?["\']',  # Hardcoded passwords
            r'token\s*===?\s*["\'].*?["\']',
            r'secret\s*===?\s*["\'].*?["\']',
            r'jwt\.sign\s*\(\s*.*?,\s*["\'].*?["\']',  # Weak JWT secrets
            r'session\s*\[\s*["\'].*?["\']\s*\]\s*=',  # Session manipulation
        ]
        
        self.config_patterns = [
            r'cors\s*:\s*true',  # Open CORS
            r'credentials\s*:\s*true',
            r'strictSSL\s*:\s*false',
            r'rejectUnauthorized\s*:\s*false',
            r'process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']0["\']'
        ]

    def analyze_code(self, code: str, filename: str) -> List[Vulnerability]:
        """Main analysis function that detects vulnerabilities in JavaScript/TypeScript code"""
        vulnerabilities = []
        lines = code.split('\n')
        
        try:
            # Parse JavaScript/TypeScript AST
            ast_tree = esprima.parseScript(code, {'loc': True, 'range': True})
        except Exception as e:
            logger.warning(f"Could not parse {filename} - {e}")
            ast_tree = None
        
        # Rule-based detection
        vulnerabilities.extend(self._detect_sql_injection(lines, filename))
        vulnerabilities.extend(self._detect_xss(lines, filename))
        vulnerabilities.extend(self._detect_auth_issues(lines, filename))
        vulnerabilities.extend(self._detect_config_issues(lines, filename))
        
        # AST-based analysis if parsing succeeded
        if ast_tree:
            vulnerabilities.extend(self._analyze_ast(ast_tree, lines, filename))
        
        return vulnerabilities

    def _detect_sql_injection(self, lines: List[str], filename: str) -> List[Vulnerability]:
        """Detect SQL injection vulnerabilities"""
        vulnerabilities = []
        
        for i, line in enumerate(lines):
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = Vulnerability(
                        id=self._generate_id(filename, i, "SQL_INJ"),
                        type=VulnerabilityType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        line=i + 1,
                        column=0,
                        description="Potential SQL injection vulnerability detected. User input appears to be directly concatenated into SQL query.",
                        code_snippet=line.strip(),
                        fix_suggestion="Use parameterized queries or prepared statements. Example: db.query('SELECT * FROM users WHERE id = ?', [userId])",
                        proof_of_concept="An attacker could inject malicious SQL: '; DROP TABLE users; --",
                        confidence=0.85,
                        attack_vector="Inject malicious SQL through user input parameters",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_xss(self, lines: List[str], filename: str) -> List[Vulnerability]:
        """Detect Cross-Site Scripting vulnerabilities"""
        vulnerabilities = []
        
        for i, line in enumerate(lines):
            for pattern in self.xss_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = Vulnerability(
                        id=self._generate_id(filename, i, "XSS"),
                        type=VulnerabilityType.XSS,
                        severity=Severity.HIGH,
                        line=i + 1,
                        column=0,
                        description="Potential XSS vulnerability. User input may be rendered without proper sanitization.",
                        code_snippet=line.strip(),
                        fix_suggestion="Sanitize user input before rendering. Use textContent instead of innerHTML, or properly escape HTML entities.",
                        proof_of_concept="An attacker could inject: <script>alert('XSS')</script> or <img src=x onerror=alert('XSS')>",
                        confidence=0.80,
                        attack_vector="Inject malicious JavaScript through user-controlled data",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_auth_issues(self, lines: List[str], filename: str) -> List[Vulnerability]:
        """Detect authentication and authorization issues"""
        vulnerabilities = []
        
        for i, line in enumerate(lines):
            for pattern in self.auth_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = Severity.CRITICAL if 'password' in line.lower() or 'secret' in line.lower() else Severity.HIGH
                    vuln = Vulnerability(
                        id=self._generate_id(filename, i, "AUTH"),
                        type=VulnerabilityType.BROKEN_AUTHENTICATION,
                        severity=severity,
                        line=i + 1,
                        column=0,
                        description="Authentication vulnerability detected. Hardcoded credentials or weak authentication mechanism.",
                        code_snippet=line.strip(),
                        fix_suggestion="Use environment variables or secure credential storage. Implement proper password hashing with bcrypt.",
                        proof_of_concept="Hardcoded credentials can be extracted from source code or memory dumps",
                        confidence=0.90,
                        attack_vector="Extract credentials from source code or exploit weak authentication",
                        cwe_id="CWE-287",
                        owasp_category="A07:2021 - Identification and Authentication Failures"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_config_issues(self, lines: List[str], filename: str) -> List[Vulnerability]:
        """Detect security misconfigurations"""
        vulnerabilities = []
        
        for i, line in enumerate(lines):
            for pattern in self.config_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = Vulnerability(
                        id=self._generate_id(filename, i, "CONFIG"),
                        type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                        severity=Severity.MEDIUM,
                        line=i + 1,
                        column=0,
                        description="Security misconfiguration detected. Insecure settings that could expose the application.",
                        code_snippet=line.strip(),
                        fix_suggestion="Review security settings. Use restrictive CORS policies, enable SSL verification, and follow security best practices.",
                        proof_of_concept="Misconfiguration could allow unauthorized access or man-in-the-middle attacks",
                        confidence=0.75,
                        attack_vector="Exploit insecure configuration settings",
                        cwe_id="CWE-16",
                        owasp_category="A05:2021 - Security Misconfiguration"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _analyze_ast(self, ast_tree, lines: List[str], filename: str) -> List[Vulnerability]:
        """Advanced AST-based analysis for complex vulnerabilities"""
        vulnerabilities = []
        
        def traverse_node(node, parent=None):
            if hasattr(node, 'type'):
                if node.type == 'CallExpression':
                    if hasattr(node, 'callee') and hasattr(node.callee, 'name'):
                        if node.callee.name == 'eval':
                            line_num = getattr(node, 'loc', {}).get('start', {}).get('line', 1)
                            vuln = Vulnerability(
                                id=self._generate_id(filename, line_num, "EVAL"),
                                type=VulnerabilityType.XSS,
                                severity=Severity.HIGH,
                                line=line_num,
                                column=getattr(node, 'loc', {}).get('start', {}).get('column', 0),
                                description="Use of eval() function detected. This can lead to code injection vulnerabilities.",
                                code_snippet=lines[line_num-1].strip() if line_num <= len(lines) else "",
                                fix_suggestion="Avoid using eval(). Use JSON.parse() for JSON data or implement safer alternatives.",
                                proof_of_concept="An attacker could inject: eval('malicious_code_here')",
                                confidence=0.95,
                                attack_vector="Inject arbitrary JavaScript code through eval() function",
                                cwe_id="CWE-95",
                                owasp_category="A03:2021 - Injection"
                            )
                            vulnerabilities.append(vuln)
            
            # Traverse child nodes
            for key, value in vars(node).items():
                if isinstance(value, list):
                    for item in value:
                        if hasattr(item, 'type'):
                            traverse_node(item, node)
                elif hasattr(value, 'type'):
                    traverse_node(value, node)
        
        traverse_node(ast_tree)
        return vulnerabilities

    def _generate_id(self, filename: str, line: int, vuln_type: str) -> str:
        """Generate unique vulnerability ID"""
        data = f"{filename}:{line}:{vuln_type}"
        return hashlib.md5(data.encode()).hexdigest()[:10]

class AttackChainAnalyzer:
    """Analyzes how multiple vulnerabilities could be chained together"""
    
    def analyze_chains(self, vulnerabilities: List[Vulnerability]) -> List[Dict]:
        """Find potential attack chains linking multiple vulnerabilities"""
        chains = []
        
        # Group vulnerabilities by type for chain analysis
        vuln_groups = {}
        for vuln in vulnerabilities:
            if vuln.type not in vuln_groups:
                vuln_groups[vuln.type] = []
            vuln_groups[vuln.type].append(vuln)
        
        # Look for common attack patterns
        if (VulnerabilityType.XSS in vuln_groups and 
            VulnerabilityType.BROKEN_AUTHENTICATION in vuln_groups):
            chains.append({
                'chain_id': 'XSS_TO_AUTH_BYPASS',
                'severity': Severity.CRITICAL,
                'description': 'XSS vulnerability could be used to steal authentication tokens, leading to account takeover',
                'steps': [
                    'Exploit XSS to inject malicious JavaScript',
                    'Steal authentication cookies or tokens',
                    'Use stolen credentials to bypass authentication',
                    'Gain unauthorized access to user accounts'
                ],
                'vulnerabilities': vuln_groups[VulnerabilityType.XSS] + vuln_groups[VulnerabilityType.BROKEN_AUTHENTICATION],
                'impact': 'Complete account takeover and data breach'
            })
        
        return chains

class DefenSysAnalyzer:
    """Main DefenSys analysis engine"""
    
    def __init__(self):
        self.detector = VulnerabilityDetector()
        self.chain_analyzer = AttackChainAnalyzer()
    
    def scan_file(self, filepath: str) -> Dict:
        """Scan a single file for vulnerabilities"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
            
            vulnerabilities = self.detector.analyze_code(code, filepath)
            attack_chains = self.chain_analyzer.analyze_chains(vulnerabilities)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(vulnerabilities, attack_chains)
            
            return {
                'file': filepath,
                'scan_time': '2024-01-01T00:00:00Z',
                'risk_score': risk_score,
                'vulnerabilities': [asdict(v) for v in vulnerabilities],
                'attack_chains': attack_chains,
                'summary': {
                    'total_vulnerabilities': len(vulnerabilities),
                    'critical': len([v for v in vulnerabilities if v.severity == Severity.CRITICAL]),
                    'high': len([v for v in vulnerabilities if v.severity == Severity.HIGH]),
                    'medium': len([v for v in vulnerabilities if v.severity == Severity.MEDIUM]),
                    'low': len([v for v in vulnerabilities if v.severity == Severity.LOW]),
                    'attack_chains': len(attack_chains)
                }
            }
        
        except Exception as e:
            return {
                'file': filepath,
                'error': str(e),
                'vulnerabilities': [],
                'attack_chains': [],
                'risk_score': 0
            }
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability], attack_chains: List[Dict]) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Base scores for vulnerability severity
        severity_scores = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3
        }
        
        for vuln in vulnerabilities:
            score += severity_scores.get(vuln.severity, 0)
        
        # Bonus for attack chains (multiplicative risk)
        if attack_chains:
            score += len(attack_chains) * 20
        
        return min(score, 100)  # Cap at 100
