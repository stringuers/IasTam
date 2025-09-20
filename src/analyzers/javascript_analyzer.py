"""
JavaScript-specific vulnerability analyzer for DefenSys.

This module provides specialized analysis for JavaScript/TypeScript code,
including framework-specific vulnerabilities and modern JS security issues.
"""

import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..models.vulnerability import Vulnerability, Severity, VulnerabilityType, CodeLocation, FixSuggestion
from ..utils.logger import setup_logger


@dataclass
class FrameworkInfo:
    """Information about detected JavaScript frameworks."""
    name: str
    version: Optional[str] = None
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class JavaScriptAnalyzer:
    """
    JavaScript-specific vulnerability analyzer.
    
    This class provides specialized analysis for JavaScript and TypeScript code,
    including framework-specific vulnerabilities and modern security issues.
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = setup_logger(__name__)
        
        # Framework detection patterns
        self.framework_patterns = {
            'express': [
                r'require\s*\(\s*["\']express["\']',
                r'import.*express',
                r'from\s+["\']express["\']'
            ],
            'react': [
                r'import.*React',
                r'from\s+["\']react["\']',
                r'jsx|tsx'
            ],
            'vue': [
                r'import.*Vue',
                r'from\s+["\']vue["\']',
                r'new\s+Vue\s*\('
            ],
            'angular': [
                r'@angular/',
                r'import.*angular',
                r'ng-'
            ],
            'nextjs': [
                r'next/',
                r'import.*next',
                r'getServerSideProps|getStaticProps'
            ]
        }
        
        # JavaScript-specific vulnerability patterns
        self.js_patterns = {
            'prototype_pollution': [
                r'__proto__\s*=',
                r'constructor\.prototype',
                r'Object\.prototype'
            ],
            'prototype_pollution_sink': [
                r'JSON\.parse\s*\(',
                r'Object\.assign\s*\(',
                r'Object\.merge\s*\(',
                r'\.\.\.\s*obj'
            ],
            'deserialization': [
                r'eval\s*\(',
                r'Function\s*\(',
                r'setTimeout\s*\(\s*["\']',
                r'setInterval\s*\(\s*["\']'
            ],
            'crypto_weak': [
                r'Math\.random\s*\(',
                r'crypto\.getRandomValues\s*\(\s*\[\s*\]',
                r'md5\s*\(',
                r'sha1\s*\('
            ],
            'cors_misconfig': [
                r'Access-Control-Allow-Origin\s*:\s*\*',
                r'cors\s*\(\s*\{\s*origin\s*:\s*true',
                r'credentials\s*:\s*true.*origin\s*:\s*["\']\*["\']'
            ],
            'jwt_weak': [
                r'jwt\.sign\s*\([^,]*,\s*["\'][^"\']{1,31}["\']',
                r'algorithm\s*:\s*["\']none["\']'
            ]
        }
    
    async def analyze_endpoint(self, endpoint: Dict[str, Any], context) -> List[Vulnerability]:
        """Analyze a JavaScript endpoint for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Detect framework
            framework = self._detect_framework(context.content)
            
            # Framework-specific analysis
            if framework:
                framework_vulns = await self._analyze_framework_vulnerabilities(framework, endpoint, context)
                vulnerabilities.extend(framework_vulns)
            
            # General JavaScript vulnerabilities
            js_vulns = await self._analyze_javascript_vulnerabilities(endpoint, context)
            vulnerabilities.extend(js_vulns)
            
            # Modern JS security issues
            modern_vulns = await self._analyze_modern_js_issues(endpoint, context)
            vulnerabilities.extend(modern_vulns)
        
        except Exception as e:
            self.logger.error(f"Error analyzing JavaScript endpoint: {e}")
        
        return vulnerabilities
    
    def _detect_framework(self, content: str) -> Optional[FrameworkInfo]:
        """Detect JavaScript framework from content."""
        for framework_name, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return FrameworkInfo(name=framework_name)
        return None
    
    async def _analyze_framework_vulnerabilities(self, framework: FrameworkInfo, 
                                               endpoint: Dict[str, Any], 
                                               context) -> List[Vulnerability]:
        """Analyze framework-specific vulnerabilities."""
        vulnerabilities = []
        
        if framework.name == 'express':
            vulns = await self._analyze_express_vulnerabilities(endpoint, context)
            vulnerabilities.extend(vulns)
        elif framework.name == 'react':
            vulns = await self._analyze_react_vulnerabilities(endpoint, context)
            vulnerabilities.extend(vulns)
        elif framework.name == 'vue':
            vulns = await self._analyze_vue_vulnerabilities(endpoint, context)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _analyze_express_vulnerabilities(self, endpoint: Dict[str, Any], 
                                             context) -> List[Vulnerability]:
        """Analyze Express.js specific vulnerabilities."""
        vulnerabilities = []
        
        # Check for missing security headers
        if 'helmet' not in context.content.lower():
            vuln = Vulnerability(
                vulnerability_type=VulnerabilityType.CONFIGURATION,
                severity=Severity.MEDIUM,
                title="Missing Security Headers",
                description="Express app missing security headers middleware (helmet)",
                location=CodeLocation(
                    file_path=endpoint['file_path'],
                    line_number=endpoint['line_number'],
                    column_number=0
                ),
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                detection_method="framework_analysis",
                confidence=0.7,
                fix_suggestions=[
                    FixSuggestion(
                        description="Install and configure helmet middleware",
                        code_example="const helmet = require('helmet');\napp.use(helmet());",
                        confidence=0.9
                    )
                ]
            )
            vulnerabilities.append(vuln)
        
        # Check for CORS misconfiguration
        if 'cors' in context.content.lower():
            if 'origin: true' in context.content or 'origin: "*"' in context.content:
                vuln = Vulnerability(
                    vulnerability_type=VulnerabilityType.CONFIGURATION,
                    severity=Severity.HIGH,
                    title="CORS Misconfiguration",
                    description="CORS configured to allow all origins",
                    location=CodeLocation(
                        file_path=endpoint['file_path'],
                        line_number=endpoint['line_number'],
                        column_number=0
                    ),
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    detection_method="framework_analysis",
                    confidence=0.8,
                    fix_suggestions=[
                        FixSuggestion(
                            description="Configure CORS with specific allowed origins",
                            code_example="app.use(cors({ origin: ['https://example.com'] }));",
                            confidence=0.9
                        )
                    ]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _analyze_react_vulnerabilities(self, endpoint: Dict[str, Any], 
                                           context) -> List[Vulnerability]:
        """Analyze React.js specific vulnerabilities."""
        vulnerabilities = []
        
        # Check for dangerouslySetInnerHTML usage
        if 'dangerouslySetInnerHTML' in context.content:
            vuln = Vulnerability(
                vulnerability_type=VulnerabilityType.XSS,
                severity=Severity.HIGH,
                title="Dangerous HTML Rendering",
                description="Use of dangerouslySetInnerHTML can lead to XSS",
                location=CodeLocation(
                    file_path=endpoint['file_path'],
                    line_number=endpoint['line_number'],
                    column_number=0
                ),
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                detection_method="framework_analysis",
                confidence=0.8,
                fix_suggestions=[
                    FixSuggestion(
                        description="Sanitize HTML content or use safer alternatives",
                        code_example="// Use DOMPurify to sanitize HTML\nimport DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(htmlContent)}} />",
                        confidence=0.9
                    )
                ]
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _analyze_vue_vulnerabilities(self, endpoint: Dict[str, Any], 
                                         context) -> List[Vulnerability]:
        """Analyze Vue.js specific vulnerabilities."""
        vulnerabilities = []
        
        # Check for v-html usage
        if 'v-html' in context.content:
            vuln = Vulnerability(
                vulnerability_type=VulnerabilityType.XSS,
                severity=Severity.HIGH,
                title="Unsafe HTML Rendering",
                description="Use of v-html directive can lead to XSS",
                location=CodeLocation(
                    file_path=endpoint['file_path'],
                    line_number=endpoint['line_number'],
                    column_number=0
                ),
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                detection_method="framework_analysis",
                confidence=0.8,
                fix_suggestions=[
                    FixSuggestion(
                        description="Sanitize HTML content or use text interpolation",
                        code_example="<!-- Use text interpolation instead -->\n<div>{{ message }}</div>\n<!-- Or sanitize HTML -->\n<div v-html=\"sanitizeHtml(htmlContent)\"></div>",
                        confidence=0.9
                    )
                ]
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _analyze_javascript_vulnerabilities(self, endpoint: Dict[str, Any], 
                                                context) -> List[Vulnerability]:
        """Analyze general JavaScript vulnerabilities."""
        vulnerabilities = []
        
        for vuln_type, patterns in self.js_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, context.content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = context.content[:match.start()].count('\n') + 1
                    
                    vuln = self._create_vulnerability_from_pattern(
                        vuln_type, match, endpoint['file_path'], line_number
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_vulnerability_from_pattern(self, vuln_type: str, match, file_path: str, 
                                         line_number: int) -> Optional[Vulnerability]:
        """Create vulnerability from pattern match."""
        vuln_configs = {
            'prototype_pollution': {
                'vulnerability_type': VulnerabilityType.INPUT_VALIDATION,
                'severity': Severity.HIGH,
                'title': 'Prototype Pollution',
                'description': 'Potential prototype pollution vulnerability',
                'cwe_id': 'CWE-1321',
                'owasp_category': 'A03:2021 - Injection'
            },
            'prototype_pollution_sink': {
                'vulnerability_type': VulnerabilityType.INPUT_VALIDATION,
                'severity': Severity.MEDIUM,
                'title': 'Prototype Pollution Sink',
                'description': 'Function that could be used for prototype pollution',
                'cwe_id': 'CWE-1321',
                'owasp_category': 'A03:2021 - Injection'
            },
            'deserialization': {
                'vulnerability_type': VulnerabilityType.DESERIALIZATION,
                'severity': Severity.CRITICAL,
                'title': 'Code Injection via Deserialization',
                'description': 'Dangerous deserialization that could lead to code execution',
                'cwe_id': 'CWE-502',
                'owasp_category': 'A08:2021 - Software and Data Integrity Failures'
            },
            'crypto_weak': {
                'vulnerability_type': VulnerabilityType.CRYPTOGRAPHIC,
                'severity': Severity.MEDIUM,
                'title': 'Weak Cryptographic Implementation',
                'description': 'Use of weak or predictable cryptographic functions',
                'cwe_id': 'CWE-327',
                'owasp_category': 'A02:2021 - Cryptographic Failures'
            },
            'cors_misconfig': {
                'vulnerability_type': VulnerabilityType.CONFIGURATION,
                'severity': Severity.HIGH,
                'title': 'CORS Misconfiguration',
                'description': 'CORS configured to allow all origins',
                'cwe_id': 'CWE-942',
                'owasp_category': 'A05:2021 - Security Misconfiguration'
            },
            'jwt_weak': {
                'vulnerability_type': VulnerabilityType.AUTHENTICATION,
                'severity': Severity.HIGH,
                'title': 'Weak JWT Implementation',
                'description': 'JWT implementation with weak secret or algorithm',
                'cwe_id': 'CWE-326',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures'
            }
        }
        
        config = vuln_configs.get(vuln_type)
        if not config:
            return None
        
        return Vulnerability(
            vulnerability_type=config['vulnerability_type'],
            severity=config['severity'],
            title=config['title'],
            description=config['description'],
            location=CodeLocation(
                file_path=file_path,
                line_number=line_number,
                column_number=match.start() - context.content[:match.start()].rfind('\n') - 1
            ),
            cwe_id=config['cwe_id'],
            owasp_category=config['owasp_category'],
            detection_method="javascript_analysis",
            confidence=0.7,
            code_snippet=match.group(0)
        )
    
    async def _analyze_modern_js_issues(self, endpoint: Dict[str, Any], 
                                      context) -> List[Vulnerability]:
        """Analyze modern JavaScript security issues."""
        vulnerabilities = []
        
        # Check for missing Content Security Policy
        if 'Content-Security-Policy' not in context.content:
            vuln = Vulnerability(
                vulnerability_type=VulnerabilityType.CONFIGURATION,
                severity=Severity.MEDIUM,
                title="Missing Content Security Policy",
                description="No Content Security Policy header found",
                location=CodeLocation(
                    file_path=endpoint['file_path'],
                    line_number=endpoint['line_number'],
                    column_number=0
                ),
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                detection_method="javascript_analysis",
                confidence=0.6,
                fix_suggestions=[
                    FixSuggestion(
                        description="Implement Content Security Policy",
                        code_example="app.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: [\"'self'\"],\n    scriptSrc: [\"'self'\"],\n    styleSrc: [\"'self'\"],\n  },\n}));",
                        confidence=0.8
                    )
                ]
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
