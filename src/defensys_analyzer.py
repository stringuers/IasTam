"""
Core vulnerability detection engine for DefenSys.

This module contains the main analyzer class that orchestrates the scanning
process and coordinates between different agents and analyzers.
"""

import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .models.vulnerability import Vulnerability, Severity
from .agents.reconnaissance_agent import ReconnaissanceAgent
from .agents.vulnerability_agent import VulnerabilityAgent
from .agents.exploit_chain_agent import ExploitChainAgent
from .utils.logger import setup_logger
from .utils.config import Config


@dataclass
class ScanConfig:
    """Configuration for vulnerability scans."""
    target_path: Path
    recursive: bool = True
    file_extensions: List[str] = None
    max_file_size_mb: int = 50
    timeout_seconds: int = 300
    parallel_scans: int = 4
    deep_analysis: bool = False
    
    def __post_init__(self):
        if self.file_extensions is None:
            self.file_extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php']


class DefenSysAnalyzer:
    """
    Main analyzer class that orchestrates vulnerability detection.
    
    This class coordinates between different agents to provide comprehensive
    security analysis of codebases.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the DefenSys analyzer."""
        self.config = config or Config()
        self.logger = setup_logger(__name__)
        
        # Initialize agents
        self.recon_agent = ReconnaissanceAgent(self.config)
        self.vuln_agent = VulnerabilityAgent(self.config)
        self.exploit_agent = ExploitChainAgent(self.config)
        
        self.vulnerabilities: List[Vulnerability] = []
        self.attack_chains: List[Dict[str, Any]] = []
    
    async def scan(self, scan_config: ScanConfig) -> Dict[str, Any]:
        """
        Perform a comprehensive vulnerability scan.
        
        Args:
            scan_config: Configuration for the scan
            
        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Starting DefenSys scan of {scan_config.target_path}")
        
        try:
            # Phase 1: Reconnaissance
            self.logger.info("Phase 1: Reconnaissance - Discovering attack surface")
            attack_surface = await self.recon_agent.discover_attack_surface(
                scan_config.target_path,
                recursive=scan_config.recursive,
                file_extensions=scan_config.file_extensions
            )
            
            # Phase 2: Vulnerability Detection
            self.logger.info("Phase 2: Vulnerability Detection - Analyzing code")
            self.vulnerabilities = await self.vuln_agent.analyze_vulnerabilities(
                attack_surface,
                deep_analysis=scan_config.deep_analysis
            )
            
            # Phase 3: Attack Chain Analysis
            self.logger.info("Phase 3: Attack Chain Analysis - Mapping exploit paths")
            self.attack_chains = await self.exploit_agent.analyze_attack_chains(
                self.vulnerabilities,
                attack_surface
            )
            
            # Generate results
            results = self._generate_scan_results(scan_config)
            
            self.logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
            return results
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise
    
    def _generate_scan_results(self, scan_config: ScanConfig) -> Dict[str, Any]:
        """Generate comprehensive scan results."""
        return {
            "scan_info": {
                "target_path": str(scan_config.target_path),
                "timestamp": asyncio.get_event_loop().time(),
                "config": {
                    "recursive": scan_config.recursive,
                    "file_extensions": scan_config.file_extensions,
                    "deep_analysis": scan_config.deep_analysis
                }
            },
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical_count": len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL]),
                "high_count": len([v for v in self.vulnerabilities if v.severity == Severity.HIGH]),
                "medium_count": len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM]),
                "low_count": len([v for v in self.vulnerabilities if v.severity == Severity.LOW]),
                "attack_chains": len(self.attack_chains)
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "attack_chains": self.attack_chains,
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if not self.vulnerabilities:
            recommendations.append({
                "type": "success",
                "message": "No vulnerabilities detected! Your code appears to be secure."
            })
            return recommendations
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vulnerability_type
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Generate recommendations for each vulnerability type
        for vuln_type, vulns in vuln_types.items():
            count = len(vulns)
            severity = max(vuln.severity for vuln in vulns)
            
            recommendations.append({
                "type": "vulnerability",
                "category": vuln_type,
                "count": count,
                "severity": severity.value,
                "message": f"Found {count} {vuln_type} vulnerability(ies) with {severity.value} severity"
            })
        
        return recommendations
