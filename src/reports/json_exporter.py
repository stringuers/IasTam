"""
JSON exporter for DefenSys.

This module provides JSON export functionality for scan results,
including structured data formats for integration with other tools.
"""

import json
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path


class JSONExporter:
    """
    JSON exporter for DefenSys scan results.
    
    This class provides various JSON export formats for different use cases,
    including standard reports, CI/CD integration, and API responses.
    """
    
    def __init__(self):
        self.supported_formats = ['standard', 'cicd', 'api', 'sarif']
    
    def export_results(self, scan_results: Dict[str, Any], format_type: str = 'standard') -> str:
        """
        Export scan results to JSON format.
        
        Args:
            scan_results: Dictionary containing scan results
            format_type: Type of JSON format ('standard', 'cicd', 'api', 'sarif')
            
        Returns:
            JSON string
        """
        if format_type not in self.supported_formats:
            raise ValueError(f"Unsupported format: {format_type}. Supported formats: {self.supported_formats}")
        
        if format_type == 'standard':
            return self._export_standard(scan_results)
        elif format_type == 'cicd':
            return self._export_cicd(scan_results)
        elif format_type == 'api':
            return self._export_api(scan_results)
        elif format_type == 'sarif':
            return self._export_sarif(scan_results)
    
    def _export_standard(self, scan_results: Dict[str, Any]) -> str:
        """Export in standard DefenSys format."""
        return json.dumps(scan_results, indent=2, default=self._json_serializer)
    
    def _export_cicd(self, scan_results: Dict[str, Any]) -> str:
        """Export in CI/CD friendly format."""
        summary = scan_results.get('summary', {})
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Calculate exit code based on vulnerabilities
        exit_code = 0
        if summary.get('critical_count', 0) > 0:
            exit_code = 1
        elif summary.get('high_count', 0) > 0:
            exit_code = 2
        
        cicd_result = {
            "exit_code": exit_code,
            "summary": {
                "total_vulnerabilities": summary.get('total_vulnerabilities', 0),
                "critical": summary.get('critical_count', 0),
                "high": summary.get('high_count', 0),
                "medium": summary.get('medium_count', 0),
                "low": summary.get('low_count', 0),
                "attack_chains": summary.get('attack_chains', 0)
            },
            "vulnerabilities": self._simplify_vulnerabilities(vulnerabilities),
            "scan_info": {
                "timestamp": scan_results.get('scan_info', {}).get('timestamp'),
                "target_path": scan_results.get('scan_info', {}).get('target_path'),
                "scanner_version": "1.0.0"
            }
        }
        
        return json.dumps(cicd_result, indent=2, default=self._json_serializer)
    
    def _export_api(self, scan_results: Dict[str, Any]) -> str:
        """Export in API response format."""
        api_result = {
            "success": True,
            "data": scan_results,
            "meta": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0",
                "format": "api"
            }
        }
        
        return json.dumps(api_result, indent=2, default=self._json_serializer)
    
    def _export_sarif(self, scan_results: Dict[str, Any]) -> str:
        """Export in SARIF (Static Analysis Results Interchange Format) format."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        scan_info = scan_results.get('scan_info', {})
        
        sarif_result = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DefenSys",
                            "version": "1.0.0",
                            "informationUri": "https://defensys.ai",
                            "rules": self._generate_sarif_rules(vulnerabilities)
                        }
                    },
                    "results": self._convert_to_sarif_results(vulnerabilities),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.fromtimestamp(
                                scan_info.get('timestamp', datetime.now().timestamp())
                            ).isoformat() + "Z"
                        }
                    ]
                }
            ]
        }
        
        return json.dumps(sarif_result, indent=2, default=self._json_serializer)
    
    def _simplify_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simplify vulnerabilities for CI/CD format."""
        simplified = []
        
        for vuln in vulnerabilities:
            simplified_vuln = {
                "title": vuln.get('title', 'Unknown'),
                "severity": vuln.get('severity', 'low'),
                "type": vuln.get('vulnerability_type', 'unknown'),
                "file": vuln.get('location', {}).get('file_path', 'Unknown'),
                "line": vuln.get('location', {}).get('line_number', 0),
                "cwe_id": vuln.get('cwe_id'),
                "description": vuln.get('description', 'No description')
            }
            simplified.append(simplified_vuln)
        
        return simplified
    
    def _generate_sarif_rules(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate SARIF rules from vulnerabilities."""
        rules = []
        rule_ids = set()
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            cwe_id = vuln.get('cwe_id')
            
            if vuln_type not in rule_ids:
                rule = {
                    "id": vuln_type,
                    "name": vuln.get('title', 'Unknown Vulnerability'),
                    "shortDescription": {
                        "text": vuln.get('description', 'No description available')
                    },
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html" if cwe_id else None
                }
                
                if cwe_id:
                    rule["properties"] = {
                        "cwe": cwe_id
                    }
                
                rules.append(rule)
                rule_ids.add(vuln_type)
        
        return rules
    
    def _convert_to_sarif_results(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert vulnerabilities to SARIF results format."""
        results = []
        
        for i, vuln in enumerate(vulnerabilities):
            location = vuln.get('location', {})
            file_path = location.get('file_path', 'Unknown')
            line_number = location.get('line_number', 0)
            column_number = location.get('column_number', 0)
            
            # Map severity to SARIF level
            severity_mapping = {
                'critical': 'error',
                'high': 'error',
                'medium': 'warning',
                'low': 'note',
                'info': 'note'
            }
            
            sarif_level = severity_mapping.get(vuln.get('severity', 'low'), 'note')
            
            result = {
                "ruleId": vuln.get('vulnerability_type', 'unknown'),
                "level": sarif_level,
                "message": {
                    "text": vuln.get('description', 'No description available')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": line_number,
                                "startColumn": column_number
                            }
                        }
                    }
                ],
                "properties": {
                    "cwe": vuln.get('cwe_id'),
                    "owasp": vuln.get('owasp_category')
                }
            }
            
            # Add code snippet if available
            code_snippet = vuln.get('code_snippet')
            if code_snippet:
                result["codeFlows"] = [
                    {
                        "threadFlows": [
                            {
                                "locations": [
                                    {
                                        "location": {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": file_path
                                                },
                                                "region": {
                                                    "startLine": line_number,
                                                    "startColumn": column_number,
                                                    "snippet": {
                                                        "text": code_snippet
                                                    }
                                                }
                                            }
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            
            results.append(result)
        
        return results
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for datetime and other objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    def export_to_file(self, scan_results: Dict[str, Any], output_path: Path, 
                      format_type: str = 'standard') -> None:
        """
        Export scan results to a JSON file.
        
        Args:
            scan_results: Dictionary containing scan results
            output_path: Path to output file
            format_type: Type of JSON format
        """
        json_content = self.export_results(scan_results, format_type)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_content)
    
    def export_summary(self, scan_results: Dict[str, Any]) -> str:
        """Export a summary-only JSON format."""
        summary = scan_results.get('summary', {})
        scan_info = scan_results.get('scan_info', {})
        
        summary_data = {
            "scan_summary": {
                "target_path": scan_info.get('target_path'),
                "timestamp": scan_info.get('timestamp'),
                "total_vulnerabilities": summary.get('total_vulnerabilities', 0),
                "critical_count": summary.get('critical_count', 0),
                "high_count": summary.get('high_count', 0),
                "medium_count": summary.get('medium_count', 0),
                "low_count": summary.get('low_count', 0),
                "attack_chains": summary.get('attack_chains', 0)
            },
            "scanner_info": {
                "name": "DefenSys",
                "version": "1.0.0",
                "description": "AI-Powered Cybersecurity Platform"
            }
        }
        
        return json.dumps(summary_data, indent=2, default=self._json_serializer)
    
    def export_vulnerabilities_only(self, scan_results: Dict[str, Any]) -> str:
        """Export only vulnerabilities in a simplified format."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        vuln_data = {
            "vulnerabilities": self._simplify_vulnerabilities(vulnerabilities),
            "count": len(vulnerabilities),
            "exported_at": datetime.now().isoformat()
        }
        
        return json.dumps(vuln_data, indent=2, default=self._json_serializer)
