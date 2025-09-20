#!/usr/bin/env python3
"""
Update vulnerability patterns from external sources.

This script downloads and updates vulnerability patterns from various
security databases and research sources.
"""

import json
import requests
import argparse
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime


class PatternUpdater:
    """Updates vulnerability patterns from external sources."""
    
    def __init__(self, patterns_dir: Path):
        self.patterns_dir = patterns_dir
        self.patterns_dir.mkdir(parents=True, exist_ok=True)
    
    def update_from_cwe(self) -> None:
        """Update patterns from CWE database."""
        print("📥 Updating patterns from CWE database...")
        
        try:
            # CWE API endpoint for common weaknesses
            cwe_url = "https://cwe.mitre.org/data/csv/1000.csv"
            response = requests.get(cwe_url, timeout=30)
            response.raise_for_status()
            
            # Parse CSV and create patterns
            patterns = self._parse_cwe_csv(response.text)
            
            # Save patterns
            cwe_file = self.patterns_dir / "cwe_patterns.json"
            with open(cwe_file, 'w', encoding='utf-8') as f:
                json.dump(patterns, f, indent=2)
            
            print(f"✅ Updated {len(patterns)} CWE patterns")
            
        except Exception as e:
            print(f"❌ Error updating CWE patterns: {e}")
    
    def update_from_owasp(self) -> None:
        """Update patterns from OWASP resources."""
        print("📥 Updating patterns from OWASP...")
        
        try:
            # OWASP Top 10 patterns
            owasp_patterns = [
                {
                    "name": "Injection - SQL",
                    "pattern": "SELECT.*\\+.*req\\.|INSERT.*\\+.*req\\.|UPDATE.*\\+.*req\\.",
                    "vulnerability_type": "sql_injection",
                    "severity": "critical",
                    "description": "SQL injection vulnerability",
                    "cwe_id": "CWE-89",
                    "owasp_category": "A03:2021 - Injection",
                    "fix_suggestion": "Use parameterized queries",
                    "confidence": 0.9
                },
                {
                    "name": "Broken Authentication",
                    "pattern": "password.*=.*req\\.|jwt\\.sign.*[\"'][^\"']{1,31}[\"']",
                    "vulnerability_type": "authentication_issue",
                    "severity": "high",
                    "description": "Authentication vulnerability",
                    "cwe_id": "CWE-287",
                    "owasp_category": "A07:2021 - Identification and Authentication Failures",
                    "fix_suggestion": "Implement proper authentication",
                    "confidence": 0.8
                }
            ]
            
            # Save OWASP patterns
            owasp_file = self.patterns_dir / "owasp_patterns.json"
            with open(owasp_file, 'w', encoding='utf-8') as f:
                json.dump(owasp_patterns, f, indent=2)
            
            print(f"✅ Updated {len(owasp_patterns)} OWASP patterns")
            
        except Exception as e:
            print(f"❌ Error updating OWASP patterns: {e}")
    
    def update_from_nvd(self) -> None:
        """Update patterns from NVD (National Vulnerability Database)."""
        print("📥 Updating patterns from NVD...")
        
        try:
            # NVD API for recent vulnerabilities
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "resultsPerPage": 100,
                "startIndex": 0,
                "pubStartDate": "2024-01-01T00:00:00.000",
                "pubEndDate": "2024-12-31T23:59:59.999"
            }
            
            response = requests.get(nvd_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            patterns = self._parse_nvd_data(data)
            
            # Save NVD patterns
            nvd_file = self.patterns_dir / "nvd_patterns.json"
            with open(nvd_file, 'w', encoding='utf-8') as f:
                json.dump(patterns, f, indent=2)
            
            print(f"✅ Updated {len(patterns)} NVD patterns")
            
        except Exception as e:
            print(f"❌ Error updating NVD patterns: {e}")
    
    def _parse_cwe_csv(self, csv_content: str) -> List[Dict[str, Any]]:
        """Parse CWE CSV content into patterns."""
        patterns = []
        lines = csv_content.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split(',')
            if len(parts) >= 3:
                cwe_id = parts[0].strip()
                name = parts[1].strip().strip('"')
                description = parts[2].strip().strip('"')
                
                pattern = {
                    "name": f"CWE-{cwe_id}: {name}",
                    "pattern": "",  # Would need specific pattern generation
                    "vulnerability_type": "unknown",
                    "severity": "medium",
                    "description": description,
                    "cwe_id": f"CWE-{cwe_id}",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "fix_suggestion": "Review and fix the identified weakness",
                    "confidence": 0.5
                }
                patterns.append(pattern)
        
        return patterns
    
    def _parse_nvd_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse NVD API data into patterns."""
        patterns = []
        
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', '')
                description = cve.get('descriptions', [{}])[0].get('value', '')
                
                # Extract CWE IDs
                cwe_ids = []
                for reference in cve.get('references', []):
                    if 'cwe' in reference.get('url', '').lower():
                        cwe_ids.append(reference['url'])
                
                if cwe_ids:
                    pattern = {
                        "name": f"{cve_id} Pattern",
                        "pattern": "",  # Would need specific pattern generation
                        "vulnerability_type": "unknown",
                        "severity": "high",
                        "description": description[:200] + "..." if len(description) > 200 else description,
                        "cwe_id": cwe_ids[0] if cwe_ids else "",
                        "owasp_category": "A05:2021 - Security Misconfiguration",
                        "fix_suggestion": "Apply security updates and patches",
                        "confidence": 0.6
                    }
                    patterns.append(pattern)
        
        return patterns
    
    def merge_patterns(self) -> None:
        """Merge all pattern files into a single comprehensive file."""
        print("🔄 Merging pattern files...")
        
        all_patterns = []
        pattern_files = [
            "sql_injection.json",
            "xss_patterns.json", 
            "auth_patterns.json",
            "config_issues.json",
            "cwe_patterns.json",
            "owasp_patterns.json",
            "nvd_patterns.json"
        ]
        
        for pattern_file in pattern_files:
            file_path = self.patterns_dir / pattern_file
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        patterns = json.load(f)
                        all_patterns.extend(patterns)
                        print(f"  ✅ Loaded {len(patterns)} patterns from {pattern_file}")
                except Exception as e:
                    print(f"  ❌ Error loading {pattern_file}: {e}")
        
        # Save merged patterns
        merged_file = self.patterns_dir / "all_patterns.json"
        with open(merged_file, 'w', encoding='utf-8') as f:
            json.dump(all_patterns, f, indent=2)
        
        print(f"✅ Merged {len(all_patterns)} patterns into all_patterns.json")
    
    def update_all(self) -> None:
        """Update all pattern sources."""
        print("🔄 Updating all vulnerability patterns...")
        print(f"📁 Patterns directory: {self.patterns_dir}")
        
        self.update_from_cwe()
        self.update_from_owasp()
        self.update_from_nvd()
        self.merge_patterns()
        
        print("🎉 Pattern update completed!")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Update DefenSys vulnerability patterns")
    parser.add_argument("--patterns-dir", default="./data/vulnerability_patterns",
                       help="Directory to store pattern files")
    parser.add_argument("--source", choices=["cwe", "owasp", "nvd", "all"], default="all",
                       help="Source to update patterns from")
    
    args = parser.parse_args()
    
    patterns_dir = Path(args.patterns_dir)
    updater = PatternUpdater(patterns_dir)
    
    if args.source == "cwe":
        updater.update_from_cwe()
    elif args.source == "owasp":
        updater.update_from_owasp()
    elif args.source == "nvd":
        updater.update_from_nvd()
    else:
        updater.update_all()


if __name__ == "__main__":
    main()
