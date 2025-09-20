"""
DefenSys Enhanced CLI Tool and REST API
Command-line interface and web API for the DefenSys security scanner
"""

import os
import sys
import json
import argparse
import glob
from pathlib import Path
from typing import List, Dict
from datetime import datetime
import asyncio

# FastAPI imports
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Import our core analyzer
from defensys_analyzer_enhanced import DefenSysAnalyzer

class ScanRequest(BaseModel):
    files: List[str]
    options: Dict = {}

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    results: Dict

class DefenSysCLI:
    """Command-line interface for DefenSys"""
    
    def __init__(self):
        self.analyzer = DefenSysAnalyzer()
        self.supported_extensions = ['.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte']
    
    def scan_directory(self, directory: str, recursive: bool = True, output_format: str = 'json') -> Dict:
        """Scan entire directory for vulnerabilities"""
        files_to_scan = []
        
        if recursive:
            for ext in self.supported_extensions:
                pattern = f"{directory}/**/*{ext}"
                files_to_scan.extend(glob.glob(pattern, recursive=True))
        else:
            for ext in self.supported_extensions:
                pattern = f"{directory}/*{ext}"
                files_to_scan.extend(glob.glob(pattern))
        
        if not files_to_scan:
            return {
                'error': f'No supported files found in {directory}',
                'supported_extensions': self.supported_extensions
            }
        
        print(f"🔍 Scanning {len(files_to_scan)} files...")
        
        all_results = []
        total_vulnerabilities = 0
        total_critical = 0
        total_high = 0
        
        for file_path in files_to_scan:
            print(f"  📁 Analyzing {file_path}...")
            result = self.analyzer.scan_file(file_path)
            all_results.append(result)
            
            if 'vulnerabilities' in result:
                total_vulnerabilities += len(result['vulnerabilities'])
                if 'summary' in result:
                    total_critical += result['summary'].get('critical', 0)
                    total_high += result['summary'].get('high', 0)
        
        # Aggregate results
        scan_results = {
            'scan_metadata': {
                'scan_time': datetime.now().isoformat(),
                'directory': directory,
                'files_scanned': len(files_to_scan),
                'total_vulnerabilities': total_vulnerabilities,
                'critical_issues': total_critical,
                'high_issues': total_high
            },
            'files': all_results,
            'overall_risk_assessment': self._assess_overall_risk(all_results)
        }
        
        return scan_results
    
    def _assess_overall_risk(self, results: List[Dict]) -> Dict:
        """Assess overall risk across all scanned files"""
        total_score = sum(r.get('risk_score', 0) for r in results)
        avg_score = total_score / len(results) if results else 0
        
        risk_level = 'LOW'
        if avg_score >= 70:
            risk_level = 'CRITICAL'
        elif avg_score >= 50:
            risk_level = 'HIGH'
        elif avg_score >= 30:
            risk_level = 'MEDIUM'
        
        return {
            'average_risk_score': round(avg_score, 2),
            'risk_level': risk_level,
            'recommendation': self._get_risk_recommendation(risk_level, avg_score)
        }
    
    def _get_risk_recommendation(self, risk_level: str, score: float) -> str:
        """Get actionable recommendations based on risk level"""
        recommendations = {
            'CRITICAL': f"🚨 IMMEDIATE ACTION REQUIRED (Score: {score:.1f}/100)\n"
                       "- Stop deployment until critical vulnerabilities are fixed\n"
                       "- Review and fix all high/critical issues immediately\n"
                       "- Consider security code review by experts\n"
                       "- Implement additional security testing",
            
            'HIGH': f"⚠️ HIGH PRIORITY FIXES NEEDED (Score: {score:.1f}/100)\n"
                   "- Address critical and high severity issues before deployment\n"
                   "- Implement automated security testing in CI/CD\n"
                   "- Review authentication and input validation\n"
                   "- Consider penetration testing",
            
            'MEDIUM': f"⚡ SECURITY IMPROVEMENTS RECOMMENDED (Score: {score:.1f}/100)\n"
                     "- Fix medium and high priority vulnerabilities\n"
                     "- Implement secure coding practices\n"
                     "- Add automated security scanning to workflow\n"
                     "- Regular security training for team",
            
            'LOW': f"✅ GOOD SECURITY POSTURE (Score: {score:.1f}/100)\n"
                  "- Address remaining low-priority issues when possible\n"
                  "- Maintain regular security scanning\n"
                  "- Keep dependencies updated\n"
                  "- Continue security best practices"
        }
        
        return recommendations.get(risk_level, "No specific recommendations available")
    
    def generate_report(self, results: Dict, format: str = 'console') -> str:
        """Generate formatted security report"""
        if format == 'console':
            return self._generate_console_report(results)
        elif format == 'json':
            return json.dumps(results, indent=2)
        elif format == 'html':
            return self._generate_html_report(results)
        else:
            return json.dumps(results, indent=2)
    
    def _generate_console_report(self, results: Dict) -> str:
        """Generate colorized console report"""
        report = []
        
        # Header
        report.append("=" * 60)
        report.append("🛡️  DEFENSYS SECURITY ANALYSIS REPORT")
        report.append("=" * 60)
        
        # Metadata
        metadata = results['scan_metadata']
        report.append(f"📅 Scan Time: {metadata['scan_time']}")
        report.append(f"📂 Directory: {metadata['directory']}")
        report.append(f"📄 Files Scanned: {metadata['files_scanned']}")
        report.append(f"🔍 Total Vulnerabilities: {metadata['total_vulnerabilities']}")
        report.append("")
        
        # Overall Risk Assessment
        risk = results['overall_risk_assessment']
        report.append("🎯 OVERALL RISK ASSESSMENT")
        report.append("-" * 30)
        report.append(f"Risk Level: {risk['risk_level']}")
        report.append(f"Average Risk Score: {risk['average_risk_score']}/100")
        report.append("")
        report.append("💡 RECOMMENDATIONS:")
        report.append(risk['recommendation'])
        report.append("")
        
        # File-by-file results
        report.append("📋 DETAILED RESULTS BY FILE")
        report.append("-" * 40)
        
        for file_result in results['files']:
            if file_result.get('error'):
                report.append(f"❌ {file_result['file']}: ERROR - {file_result['error']}")
                continue
            
            file_path = file_result['file']
            risk_score = file_result['risk_score']
            summary = file_result['summary']
            
            # File header
            report.append(f"📁 {file_path}")
            report.append(f"   Risk Score: {risk_score}/100")
            report.append(f"   Issues: {summary['critical']}C, {summary['high']}H, {summary['medium']}M, {summary['low']}L")
            
            # List vulnerabilities
            if file_result['vulnerabilities']:
                for vuln in file_result['vulnerabilities']:
                    severity_emoji = {'Critical': '🚨', 'High': '⚠️', 'Medium': '⚡', 'Low': '💡'}
                    emoji = severity_emoji.get(vuln['severity'], '❓')
                    
                    report.append(f"   {emoji} Line {vuln['line']}: {vuln['type']} ({vuln['severity']})")
                    report.append(f"      {vuln['description']}")
                    report.append(f"      Fix: {vuln['fix_suggestion']}")
                    report.append("")
            
            # Attack chains
            if file_result['attack_chains']:
                report.append("   🔗 ATTACK CHAINS DETECTED:")
                for chain in file_result['attack_chains']:
                    report.append(f"      🎯 {chain['chain_id']}: {chain['description']}")
                    report.append(f"         Impact: {chain['impact']}")
                report.append("")
        
        return "\n".join(report)
    
    def _generate_html_report(self, results: Dict) -> str:
        """Generate HTML security report"""
        html_template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>DefenSys Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
                .header { text-align: center; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 20px; }
                .risk-critical { color: #e74c3c; }
                .risk-high { color: #f39c12; }
                .risk-medium { color: #f1c40f; }
                .risk-low { color: #27ae60; }
                .vulnerability { margin: 10px 0; padding: 15px; border-left: 4px solid #3498db; background: #f8f9fa; }
                .file-section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                .summary-box { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .attack-chain { background: #ffe6e6; border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }
                .metric { display: inline-block; margin: 10px; padding: 10px; background: #3498db; color: white; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ DefenSys Security Analysis Report</h1>
                    <p>Generated on {scan_time}</p>
                </div>
                
                <div class="summary-box">
                    <h2>📊 Executive Summary</h2>
                    <div class="metric">Files Scanned: {files_scanned}</div>
                    <div class="metric">Total Vulnerabilities: {total_vulnerabilities}</div>
                    <div class="metric">Risk Level: {risk_level}</div>
                    <div class="metric">Average Score: {avg_score}/100</div>
                </div>
                
                <div class="summary-box">
                    <h3>💡 Recommendations</h3>
                    <pre>{recommendations}</pre>
                </div>
                
                {file_sections}
            </div>
        </body>
        </html>
        '''
        
        # Build file sections
        file_sections = []
        for file_result in results['files']:
            if file_result.get('error'):
                continue
                
            file_html = f'''
            <div class="file-section">
                <h3>📁 {file_result['file']}</h3>
                <p><strong>Risk Score:</strong> {file_result['risk_score']}/100</p>
                <p><strong>Issues:</strong> {file_result['summary']['critical']}C, {file_result['summary']['high']}H, {file_result['summary']['medium']}M, {file_result['summary']['low']}L</p>
            '''
            
            for vuln in file_result['vulnerabilities']:
                severity_class = f"risk-{vuln['severity'].lower()}"
                file_html += f'''
                <div class="vulnerability {severity_class}">
                    <h4>Line {vuln['line']}: {vuln['type']} ({vuln['severity']})</h4>
                    <p><strong>Description:</strong> {vuln['description']}</p>
                    <p><strong>Code:</strong> <code>{vuln['code_snippet']}</code></p>
                    <p><strong>Fix:</strong> {vuln['fix_suggestion']}</p>
                    <p><strong>Proof of Concept:</strong> {vuln['proof_of_concept']}</p>
                </div>
                '''
            
            for chain in file_result['attack_chains']:
                file_html += f'''
                <div class="attack-chain">
                    <h4>🔗 Attack Chain: {chain['chain_id']}</h4>
                    <p><strong>Description:</strong> {chain['description']}</p>
                    <p><strong>Impact:</strong> {chain['impact']}</p>
                </div>
                '''
            
            file_html += '</div>'
            file_sections.append(file_html)
        
        # Format the template
        return html_template.format(
            scan_time=results['scan_metadata']['scan_time'],
            files_scanned=results['scan_metadata']['files_scanned'],
            total_vulnerabilities=results['scan_metadata']['total_vulnerabilities'],
            risk_level=results['overall_risk_assessment']['risk_level'],
            avg_score=results['overall_risk_assessment']['average_risk_score'],
            recommendations=results['overall_risk_assessment']['recommendation'],
            file_sections=''.join(file_sections)
        )

# FastAPI Application
app = FastAPI(
    title="DefenSys API",
    description="AI-powered cybersecurity analysis API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global analyzer instance
defensys_analyzer = DefenSysAnalyzer()
cli = DefenSysCLI()

@app.get("/")
async def root():
    return {
        "message": "DefenSys AI Security Scanner API",
        "version": "1.0.0",
        "endpoints": [
            "/scan/file - Scan a single file",
            "/scan/directory - Scan entire directory", 
            "/health - Health check",
            "/docs - API documentation"
        ]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/scan/file")
async def scan_file(file_path: str):
    """Scan a single file for vulnerabilities"""
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    if not any(file_path.endswith(ext) for ext in cli.supported_extensions):
        raise HTTPException(status_code=400, detail=f"Unsupported file type. Supported: {cli.supported_extensions}")
    
    try:
        result = defensys_analyzer.scan_file(file_path)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/directory")
async def scan_directory(directory: str, recursive: bool = True, format: str = "json"):
    """Scan entire directory for vulnerabilities"""
    if not os.path.exists(directory):
        raise HTTPException(status_code=404, detail="Directory not found")
    
    if not os.path.isdir(directory):
        raise HTTPException(status_code=400, detail="Path is not a directory")
    
    try:
        results = cli.scan_directory(directory, recursive, format)
        if 'error' in results:
            raise HTTPException(status_code=400, detail=results['error'])
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/report/{format}")
async def get_report(scan_data: Dict, format: str = "json"):
    """Generate formatted report from scan data"""
    try:
        if format not in ["json", "html", "console"]:
            raise HTTPException(status_code=400, detail="Format must be json, html, or console")
        
        report = cli.generate_report(scan_data, format)
        
        if format == "html":
            return {"content": report, "content_type": "text/html"}
        elif format == "console":
            return {"content": report, "content_type": "text/plain"}
        else:
            return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='DefenSys AI-powered Security Scanner')
    parser.add_argument('target', nargs='?', help='File or directory to scan')
    parser.add_argument('-r', '--recursive', action='store_true', help='Scan directories recursively')
    parser.add_argument('-f', '--format', choices=['json', 'console', 'html'], default='console', help='Output format')
    parser.add_argument('-o', '--output', help='Output file (optional)')
    parser.add_argument('--api', action='store_true', help='Start API server instead of CLI scan')
    parser.add_argument('--port', type=int, default=8000, help='API server port')
    
    args = parser.parse_args()
    
    if args.api:
        print("🚀 Starting DefenSys API server...")
        print(f"📍 Server will be available at: http://localhost:{args.port}")
        print("📚 API docs available at: http://localhost:{args.port}/docs")
        uvicorn.run(app, host="0.0.0.0", port=args.port)
        return
    
    if not args.target:
        parser.error("target is required when not using --api")
    
    cli = DefenSysCLI()
    
    print("🛡️ DefenSys AI Security Scanner")
    print("=" * 50)
    
    # Determine if target is file or directory
    if os.path.isfile(args.target):
        print(f"🔍 Scanning file: {args.target}")
        result = cli.analyzer.scan_file(args.target)
        # Wrap single file result in directory-style structure for consistent reporting
        results = {
            'scan_metadata': {
                'scan_time': datetime.now().isoformat(),
                'directory': os.path.dirname(args.target),
                'files_scanned': 1,
                'total_vulnerabilities': len(result.get('vulnerabilities', [])),
                'critical_issues': result.get('summary', {}).get('critical', 0),
                'high_issues': result.get('summary', {}).get('high', 0)
            },
            'files': [result],
            'overall_risk_assessment': cli._assess_overall_risk([result])
        }
    elif os.path.isdir(args.target):
        print(f"🔍 Scanning directory: {args.target}")
        results = cli.scan_directory(args.target, args.recursive, args.format)
    else:
        print(f"❌ Error: {args.target} not found")
        sys.exit(1)
    
    # Generate report
    report = cli.generate_report(results, args.format)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"📝 Report saved to: {args.output}")
    else:
        print(report)
    
    # Exit with error code if critical vulnerabilities found
    if results['overall_risk_assessment']['risk_level'] in ['CRITICAL', 'HIGH']:
        print(f"\n⚠️  Exiting with error code due to {results['overall_risk_assessment']['risk_level']} risk level")
        sys.exit(1)

if __name__ == "__main__":
    main()
