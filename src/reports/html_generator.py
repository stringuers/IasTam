"""
HTML report generator for DefenSys.

This module generates beautiful, interactive HTML reports for vulnerability
scan results with charts, filtering, and detailed analysis.
"""

import json
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path


class HTMLGenerator:
    """
    HTML report generator for DefenSys scan results.
    
    This class generates comprehensive HTML reports with interactive features,
    charts, and detailed vulnerability information.
    """
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
    
    def generate_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate an HTML report from scan results.
        
        Args:
            scan_results: Dictionary containing scan results
            
        Returns:
            HTML content as string
        """
        html_content = self._get_base_html()
        
        # Replace placeholders with actual data
        html_content = html_content.replace("{{SCAN_SUMMARY}}", self._generate_summary_section(scan_results))
        html_content = html_content.replace("{{VULNERABILITIES_TABLE}}", self._generate_vulnerabilities_table(scan_results))
        html_content = html_content.replace("{{ATTACK_CHAINS}}", self._generate_attack_chains_section(scan_results))
        html_content = html_content.replace("{{RECOMMENDATIONS}}", self._generate_recommendations_section(scan_results))
        html_content = html_content.replace("{{CHARTS}}", self._generate_charts_section(scan_results))
        
        return html_content
    
    def _get_base_html(self) -> str:
        """Get the base HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefenSys Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        
        .card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .critical { color: #e74c3c; }
        .high { color: #f39c12; }
        .medium { color: #f1c40f; }
        .low { color: #27ae60; }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .vulnerability-item {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: box-shadow 0.3s ease;
        }
        
        .vulnerability-item:hover {
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .vuln-header {
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8f9fa;
        }
        
        .vuln-title {
            font-weight: bold;
            font-size: 1.1em;
            color: #2c3e50;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }
        
        .severity-critical { background: #e74c3c; }
        .severity-high { background: #f39c12; }
        .severity-medium { background: #f1c40f; }
        .severity-low { background: #27ae60; }
        
        .vuln-details {
            padding: 20px;
            display: none;
            background: white;
        }
        
        .vuln-details.show {
            display: block;
        }
        
        .vuln-info {
            margin-bottom: 15px;
        }
        
        .vuln-info strong {
            color: #2c3e50;
        }
        
        .code-snippet {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        .fix-suggestion {
            background: #e8f5e8;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 5px 5px 0;
        }
        
        .attack-chain {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
        
        .chain-step {
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            position: relative;
        }
        
        .chain-step::before {
            content: "→";
            position: absolute;
            left: -15px;
            top: 50%;
            transform: translateY(-50%);
            background: #667eea;
            color: white;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        
        .filter-bar {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .filter-bar select, .filter-bar input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .chart-container {
            height: 400px;
            margin: 20px 0;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #eee;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
            
            .filter-bar {
                flex-direction: column;
                align-items: stretch;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DefenSys Security Report</h1>
            <p>AI-Powered Vulnerability Analysis</p>
            <p>Generated on {{TIMESTAMP}}</p>
        </div>
        
        {{SCAN_SUMMARY}}
        
        {{CHARTS}}
        
        <div class="section">
            <h2>🔍 Vulnerability Analysis</h2>
            <div class="filter-bar">
                <select id="severityFilter">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <select id="typeFilter">
                    <option value="">All Types</option>
                    <option value="sql_injection">SQL Injection</option>
                    <option value="xss">XSS</option>
                    <option value="authentication">Authentication</option>
                    <option value="file_upload">File Upload</option>
                </select>
                <input type="text" id="searchFilter" placeholder="Search vulnerabilities...">
            </div>
            {{VULNERABILITIES_TABLE}}
        </div>
        
        {{ATTACK_CHAINS}}
        
        {{RECOMMENDATIONS}}
        
        <div class="footer">
            <p>Generated by DefenSys v1.0.0 | <a href="https://defensys.ai">defensys.ai</a></p>
        </div>
    </div>
    
    <script>
        // Add interactivity
        document.addEventListener('DOMContentLoaded', function() {
            // Toggle vulnerability details
            document.querySelectorAll('.vuln-header').forEach(header => {
                header.addEventListener('click', function() {
                    const details = this.nextElementSibling;
                    details.classList.toggle('show');
                });
            });
            
            // Filter functionality
            const severityFilter = document.getElementById('severityFilter');
            const typeFilter = document.getElementById('typeFilter');
            const searchFilter = document.getElementById('searchFilter');
            
            function filterVulnerabilities() {
                const severity = severityFilter.value;
                const type = typeFilter.value;
                const search = searchFilter.value.toLowerCase();
                
                document.querySelectorAll('.vulnerability-item').forEach(item => {
                    const severityClass = item.querySelector('.severity-badge').classList[1];
                    const typeText = item.querySelector('.vuln-title').textContent.toLowerCase();
                    const searchText = item.textContent.toLowerCase();
                    
                    const severityMatch = !severity || severityClass.includes(severity);
                    const typeMatch = !type || typeText.includes(type);
                    const searchMatch = !search || searchText.includes(search);
                    
                    if (severityMatch && typeMatch && searchMatch) {
                        item.style.display = 'block';
                    } else {
                        item.style.display = 'none';
                    }
                });
            }
            
            severityFilter.addEventListener('change', filterVulnerabilities);
            typeFilter.addEventListener('change', filterVulnerabilities);
            searchFilter.addEventListener('input', filterVulnerabilities);
        });
    </script>
</body>
</html>
        """.replace("{{TIMESTAMP}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def _generate_summary_section(self, scan_results: Dict[str, Any]) -> str:
        """Generate the summary section with key metrics."""
        summary = scan_results.get('summary', {})
        
        return f"""
        <div class="summary-cards">
            <div class="card">
                <h3>Total Vulnerabilities</h3>
                <div class="number">{summary.get('total_vulnerabilities', 0)}</div>
                <p>Security issues found</p>
            </div>
            <div class="card">
                <h3>Critical</h3>
                <div class="number critical">{summary.get('critical_count', 0)}</div>
                <p>Immediate attention required</p>
            </div>
            <div class="card">
                <h3>High</h3>
                <div class="number high">{summary.get('high_count', 0)}</div>
                <p>Should be fixed soon</p>
            </div>
            <div class="card">
                <h3>Attack Chains</h3>
                <div class="number">{summary.get('attack_chains', 0)}</div>
                <p>Potential exploit paths</p>
            </div>
        </div>
        """
    
    def _generate_vulnerabilities_table(self, scan_results: Dict[str, Any]) -> str:
        """Generate the vulnerabilities table."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return '<p>No vulnerabilities found! 🎉</p>'
        
        vuln_html = ""
        for vuln in vulnerabilities:
            severity_class = f"severity-{vuln.get('severity', 'low')}"
            vuln_html += f"""
            <div class="vulnerability-item">
                <div class="vuln-header">
                    <div class="vuln-title">{vuln.get('title', 'Unknown')}</div>
                    <div class="severity-badge {severity_class}">{vuln.get('severity', 'low').upper()}</div>
                </div>
                <div class="vuln-details">
                    <div class="vuln-info">
                        <strong>Description:</strong> {vuln.get('description', 'No description available')}
                    </div>
                    <div class="vuln-info">
                        <strong>Location:</strong> {vuln.get('location', {}).get('file_path', 'Unknown')} (Line {vuln.get('location', {}).get('line_number', '?')})
                    </div>
                    <div class="vuln-info">
                        <strong>CWE ID:</strong> {vuln.get('cwe_id', 'N/A')}
                    </div>
                    <div class="vuln-info">
                        <strong>OWASP Category:</strong> {vuln.get('owasp_category', 'N/A')}
                    </div>
                    {self._generate_code_snippet(vuln)}
                    {self._generate_fix_suggestions(vuln)}
                </div>
            </div>
            """
        
        return vuln_html
    
    def _generate_code_snippet(self, vuln: Dict[str, Any]) -> str:
        """Generate code snippet section."""
        code_snippet = vuln.get('code_snippet')
        if not code_snippet:
            return ""
        
        return f"""
        <div class="vuln-info">
            <strong>Code Snippet:</strong>
            <div class="code-snippet">{code_snippet}</div>
        </div>
        """
    
    def _generate_fix_suggestions(self, vuln: Dict[str, Any]) -> str:
        """Generate fix suggestions section."""
        suggestions = vuln.get('fix_suggestions', [])
        if not suggestions:
            return ""
        
        suggestions_html = ""
        for suggestion in suggestions:
            suggestions_html += f"""
            <div class="fix-suggestion">
                <strong>Fix Suggestion:</strong> {suggestion.get('description', 'No suggestion available')}
                {f'<div class="code-snippet">{suggestion.get("code_example", "")}</div>' if suggestion.get('code_example') else ''}
            </div>
            """
        
        return suggestions_html
    
    def _generate_attack_chains_section(self, scan_results: Dict[str, Any]) -> str:
        """Generate attack chains section."""
        attack_chains = scan_results.get('attack_chains', [])
        
        if not attack_chains:
            return ""
        
        return f"""
        <div class="section">
            <h2>🔗 Attack Chains</h2>
            <p>Potential attack paths that combine multiple vulnerabilities:</p>
            {self._generate_attack_chains_content(attack_chains)}
        </div>
        """
    
    def _generate_attack_chains_content(self, attack_chains: List[Dict[str, Any]]) -> str:
        """Generate attack chains content."""
        chains_html = ""
        for chain in attack_chains:
            chains_html += f"""
            <div class="attack-chain">
                <h3>{chain.get('description', 'Attack Chain')}</h3>
                <p><strong>Risk Score:</strong> {chain.get('total_risk_score', 0):.1f}/10</p>
                <p><strong>Impact:</strong> {chain.get('attack_impact', 'Unknown')}</p>
                {self._generate_chain_steps(chain.get('steps', []))}
            </div>
            """
        
        return chains_html
    
    def _generate_chain_steps(self, steps: List[Dict[str, Any]]) -> str:
        """Generate chain steps."""
        steps_html = ""
        for step in steps:
            steps_html += f"""
            <div class="chain-step">
                <strong>{step.get('step', 'Step')}:</strong> {step.get('description', 'No description')}
                <br><small>Risk Score: {step.get('risk_score', 0):.1f}</small>
            </div>
            """
        
        return steps_html
    
    def _generate_recommendations_section(self, scan_results: Dict[str, Any]) -> str:
        """Generate recommendations section."""
        recommendations = scan_results.get('recommendations', [])
        
        if not recommendations:
            return ""
        
        return f"""
        <div class="section">
            <h2>💡 Security Recommendations</h2>
            {self._generate_recommendations_content(recommendations)}
        </div>
        """
    
    def _generate_recommendations_content(self, recommendations: List[Dict[str, Any]]) -> str:
        """Generate recommendations content."""
        rec_html = ""
        for rec in recommendations:
            rec_type = rec.get('type', 'info')
            if rec_type == 'success':
                rec_html += f'<div class="fix-suggestion">{rec.get("message", "")}</div>'
            else:
                rec_html += f"""
                <div class="vuln-info">
                    <strong>{rec.get('category', 'Recommendation').title()}:</strong> 
                    {rec.get('message', 'No message available')}
                    {f'<br><small>Count: {rec.get("count", 0)} | Severity: {rec.get("severity", "unknown")}</small>' if rec.get('count') else ''}
                </div>
                """
        
        return rec_html
    
    def _generate_charts_section(self, scan_results: Dict[str, Any]) -> str:
        """Generate charts section."""
        summary = scan_results.get('summary', {})
        
        return f"""
        <div class="section">
            <h2>📊 Vulnerability Distribution</h2>
            <div class="chart-container">
                <canvas id="severityChart" width="400" height="200"></canvas>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            const ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        data: [
                            {summary.get('critical_count', 0)},
                            {summary.get('high_count', 0)},
                            {summary.get('medium_count', 0)},
                            {summary.get('low_count', 0)}
                        ],
                        backgroundColor: [
                            '#e74c3c',
                            '#f39c12', 
                            '#f1c40f',
                            '#27ae60'
                        ]
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom'
                        }}
                    }}
                }}
            }});
        </script>
        """
