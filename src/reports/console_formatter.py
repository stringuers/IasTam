"""
Console formatter for DefenSys.

This module provides formatted console output for scan results with colors,
tables, and progress indicators.
"""

from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box
from datetime import datetime


class ConsoleFormatter:
    """
    Console formatter for DefenSys scan results.
    
    This class provides beautiful, colored console output for scan results
    using the Rich library.
    """
    
    def __init__(self):
        self.console = Console()
    
    def format_results(self, scan_results: Dict[str, Any]) -> str:
        """
        Format scan results for console output.
        
        Args:
            scan_results: Dictionary containing scan results
            
        Returns:
            Formatted string for console output
        """
        output = []
        
        # Header
        output.append(self._format_header(scan_results))
        
        # Summary
        output.append(self._format_summary(scan_results))
        
        # Vulnerabilities
        output.append(self._format_vulnerabilities(scan_results))
        
        # Attack chains
        output.append(self._format_attack_chains(scan_results))
        
        # Recommendations
        output.append(self._format_recommendations(scan_results))
        
        return "\n".join(output)
    
    def _format_header(self, scan_results: Dict[str, Any]) -> str:
        """Format the header section."""
        scan_info = scan_results.get('scan_info', {})
        target_path = scan_info.get('target_path', 'Unknown')
        timestamp = scan_info.get('timestamp', datetime.now().timestamp())
        
        header_text = Text()
        header_text.append("🛡️ ", style="bold blue")
        header_text.append("DefenSys Security Report", style="bold white")
        header_text.append("\n", style="white")
        header_text.append("AI-Powered Vulnerability Analysis", style="italic white")
        header_text.append("\n", style="white")
        header_text.append(f"Target: {target_path}", style="dim white")
        header_text.append("\n", style="white")
        header_text.append(f"Generated: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}", style="dim white")
        
        panel = Panel(header_text, box=box.DOUBLE, style="blue")
        return str(panel)
    
    def _format_summary(self, scan_results: Dict[str, Any]) -> str:
        """Format the summary section."""
        summary = scan_results.get('summary', {})
        
        table = Table(title="📊 Scan Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", style="magenta", justify="right")
        table.add_column("Status", style="green")
        
        total_vulns = summary.get('total_vulnerabilities', 0)
        critical = summary.get('critical_count', 0)
        high = summary.get('high_count', 0)
        medium = summary.get('medium_count', 0)
        low = summary.get('low_count', 0)
        attack_chains = summary.get('attack_chains', 0)
        
        # Add rows with appropriate styling
        table.add_row("Total Vulnerabilities", str(total_vulns), self._get_status_emoji(total_vulns))
        table.add_row("Critical", str(critical), self._get_severity_emoji(critical, "critical"))
        table.add_row("High", str(high), self._get_severity_emoji(high, "high"))
        table.add_row("Medium", str(medium), self._get_severity_emoji(medium, "medium"))
        table.add_row("Low", str(low), self._get_severity_emoji(low, "low"))
        table.add_row("Attack Chains", str(attack_chains), self._get_status_emoji(attack_chains))
        
        return str(table)
    
    def _format_vulnerabilities(self, scan_results: Dict[str, Any]) -> str:
        """Format the vulnerabilities section."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return self._format_no_vulnerabilities()
        
        # Group by severity
        vuln_by_severity = self._group_vulnerabilities_by_severity(vulnerabilities)
        
        output = []
        output.append("\n🔍 Vulnerability Details\n")
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in vuln_by_severity:
                output.append(self._format_severity_section(severity, vuln_by_severity[severity]))
        
        return "\n".join(output)
    
    def _format_no_vulnerabilities(self) -> str:
        """Format message when no vulnerabilities are found."""
        text = Text()
        text.append("🎉 ", style="bold green")
        text.append("No vulnerabilities found!", style="bold green")
        text.append("\n", style="white")
        text.append("Your code appears to be secure.", style="white")
        
        panel = Panel(text, box=box.ROUNDED, style="green")
        return str(panel)
    
    def _group_vulnerabilities_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by severity."""
        groups = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity not in groups:
                groups[severity] = []
            groups[severity].append(vuln)
        return groups
    
    def _format_severity_section(self, severity: str, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format a section for a specific severity level."""
        severity_colors = {
            'critical': 'red',
            'high': 'yellow',
            'medium': 'blue',
            'low': 'green'
        }
        
        color = severity_colors.get(severity, 'white')
        severity_emoji = self._get_severity_emoji(len(vulnerabilities), severity)
        
        text = Text()
        text.append(f"{severity_emoji} ", style=f"bold {color}")
        text.append(f"{severity.upper()} ({len(vulnerabilities)})", style=f"bold {color}")
        
        output = [str(Panel(text, box=box.ROUNDED, style=color))]
        
        for i, vuln in enumerate(vulnerabilities, 1):
            output.append(self._format_vulnerability_item(vuln, i))
        
        return "\n".join(output)
    
    def _format_vulnerability_item(self, vuln: Dict[str, Any], index: int) -> str:
        """Format a single vulnerability item."""
        title = vuln.get('title', 'Unknown Vulnerability')
        description = vuln.get('description', 'No description available')
        location = vuln.get('location', {})
        file_path = location.get('file_path', 'Unknown')
        line_number = location.get('line_number', '?')
        cwe_id = vuln.get('cwe_id', 'N/A')
        owasp_category = vuln.get('owasp_category', 'N/A')
        
        # Create vulnerability details
        details = []
        details.append(f"  {index}. {title}")
        details.append(f"     Description: {description}")
        details.append(f"     Location: {file_path}:{line_number}")
        details.append(f"     CWE: {cwe_id} | OWASP: {owasp_category}")
        
        # Add code snippet if available
        code_snippet = vuln.get('code_snippet')
        if code_snippet:
            details.append(f"     Code: {code_snippet}")
        
        # Add fix suggestions if available
        fix_suggestions = vuln.get('fix_suggestions', [])
        if fix_suggestions:
            details.append("     Fix Suggestions:")
            for suggestion in fix_suggestions[:2]:  # Limit to first 2 suggestions
                desc = suggestion.get('description', 'No suggestion available')
                details.append(f"       • {desc}")
        
        return "\n".join(details)
    
    def _format_attack_chains(self, scan_results: Dict[str, Any]) -> str:
        """Format the attack chains section."""
        attack_chains = scan_results.get('attack_chains', [])
        
        if not attack_chains:
            return ""
        
        output = []
        output.append("\n🔗 Attack Chains\n")
        
        for i, chain in enumerate(attack_chains, 1):
            output.append(self._format_attack_chain(chain, i))
        
        return "\n".join(output)
    
    def _format_attack_chain(self, chain: Dict[str, Any], index: int) -> str:
        """Format a single attack chain."""
        description = chain.get('description', 'Attack Chain')
        risk_score = chain.get('total_risk_score', 0)
        impact = chain.get('attack_impact', 'Unknown')
        steps = chain.get('steps', [])
        
        # Create chain details
        details = []
        details.append(f"  {index}. {description}")
        details.append(f"     Risk Score: {risk_score:.1f}/10")
        details.append(f"     Impact: {impact}")
        
        if steps:
            details.append("     Steps:")
            for j, step in enumerate(steps[:3], 1):  # Limit to first 3 steps
                step_desc = step.get('description', 'Unknown step')
                step_risk = step.get('risk_score', 0)
                details.append(f"       {j}. {step_desc} (Risk: {step_risk:.1f})")
        
        text = Text("\n".join(details))
        panel = Panel(text, box=box.ROUNDED, style="yellow")
        return str(panel)
    
    def _format_recommendations(self, scan_results: Dict[str, Any]) -> str:
        """Format the recommendations section."""
        recommendations = scan_results.get('recommendations', [])
        
        if not recommendations:
            return ""
        
        output = []
        output.append("\n💡 Security Recommendations\n")
        
        for i, rec in enumerate(recommendations, 1):
            output.append(self._format_recommendation(rec, i))
        
        return "\n".join(output)
    
    def _format_recommendation(self, rec: Dict[str, Any], index: int) -> str:
        """Format a single recommendation."""
        rec_type = rec.get('type', 'info')
        message = rec.get('message', 'No recommendation available')
        
        if rec_type == 'success':
            text = Text()
            text.append("✅ ", style="bold green")
            text.append(message, style="green")
            return str(Panel(text, box=box.ROUNDED, style="green"))
        else:
            category = rec.get('category', 'Recommendation')
            count = rec.get('count', 0)
            severity = rec.get('severity', 'unknown')
            
            details = []
            details.append(f"  {index}. {category}")
            details.append(f"     {message}")
            if count > 0:
                details.append(f"     Count: {count} | Severity: {severity}")
            
            text = Text("\n".join(details))
            panel = Panel(text, box=box.ROUNDED, style="blue")
            return str(panel)
    
    def _get_status_emoji(self, count: int) -> str:
        """Get emoji based on count."""
        if count == 0:
            return "✅"
        elif count < 5:
            return "⚠️"
        else:
            return "❌"
    
    def _get_severity_emoji(self, count: int, severity: str) -> str:
        """Get emoji based on severity and count."""
        if count == 0:
            return "✅"
        
        severity_emojis = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        
        return severity_emojis.get(severity, '⚪')
    
    def format_progress(self, message: str) -> str:
        """Format a progress message."""
        text = Text()
        text.append("🔄 ", style="bold blue")
        text.append(message, style="white")
        return str(text)
    
    def format_error(self, message: str) -> str:
        """Format an error message."""
        text = Text()
        text.append("❌ ", style="bold red")
        text.append(message, style="red")
        return str(text)
    
    def format_success(self, message: str) -> str:
        """Format a success message."""
        text = Text()
        text.append("✅ ", style="bold green")
        text.append(message, style="green")
        return str(text)
