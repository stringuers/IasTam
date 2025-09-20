#!/usr/bin/env python3
"""
DefenSys Enhanced Demo Script
Demonstrates the advanced features of the DefenSys AI Security Platform
"""

import os
import sys
import json
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from defensys_analyzer_enhanced import DefenSysAnalyzer
from defensys_cli_api_enhanced import DefenSysCLI

def print_banner():
    """Print the DefenSys banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    🛡️  DEFENSYS AI SECURITY PLATFORM - ENHANCED DEMO        ║
    ║                                                              ║
    ║    Where Intelligence Meets Security                        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def create_demo_files():
    """Create demo files with various vulnerabilities"""
    demo_dir = Path("demo_vulnerable_code")
    demo_dir.mkdir(exist_ok=True)
    
    # SQL Injection vulnerabilities
    sql_injection_code = '''
// SQL Injection vulnerabilities for testing
const express = require('express');
const mysql = require('mysql');
const app = express();

// Vulnerable: Direct string concatenation
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    mysql.query(query, (err, results) => {
        res.json(results);
    });
});

// Vulnerable: Template string injection
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    mysql.query(query, (err, results) => {
        if (results.length > 0) {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    });
});

// Safe: Parameterized query (should not trigger)
app.get('/safe-users/:id', (req, res) => {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = ?";
    mysql.query(query, [userId], (err, results) => {
        res.json(results);
    });
});
'''
    
    # XSS vulnerabilities
    xss_code = '''
// XSS vulnerabilities for testing
function displayMessage(userInput) {
    // Vulnerable: Direct innerHTML assignment
    document.getElementById('message').innerHTML = userInput;
}

function showAlert(message) {
    // Vulnerable: eval usage
    eval('alert("' + message + '")');
}

// Vulnerable: document.write
function writeContent(content) {
    document.write("<div>" + content + "</div>");
}

// React XSS vulnerability
function UserProfile({ user }) {
    return (
        <div dangerouslySetInnerHTML={{__html: user.bio}} />
    );
}

// Safe alternative (should not trigger)
function safeDisplayMessage(userInput) {
    document.getElementById('message').textContent = userInput;
}
'''
    
    # Authentication issues
    auth_code = '''
// Authentication vulnerabilities
const jwt = require('jsonwebtoken');

// Vulnerable: Hardcoded secret
const secret = 'my-super-secret-key';
const token = jwt.sign({ userId: 123 }, secret);

// Vulnerable: Hardcoded password
const adminPassword = 'admin123';
if (password === adminPassword) {
    // Grant access
}

// Vulnerable: Weak JWT secret
const weakSecret = '123456';
const weakToken = jwt.sign({ userId: 123 }, weakSecret);

// Safe: Environment variable
const safeSecret = process.env.JWT_SECRET;
const safeToken = jwt.sign({ userId: 123 }, safeSecret);
'''
    
    # Configuration issues
    config_code = '''
// Security misconfigurations
const cors = require('cors');
const https = require('https');

// Vulnerable: Open CORS
app.use(cors({
    origin: true,
    credentials: true
}));

// Vulnerable: Disabled SSL verification
const agent = new https.Agent({
    rejectUnauthorized: false
});

// Vulnerable: Disabled TLS rejection
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Safe configuration
app.use(cors({
    origin: ['https://trusted-domain.com'],
    credentials: true
}));
'''
    
    # Write demo files
    (demo_dir / "sql_injection.js").write_text(sql_injection_code)
    (demo_dir / "xss_vulnerabilities.js").write_text(xss_code)
    (demo_dir / "auth_issues.js").write_text(auth_code)
    (demo_dir / "config_issues.js").write_text(config_code)
    
    return demo_dir

def run_enhanced_demo():
    """Run the enhanced DefenSys demo"""
    print_banner()
    
    print("🚀 Creating demo vulnerable code...")
    demo_dir = create_demo_files()
    print(f"✅ Created demo files in: {demo_dir}")
    
    print("\n" + "="*60)
    print("🔍 RUNNING ENHANCED DEFENSYS ANALYSIS")
    print("="*60)
    
    # Initialize the enhanced analyzer
    analyzer = DefenSysAnalyzer()
    cli = DefenSysCLI()
    
    print(f"\n📁 Scanning directory: {demo_dir}")
    print("🔍 Analyzing files for vulnerabilities...")
    
    # Scan the demo directory
    results = cli.scan_directory(str(demo_dir), recursive=True, output_format='console')
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    # Generate and display console report
    console_report = cli.generate_report(results, 'console')
    print("\n" + console_report)
    
    # Generate HTML report
    print("\n📊 Generating HTML report...")
    html_report = cli.generate_report(results, 'html')
    html_file = Path("defensys_demo_report.html")
    html_file.write_text(html_report)
    print(f"✅ HTML report saved to: {html_file}")
    
    # Generate JSON report
    print("\n📄 Generating JSON report...")
    json_report = cli.generate_report(results, 'json')
    json_file = Path("defensys_demo_results.json")
    json_file.write_text(json_report)
    print(f"✅ JSON report saved to: {json_file}")
    
    # Show attack chain analysis
    print("\n🔗 ATTACK CHAIN ANALYSIS")
    print("-" * 40)
    
    total_chains = 0
    for file_result in results['files']:
        if file_result.get('attack_chains'):
            total_chains += len(file_result['attack_chains'])
            print(f"\n📁 {file_result['file']}:")
            for chain in file_result['attack_chains']:
                print(f"  🎯 {chain['chain_id']}: {chain['description']}")
                print(f"     Impact: {chain['impact']}")
                print(f"     Steps: {' → '.join(chain['steps'])}")
    
    if total_chains == 0:
        print("✅ No attack chains detected")
    else:
        print(f"\n🔗 Total attack chains found: {total_chains}")
    
    # Show risk assessment
    risk = results['overall_risk_assessment']
    print(f"\n🎯 OVERALL RISK ASSESSMENT")
    print("-" * 30)
    print(f"Risk Level: {risk['risk_level']}")
    print(f"Average Risk Score: {risk['average_risk_score']}/100")
    
    # Show recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    print(risk['recommendation'])
    
    # Show file statistics
    metadata = results['scan_metadata']
    print(f"\n📊 SCAN STATISTICS")
    print("-" * 20)
    print(f"Files Scanned: {metadata['files_scanned']}")
    print(f"Total Vulnerabilities: {metadata['total_vulnerabilities']}")
    print(f"Critical Issues: {metadata['critical_issues']}")
    print(f"High Priority Issues: {metadata['high_issues']}")
    
    print(f"\n🎉 Demo completed! Check the generated reports:")
    print(f"   📊 HTML Report: {html_file}")
    print(f"   📄 JSON Report: {json_file}")
    
    # Cleanup
    print(f"\n🧹 Cleaning up demo files...")
    import shutil
    shutil.rmtree(demo_dir)
    print("✅ Demo files cleaned up")

def main():
    """Main demo function"""
    try:
        run_enhanced_demo()
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
