#!/usr/bin/env python3
"""
DefenSys Simple Demo Script
Demonstrates the core functionality of the DefenSys AI Security Platform
"""

import os
import sys
import json
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def print_banner():
    """Print the DefenSys banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    🛡️  DEFENSYS AI SECURITY PLATFORM - SIMPLE DEMO          ║
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

def simple_vulnerability_scanner(file_path):
    """Simple vulnerability scanner for demo purposes"""
    vulnerabilities = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # SQL Injection patterns
        sql_patterns = [
            r'query\s*\(\s*["\'].*?\+.*?["\']',
            r'SELECT.*?\+.*?FROM',
            r'INSERT.*?\+.*?VALUES',
            r'UPDATE.*?\+.*?SET',
            r'DELETE.*?\+.*?WHERE'
        ]
        
        # XSS patterns
        xss_patterns = [
            r'innerHTML\s*=\s*.*?\+',
            r'document\.write\s*\(\s*.*?\+',
            r'eval\s*\(\s*.*?\+',
            r'dangerouslySetInnerHTML.*?__html\s*:'
        ]
        
        # Auth patterns
        auth_patterns = [
            r'password\s*===?\s*["\'].*?["\']',
            r'token\s*===?\s*["\'].*?["\']',
            r'secret\s*===?\s*["\'].*?["\']'
        ]
        
        # Config patterns
        config_patterns = [
            r'cors\s*:\s*true',
            r'rejectUnauthorized\s*:\s*false',
            r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']0["\']'
        ]
        
        import re
        
        # Check for SQL injection
        for i, line in enumerate(lines):
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'line': i + 1,
                        'description': 'Potential SQL injection vulnerability detected',
                        'code': line.strip(),
                        'fix': 'Use parameterized queries or prepared statements'
                    })
        
        # Check for XSS
        for i, line in enumerate(lines):
            for pattern in xss_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'line': i + 1,
                        'description': 'Potential XSS vulnerability detected',
                        'code': line.strip(),
                        'fix': 'Sanitize user input before rendering'
                    })
        
        # Check for auth issues
        for i, line in enumerate(lines):
            for pattern in auth_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = 'Critical' if 'password' in line.lower() or 'secret' in line.lower() else 'High'
                    vulnerabilities.append({
                        'type': 'Authentication Issue',
                        'severity': severity,
                        'line': i + 1,
                        'description': 'Hardcoded credentials or weak authentication detected',
                        'code': line.strip(),
                        'fix': 'Use environment variables for sensitive data'
                    })
        
        # Check for config issues
        for i, line in enumerate(lines):
            for pattern in config_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'Medium',
                        'line': i + 1,
                        'description': 'Insecure configuration detected',
                        'code': line.strip(),
                        'fix': 'Review and secure configuration settings'
                    })
        
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
    
    return vulnerabilities

def run_simple_demo():
    """Run the simple DefenSys demo"""
    print_banner()
    
    print("🚀 Creating demo vulnerable code...")
    demo_dir = create_demo_files()
    print(f"✅ Created demo files in: {demo_dir}")
    
    print("\n" + "="*60)
    print("🔍 RUNNING DEFENSYS SECURITY ANALYSIS")
    print("="*60)
    
    all_vulnerabilities = []
    total_files = 0
    
    # Scan all JavaScript files
    for file_path in demo_dir.glob("*.js"):
        total_files += 1
        print(f"\n📁 Scanning: {file_path.name}")
        
        vulnerabilities = simple_vulnerability_scanner(file_path)
        all_vulnerabilities.extend(vulnerabilities)
        
        if vulnerabilities:
            print(f"   Found {len(vulnerabilities)} vulnerabilities:")
            for vuln in vulnerabilities:
                emoji = {'Critical': '🚨', 'High': '⚠️', 'Medium': '⚡', 'Low': '💡'}
                print(f"   {emoji.get(vuln['severity'], '❓')} Line {vuln['line']}: {vuln['type']} ({vuln['severity']})")
        else:
            print("   ✅ No vulnerabilities found")
    
    # Generate summary report
    print("\n" + "="*60)
    print("📊 SECURITY ANALYSIS SUMMARY")
    print("="*60)
    
    print(f"📁 Files Scanned: {total_files}")
    print(f"🔍 Total Vulnerabilities: {len(all_vulnerabilities)}")
    
    # Count by severity
    critical = len([v for v in all_vulnerabilities if v['severity'] == 'Critical'])
    high = len([v for v in all_vulnerabilities if v['severity'] == 'High'])
    medium = len([v for v in all_vulnerabilities if v['severity'] == 'Medium'])
    low = len([v for v in all_vulnerabilities if v['severity'] == 'Low'])
    
    print(f"🚨 Critical: {critical}")
    print(f"⚠️  High: {high}")
    print(f"⚡ Medium: {medium}")
    print(f"💡 Low: {low}")
    
    # Calculate risk score
    risk_score = (critical * 25) + (high * 15) + (medium * 8) + (low * 3)
    risk_score = min(risk_score, 100)
    
    print(f"\n🎯 Risk Score: {risk_score}/100")
    
    if risk_score >= 70:
        risk_level = "CRITICAL"
        emoji = "🚨"
    elif risk_score >= 50:
        risk_level = "HIGH"
        emoji = "⚠️"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
        emoji = "⚡"
    else:
        risk_level = "LOW"
        emoji = "✅"
    
    print(f"📈 Risk Level: {emoji} {risk_level}")
    
    # Show detailed vulnerabilities
    if all_vulnerabilities:
        print(f"\n📋 DETAILED VULNERABILITIES")
        print("-" * 40)
        
        for i, vuln in enumerate(all_vulnerabilities, 1):
            print(f"\n{i}. {vuln['type']} ({vuln['severity']})")
            print(f"   File: Line {vuln['line']}")
            print(f"   Description: {vuln['description']}")
            print(f"   Code: {vuln['code']}")
            print(f"   Fix: {vuln['fix']}")
    
    # Generate recommendations
    print(f"\n💡 RECOMMENDATIONS")
    print("-" * 20)
    
    if critical > 0:
        print("🚨 IMMEDIATE ACTION REQUIRED:")
        print("- Fix all critical vulnerabilities before deployment")
        print("- Implement proper input validation")
        print("- Use parameterized queries for database operations")
    
    if high > 0:
        print("⚠️ HIGH PRIORITY:")
        print("- Address high-severity issues")
        print("- Implement secure coding practices")
        print("- Add security testing to CI/CD pipeline")
    
    if medium > 0:
        print("⚡ MEDIUM PRIORITY:")
        print("- Review and fix configuration issues")
        print("- Implement security headers")
        print("- Regular security audits")
    
    if risk_score < 30:
        print("✅ GOOD SECURITY POSTURE:")
        print("- Continue current security practices")
        print("- Regular security scanning")
        print("- Keep dependencies updated")
    
    # Save results to JSON
    results = {
        'scan_metadata': {
            'total_files': total_files,
            'total_vulnerabilities': len(all_vulnerabilities),
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low,
            'risk_score': risk_score,
            'risk_level': risk_level
        },
        'vulnerabilities': all_vulnerabilities
    }
    
    json_file = Path("defensys_demo_results.json")
    json_file.write_text(json.dumps(results, indent=2))
    print(f"\n📄 Results saved to: {json_file}")
    
    # Cleanup
    print(f"\n🧹 Cleaning up demo files...")
    import shutil
    shutil.rmtree(demo_dir)
    print("✅ Demo files cleaned up")
    
    print(f"\n🎉 Demo completed! DefenSys successfully detected {len(all_vulnerabilities)} vulnerabilities.")
    print("This demonstrates how DefenSys can help secure your code before deployment!")

def main():
    """Main demo function"""
    try:
        run_simple_demo()
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
