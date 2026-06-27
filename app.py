from flask import Flask, render_template, request, jsonify
import re
import json
import urllib.request
import ssl
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# ============ SMART CONTRACT VULNERABILITY RULES ============
VULNERABILITY_PATTERNS = {
    "reentrancy": {
        "pattern": r"(call\{value:|\.call\s*\(.*?)\s*\{.*?value:",
        "severity": "CRITICAL",
        "description": "External call before state update can lead to reentrancy attacks (e.g., The DAO hack).",
        "fix": "Update state variables BEFORE external calls. Use Checks-Effects-Interactions pattern.",
        "example_bad": "(bool success,) = msg.sender.call{value: balance}(''); balances[msg.sender] = 0;",
        "example_good": "balances[msg.sender] = 0; (bool success,) = msg.sender.call{value: balance}('');"
    },
    "unchecked_send": {
        "pattern": r"(\.send\s*\(|\.transfer\s*\()",
        "severity": "HIGH",
        "description": "Using .send() or .transfer() without checking return value can fail silently.",
        "fix": "Use low-level .call() with proper error handling, or check return value explicitly.",
        "example_bad": "msg.sender.transfer(amount);",
        "example_good": "(bool success,) = msg.sender.call{value: amount}(''); require(success, 'Transfer failed');"
    },
    "tx_origin": {
        "pattern": r"tx\.origin",
        "severity": "CRITICAL",
        "description": "Using tx.origin for authorization is vulnerable to phishing attacks.",
        "fix": "Always use msg.sender for authorization checks.",
        "example_bad": "require(tx.origin == owner);",
        "example_good": "require(msg.sender == owner);"
    },
    "integer_overflow": {
        "pattern": r"(\+\+[^;]*;|[^+]+\+[^+]*;|uint\d*\s+\w+\s*=\s*\w+\s*[*+])",
        "severity": "HIGH",
        "description": "Solidity <0.8.0 has no built-in overflow protection. Arithmetic can wrap around.",
        "fix": "Use Solidity ^0.8.0 (has built-in checks) or OpenZeppelin SafeMath library.",
        "example_bad": "uint256 result = a + b; // Can overflow",
        "example_good": "uint256 result = a + b; // Safe in Solidity ^0.8.0"
    },
    "delegatecall": {
        "pattern": r"delegatecall",
        "severity": "CRITICAL",
        "description": "delegatecall preserves context - can lead to storage collision and self-destruct attacks.",
        "fix": "Use delegatecall only with trusted, verified contracts. Implement proxy patterns carefully.",
        "example_bad": "target.delegatecall(data);",
        "example_good": "require(isTrusted[target], 'Untrusted target'); target.delegatecall(data);"
    },
    "selfdestruct": {
        "pattern": r"selfdestruct",
        "severity": "HIGH",
        "description": "selfdestruct can forcibly send ETH and destroy contract, bypassing fallback functions.",
        "fix": "Remove selfdestruct unless absolutely necessary. Add multi-sig or timelock controls.",
        "example_bad": "selfdestruct(payable(msg.sender));",
        "example_good": "// Avoid selfdestruct. Use pause() + withdraw() pattern instead."
    },
    "timestamp_dependence": {
        "pattern": r"(block\.timestamp|now\b)",
        "severity": "MEDIUM",
        "description": "Miners can manipulate block.timestamp slightly (+-15 seconds), affecting game mechanics.",
        "fix": "Don't use timestamp for critical randomness or time-sensitive logic. Use block.number instead.",
        "example_bad": "if (block.timestamp % 2 == 0) winner = player;",
        "example_good": "uint256 random = uint256(keccak256(abi.encodePacked(blockhash(block.number-1))));"
    },
    "randomness": {
        "pattern": r"(keccak256\s*\(\s*abi\.encodePacked\s*\(\s*block\.timestamp|block\.difficulty|blockhash)",
        "severity": "HIGH",
        "description": "On-chain randomness is predictable. Miners can influence blockhash/timestamp.",
        "fix": "Use Chainlink VRF (Verifiable Random Function) for secure randomness.",
        "example_bad": "uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));",
        "example_good": "uint256 rand = vrfCoordinator.requestRandomWords(keyHash, subId, minReqConf, callbackGasLimit, numWords);"
    },
    "access_control": {
        "pattern": r"(function\s+\w+\s*\(.*?\)\s*\{[^}]*\})(?!.*?(onlyOwner|require\s*\(\s*msg\.sender|modifier\s+\w*Owner))",
        "severity": "HIGH",
        "description": "Sensitive functions lack access control. Anyone can call critical functions.",
        "fix": "Add onlyOwner modifier or require(msg.sender == owner) checks.",
        "example_bad": "function withdraw() public { payable(msg.sender).transfer(address(this).balance); }",
        "example_good": "function withdraw() public onlyOwner { payable(msg.sender).transfer(address(this).balance); }"
    },
    "uninitialized_storage": {
        "pattern": r"(\w+\s+storage\s+\w+;|\w+\s+storage\s+\w+\s*=\s*\w+\[)[^;]*;",
        "severity": "MEDIUM",
        "description": "Uninitialized storage pointers can point to slot 0, corrupting critical state.",
        "fix": "Always initialize storage variables explicitly. Use memory for temporary data.",
        "example_bad": "User storage user; user.balance = 100;",
        "example_good": "User storage user = users[msg.sender]; user.balance = 100;"
    }
}

# ============ WEBSITE SECURITY SCANNER ============
WEB_SECURITY_CHECKS = {
    "missing_https": {
        "severity": "CRITICAL",
        "description": "Website does not use HTTPS. All data transmitted is unencrypted and vulnerable to interception.",
        "fix": "Enable SSL/TLS certificate. Use Let's Encrypt for free HTTPS. Redirect all HTTP traffic to HTTPS.",
        "impact": "Man-in-the-middle attacks, credential theft, session hijacking"
    },
    "missing_security_headers": {
        "severity": "HIGH",
        "description": "Critical security headers are missing. The site is vulnerable to XSS, clickjacking, and MIME sniffing attacks.",
        "fix": "Add headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security",
        "impact": "XSS, clickjacking, drive-by downloads"
    },
    "exposed_server_info": {
        "severity": "MEDIUM",
        "description": "Server version and technology stack are exposed in headers, aiding attackers in targeted exploits.",
        "fix": "Remove Server, X-Powered-By headers. Use generic server signatures.",
        "impact": "Targeted exploits using known CVEs"
    },
    "missing_csp": {
        "severity": "HIGH",
        "description": "No Content Security Policy header. The site is vulnerable to XSS and data injection attacks.",
        "fix": "Implement CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "impact": "Cross-site scripting, data exfiltration"
    },
    "clickjacking_risk": {
        "severity": "HIGH",
        "description": "No X-Frame-Options header. Site can be embedded in malicious iframes for clickjacking attacks.",
        "fix": "Add X-Frame-Options: DENY or SAMEORIGIN header",
        "impact": "UI redressing, unauthorized actions"
    },
    "missing_hsts": {
        "severity": "MEDIUM",
        "description": "No HTTP Strict Transport Security header. Users can be downgraded to HTTP connections.",
        "fix": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "impact": "SSL stripping attacks"
    },
    "insecure_cookies": {
        "severity": "HIGH",
        "description": "Cookies are set without Secure, HttpOnly, or SameSite flags, making them vulnerable to theft.",
        "fix": "Set Secure, HttpOnly, and SameSite=Strict flags on all cookies",
        "impact": "Session hijacking, CSRF attacks"
    },
    "open_directory_listing": {
        "severity": "MEDIUM",
        "description": "Directory listing is enabled, exposing file structure and potentially sensitive files.",
        "fix": "Disable directory listing in web server config (Options -Indexes in Apache)",
        "impact": "Information disclosure"
    },
    "missing_referrer_policy": {
        "severity": "LOW",
        "description": "No Referrer-Policy header. Sensitive URL data may leak to third-party sites.",
        "fix": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "impact": "Information leakage"
    },
    "missing_permissions_policy": {
        "severity": "LOW",
        "description": "No Permissions-Policy header. Browser features may be abused by malicious scripts.",
        "fix": "Add Permissions-Policy header restricting camera, microphone, geolocation",
        "impact": "Privacy violations"
    }
}

def fetch_website(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        response = urllib.request.urlopen(req, timeout=10, context=ctx)
        headers = dict(response.headers)
        content = response.read().decode('utf-8', errors='ignore')[:50000]
        status = response.getcode()
        final_url = response.geturl()
        return {
            "success": True,
            "url": final_url,
            "status": status,
            "headers": headers,
            "content": content,
            "is_https": final_url.startswith('https://')
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "url": url
        }

def analyze_website_security(data):
    findings = []
    headers = {k.lower(): v for k, v in data["headers"].items()}
    content = data["content"].lower()
    is_https = data["is_https"]

    if not is_https:
        findings.append({
            "id": "missing_https",
            "severity": "CRITICAL",
            "title": "Missing HTTPS Encryption",
            "description": WEB_SECURITY_CHECKS["missing_https"]["description"],
            "fix": WEB_SECURITY_CHECKS["missing_https"]["fix"],
            "impact": WEB_SECURITY_CHECKS["missing_https"]["impact"],
            "confidence": "100%",
            "location": "Protocol Layer"
        })

    security_headers = {
        'content-security-policy': 'missing_csp',
        'x-frame-options': 'clickjacking_risk',
        'strict-transport-security': 'missing_hsts',
        'x-content-type-options': 'missing_security_headers',
        'x-xss-protection': 'missing_security_headers',
        'referrer-policy': 'missing_referrer_policy',
        'permissions-policy': 'missing_permissions_policy'
    }

    for header, check_id in security_headers.items():
        if header not in headers:
            if check_id not in [f["id"] for f in findings]:
                check = WEB_SECURITY_CHECKS[check_id]
                findings.append({
                    "id": check_id,
                    "severity": check["severity"],
                    "title": check_id.replace("_", " ").title(),
                    "description": check["description"],
                    "fix": check["fix"],
                    "impact": check["impact"],
                    "confidence": "95%",
                    "location": "HTTP Response Headers"
                })

    server_header = headers.get('server', '')
    powered_by = headers.get('x-powered-by', '')
    if server_header or powered_by:
        findings.append({
            "id": "exposed_server_info",
            "severity": "MEDIUM",
            "title": "Exposed Server Information",
            "description": f"Server reveals technology: {server_header or powered_by}",
            "fix": WEB_SECURITY_CHECKS["exposed_server_info"]["fix"],
            "impact": WEB_SECURITY_CHECKS["exposed_server_info"]["impact"],
            "confidence": "98%",
            "location": "HTTP Headers"
        })

    if 'set-cookie' in headers:
        cookies = headers['set-cookie']
        if 'secure' not in cookies.lower() or 'httponly' not in cookies.lower():
            findings.append({
                "id": "insecure_cookies",
                "severity": "HIGH",
                "title": "Insecure Cookie Configuration",
                "description": WEB_SECURITY_CHECKS["insecure_cookies"]["description"],
                "fix": WEB_SECURITY_CHECKS["insecure_cookies"]["fix"],
                "impact": WEB_SECURITY_CHECKS["insecure_cookies"]["impact"],
                "confidence": "92%",
                "location": "Cookie Headers"
            })

    if '<title>index of' in content or 'directory listing' in content:
        findings.append({
            "id": "open_directory_listing",
            "severity": "MEDIUM",
            "title": "Open Directory Listing",
            "description": WEB_SECURITY_CHECKS["open_directory_listing"]["description"],
            "fix": WEB_SECURITY_CHECKS["open_directory_listing"]["fix"],
            "impact": WEB_SECURITY_CHECKS["open_directory_listing"]["impact"],
            "confidence": "90%",
            "location": "Directory Index"
        })

    sensitive_patterns = [
        (r'\.env', "Exposed .env file reference"),
        (r'config\.php', "Exposed config file reference"),
        (r'\.git/', "Exposed .git directory"),
        (r'phpmyadmin', "phpMyAdmin exposed"),
        (r'admin\.php|admin\.html', "Admin panel exposed"),
        (r'wp-config', "WordPress config exposed"),
        (r'\.sql', "Database dump exposed"),
        (r'\.backup', "Backup file exposed")
    ]

    for pattern, desc in sensitive_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append({
                "id": "sensitive_exposure",
                "severity": "HIGH",
                "title": "Sensitive Resource Exposure",
                "description": f"Potential {desc} found in page content or links.",
                "fix": "Remove sensitive files from public access. Use .htaccess or nginx deny rules.",
                "impact": "Information disclosure, unauthorized access",
                "confidence": "85%",
                "location": "Page Content"
            })
            break

    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
    dangerous_patterns = ['eval(', 'document.write', 'innerHTML', 'onclick=', 'onerror=']
    has_dangerous = any(any(p in s.lower() for p in dangerous_patterns) for s in inline_scripts)

    if has_dangerous:
        findings.append({
            "id": "xss_risk",
            "severity": "HIGH",
            "title": "Potential XSS Vectors",
            "description": "Dangerous JavaScript patterns detected (eval, document.write, inline event handlers). These can be exploited for XSS attacks.",
            "fix": "Remove eval(), use textContent instead of innerHTML, avoid inline event handlers. Implement CSP with script-src directive.",
            "impact": "Cross-site scripting, session theft, malware distribution",
            "confidence": "88%",
            "location": "JavaScript Content"
        })

    forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL | re.IGNORECASE)
    for form in forms:
        if 'method="post"' in form.lower() and 'csrf' not in form.lower() and '_token' not in form.lower():
            findings.append({
                "id": "missing_csrf",
                "severity": "HIGH",
                "title": "Missing CSRF Protection",
                "description": "POST forms detected without CSRF tokens. Attackers can forge requests on behalf of authenticated users.",
                "fix": "Add CSRF tokens to all state-changing forms. Use synchronizer token pattern or double-submit cookie.",
                "impact": "Account takeover, unauthorized actions, data manipulation",
                "confidence": "90%",
                "location": "HTML Forms"
            })
            break

    if '<input type="password"' in content.lower() and 'autocomplete="off"' not in content.lower():
        findings.append({
            "id": "password_autocomplete",
            "severity": "LOW",
            "title": "Password Autocomplete Enabled",
            "description": "Password fields allow browser autocomplete, which may store credentials on shared computers.",
            "fix": "Add autocomplete=\"off\" or autocomplete=\"new-password\" to password inputs.",
            "impact": "Credential exposure on shared devices",
            "confidence": "95%",
            "location": "Login Forms"
        })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 99))
    return findings

def calculate_website_score(findings):
    base_score = 100
    severity_weights = {"CRITICAL": -20, "HIGH": -12, "MEDIUM": -6, "LOW": -2}
    for finding in findings:
        base_score += severity_weights.get(finding["severity"], -3)
    return max(0, min(100, base_score))

def generate_website_summary(findings, score, url):
    domain = urlparse(url).netloc or url
    if score >= 90:
        return f"{domain} appears well-secured with strong security headers and HTTPS configuration. Good security posture detected."
    elif score >= 70:
        return f"{domain} has moderate security concerns. {len(findings)} issues found - mostly addressable with header configurations. Recommend implementing missing security headers."
    elif score >= 50:
        return f"Significant vulnerabilities detected on {domain} ({len(findings)} issues). Several HIGH/CRITICAL severity findings require immediate attention before production use."
    else:
        return f"CRITICAL: {domain} has severe security flaws ({len(findings)} issues). Multiple CRITICAL vulnerabilities present. High risk of compromise. Immediate remediation required."

# ============ SMART CONTRACT ANALYSIS ============
def analyze_contract(code):
    findings = []
    lines = code.split('\n')
    for vuln_name, vuln_data in VULNERABILITY_PATTERNS.items():
        matches = list(re.finditer(vuln_data["pattern"], code, re.IGNORECASE))
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            findings.append({
                "id": vuln_name,
                "severity": vuln_data["severity"],
                "title": vuln_name.replace("_", " ").title(),
                "description": vuln_data["description"],
                "line": line_num,
                "code_snippet": line_content[:80] + "..." if len(line_content) > 80 else line_content,
                "fix": vuln_data["fix"],
                "example_bad": vuln_data.get("example_bad", ""),
                "example_good": vuln_data.get("example_good", ""),
                "confidence": "92%" if vuln_name in ["reentrancy", "tx_origin", "delegatecall"] else "87%"
            })
    return findings

def calculate_security_score(findings):
    base_score = 100
    severity_weights = {"CRITICAL": -25, "HIGH": -15, "MEDIUM": -8, "LOW": -3}
    for finding in findings:
        base_score += severity_weights.get(finding["severity"], -5)
    return max(0, min(100, base_score))

def generate_ai_summary(findings, score):
    if score >= 90:
        return "This contract appears well-secured with minimal risk exposure. Good use of access controls and safe arithmetic patterns detected."
    elif score >= 70:
        return f"Contract has moderate security concerns. {len(findings)} issues found - mostly addressable with standard fixes. Recommend thorough review before deployment."
    elif score >= 50:
        return f"Significant vulnerabilities detected ({len(findings)} issues). Several HIGH/CRITICAL severity findings require immediate attention. Not recommended for production without fixes."
    else:
        return f"CRITICAL: Contract has severe security flaws ({len(findings)} issues). Multiple CRITICAL vulnerabilities present. High risk of fund loss or contract compromise."

# ============ ROUTES ============

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    code = data.get('code', '')
    if not code or len(code) < 50:
        return jsonify({"error": "Please provide valid Solidity code (minimum 50 characters)"}), 400
    findings = analyze_contract(code)
    score = calculate_security_score(findings)
    summary = generate_ai_summary(findings, score)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 99))
    return jsonify({
        "score": score,
        "summary": summary,
        "findings_count": len(findings),
        "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium_count": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "findings": findings,
        "analyzed_at": datetime.now().isoformat(),
        "type": "contract"
    })

@app.route('/scan-website', methods=['POST'])
def scan_website():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "Please provide a valid URL"}), 400
    website_data = fetch_website(url)
    if not website_data["success"]:
        return jsonify({
            "error": f"Failed to fetch website: {website_data.get('error', 'Unknown error')}",
            "url": url
        }), 400
    findings = analyze_website_security(website_data)
    score = calculate_website_score(findings)
    summary = generate_website_summary(findings, score, website_data["url"])
    return jsonify({
        "score": score,
        "summary": summary,
        "url": website_data["url"],
        "status": website_data["status"],
        "findings_count": len(findings),
        "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium_count": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "findings": findings,
        "headers": {k: v for k, v in website_data["headers"].items()},
        "is_https": website_data["is_https"],
        "analyzed_at": datetime.now().isoformat(),
        "type": "website"
    })

@app.route('/sample')
def sample():
    sample_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // CRITICAL: Reentrancy vulnerability
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // State update AFTER external call!
    }

    // CRITICAL: tx.origin phishing vulnerability
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    // HIGH: No access control on drain function
    function emergencyDrain() public {
        selfdestruct(payable(msg.sender));
    }

    // MEDIUM: Timestamp dependence for randomness
    function isWinner() public view returns (bool) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 2 == 0;
    }
}"""
    return jsonify({"code": sample_code})

@app.route('/docs')
def docs_page():
    return render_template('documentation.html')

@app.route('/api')
def api_page():
    return render_template('api_reference.html')

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
