# SentinelAI - Smart Contract & Website Security Auditor

An AI-powered web application that analyzes Solidity smart contracts and live websites for security vulnerabilities. Built by Mohammad Arman Mansoori (GToxicK), B.Tech CSE student at Jiwaji University, Gwalior.

## Features

### Smart Contract Scanner
- **10+ Vulnerability Patterns**: Detects reentrancy, tx.origin, delegatecall, timestamp dependence, and more
- **Real-Time Analysis**: Instant security feedback with animated loading states
- **Detailed Fix Guidance**: Every finding includes bad vs good code examples
- **Security Score**: Weighted scoring system that prioritizes critical vulnerabilities

### Website Security Scanner
- **HTTPS & SSL Check**: Verifies secure connection configuration
- **Security Headers Analysis**: Checks for CSP, X-Frame-Options, HSTS, and more
- **XSS & CSRF Detection**: Finds dangerous JavaScript patterns and missing CSRF tokens
- **Sensitive Data Exposure**: Detects exposed .env files, config files, admin panels
- **Cookie Security**: Validates Secure, HttpOnly, and SameSite flags

## Vulnerabilities Detected

### Smart Contracts
| Vulnerability | Severity | Real Hack It Prevents |
|--------------|----------|----------------------|
| Reentrancy | CRITICAL | The DAO hack ($60M stolen) |
| tx.origin | CRITICAL | Phishing attacks on wallets |
| delegatecall | CRITICAL | Parity wallet freeze ($150M) |
| Unchecked send | HIGH | Silent transfer failures |
| Integer overflow | HIGH | BeautyChain hack ($870M) |

### Websites
| Vulnerability | Severity | Impact |
|--------------|----------|--------|
| Missing HTTPS | CRITICAL | MITM attacks, credential theft |
| Missing CSP | HIGH | XSS, data injection |
| Missing X-Frame-Options | HIGH | Clickjacking |
| Insecure Cookies | HIGH | Session hijacking |
| Missing CSRF | HIGH | Account takeover |
| Exposed Server Info | MEDIUM | Targeted CVE exploits |

## Installation

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000` in your browser.

## How to Use

### Smart Contract Audit
1. Switch to "Smart Contract Scanner" tab
2. Paste your Solidity code in the editor
3. Click "Run Security Audit"
4. Review the security score and vulnerability findings
5. Click on "Vulnerable" / "Fixed" tabs to see code examples

### Website Security Scan
1. Switch to "Website Security Scanner" tab
2. Enter any website URL (e.g., `example.com`)
3. Click "Scan Website"
4. Review security headers, missing protections, and vulnerabilities
5. Check the impact assessment and recommended fixes

## Tech Stack

- **Backend**: Python Flask
- **Frontend**: Vanilla HTML/CSS/JS (no frameworks needed)
- **Design**: Custom dark theme with CSS animations
- **Analysis**: Regex-based pattern matching (simulates AI analysis)

## For Your Pitch

**Problem**: $2B+ lost to smart contract hacks + millions of websites vulnerable to XSS, CSRF, and MITM attacks
**Solution**: Automated security auditing for both blockchain and web applications
**Impact**: Catches critical bugs before deployment
**Demo**: 
- Load sample contract to see 5+ vulnerabilities detected instantly
- Scan any website to check its security posture

## Credits

**Mohammad Arman Mansoori (GToxicK)**
- B.Tech CSE Student
- Jiwaji University, Gwalior

## Note

This is a demonstration project for educational purposes. For production use, integrate with:
- Slither, Mythril for smart contracts
- OWASP ZAP, Burp Suite for web applications
- CertiK/Quantstamp for formal verification
