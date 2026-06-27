// ============ DOM ELEMENTS ============
const codeEditor = document.getElementById('codeEditor');
const lineNumbers = document.getElementById('lineNumbers');
const lineCount = document.getElementById('lineCount');
const charCount = document.getElementById('charCount');
const loadingOverlay = document.getElementById('loadingOverlay');
const loadingTitle = document.getElementById('loadingTitle');
const loadingText = document.getElementById('loadingText');
const progressBar = document.getElementById('progressBar');
const resultsSection = document.getElementById('resultsSection');
const findingsList = document.getElementById('findingsList');
const scoreValue = document.getElementById('scoreValue');
const scoreRingProgress = document.getElementById('scoreRingProgress');
const scoreTitle = document.getElementById('scoreTitle');
const scoreDescription = document.getElementById('scoreDescription');
const criticalCount = document.getElementById('criticalCount');
const highCount = document.getElementById('highCount');
const mediumCount = document.getElementById('mediumCount');
const summarySection = document.getElementById('summarySection');
const summaryGrid = document.getElementById('summaryGrid');
const roadmapList = document.getElementById('roadmapList');

let currentScanType = 'contract';
let lastAnalysisData = null;

// ============ TAB SWITCHING ============
function switchTab(tab) {
    currentScanType = tab;

    document.querySelectorAll('.scanner-tab').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tab) {
            btn.classList.add('active');
        }
    });

    const contractSection = document.getElementById('contractSection');
    const websiteSection = document.getElementById('websiteSection');

    if (tab === 'contract') {
        contractSection.style.display = 'block';
        websiteSection.style.display = 'none';
        loadingTitle.textContent = 'AI Security Analysis in Progress';
    } else {
        contractSection.style.display = 'none';
        websiteSection.style.display = 'block';
        loadingTitle.textContent = 'Website Security Scan in Progress';
    }

    resultsSection.classList.remove('active');
    summarySection.classList.remove('active');
}

// ============ LINE NUMBERS ============
function updateLineNumbers() {
    const lines = codeEditor.value.split('\n');
    const count = lines.length;
    lineNumbers.innerHTML = Array.from({length: count}, (_, i) => i + 1).join('\n');
    lineCount.textContent = `${count} lines`;
    charCount.textContent = `${codeEditor.value.length} chars`;
}

codeEditor.addEventListener('input', updateLineNumbers);
codeEditor.addEventListener('scroll', () => {
    lineNumbers.scrollTop = codeEditor.scrollTop;
});

codeEditor.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
        e.preventDefault();
        const start = codeEditor.selectionStart;
        const end = codeEditor.selectionEnd;
        codeEditor.value = codeEditor.value.substring(0, start) + '    ' + codeEditor.value.substring(end);
        codeEditor.selectionStart = codeEditor.selectionEnd = start + 4;
        updateLineNumbers();
    }
});

// ============ LOAD SAMPLE ============
function loadSample() {
    fetch('/sample')
        .then(res => res.json())
        .then(data => {
            codeEditor.value = data.code;
            updateLineNumbers();
            setTimeout(() => {
                analyzeContract();
            }, 500);
        });
}

// ============ ANALYZE CONTRACT ============
function analyzeContract() {
    const code = codeEditor.value.trim();

    if (!code || code.length < 50) {
        alert('Please paste a valid Solidity contract (minimum 50 characters)');
        return;
    }

    showLoading('contract');

    const steps = [
        { text: 'Parsing AST structure...', progress: 15 },
        { text: 'Analyzing control flow graph...', progress: 35 },
        { text: 'Detecting reentrancy patterns...', progress: 55 },
        { text: 'Checking access controls...', progress: 75 },
        { text: 'Running symbolic execution...', progress: 90 },
        { text: 'Generating security report...', progress: 100 }
    ];

    runLoadingSteps(steps, () => {
        fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        })
        .then(res => res.json())
        .then(data => {
            hideLoading();
            lastAnalysisData = data;
            displayContractResults(data);
            generateSummary(data, 'contract');
        })
        .catch(err => {
            hideLoading();
            console.error('Analysis error:', err);
            alert('Analysis failed. Please try again.');
        });
    });
}

// ============ SCAN WEBSITE ============
function scanWebsite() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();

    if (!url) {
        alert('Please enter a website URL');
        return;
    }

    showLoading('website');

    const steps = [
        { text: 'Resolving DNS and establishing connection...', progress: 15 },
        { text: 'Fetching HTTP headers...', progress: 30 },
        { text: 'Analyzing SSL/TLS configuration...', progress: 45 },
        { text: 'Checking security headers...', progress: 60 },
        { text: 'Scanning for XSS and CSRF vectors...', progress: 80 },
        { text: 'Detecting sensitive data exposure...', progress: 95 },
        { text: 'Generating security report...', progress: 100 }
    ];

    runLoadingSteps(steps, () => {
        fetch('/scan-website', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        })
        .then(res => res.json())
        .then(data => {
            hideLoading();
            if (data.error) {
                alert(data.error);
                return;
            }
            lastAnalysisData = data;
            displayWebsiteResults(data);
            generateSummary(data, 'website');
        })
        .catch(err => {
            hideLoading();
            console.error('Scan error:', err);
            alert('Website scan failed. Please check the URL and try again.');
        });
    });
}

// ============ LOADING UTILITIES ============
function showLoading(type) {
    loadingOverlay.classList.add('active');
    loadingTitle.textContent = type === 'contract' 
        ? 'AI Security Analysis in Progress' 
        : 'Website Security Scan in Progress';
}

function hideLoading() {
    loadingOverlay.classList.remove('active');
}

function runLoadingSteps(steps, callback) {
    let stepIndex = 0;
    const stepInterval = setInterval(() => {
        if (stepIndex < steps.length) {
            loadingText.textContent = steps[stepIndex].text;
            progressBar.style.width = steps[stepIndex].progress + '%';
            stepIndex++;
        } else {
            clearInterval(stepInterval);
            setTimeout(callback, 300);
        }
    }, 400);
}

// ============ DISPLAY CONTRACT RESULTS ============
function displayContractResults(data) {
    resultsSection.classList.add('active');

    const circumference = 2 * Math.PI * 54;
    const offset = circumference - (data.score / 100) * circumference;

    scoreValue.textContent = data.score;
    scoreRingProgress.style.strokeDashoffset = offset;

    let scoreColor = '#22c55e';
    if (data.score < 50) scoreColor = '#ef4444';
    else if (data.score < 70) scoreColor = '#f97316';
    else if (data.score < 90) scoreColor = '#eab308';

    scoreRingProgress.style.stroke = scoreColor;
    scoreValue.style.color = scoreColor;

    scoreTitle.textContent = data.score >= 70 ? 'Security Assessment Complete' : 'Critical Issues Found';
    scoreDescription.textContent = data.summary;

    criticalCount.textContent = data.critical_count;
    highCount.textContent = data.high_count;
    mediumCount.textContent = data.medium_count;

    renderContractFindings(data.findings);

    setTimeout(() => {
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);
}

function renderContractFindings(findings) {
    if (findings.length === 0) {
        findingsList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🎉</div>
                <h4>No vulnerabilities found!</h4>
                <p>Your contract passed all security checks.</p>
            </div>
        `;
        return;
    }

    findingsList.innerHTML = findings.map((finding, index) => `
        <div class="finding-card" data-severity="${finding.severity}" style="animation-delay: ${index * 0.05}s">
            <div class="finding-header">
                <div class="finding-title-section">
                    <span class="severity-badge ${finding.severity}">${finding.severity}</span>
                    <span class="finding-name">${finding.title}</span>
                </div>
                <div class="finding-meta">
                    <span class="finding-line">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="8" y1="6" x2="21" y2="6"/>
                            <line x1="8" y1="12" x2="21" y2="12"/>
                            <line x1="8" y1="18" x2="21" y2="18"/>
                            <line x1="3" y1="6" x2="3.01" y2="6"/>
                            <line x1="3" y1="12" x2="3.01" y2="12"/>
                            <line x1="3" y1="18" x2="3.01" y2="18"/>
                        </svg>
                        Line ${finding.line}
                    </span>
                    <span class="finding-confidence">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        ${finding.confidence} confidence
                    </span>
                </div>
            </div>

            <p class="finding-description">${finding.description}</p>

            <div class="finding-code">
                <div class="code-header">
                    <div class="code-tab active" onclick="switchCodeTab(this, 'bad-${index}')">❌ Vulnerable</div>
                    <div class="code-tab" onclick="switchCodeTab(this, 'good-${index}')">✅ Fixed</div>
                </div>
                <div class="code-content active" id="bad-${index}">
                    <code class="code-bad">${escapeHtml(finding.example_bad || '// No example available')}</code>
                </div>
                <div class="code-content" id="good-${index}">
                    <code class="code-good">${escapeHtml(finding.example_good || '// No example available')}</code>
                </div>
            </div>

            <div class="finding-fix">
                <strong>🔧 Fix:</strong> ${finding.fix}
            </div>
        </div>
    `).join('');
}

// ============ DISPLAY WEBSITE RESULTS ============
function displayWebsiteResults(data) {
    resultsSection.classList.add('active');

    const circumference = 2 * Math.PI * 54;
    const offset = circumference - (data.score / 100) * circumference;

    scoreValue.textContent = data.score;
    scoreRingProgress.style.strokeDashoffset = offset;

    let scoreColor = '#22c55e';
    if (data.score < 50) scoreColor = '#ef4444';
    else if (data.score < 70) scoreColor = '#f97316';
    else if (data.score < 90) scoreColor = '#eab308';

    scoreRingProgress.style.stroke = scoreColor;
    scoreValue.style.color = scoreColor;

    const domain = new URL(data.url).hostname;
    scoreTitle.textContent = `Scan Complete: ${domain}`;
    scoreDescription.textContent = data.summary;

    criticalCount.textContent = data.critical_count;
    highCount.textContent = data.high_count;
    mediumCount.textContent = data.medium_count;

    renderWebsiteFindings(data.findings, data.headers);

    setTimeout(() => {
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);
}

function renderWebsiteFindings(findings, headers) {
    if (findings.length === 0) {
        findingsList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🎉</div>
                <h4>No vulnerabilities found!</h4>
                <p>This website has strong security configurations.</p>
            </div>
        `;
        return;
    }

    let headersHtml = '';
    if (headers && Object.keys(headers).length > 0) {
        const headerRows = Object.entries(headers)
            .slice(0, 10)
            .map(([key, value]) => `
                <tr>
                    <td>${escapeHtml(key)}</td>
                    <td>${escapeHtml(value.substring(0, 100))}${value.length > 100 ? '...' : ''}</td>
                </tr>
            `).join('');

        headersHtml = `
            <div class="finding-card" style="margin-bottom: 1rem;">
                <div class="finding-header">
                    <div class="finding-title-section">
                        <span class="severity-badge LOW">INFO</span>
                        <span class="finding-name">HTTP Response Headers</span>
                    </div>
                </div>
                <table class="headers-table">
                    <thead>
                        <tr><th>Header</th><th>Value</th></tr>
                    </thead>
                    <tbody>${headerRows}</tbody>
                </table>
            </div>
        `;
    }

    const findingsHtml = findings.map((finding, index) => `
        <div class="finding-card" data-severity="${finding.severity}" style="animation-delay: ${index * 0.05}s">
            <div class="finding-header">
                <div class="finding-title-section">
                    <span class="severity-badge ${finding.severity}">${finding.severity}</span>
                    <span class="finding-name">${finding.title}</span>
                    <span class="finding-location">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
                            <circle cx="12" cy="10" r="3"/>
                        </svg>
                        ${finding.location}
                    </span>
                </div>
                <div class="finding-meta">
                    <span class="finding-confidence">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        ${finding.confidence} confidence
                    </span>
                </div>
            </div>

            <p class="finding-description">${finding.description}</p>

            <div class="finding-fix">
                <strong>🔧 Fix:</strong> ${finding.fix}
            </div>

            <div class="finding-impact">
                <strong>⚠️ Impact:</strong> ${finding.impact}
            </div>
        </div>
    `).join('');

    findingsList.innerHTML = headersHtml + findingsHtml;
}

// ============ SUMMARY DASHBOARD ============
function generateSummary(data, type) {
    summarySection.classList.add('active');

    const findings = data.findings || [];
    const score = data.score;

    // Group findings by severity
    const critical = findings.filter(f => f.severity === 'CRITICAL');
    const high = findings.filter(f => f.severity === 'HIGH');
    const medium = findings.filter(f => f.severity === 'MEDIUM');
    const low = findings.filter(f => f.severity === 'LOW');

    // Generate summary cards
    const summaryCards = [];

    if (critical.length > 0) {
        summaryCards.push({
            icon: 'critical',
            title: 'Critical Issues',
            count: critical.length,
            desc: 'Immediate action required. These vulnerabilities can lead to complete system compromise or fund loss.',
            items: critical.slice(0, 3).map(f => f.title)
        });
    }

    if (high.length > 0) {
        summaryCards.push({
            icon: 'high',
            title: 'High Risk Issues',
            count: high.length,
            desc: 'Serious vulnerabilities that should be fixed before production deployment.',
            items: high.slice(0, 3).map(f => f.title)
        });
    }

    if (medium.length > 0) {
        summaryCards.push({
            icon: 'medium',
            title: 'Medium Risk Issues',
            count: medium.length,
            desc: 'Moderate concerns that should be addressed to improve overall security posture.',
            items: medium.slice(0, 3).map(f => f.title)
        });
    }

    if (findings.length === 0) {
        summaryCards.push({
            icon: 'good',
            title: 'All Clear',
            count: 0,
            desc: 'No vulnerabilities detected. Your ' + (type === 'contract' ? 'contract' : 'website') + ' has passed all security checks.',
            items: ['No action needed']
        });
    }

    // Add overall assessment card
    let assessmentText = '';
    let assessmentIcon = '';
    if (score >= 90) {
        assessmentText = 'Strong security posture with minimal risk exposure.';
        assessmentIcon = 'good';
    } else if (score >= 70) {
        assessmentText = 'Moderate security concerns. Address findings to improve score.';
        assessmentIcon = 'info';
    } else if (score >= 50) {
        assessmentText = 'Significant vulnerabilities present. Immediate attention required.';
        assessmentIcon = 'warning';
    } else {
        assessmentText = 'Critical security flaws detected. Not safe for production.';
        assessmentIcon = 'critical';
    }

    summaryCards.push({
        icon: assessmentIcon,
        title: 'Overall Assessment',
        count: score,
        desc: assessmentText,
        items: [`Security Score: ${score}/100`],
        isScore: true
    });

    // Render summary cards
    summaryGrid.innerHTML = summaryCards.map(card => `
        <div class="summary-card">
            <div class="summary-card-header">
                <div class="summary-card-icon ${card.icon}">
                    ${getIconSvg(card.icon)}
                </div>
                <span class="summary-card-title">${card.title}</span>
            </div>
            <div class="summary-card-count ${card.icon}">${card.isScore ? card.count + '/100' : card.count}</div>
            <p class="summary-card-desc">${card.desc}</p>
            <ul class="summary-card-list">
                ${card.items.map(item => `<li>${item}</li>`).join('')}
            </ul>
        </div>
    `).join('');

    // Generate improvement roadmap
    generateRoadmap(findings, type, score);

    setTimeout(() => {
        summarySection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 500);
}

function getIconSvg(icon) {
    const icons = {
        critical: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        high: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>',
        medium: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
        good: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
    };
    return icons[icon] || icons.info;
}

function generateRoadmap(findings, type, score) {
    const roadmapItems = [];

    // Priority 1: Critical issues
    const critical = findings.filter(f => f.severity === 'CRITICAL');
    if (critical.length > 0) {
        roadmapItems.push({
            step: 1,
            severity: 'critical',
            title: `Fix ${critical.length} Critical ${critical.length === 1 ? 'Issue' : 'Issues'}`,
            desc: critical[0].description,
            action: critical[0].fix.substring(0, 100) + (critical[0].fix.length > 100 ? '...' : '')
        });
    }

    // Priority 2: High issues
    const high = findings.filter(f => f.severity === 'HIGH');
    if (high.length > 0) {
        roadmapItems.push({
            step: roadmapItems.length + 1,
            severity: 'high',
            title: `Address ${high.length} High Risk ${high.length === 1 ? 'Finding' : 'Findings'}`,
            desc: high[0].description,
            action: high[0].fix.substring(0, 100) + (high[0].fix.length > 100 ? '...' : '')
        });
    }

    // Priority 3: Medium issues
    const medium = findings.filter(f => f.severity === 'MEDIUM');
    if (medium.length > 0) {
        roadmapItems.push({
            step: roadmapItems.length + 1,
            severity: 'medium',
            title: `Resolve ${medium.length} Medium Risk ${medium.length === 1 ? 'Issue' : 'Issues'}`,
            desc: medium[0].description,
            action: medium[0].fix.substring(0, 100) + (medium[0].fix.length > 100 ? '...' : '')
        });
    }

    // Priority 4: General improvements
    if (score < 90) {
        if (type === 'contract') {
            roadmapItems.push({
                step: roadmapItems.length + 1,
                severity: 'low',
                title: 'Add Comprehensive Unit Tests',
                desc: 'Write tests covering edge cases, reentrancy scenarios, and access control validation.',
                action: 'Use Foundry or Hardhat to create test suites with 100% coverage.'
            });
            roadmapItems.push({
                step: roadmapItems.length + 1,
                severity: 'low',
                title: 'Get External Audit',
                desc: 'Before mainnet deployment, have your contract reviewed by professional auditors.',
                action: 'Contact CertiK, Trail of Bits, or OpenZeppelin for formal verification.'
            });
        } else {
            roadmapItems.push({
                step: roadmapItems.length + 1,
                severity: 'low',
                title: 'Implement Security Headers',
                desc: 'Add all recommended security headers to protect against common web attacks.',
                action: 'Configure CSP, HSTS, X-Frame-Options, and Referrer-Policy in your server config.'
            });
            roadmapItems.push({
                step: roadmapItems.length + 1,
                severity: 'low',
                title: 'Set Up Monitoring',
                desc: 'Deploy security monitoring to detect and alert on suspicious activity.',
                action: 'Use tools like OWASP ZAP, Snyk, or GitHub Dependabot for continuous scanning.'
            });
        }
    }

    if (roadmapItems.length === 0) {
        roadmapItems.push({
            step: 1,
            severity: 'low',
            title: 'Maintain Security Posture',
            desc: 'Your ' + (type === 'contract' ? 'contract' : 'website') + ' is secure. Keep it that way with regular audits.',
            action: 'Schedule quarterly security reviews and stay updated on new vulnerabilities.'
        });
    }

    roadmapList.innerHTML = roadmapItems.map((item, index) => `
        <div class="roadmap-timeline">
            <div class="roadmap-item">
                <div class="roadmap-step ${item.severity}">${item.step}</div>
                <div class="roadmap-content">
                    <div class="roadmap-item-title">${item.title}</div>
                    <div class="roadmap-item-desc">${item.desc}</div>
                    <div class="roadmap-item-action">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                            <polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        ${item.action}
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function switchCodeTab(tab, contentId) {
    const card = tab.closest('.finding-code');
    card.querySelectorAll('.code-tab').forEach(t => t.classList.remove('active'));
    card.querySelectorAll('.code-content').forEach(c => c.classList.remove('active'));

    tab.classList.add('active');
    document.getElementById(contentId).classList.add('active');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============ FILTER FINDINGS ============
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const filter = btn.dataset.filter;
        const cards = document.querySelectorAll('.finding-card');

        cards.forEach(card => {
            if (filter === 'all' || card.dataset.severity === filter) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    });
});

// ============ URL INPUT ENTER KEY ============
document.getElementById('urlInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        scanWebsite();
    }
});

// ============ INITIALIZE ============
updateLineNumbers();
