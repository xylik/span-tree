#!/usr/bin/env node
/**
 * Browser Extension Security Analysis Tool for SpanTree
 * 
 * This tool performs comprehensive security analysis of browser extensions,
 * focusing on common vulnerabilities and attack vectors specific to extensions.
 */

const fs = require('fs');
const path = require('path');

class BrowserExtensionSecurityAnalyzer {
    constructor() {
        this.findings = [];
        this.extensionPath = process.cwd();
        this.manifestPath = path.join(this.extensionPath, 'manifest.json');
        this.packagePath = path.join(this.extensionPath, 'package.json');
    }

    // Security severity levels
    getSeverityColor(severity) {
        const colors = {
            'CRITICAL': '\x1b[31m', // Red
            'HIGH': '\x1b[91m',     // Light Red
            'MEDIUM': '\x1b[33m',   // Yellow
            'LOW': '\x1b[36m',      // Cyan
            'INFO': '\x1b[37m'      // White
        };
        return colors[severity] || '\x1b[37m';
    }

    addFinding(type, severity, description, file = null, line = null, remediation = null) {
        this.findings.push({
            type,
            severity,
            description,
            file,
            line,
            remediation,
            timestamp: new Date().toISOString()
        });
    }

    // Analyze manifest.json for security issues
    analyzeManifest() {
        console.log('🔍 Analyzing manifest.json for security issues...');
        
        if (!fs.existsSync(this.manifestPath)) {
            this.addFinding('MANIFEST', 'HIGH', 'manifest.json file not found', this.manifestPath, null, 'Create a valid manifest.json file');
            return;
        }

        const manifest = JSON.parse(fs.readFileSync(this.manifestPath, 'utf8'));

        // Check for overly broad permissions
        if (manifest.host_permissions && manifest.host_permissions.includes('<all_urls>')) {
            this.addFinding(
                'PERMISSIONS',
                'CRITICAL',
                'Extension requests access to all URLs (<all_urls>) which violates least privilege principle',
                'manifest.json',
                null,
                'Restrict host_permissions to only necessary domains like "https://gitlab.com/*"'
            );
        }

        // Check for dangerous permissions
        const dangerousPermissions = ['activeTab', 'tabs', 'cookies', 'storage', 'background', 'nativeMessaging'];
        if (manifest.permissions) {
            manifest.permissions.forEach(permission => {
                if (dangerousPermissions.includes(permission)) {
                    this.addFinding(
                        'PERMISSIONS',
                        'MEDIUM',
                        `Extension requests potentially dangerous permission: ${permission}`,
                        'manifest.json',
                        null,
                        'Ensure this permission is absolutely necessary and document its usage'
                    );
                }
            });
        }

        // Check content scripts
        if (manifest.content_scripts) {
            manifest.content_scripts.forEach((script, index) => {
                if (script.matches && script.matches.includes('<all_urls>')) {
                    this.addFinding(
                        'CONTENT_SCRIPTS',
                        'HIGH',
                        `Content script ${index} runs on all URLs, potential for data theft and XSS`,
                        'manifest.json',
                        null,
                        'Limit content script matches to specific GitLab domains only'
                    );
                }
                if (script.run_at === 'document_start') {
                    this.addFinding(
                        'CONTENT_SCRIPTS',
                        'MEDIUM',
                        `Content script ${index} runs at document_start, increasing attack surface`,
                        'manifest.json',
                        null,
                        'Consider running at document_idle unless document_start is absolutely necessary'
                    );
                }
            });
        }

        // Check web accessible resources
        if (manifest.web_accessible_resources) {
            manifest.web_accessible_resources.forEach((resource, index) => {
                if (resource.matches && resource.matches.includes('<all_urls>')) {
                    this.addFinding(
                        'WEB_RESOURCES',
                        'MEDIUM',
                        `Web accessible resources exposed to all URLs, potential for resource theft`,
                        'manifest.json',
                        null,
                        'Restrict web accessible resources to specific domains'
                    );
                }
            });
        }

        // Check for missing CSP
        if (!manifest.content_security_policy) {
            this.addFinding(
                'CSP',
                'HIGH',
                'No Content Security Policy defined, vulnerable to XSS attacks',
                'manifest.json',
                null,
                'Add strict CSP: "script-src \'self\'; object-src \'none\'; base-uri \'none\';"'
            );
        }

        console.log('✅ Manifest analysis complete');
    }

    // Analyze JavaScript files for security vulnerabilities
    analyzeJavaScriptFiles() {
        console.log('🔍 Analyzing JavaScript files for security vulnerabilities...');
        
        const jsFiles = this.findFiles(this.extensionPath, '.js');
        
        jsFiles.forEach(filePath => {
            this.analyzeJavaScriptFile(filePath);
        });

        console.log(`✅ Analyzed ${jsFiles.length} JavaScript files`);
    }

    analyzeJavaScriptFile(filePath) {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        const relativePath = path.relative(this.extensionPath, filePath);

        // Check for dangerous functions
        const dangerousPatterns = [
            { pattern: /eval\s*\(/g, severity: 'CRITICAL', message: 'Use of eval() can lead to code injection', remediation: 'Replace eval() with safer alternatives like JSON.parse()' },
            { pattern: /Function\s*\(/g, severity: 'HIGH', message: 'Use of Function constructor can lead to code injection', remediation: 'Avoid Function constructor, use predefined functions' },
            { pattern: /innerHTML\s*=/g, severity: 'HIGH', message: 'Use of innerHTML can lead to XSS', remediation: 'Use textContent or createElement methods instead' },
            { pattern: /outerHTML\s*=/g, severity: 'HIGH', message: 'Use of outerHTML can lead to XSS', remediation: 'Use safer DOM manipulation methods' },
            { pattern: /document\.write\s*\(/g, severity: 'HIGH', message: 'Use of document.write can lead to XSS', remediation: 'Use DOM manipulation methods instead' },
            { pattern: /execScript\s*\(/g, severity: 'CRITICAL', message: 'Use of execScript can lead to code injection', remediation: 'Remove execScript usage' },
            { pattern: /setTimeout\s*\(\s*["'`][^"'`]*["'`]/g, severity: 'MEDIUM', message: 'setTimeout with string argument can be dangerous', remediation: 'Use function instead of string for setTimeout' },
            { pattern: /setInterval\s*\(\s*["'`][^"'`]*["'`]/g, severity: 'MEDIUM', message: 'setInterval with string argument can be dangerous', remediation: 'Use function instead of string for setInterval' }
        ];

        dangerousPatterns.forEach(({ pattern, severity, message, remediation }) => {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const lineNumber = content.substr(0, match.index).split('\n').length;
                this.addFinding('DANGEROUS_CODE', severity, message, relativePath, lineNumber, remediation);
            }
        });

        // Check for insecure HTTP requests
        const httpPatterns = [
            { pattern: /http:\/\/[^"'`\s)]+/g, severity: 'MEDIUM', message: 'Insecure HTTP request detected', remediation: 'Use HTTPS instead of HTTP' }
        ];

        httpPatterns.forEach(({ pattern, severity, message, remediation }) => {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const lineNumber = content.substr(0, match.index).split('\n').length;
                this.addFinding('INSECURE_NETWORK', severity, message, relativePath, lineNumber, remediation);
            }
        });

        // Check for postMessage usage without origin validation
        lines.forEach((line, index) => {
            if (line.includes('postMessage') && !line.includes('origin')) {
                this.addFinding(
                    'MESSAGE_PASSING',
                    'HIGH',
                    'postMessage used without proper origin validation',
                    relativePath,
                    index + 1,
                    'Always validate origin in postMessage handlers'
                );
            }

            if (line.includes('localStorage') || line.includes('sessionStorage')) {
                this.addFinding(
                    'INSECURE_STORAGE',
                    'MEDIUM',
                    'Sensitive data may be stored insecurely in browser storage',
                    relativePath,
                    index + 1,
                    'Encrypt sensitive data before storing or use chrome.storage.local with encryption'
                );
            }

            // Check for hardcoded credentials or API keys
            const credentialPatterns = [
                /password\s*[:=]\s*["'][^"']+["']/i,
                /api[_-]?key\s*[:=]\s*["'][^"']+["']/i,
                /secret\s*[:=]\s*["'][^"']+["']/i,
                /token\s*[:=]\s*["'][^"']+["']/i
            ];

            credentialPatterns.forEach(pattern => {
                if (pattern.test(line)) {
                    this.addFinding(
                        'CREDENTIALS',
                        'CRITICAL',
                        'Potential hardcoded credentials or API keys detected',
                        relativePath,
                        index + 1,
                        'Move credentials to secure configuration or use environment variables'
                    );
                }
            });
        });
    }

    // Analyze dependencies for vulnerabilities
    async analyzeDependencies() {
        console.log('🔍 Analyzing dependencies for known vulnerabilities...');

        if (!fs.existsSync(this.packagePath)) {
            this.addFinding('DEPENDENCIES', 'MEDIUM', 'package.json not found', this.packagePath, null, 'Create package.json with proper dependency management');
            return;
        }

        const packageJson = JSON.parse(fs.readFileSync(this.packagePath, 'utf8'));

        // Check for outdated and vulnerable packages
        const vulnerablePackages = {
            'axios': { version: '0.21.1', vulnerability: 'SSRF and credential leakage vulnerabilities', remediation: 'Update to axios >= 0.21.2' },
            'babel-core': { version: '6.24.1', vulnerability: 'Arbitrary code execution vulnerability', remediation: 'Update to latest stable version' },
            'webpack': { version: '5.37.1', vulnerability: 'XSS vulnerabilities', remediation: 'Update to webpack >= 5.94.0' }
        };

        const allDeps = { ...packageJson.dependencies, ...packageJson.devDependencies };
        
        Object.keys(allDeps).forEach(pkg => {
            if (vulnerablePackages[pkg]) {
                this.addFinding(
                    'VULNERABLE_DEPENDENCY',
                    'HIGH',
                    `Vulnerable package detected: ${pkg}@${allDeps[pkg]} - ${vulnerablePackages[pkg].vulnerability}`,
                    'package.json',
                    null,
                    vulnerablePackages[pkg].remediation
                );
            }
        });

        console.log('✅ Dependency analysis complete');
    }

    // Check for secure communication practices
    analyzeNetworkSecurity() {
        console.log('🔍 Analyzing network security practices...');

        const jsFiles = this.findFiles(this.extensionPath, '.js');
        
        jsFiles.forEach(filePath => {
            const content = fs.readFileSync(filePath, 'utf8');
            const relativePath = path.relative(this.extensionPath, filePath);

            // Check for axios configuration
            if (content.includes('axios.create') || content.includes('axios.defaults')) {
                const lines = content.split('\n');
                let hasTimeout = false;
                let hasSSLVerification = true;

                lines.forEach((line, index) => {
                    if (line.includes('timeout')) hasTimeout = true;
                    if (line.includes('rejectUnauthorized') && line.includes('false')) {
                        hasSSLVerification = false;
                        this.addFinding(
                            'NETWORK_SECURITY',
                            'CRITICAL',
                            'SSL certificate verification disabled',
                            relativePath,
                            index + 1,
                            'Enable SSL certificate verification for security'
                        );
                    }
                });

                if (!hasTimeout) {
                    this.addFinding(
                        'NETWORK_SECURITY',
                        'LOW',
                        'No request timeout configured, potential for DoS',
                        relativePath,
                        null,
                        'Set appropriate timeout values for HTTP requests'
                    );
                }
            }

            // Check for dynamic URL construction
            if (content.includes('window.location.origin') || content.includes('location.origin')) {
                this.addFinding(
                    'NETWORK_SECURITY',
                    'MEDIUM',
                    'Dynamic URL construction from location.origin may be vulnerable to manipulation',
                    relativePath,
                    null,
                    'Validate and sanitize URLs before use'
                );
            }
        });

        console.log('✅ Network security analysis complete');
    }

    // Utility method to find files with specific extension
    findFiles(dir, extension) {
        let files = [];
        
        const scan = (currentDir) => {
            const items = fs.readdirSync(currentDir);
            
            items.forEach(item => {
                const fullPath = path.join(currentDir, item);
                const stat = fs.statSync(fullPath);
                
                if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules' && item !== 'build') {
                    scan(fullPath);
                } else if (stat.isFile() && fullPath.endsWith(extension)) {
                    files.push(fullPath);
                }
            });
        };
        
        scan(dir);
        return files;
    }

    // Generate comprehensive security report
    generateReport() {
        console.log('\n📊 BROWSER EXTENSION SECURITY ANALYSIS REPORT');
        console.log('='.repeat(60));
        
        const severityCounts = this.findings.reduce((acc, finding) => {
            acc[finding.severity] = (acc[finding.severity] || 0) + 1;
            return acc;
        }, {});

        // Summary
        console.log('\n📈 SECURITY SUMMARY:');
        Object.entries(severityCounts).forEach(([severity, count]) => {
            const color = this.getSeverityColor(severity);
            console.log(`${color}${severity}: ${count} issues\x1b[0m`);
        });

        // Calculate risk score
        const riskScore = this.calculateRiskScore(severityCounts);
        const riskLevel = this.getRiskLevel(riskScore);
        console.log(`\n🎯 OVERALL RISK LEVEL: ${this.getSeverityColor(riskLevel)}${riskLevel} (Score: ${riskScore}/100)\x1b[0m`);

        // Detailed findings
        console.log('\n🔍 DETAILED FINDINGS:');
        console.log('-'.repeat(60));

        this.findings
            .sort((a, b) => this.getSeverityWeight(b.severity) - this.getSeverityWeight(a.severity))
            .forEach((finding, index) => {
                const color = this.getSeverityColor(finding.severity);
                console.log(`\n${index + 1}. ${color}[${finding.severity}] ${finding.type}\x1b[0m`);
                console.log(`   📄 Description: ${finding.description}`);
                
                if (finding.file) {
                    const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
                    console.log(`   📍 Location: ${location}`);
                }
                
                if (finding.remediation) {
                    console.log(`   🔧 Remediation: ${finding.remediation}`);
                }
            });

        // Write JSON report
        this.writeJsonReport();
        
        // Security recommendations
        this.generateRecommendations();

        console.log('\n✅ Security analysis complete!');
        console.log(`📄 Detailed JSON report saved to: security-report.json`);
    }

    calculateRiskScore(severityCounts) {
        const weights = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 1 };
        return Object.entries(severityCounts).reduce((score, [severity, count]) => {
            return score + (weights[severity] || 0) * count;
        }, 0);
    }

    getRiskLevel(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 50) return 'HIGH';
        if (score >= 25) return 'MEDIUM';
        return 'LOW';
    }

    getSeverityWeight(severity) {
        const weights = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
        return weights[severity] || 0;
    }

    writeJsonReport() {
        const report = {
            extension: 'SpanTree',
            analysisDate: new Date().toISOString(),
            summary: {
                totalFindings: this.findings.length,
                severityCounts: this.findings.reduce((acc, finding) => {
                    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
                    return acc;
                }, {}),
                riskScore: this.calculateRiskScore(this.findings.reduce((acc, finding) => {
                    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
                    return acc;
                }, {}))
            },
            findings: this.findings
        };

        fs.writeFileSync(
            path.join(this.extensionPath, 'security-report.json'),
            JSON.stringify(report, null, 2)
        );
    }

    generateRecommendations() {
        console.log('\n💡 SECURITY RECOMMENDATIONS:');
        console.log('-'.repeat(60));

        const recommendations = [
            '1. 🔒 Implement strict Content Security Policy (CSP)',
            '2. 🎯 Reduce extension permissions to minimum required (principle of least privilege)',
            '3. 🌐 Restrict host permissions to specific GitLab domains only',
            '4. 🔐 Encrypt sensitive data before storing in browser storage',
            '5. ✅ Implement proper input validation and sanitization',
            '6. 🔄 Update all vulnerable dependencies to latest secure versions',
            '7. 🛡️ Validate origins in postMessage handlers',
            '8. 🚫 Avoid using innerHTML, eval, and other dangerous functions',
            '9. 🔍 Implement regular security audits and dependency scanning',
            '10. 📝 Document security practices and review processes'
        ];

        recommendations.forEach(rec => console.log(rec));
    }

    // Main analysis method
    async run() {
        console.log('🚀 Starting Browser Extension Security Analysis...\n');
        
        this.analyzeManifest();
        this.analyzeJavaScriptFiles();
        await this.analyzeDependencies();
        this.analyzeNetworkSecurity();
        
        this.generateReport();
    }
}

// Run the security analyzer
if (require.main === module) {
    const analyzer = new BrowserExtensionSecurityAnalyzer();
    analyzer.run().catch(console.error);
}

module.exports = BrowserExtensionSecurityAnalyzer;