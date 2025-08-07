#!/usr/bin/env node
/**
 * Security Validation Script for SpanTree Browser Extension
 * 
 * This script validates that security fixes have been properly applied
 * and provides continuous security monitoring capabilities.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SecurityValidator {
    constructor() {
        this.extensionPath = process.cwd();
        this.validationResults = [];
        this.securityScore = 0;
        this.maxScore = 100;
    }

    addValidation(category, test, passed, score, description, remediation = null) {
        this.validationResults.push({
            category,
            test,
            passed,
            score: passed ? score : 0,
            description,
            remediation,
            timestamp: new Date().toISOString()
        });

        if (passed) {
            this.securityScore += score;
        }
    }

    // Validate manifest security improvements
    validateManifestSecurity() {
        console.log('🔍 Validating manifest security...');
        
        const manifestPath = path.join(this.extensionPath, 'manifest.json');
        
        if (!fs.existsSync(manifestPath)) {
            this.addValidation('MANIFEST', 'existence', false, 0, 'manifest.json exists', 'Create manifest.json file');
            return;
        }

        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

        // Check if permissions are restricted
        const hasRestrictedPermissions = manifest.host_permissions && 
            !manifest.host_permissions.includes('<all_urls>') &&
            manifest.host_permissions.some(p => p.includes('gitlab'));

        this.addValidation(
            'PERMISSIONS',
            'host_permissions_restricted',
            hasRestrictedPermissions,
            15,
            'Host permissions restricted to necessary domains',
            'Restrict host_permissions to GitLab domains only'
        );

        // Check content script restrictions
        let contentScriptsSecure = true;
        if (manifest.content_scripts) {
            manifest.content_scripts.forEach(script => {
                if (script.matches && script.matches.includes('<all_urls>')) {
                    contentScriptsSecure = false;
                }
            });
        }

        this.addValidation(
            'CONTENT_SCRIPTS',
            'restricted_matches',
            contentScriptsSecure,
            10,
            'Content scripts limited to specific domains',
            'Restrict content script matches to necessary domains'
        );

        // Check for CSP
        const hasCSP = manifest.content_security_policy && 
            typeof manifest.content_security_policy === 'object';

        this.addValidation(
            'CSP',
            'policy_defined',
            hasCSP,
            15,
            'Content Security Policy is defined',
            'Add strict CSP to manifest'
        );

        // Check web accessible resources
        let webResourcesSecure = true;
        if (manifest.web_accessible_resources) {
            manifest.web_accessible_resources.forEach(resource => {
                if (resource.matches && resource.matches.includes('<all_urls>')) {
                    webResourcesSecure = false;
                }
            });
        }

        this.addValidation(
            'WEB_RESOURCES',
            'restricted_access',
            webResourcesSecure,
            8,
            'Web accessible resources properly restricted',
            'Restrict web accessible resources to necessary domains'
        );
    }

    // Validate secure utilities exist and are properly implemented
    validateSecurityUtilities() {
        console.log('🔍 Validating security utilities...');

        const secureMessagingPath = path.join(this.extensionPath, 'secure-messaging.js');
        const secureStoragePath = path.join(this.extensionPath, 'secure-storage.js');

        // Check secure messaging utility
        const hasSecureMessaging = fs.existsSync(secureMessagingPath);
        this.addValidation(
            'UTILITIES',
            'secure_messaging_exists',
            hasSecureMessaging,
            8,
            'Secure messaging utility is available',
            'Implement secure messaging wrapper'
        );

        if (hasSecureMessaging) {
            const messagingContent = fs.readFileSync(secureMessagingPath, 'utf8');
            const hasOriginValidation = messagingContent.includes('isOriginAllowed') && 
                                       messagingContent.includes('allowedOrigins');
            
            this.addValidation(
                'UTILITIES',
                'messaging_origin_validation',
                hasOriginValidation,
                5,
                'Secure messaging includes origin validation',
                'Add origin validation to messaging'
            );
        }

        // Check secure storage utility
        const hasSecureStorage = fs.existsSync(secureStoragePath);
        this.addValidation(
            'UTILITIES',
            'secure_storage_exists',
            hasSecureStorage,
            8,
            'Secure storage utility is available',
            'Implement secure storage wrapper'
        );

        if (hasSecureStorage) {
            const storageContent = fs.readFileSync(secureStoragePath, 'utf8');
            const hasEncryption = storageContent.includes('crypto.subtle.encrypt') && 
                                 storageContent.includes('AES-GCM');
            
            this.addValidation(
                'UTILITIES',
                'storage_encryption',
                hasEncryption,
                7,
                'Secure storage includes proper encryption',
                'Add encryption to storage utility'
            );
        }
    }

    // Validate code security practices
    validateCodeSecurity() {
        console.log('🔍 Validating code security practices...');

        const jsFiles = this.findFiles(this.extensionPath, '.js');
        let hasEval = false;
        let hasInnerHTML = false;
        let hasUnsafePostMessage = false;
        let filesWithIssues = [];

        jsFiles.forEach(filePath => {
            if (filePath.includes('node_modules') || filePath.includes('security-')) {
                return; // Skip node_modules and our security tools
            }

            const content = fs.readFileSync(filePath, 'utf8');
            const relativePath = path.relative(this.extensionPath, filePath);

            if (content.includes('eval(')) {
                hasEval = true;
                filesWithIssues.push(relativePath);
            }

            if (content.includes('innerHTML =')) {
                hasInnerHTML = true;
                filesWithIssues.push(relativePath);
            }

            if (content.includes('postMessage') && !content.includes('origin')) {
                hasUnsafePostMessage = true;
                filesWithIssues.push(relativePath);
            }
        });

        this.addValidation(
            'CODE_SECURITY',
            'no_eval_usage',
            !hasEval,
            10,
            'No dangerous eval() usage detected',
            'Replace eval() with safer alternatives'
        );

        this.addValidation(
            'CODE_SECURITY',
            'safe_dom_manipulation',
            !hasInnerHTML,
            8,
            'Safe DOM manipulation practices followed',
            'Replace innerHTML with safer methods'
        );

        this.addValidation(
            'CODE_SECURITY',
            'secure_messaging',
            !hasUnsafePostMessage,
            7,
            'Secure messaging practices followed',
            'Add origin validation to postMessage handlers'
        );
    }

    // Validate dependency security
    validateDependencies() {
        console.log('🔍 Validating dependency security...');

        const packagePath = path.join(this.extensionPath, 'package.json');
        
        if (!fs.existsSync(packagePath)) {
            this.addValidation('DEPENDENCIES', 'package_exists', false, 0, 'package.json exists', 'Create package.json');
            return;
        }

        const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
        
        // Check for known vulnerable packages (simplified check)
        const vulnerablePackages = ['axios@0.21.1', 'babel-core@6.24.1', 'webpack@5.37.1'];
        const allDeps = { ...packageJson.dependencies, ...packageJson.devDependencies };
        
        let hasVulnerableDeps = false;
        vulnerablePackages.forEach(vuln => {
            const [pkg, version] = vuln.split('@');
            if (allDeps[pkg] && allDeps[pkg].includes(version)) {
                hasVulnerableDeps = true;
            }
        });

        this.addValidation(
            'DEPENDENCIES',
            'no_vulnerable_deps',
            !hasVulnerableDeps,
            12,
            'No known vulnerable dependencies detected',
            'Update vulnerable dependencies to secure versions'
        );

        // Check if package-lock.json exists for security
        const hasPackageLock = fs.existsSync(path.join(this.extensionPath, 'package-lock.json'));
        this.addValidation(
            'DEPENDENCIES',
            'lockfile_exists',
            hasPackageLock,
            3,
            'Package lockfile exists for dependency security',
            'Generate package-lock.json with npm install'
        );
    }

    // Validate security documentation
    validateDocumentation() {
        console.log('🔍 Validating security documentation...');

        const securityDocPath = path.join(this.extensionPath, 'SECURITY.md');
        const hasSecurityDoc = fs.existsSync(securityDocPath);

        this.addValidation(
            'DOCUMENTATION',
            'security_doc_exists',
            hasSecurityDoc,
            5,
            'Security documentation exists',
            'Create comprehensive security documentation'
        );

        if (hasSecurityDoc) {
            const content = fs.readFileSync(securityDocPath, 'utf8');
            const hasVulnReporting = content.includes('Vulnerability Reporting') || 
                                   content.includes('vulnerability reporting');
            
            this.addValidation(
                'DOCUMENTATION',
                'vulnerability_reporting',
                hasVulnReporting,
                3,
                'Vulnerability reporting process documented',
                'Add vulnerability reporting process to documentation'
            );
        }
    }

    // Perform runtime security checks
    performRuntimeChecks() {
        console.log('🔍 Performing runtime security checks...');

        // Check for secure communication setup
        const secureMessagingExists = fs.existsSync(path.join(this.extensionPath, 'secure-messaging.js'));
        const hasMessagingUsage = this.checkForSecureMessagingUsage();

        this.addValidation(
            'RUNTIME',
            'secure_messaging_implemented',
            secureMessagingExists && hasMessagingUsage,
            5,
            'Secure messaging is properly implemented',
            'Implement and use secure messaging utilities'
        );

        // Check for secure storage setup
        const secureStorageExists = fs.existsSync(path.join(this.extensionPath, 'secure-storage.js'));
        const hasStorageUsage = this.checkForSecureStorageUsage();

        this.addValidation(
            'RUNTIME',
            'secure_storage_implemented',
            secureStorageExists && hasStorageUsage,
            5,
            'Secure storage is properly implemented',
            'Implement and use secure storage utilities'
        );
    }

    // Check if secure messaging is actually used in code
    checkForSecureMessagingUsage() {
        const jsFiles = this.findFiles(this.extensionPath, '.js');
        
        return jsFiles.some(filePath => {
            if (filePath.includes('node_modules') || filePath.includes('security-')) {
                return false;
            }
            
            const content = fs.readFileSync(filePath, 'utf8');
            return content.includes('SecureMessaging') || content.includes('securePostMessage');
        });
    }

    // Check if secure storage is actually used in code
    checkForSecureStorageUsage() {
        const jsFiles = this.findFiles(this.extensionPath, '.js');
        
        return jsFiles.some(filePath => {
            if (filePath.includes('node_modules') || filePath.includes('security-')) {
                return false;
            }
            
            const content = fs.readFileSync(filePath, 'utf8');
            return content.includes('SecureStorage') || content.includes('setSecureItem');
        });
    }

    // Utility method to find files with specific extension
    findFiles(dir, extension) {
        let files = [];
        
        const scan = (currentDir) => {
            try {
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
            } catch (err) {
                // Ignore permission errors
            }
        };
        
        scan(dir);
        return files;
    }

    // Generate comprehensive validation report
    generateValidationReport() {
        console.log('\n📊 SECURITY VALIDATION REPORT');
        console.log('='.repeat(60));
        
        const passedTests = this.validationResults.filter(r => r.passed).length;
        const totalTests = this.validationResults.length;
        const passRate = ((passedTests / totalTests) * 100).toFixed(1);

        console.log(`\n📈 VALIDATION SUMMARY:`);
        console.log(`✅ Passed: ${passedTests}/${totalTests} tests (${passRate}%)`);
        console.log(`🔢 Security Score: ${this.securityScore}/${this.maxScore} (${((this.securityScore/this.maxScore)*100).toFixed(1)}%)`);

        // Determine overall security level
        const securityLevel = this.getSecurityLevel(this.securityScore);
        const levelColor = this.getSecurityLevelColor(securityLevel);
        console.log(`🛡️  Security Level: ${levelColor}${securityLevel}\x1b[0m`);

        // Category breakdown
        const categories = this.validationResults.reduce((acc, result) => {
            if (!acc[result.category]) {
                acc[result.category] = { passed: 0, total: 0, score: 0 };
            }
            acc[result.category].total++;
            if (result.passed) {
                acc[result.category].passed++;
            }
            acc[result.category].score += result.score;
            return acc;
        }, {});

        console.log('\n📊 CATEGORY BREAKDOWN:');
        Object.entries(categories).forEach(([category, stats]) => {
            const rate = ((stats.passed / stats.total) * 100).toFixed(1);
            console.log(`${category}: ${stats.passed}/${stats.total} (${rate}%) - Score: ${stats.score}`);
        });

        // Failed validations
        const failedValidations = this.validationResults.filter(r => !r.passed);
        if (failedValidations.length > 0) {
            console.log('\n❌ FAILED VALIDATIONS:');
            console.log('-'.repeat(60));
            
            failedValidations.forEach((validation, index) => {
                console.log(`\n${index + 1}. ${validation.category} - ${validation.test}`);
                console.log(`   Description: ${validation.description}`);
                if (validation.remediation) {
                    console.log(`   Remediation: ${validation.remediation}`);
                }
            });
        }

        // Write detailed JSON report
        this.writeValidationReport();
        
        // Security recommendations based on results
        this.generateSecurityRecommendations();
    }

    getSecurityLevel(score) {
        if (score >= 85) return 'EXCELLENT';
        if (score >= 70) return 'GOOD';
        if (score >= 50) return 'FAIR';
        if (score >= 30) return 'POOR';
        return 'CRITICAL';
    }

    getSecurityLevelColor(level) {
        const colors = {
            'EXCELLENT': '\x1b[32m', // Green
            'GOOD': '\x1b[36m',      // Cyan
            'FAIR': '\x1b[33m',      // Yellow
            'POOR': '\x1b[91m',      // Light Red
            'CRITICAL': '\x1b[31m'   // Red
        };
        return colors[level] || '\x1b[37m';
    }

    writeValidationReport() {
        const report = {
            extension: 'SpanTree',
            validationDate: new Date().toISOString(),
            summary: {
                totalTests: this.validationResults.length,
                passedTests: this.validationResults.filter(r => r.passed).length,
                securityScore: this.securityScore,
                maxScore: this.maxScore,
                securityLevel: this.getSecurityLevel(this.securityScore)
            },
            validations: this.validationResults,
            recommendations: this.generateRecommendationsList()
        };

        fs.writeFileSync(
            path.join(this.extensionPath, 'security-validation-report.json'),
            JSON.stringify(report, null, 2)
        );

        console.log(`\n📄 Validation report saved to: security-validation-report.json`);
    }

    generateRecommendationsList() {
        const failedValidations = this.validationResults.filter(r => !r.passed);
        return failedValidations.map(v => ({
            category: v.category,
            test: v.test,
            priority: this.getPriority(v.score),
            remediation: v.remediation
        })).sort((a, b) => b.priority - a.priority);
    }

    getPriority(score) {
        if (score >= 10) return 5; // High priority
        if (score >= 7) return 4;  // Medium-high priority
        if (score >= 5) return 3;  // Medium priority
        if (score >= 3) return 2;  // Low-medium priority
        return 1; // Low priority
    }

    generateSecurityRecommendations() {
        console.log('\n💡 SECURITY RECOMMENDATIONS:');
        console.log('-'.repeat(60));

        const recommendations = [
            '1. 🎯 Focus on fixing CRITICAL and HIGH priority issues first',
            '2. 🔒 Implement all missing security utilities (secure messaging, storage)',
            '3. 📝 Complete security documentation including vulnerability reporting',
            '4. 🔄 Set up automated dependency vulnerability scanning',
            '5. 🧪 Implement security testing in your CI/CD pipeline',
            '6. 👥 Conduct regular security code reviews',
            '7. 📊 Monitor security metrics and trends over time',
            '8. 🛡️ Consider additional security measures like rate limiting',
            '9. 🔍 Perform penetration testing on critical functionality',
            '10. 📚 Keep up with latest browser extension security best practices'
        ];

        recommendations.forEach(rec => console.log(rec));
    }

    // Main validation method
    async runValidation() {
        console.log('🚀 Starting Security Validation...\n');
        
        this.validateManifestSecurity();
        this.validateSecurityUtilities();
        this.validateCodeSecurity();
        this.validateDependencies();
        this.validateDocumentation();
        this.performRuntimeChecks();
        
        this.generateValidationReport();
        
        console.log('\n✅ Security validation complete!');
        
        // Return validation summary for programmatic use
        return {
            passed: this.validationResults.filter(r => r.passed).length,
            total: this.validationResults.length,
            score: this.securityScore,
            level: this.getSecurityLevel(this.securityScore)
        };
    }
}

// Run the security validator
if (require.main === module) {
    const validator = new SecurityValidator();
    validator.runValidation().catch(console.error);
}

module.exports = SecurityValidator;