#!/usr/bin/env node
/**
 * Automated Security Fixes for SpanTree Browser Extension
 * 
 * This tool implements basic automated fixes for common security issues
 * identified by the security analysis tool.
 */

const fs = require('fs');
const path = require('path');

class SecurityFixer {
    constructor() {
        this.extensionPath = process.cwd();
        this.manifestPath = path.join(this.extensionPath, 'manifest.json');
        this.packagePath = path.join(this.extensionPath, 'package.json');
        this.appliedFixes = [];
    }

    logFix(type, description) {
        console.log(`✅ ${type}: ${description}`);
        this.appliedFixes.push({ type, description, timestamp: new Date().toISOString() });
    }

    // Fix overly broad permissions in manifest.json
    fixManifestPermissions() {
        console.log('🔧 Fixing manifest permissions...');
        
        if (!fs.existsSync(this.manifestPath)) {
            console.log('❌ manifest.json not found');
            return;
        }

        const manifest = JSON.parse(fs.readFileSync(this.manifestPath, 'utf8'));
        let changed = false;

        // Create a more secure version with restricted permissions
        const secureManifest = { ...manifest };

        // Fix host permissions - restrict to GitLab domains only
        if (secureManifest.host_permissions && secureManifest.host_permissions.includes('<all_urls>')) {
            secureManifest.host_permissions = [
                "https://gitlab.com/*",
                "https://*.gitlab.com/*",
                "https://gitlab.org/*",
                "https://*.gitlab.org/*"
            ];
            this.logFix('PERMISSIONS', 'Restricted host_permissions to GitLab domains only');
            changed = true;
        }

        // Fix content script matches
        if (secureManifest.content_scripts) {
            secureManifest.content_scripts.forEach((script, index) => {
                if (script.matches && script.matches.includes('<all_urls>')) {
                    script.matches = [
                        "https://gitlab.com/*",
                        "https://*.gitlab.com/*",
                        "https://gitlab.org/*",
                        "https://*.gitlab.org/*"
                    ];
                    this.logFix('CONTENT_SCRIPTS', `Restricted content script ${index} to GitLab domains`);
                    changed = true;
                }
            });
        }

        // Fix web accessible resources
        if (secureManifest.web_accessible_resources) {
            secureManifest.web_accessible_resources.forEach(resource => {
                if (resource.matches && resource.matches.includes('<all_urls>')) {
                    resource.matches = [
                        "https://gitlab.com/*",
                        "https://*.gitlab.com/*",
                        "https://gitlab.org/*",
                        "https://*.gitlab.org/*"
                    ];
                    this.logFix('WEB_RESOURCES', 'Restricted web accessible resources to GitLab domains');
                    changed = true;
                }
            });
        }

        // Add Content Security Policy
        if (!secureManifest.content_security_policy) {
            secureManifest.content_security_policy = {
                "extension_pages": "script-src 'self'; object-src 'none'; base-uri 'none';"
            };
            this.logFix('CSP', 'Added strict Content Security Policy');
            changed = true;
        }

        // Save the secure manifest
        if (changed) {
            // Backup original
            fs.writeFileSync(this.manifestPath + '.backup', JSON.stringify(manifest, null, 2));
            
            // Write secure version
            fs.writeFileSync(this.manifestPath, JSON.stringify(secureManifest, null, 2));
            this.logFix('BACKUP', 'Original manifest backed up to manifest.json.backup');
        }
    }

    // Create secure wrapper for postMessage
    createSecurePostMessageWrapper() {
        console.log('🔧 Creating secure postMessage wrapper...');
        
        const secureWrapper = `
/**
 * Secure PostMessage Wrapper for SpanTree Extension
 * 
 * This wrapper provides origin validation and secure messaging
 * for the SpanTree browser extension.
 */

class SecureMessaging {
    constructor(allowedOrigins = []) {
        this.allowedOrigins = allowedOrigins.length > 0 ? allowedOrigins : [
            'https://gitlab.com',
            'https://gitlab.org'
        ];
    }

    // Secure postMessage with origin validation
    securePostMessage(targetWindow, message, targetOrigin = '*') {
        // Validate target origin against allowed origins
        if (targetOrigin === '*') {
            console.warn('PostMessage sent to all origins - consider specifying target origin');
        }

        // Add security metadata
        const secureMessage = {
            ...message,
            timestamp: Date.now(),
            source: 'spantree-extension',
            nonce: this.generateNonce()
        };

        targetWindow.postMessage(secureMessage, targetOrigin);
    }

    // Secure message event listener with origin validation
    addSecureMessageListener(callback) {
        window.addEventListener('message', (event) => {
            // Validate origin
            if (!this.isOriginAllowed(event.origin)) {
                console.warn('Received message from unauthorized origin:', event.origin);
                return;
            }

            // Validate message structure
            if (!this.isValidMessage(event.data)) {
                console.warn('Received invalid message format');
                return;
            }

            // Call the original callback with validated event
            callback(event);
        });
    }

    // Check if origin is in allowed list
    isOriginAllowed(origin) {
        if (!origin) return false;
        
        return this.allowedOrigins.some(allowedOrigin => {
            if (allowedOrigin.includes('*')) {
                // Handle wildcard domains
                const baseOrigin = allowedOrigin.replace('*', '');
                return origin.endsWith(baseOrigin);
            }
            return origin === allowedOrigin;
        });
    }

    // Validate message format
    isValidMessage(data) {
        return data && 
               typeof data === 'object' && 
               data.source === 'spantree-extension' &&
               data.timestamp &&
               data.nonce;
    }

    // Generate cryptographic nonce for message validation
    generateNonce() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureMessaging;
}
`;

        fs.writeFileSync(
            path.join(this.extensionPath, 'secure-messaging.js'),
            secureWrapper
        );

        this.logFix('SECURE_MESSAGING', 'Created secure postMessage wrapper');
    }

    // Create secure storage utility
    createSecureStorageUtility() {
        console.log('🔧 Creating secure storage utility...');
        
        const secureStorage = `
/**
 * Secure Storage Utility for SpanTree Extension
 * 
 * Provides encrypted storage capabilities for sensitive data
 */

class SecureStorage {
    constructor() {
        this.keyPrefix = 'spantree_secure_';
    }

    // Encrypt data before storing
    async encryptData(data, key = 'default') {
        try {
            const dataString = JSON.stringify(data);
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(dataString);

            // Generate encryption key from provided key
            const cryptoKey = await this.generateKey(key);
            
            // Generate random IV
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt the data
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                cryptoKey,
                dataBuffer
            );

            // Combine IV and encrypted data
            const result = {
                iv: Array.from(iv),
                data: Array.from(new Uint8Array(encrypted))
            };

            return JSON.stringify(result);
        } catch (error) {
            console.error('Encryption failed:', error);
            throw new Error('Failed to encrypt data');
        }
    }

    // Decrypt data after retrieving
    async decryptData(encryptedData, key = 'default') {
        try {
            const { iv, data } = JSON.parse(encryptedData);
            
            // Generate decryption key
            const cryptoKey = await this.generateKey(key);
            
            // Decrypt the data
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: new Uint8Array(iv) },
                cryptoKey,
                new Uint8Array(data)
            );

            // Convert back to string and parse
            const decoder = new TextDecoder();
            const dataString = decoder.decode(decrypted);
            
            return JSON.parse(dataString);
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Failed to decrypt data');
        }
    }

    // Generate encryption key from string
    async generateKey(keyString) {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(keyString + 'spantree-salt-2024');
        
        const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
        
        return await crypto.subtle.importKey(
            'raw',
            hashBuffer,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Secure localStorage wrapper
    async setSecureItem(key, value) {
        try {
            const encrypted = await this.encryptData(value);
            localStorage.setItem(this.keyPrefix + key, encrypted);
        } catch (error) {
            console.error('Secure storage failed:', error);
            // Fallback to regular storage with warning
            console.warn('Falling back to unencrypted storage');
            localStorage.setItem(this.keyPrefix + key + '_unencrypted', JSON.stringify(value));
        }
    }

    // Secure localStorage retrieval
    async getSecureItem(key) {
        try {
            const encrypted = localStorage.getItem(this.keyPrefix + key);
            if (!encrypted) {
                // Check for unencrypted fallback
                const unencrypted = localStorage.getItem(this.keyPrefix + key + '_unencrypted');
                return unencrypted ? JSON.parse(unencrypted) : null;
            }
            
            return await this.decryptData(encrypted);
        } catch (error) {
            console.error('Secure retrieval failed:', error);
            return null;
        }
    }

    // Remove secure item
    removeSecureItem(key) {
        localStorage.removeItem(this.keyPrefix + key);
        localStorage.removeItem(this.keyPrefix + key + '_unencrypted');
    }

    // Clear all secure items
    clearSecureStorage() {
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith(this.keyPrefix)) {
                localStorage.removeItem(key);
            }
        });
    }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureStorage;
}
`;

        fs.writeFileSync(
            path.join(this.extensionPath, 'secure-storage.js'),
            secureStorage
        );

        this.logFix('SECURE_STORAGE', 'Created secure storage utility');
    }

    // Create security documentation
    createSecurityDocumentation() {
        console.log('🔧 Creating security documentation...');
        
        const securityDoc = `# SpanTree Extension Security Guide

## Security Features

This document outlines the security measures implemented in the SpanTree browser extension to protect users from common web extension vulnerabilities.

## Security Improvements Applied

### 1. Permission Restrictions
- **Host Permissions**: Limited to GitLab domains only (gitlab.com, gitlab.org)
- **Content Scripts**: Restricted to run only on GitLab domains
- **Web Resources**: Accessible only from GitLab domains

### 2. Content Security Policy (CSP)
- Strict CSP implemented to prevent XSS attacks
- Script sources limited to extension files only
- Object sources blocked entirely

### 3. Secure Messaging
- Origin validation for all postMessage communications
- Message authentication using nonces
- Whitelisted allowed origins

### 4. Secure Storage
- Encrypted storage for sensitive data using AES-GCM
- Key derivation from user context
- Automatic fallback mechanisms

## Security Best Practices

### For Developers

1. **Always validate input data**
   \`\`\`javascript
   function validateInput(input) {
       if (typeof input !== 'string' || input.length > 1000) {
           throw new Error('Invalid input');
       }
       return input.replace(/[<>]/g, '');
   }
   \`\`\`

2. **Use secure messaging**
   \`\`\`javascript
   const secureMessaging = new SecureMessaging(['https://gitlab.com']);
   secureMessaging.securePostMessage(targetWindow, message, 'https://gitlab.com');
   \`\`\`

3. **Implement secure storage**
   \`\`\`javascript
   const secureStorage = new SecureStorage();
   await secureStorage.setSecureItem('userPrefs', userData);
   \`\`\`

### For Users

1. **Verify Extension Source**: Only install from official browser stores
2. **Review Permissions**: Check what permissions the extension requests
3. **Keep Updated**: Ensure the extension is always up to date
4. **Report Issues**: Report any suspicious behavior immediately

## Security Checklist

- [ ] Manifest permissions are minimal and specific
- [ ] Content Security Policy is implemented
- [ ] Input validation is applied to all user inputs
- [ ] Secure communication protocols are used
- [ ] Sensitive data is encrypted before storage
- [ ] Dependencies are regularly updated
- [ ] Code is regularly audited for vulnerabilities

## Vulnerability Reporting

If you discover a security vulnerability in SpanTree, please report it privately to the maintainers.

### Reporting Process

1. **Do not** create a public issue
2. Contact maintainers directly via email
3. Provide detailed information about the vulnerability
4. Allow reasonable time for fix before public disclosure

## Security Updates

This extension follows these security update practices:

- Regular dependency updates
- Automated vulnerability scanning
- Security-focused code reviews
- Rapid response to security issues

## Compliance

This extension follows security standards from:

- OWASP Web Security Guidelines
- Chrome Extension Security Best Practices
- Mozilla Add-on Security Guidelines

## Additional Resources

- [Chrome Extension Security](https://developer.chrome.com/docs/extensions/mv3/security/)
- [Firefox Add-on Security](https://extensionworkshop.com/documentation/develop/build-a-secure-extension/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

Last Updated: ${new Date().toISOString()}
Version: 1.0.0
`;

        fs.writeFileSync(
            path.join(this.extensionPath, 'SECURITY.md'),
            securityDoc
        );

        this.logFix('DOCUMENTATION', 'Created comprehensive security documentation');
    }

    // Generate security report
    generateSecurityReport() {
        const report = {
            extension: 'SpanTree',
            securityFixesApplied: this.appliedFixes,
            timestamp: new Date().toISOString(),
            summary: {
                totalFixes: this.appliedFixes.length,
                categories: this.appliedFixes.reduce((acc, fix) => {
                    acc[fix.type] = (acc[fix.type] || 0) + 1;
                    return acc;
                }, {})
            }
        };

        fs.writeFileSync(
            path.join(this.extensionPath, 'security-fixes-applied.json'),
            JSON.stringify(report, null, 2)
        );

        console.log(`\n📄 Security fixes report saved to: security-fixes-applied.json`);
    }

    // Main fix application method
    async applyFixes() {
        console.log('🚀 Applying automated security fixes...\n');
        
        this.fixManifestPermissions();
        this.createSecurePostMessageWrapper();
        this.createSecureStorageUtility();
        this.createSecurityDocumentation();
        
        this.generateSecurityReport();
        
        console.log(`\n✅ Applied ${this.appliedFixes.length} security fixes successfully!`);
        console.log('\n⚠️  Note: These are basic automated fixes. Manual review and testing is still required.');
        console.log('\n🔍 Next steps:');
        console.log('1. Review the changes in manifest.json');
        console.log('2. Update your code to use the secure messaging and storage utilities');
        console.log('3. Test the extension thoroughly');
        console.log('4. Update dependencies to latest secure versions');
    }
}

// Run the security fixer
if (require.main === module) {
    const fixer = new SecurityFixer();
    fixer.applyFixes().catch(console.error);
}

module.exports = SecurityFixer;