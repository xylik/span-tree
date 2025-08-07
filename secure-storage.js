
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
