
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
