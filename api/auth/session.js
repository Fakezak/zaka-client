// Vercel serverless function for Zaka Authentication
const crypto = require('crypto');

// Client signature configuration
const CLIENT_SIGNATURE = {
    clientId: 'zaka-ff-client-v1',
    clientSecret: process.env.CLIENT_SECRET || 'zaka_ff_2024_secure_key',
    platform: 'freefire',
    version: '1.0.0',
    signatureHeader: 'x-zaka-signature',
    timestampHeader: 'x-zaka-timestamp',
    nonceHeader: 'x-zaka-nonce'
};

// Simple in-memory rate limiting (for serverless, use Upstash Redis in production)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 100; // Max requests per window

// Simple in-memory nonce storage (use Redis in production)
const nonceStore = new Set();

// Rate limiting function
function checkRateLimit(ip) {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW;
    
    // Clean up old entries
    for (const [key, timestamp] of rateLimitMap.entries()) {
        if (timestamp < windowStart) {
            rateLimitMap.delete(key);
        }
    }
    
    // Count requests from this IP
    const requestCount = Array.from(rateLimitMap.entries())
        .filter(([key, timestamp]) => key.startsWith(ip) && timestamp > windowStart)
        .length;
    
    if (requestCount >= RATE_LIMIT_MAX) {
        return false;
    }
    
    // Add current request
    rateLimitMap.set(`${ip}:${now}`, now);
    return true;
}

// Validate client signature
function validateClientSignature(req) {
    const signature = req.headers[CLIENT_SIGNATURE.signatureHeader];
    const timestamp = req.headers[CLIENT_SIGNATURE.timestampHeader];
    const nonce = req.headers[CLIENT_SIGNATURE.nonceHeader];
    
    if (!signature || !timestamp || !nonce) {
        return { valid: false, error: 'Missing signature headers', code: 'MISSING_HEADERS' };
    }

    // Check timestamp freshness (5 minutes window)
    const timestampNum = parseInt(timestamp);
    const now = Date.now();
    if (isNaN(timestampNum) || Math.abs(now - timestampNum) > 300000) {
        return { valid: false, error: 'Request timestamp expired', code: 'TIMESTAMP_EXPIRED' };
    }

    // Check nonce uniqueness (prevent replay attacks)
    if (nonceStore.has(nonce)) {
        return { valid: false, error: 'Nonce already used', code: 'NONCE_REUSED' };
    }

    // Generate expected signature
    const payload = `${req.method}${req.url}${timestamp}${nonce}${JSON.stringify(req.body)}`;
    const expectedSignature = crypto
        .createHmac('sha256', CLIENT_SIGNATURE.clientSecret)
        .update(payload)
        .digest('hex');

    if (signature !== expectedSignature) {
        return { valid: false, error: 'Invalid signature', code: 'INVALID_SIGNATURE' };
    }

    // Store nonce with TTL
    nonceStore.add(nonce);
    setTimeout(() => nonceStore.delete(nonce), 300000);

    return { valid: true };
}

// Main handler
module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-zaka-signature, x-zaka-timestamp, x-zaka-nonce');
    res.setHeader('Access-Control-Max-Age', '86400');

    // Handle OPTIONS request for CORS preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    // Only allow POST requests
    if (req.method !== 'POST') {
        return res.status(405).json({
            success: false,
            error: 'Method not allowed',
            code: 'METHOD_NOT_ALLOWED',
            timestamp: new Date().toISOString()
        });
    }

    try {
        // Rate limiting
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
        if (!checkRateLimit(clientIp)) {
            return res.status(429).json({
                success: false,
                error: 'Too many requests',
                code: 'RATE_LIMIT_EXCEEDED',
                timestamp: new Date().toISOString()
            });
        }

        // Validate client signature
        const signatureValidation = validateClientSignature(req);
        if (!signatureValidation.valid) {
            return res.status(401).json({
                success: false,
                error: signatureValidation.error,
                code: signatureValidation.code,
                timestamp: new Date().toISOString()
            });
        }

        // Parse request body
        const { account_id, request_id, platform, client_version } = req.body || {};

        // Validate required fields
        if (!account_id || typeof account_id !== 'string' || account_id.length < 3) {
            return res.status(400).json({
                success: false,
                error: 'Invalid account_id',
                code: 'INVALID_ACCOUNT_ID',
                timestamp: new Date().toISOString()
            });
        }

        if (platform && platform !== CLIENT_SIGNATURE.platform) {
            return res.status(400).json({
                success: false,
                error: 'Invalid platform',
                code: 'INVALID_PLATFORM',
                timestamp: new Date().toISOString()
            });
        }

        if (client_version && client_version !== CLIENT_SIGNATURE.version) {
            return res.status(400).json({
                success: false,
                error: 'Client version mismatch',
                code: 'VERSION_MISMATCH',
                timestamp: new Date().toISOString()
            });
        }

        // Generate or validate request_id
        let finalRequestId = request_id;
        if (!finalRequestId) {
            finalRequestId = crypto.randomUUID();
        } else {
            // Validate UUID format
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(finalRequestId)) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid request_id format',
                    code: 'INVALID_REQUEST_ID',
                    timestamp: new Date().toISOString()
                });
            }
        }

        // Generate session token
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const expiresIn = 3600; // 1 hour

        // In production, store session in Redis or database
        // For now, return session data directly

        return res.status(200).json({
            success: true,
            data: {
                request_id: finalRequestId,
                account_id,
                session_token: sessionToken,
                message: `Welcome user${account_id} to zaka project :)`,
                expires_in: expiresIn,
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Zaka auth error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
            timestamp: new Date().toISOString()
        });
    }
};
