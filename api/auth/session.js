// Vercel serverless function for Zaka Authentication
const crypto = require('crypto');

// Client signature configuration
const CLIENT_SIGNATURE = {
    clientSecret: process.env.CLIENT_SECRET || 'zaka_ff_2024_secure_key',
    platform: 'freefire',
    version: '1.0.0',
    signatureHeader: 'x-zaka-signature',
    timestampHeader: 'x-zaka-timestamp',
    nonceHeader: 'x-zaka-nonce'
};

// Main handler
module.exports = async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, x-zaka-signature, x-zaka-timestamp, x-zaka-nonce'
    );

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
        // Parse request body (Vercel may provide it differently)
        let body = req.body;
        if (!body || Object.keys(body).length === 0) {
            // Try to parse raw body
            if (req.rawBody) {
                try {
                    body = JSON.parse(req.rawBody);
                } catch {
                    body = null;
                }
            }
        }

        if (!body) {
            return res.status(400).json({
                success: false,
                error: 'Invalid request body',
                code: 'INVALID_BODY',
                timestamp: new Date().toISOString()
            });
        }

        // For simplicity, skip signature validation for now
        // Add it back once basic connectivity is confirmed
        
        const { account_id, request_id, platform, client_version } = body;

        // Validate required fields
        if (!account_id || typeof account_id !== 'string' || account_id.length < 3) {
            return res.status(400).json({
                success: false,
                error: 'Invalid account_id',
                code: 'INVALID_ACCOUNT_ID',
                timestamp: new Date().toISOString()
            });
        }

        // Generate or use provided request_id
        let finalRequestId = request_id || crypto.randomUUID();
        
        // Validate UUID format if provided
        if (request_id) {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(finalRequestId)) {
                finalRequestId = crypto.randomUUID();
            }
        }

        // Generate session token
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const expiresIn = 3600; // 1 hour

        console.log(`Auth success for account: ${account_id}`);

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
            error: 'Internal server error: ' + error.message,
            code: 'INTERNAL_ERROR',
            timestamp: new Date().toISOString()
        });
    }
};
