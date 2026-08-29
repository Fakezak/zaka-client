const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4, validate: uuidValidate } = require('uuid');
const helmet = require('helmet');
const https = require('https');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 443;

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

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

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests', code: 'RATE_LIMIT_EXCEEDED' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Session storage (in production, use Redis or similar)
const activeSessions = new Map();

// Validate client signature
function validateClientSignature(req) {
    const signature = req.headers[CLIENT_SIGNATURE.signatureHeader];
    const timestamp = req.headers[CLIENT_SIGNATURE.timestampHeader];
    const nonce = req.headers[CLIENT_SIGNATURE.nonceHeader];
    
    if (!signature || !timestamp || !nonce) {
        return { valid: false, error: 'Missing signature headers' };
    }

    // Check timestamp freshness (5 minutes window)
    const timestampNum = parseInt(timestamp);
    const now = Date.now();
    if (Math.abs(now - timestampNum) > 300000) {
        return { valid: false, error: 'Request timestamp expired' };
    }

    // Check nonce uniqueness (prevent replay attacks)
    if (recentNonces.has(nonce)) {
        return { valid: false, error: 'Nonce already used' };
    }

    // Generate expected signature
    const payload = `${req.method}${req.originalUrl}${timestamp}${nonce}${JSON.stringify(req.body)}`;
    const expectedSignature = crypto
        .createHmac('sha256', CLIENT_SIGNATURE.clientSecret)
        .update(payload)
        .digest('hex');

    if (signature !== expectedSignature) {
        return { valid: false, error: 'Invalid signature' };
    }

    // Store nonce (in production, use Redis with TTL)
    recentNonces.add(nonce);
    setTimeout(() => recentNonces.delete(nonce), 300000);

    return { valid: true };
}

// Nonce storage (in production, use Redis)
const recentNonces = new Set();

// API endpoint for session authentication
app.post('/api/auth/session', authLimiter, async (req, res) => {
    try {
        // Validate client signature
        const signatureValidation = validateClientSignature(req);
        if (!signatureValidation.valid) {
            return res.status(401).json({
                success: false,
                error: signatureValidation.error,
                code: 'INVALID_SIGNATURE',
                timestamp: new Date().toISOString()
            });
        }

        // Validate request body
        const { account_id, platform, client_version } = req.body;
        
        if (!account_id || typeof account_id !== 'string' || account_id.length < 5) {
            return res.status(400).json({
                success: false,
                error: 'Invalid account_id',
                code: 'INVALID_ACCOUNT_ID',
                timestamp: new Date().toISOString()
            });
        }

        if (platform !== CLIENT_SIGNATURE.platform) {
            return res.status(400).json({
                success: false,
                error: 'Invalid platform',
                code: 'INVALID_PLATFORM',
                timestamp: new Date().toISOString()
            });
        }

        if (client_version !== CLIENT_SIGNATURE.version) {
            return res.status(400).json({
                success: false,
                error: 'Client version mismatch',
                code: 'VERSION_MISMATCH',
                timestamp: new Date().toISOString()
            });
        }

        // Generate request_id (if client didn't provide one)
        const request_id = req.body.request_id || uuidv4();

        // Validate request_id if provided
        if (req.body.request_id && !uuidValidate(req.body.request_id)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid request_id format',
                code: 'INVALID_REQUEST_ID',
                timestamp: new Date().toISOString()
            });
        }

        // Create session
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const sessionData = {
            account_id,
            request_id,
            session_token: sessionToken,
            created_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 3600000).toISOString(), // 1 hour
            platform,
            client_version,
            ip_address: req.ip
        };

        // Store session
        activeSessions.set(sessionToken, sessionData);

        // Return success response
        return res.status(200).json({
            success: true,
            data: {
                request_id,
                account_id,
                session_token: sessionToken,
                message: `Welcome user${account_id} to zaka project :)`,
                expires_in: 3600,
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Session creation error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
            timestamp: new Date().toISOString()
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        service: 'zaka-auth-gateway'
    });
});

// Blank landing page
app.get('/', (req, res) => {
    res.send(''); // Blank page for unauthenticated visitors
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Not found',
        code: 'NOT_FOUND',
        timestamp: new Date().toISOString()
    });
});

// HTTPS server
if (process.env.NODE_ENV === 'production') {
    const httpsOptions = {
        key: fs.readFileSync('/etc/letsencrypt/live/zaka.example.com/privkey.pem'),
        cert: fs.readFileSync('/etc/letsencrypt/live/zaka.example.com/cert.pem'),
        ca: fs.readFileSync('/etc/letsencrypt/live/zaka.example.com/chain.pem')
    };
    
    https.createServer(httpsOptions, app).listen(PORT, () => {
        console.log(`Zaka Auth Gateway running on HTTPS port ${PORT}`);
    });
} else {
    app.listen(3000, () => {
        console.log('Zaka Auth Gateway running on HTTP port 3000 (development)');
    });
}
