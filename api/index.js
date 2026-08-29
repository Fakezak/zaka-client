// Vercel serverless function for API root
module.exports = async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle OPTIONS request for CORS preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    // Return API information
    return res.status(200).json({
        success: true,
        service: 'Zaka Authentication Gateway API',
        version: '1.0.0',
        endpoints: [
            {
                path: '/api/health',
                method: 'GET',
                description: 'Health check endpoint'
            },
            {
                path: '/api/auth/session',
                method: 'POST',
                description: 'Authentication session endpoint'
            }
        ],
        timestamp: new Date().toISOString()
    });
};
