// Vercel serverless function for health check
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

    // Only allow GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({
            success: false,
            error: 'Method not allowed',
            code: 'METHOD_NOT_ALLOWED',
            timestamp: new Date().toISOString()
        });
    }

    try {
        // Collect health information
        const healthData = {
            success: true,
            status: 'healthy',
            service: 'zaka-auth-gateway',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            environment: process.env.NODE_ENV || 'development',
            platform: process.platform,
            node_version: process.version,
            memory_usage: process.memoryUsage(),
            request_id: req.headers['x-request-id'] || null
        };

        // Log the health check
        console.log(`Health check successful at ${healthData.timestamp}`);

        // Return health status
        return res.status(200).json(healthData);

    } catch (error) {
        console.error('Health check error:', error);
        
        return res.status(503).json({
            success: false,
            status: 'unhealthy',
            service: 'zaka-auth-gateway',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
};
