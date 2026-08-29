module.exports = async (req, res) => {
    res.status(200).json({
        status: 'healthy',
        service: 'zaka-auth-gateway',
        timestamp: new Date().toISOString()
    });
};
