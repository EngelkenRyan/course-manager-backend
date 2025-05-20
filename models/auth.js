const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET;

// Verify JWT token
function authenticateToken(req, res, next) {
    const token = req.headers['x-auth'];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// Auth for teachers
function authorizeTeachersOnly(req, res, next) {
    if (req.user.role !== 'teacher') {
        return res.status(403).json({ error: 'Only teachers can perform this action' });
    }
    next();
}

module.exports = { authenticateToken, authorizeTeachersOnly };
