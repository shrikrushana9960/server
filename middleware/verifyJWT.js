const jwt = require('jsonwebtoken');
const authConfig = require('../config/auth.config');

const verifyJWT = (req, res, next) => {

    const token = req.headers.authorization || req.cookies.access_token;
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, authConfig.secret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Unauthorized: Invalid token' });
        }


        req.user = decoded;
        next();
    });
};

module.exports = verifyJWT;
