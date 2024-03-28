var jwt = require('jsonwebtoken');
const authConfig = require('../config/auth.config');
const getJWT = (values) => {
    const token = jwt.sign({ ...values },
        authConfig.secret,
        {
            algorithm: 'HS256',
            allowInsecureKeySizes: true,
            expiresIn: 86400, // 24 hours
        });
    return token;
}

module.exports = { getJWT }