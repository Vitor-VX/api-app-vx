const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRECT;

const verifyTokenRouter = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Token de autenticação não fornecido.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        jwt.verify(token, JWT_SECRET);

        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Reinicie o app.' });
    }
};

const verifyCookieTokenSession = (req, res, next) => {
    const authCookie = req.cookie.token_account

    try {
        jwt.verify(authCookie, JWT_SECRET);

        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Reinicie o app.' });
    }
}

module.exports = {
    verifyTokenRouter, verifyCookieTokenSession
}