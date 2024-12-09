import jwt from 'jsonwebtoken';
import Session from "../models/Session.js";

export const verifyToken = async (req, res, next) => {
    try {
        // Extract the token from the 'Authorization' header
        const authHeader = req.headers['authorization'];

        // Ensure Authorization header exists and follows the 'Bearer <token>' format
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(403).json({ error: 'Authorization header is required and should start with Bearer' });
        }

        // Extract the token from the header
        const token = authHeader.split(' ')[1];

        // Check if the token exists in the Session database
        const session = await Session.findOne({ where: { token } });
        if (!session) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        // Verify the token using the secret key
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach user information to the request object for use in subsequent middlewares or routes
        req.user = {
            id: decoded.id,      // Example: user ID from the token payload
            email: decoded.email // Example: email from the token payload
        };

        next(); // Token is valid, proceed to the next middleware/route handler
    } catch (error) {
        console.error('Token verification error:', error.message);
        return res.status(403).json({ error: 'Invalid or expired token', details: error.message });
    }
};
