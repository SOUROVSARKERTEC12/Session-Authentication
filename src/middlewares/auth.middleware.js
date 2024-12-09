import Session from "../models/Session.js";
import User from "../models/User.js";


export const authenticateSession = async (req, res, next) => {
    try {
        // Extract session ID from cookie
        const sessionId = req.headers.cookie?.split('=')[1];
        if (!sessionId) {
            return res.status(401).json({ error: 'Unauthorized: No session provided' });
        }

        // Validate session in the database
        const session = await Session.findOne({ where: { id: sessionId } });
        if (!session || new Date() > session.expiresAt) {
            return res.status(401).json({ error: 'Unauthorized: Invalid or expired session' });
        }

        // Attach user to the request
        const user = await User.findByPk(session.userId);
        req.user = user;

        next();
    } catch (error) {
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
};
