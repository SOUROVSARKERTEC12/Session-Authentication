import express from 'express';
import {
    register,
    verifyEmailOTP,
    login,
    verifyLoginOTP,
    logout,
    homepage,
} from '../controllers/index.js';
import {verifyToken} from "../middlewares/token.middleware.js";

const router = express.Router();

// Register a new user
router.post('/register', register);

// Verify email OTP for registration
router.post('/verify-email-otp', verifyEmailOTP);

// Login a user
router.post('/login', login);
//
// Verify OTP for login
router.post('/verify-login-otp', verifyLoginOTP);
//
// Logout the user
router.post('/logout', logout);
//
// Homepage route (accessible to logged-in users only)
router.get('/home',verifyToken, homepage);

export default router;
