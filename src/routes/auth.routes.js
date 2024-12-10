import express from 'express';
import {
    register,
    verifyEmailOTP,
    loginFirst,
    verifyLogin,
    login,
    // Forgot password,
    // Reset password,
    // Change password,
    logout,
    homepage,
    // generate2FAG,
    // verify2FA,
} from '../controllers/index.js';
import {verifyToken} from "../middlewares/token.middleware.js";

const router = express.Router();

// Register a new user
router.post('/register', register);

// Verify email OTP for registration
router.post('/verify-email-otp', verifyEmailOTP);

// Login a user
router.post('/login-first', loginFirst);

// Verify OTP for login
router.post('/verify-login', verifyLogin);

// User Login
router.post('/login', login);

// Logout the user
router.post('/logout', logout);

// Google Authenticator Generator
// router.post('/google-authenticator', generate2FAG);

// QR Code Authenticator
// router.post('/qrcode-authenticator', verify2FA)

// Homepage route (accessible to logged-in users only)
router.get('/home',verifyToken, homepage);

export default router;
