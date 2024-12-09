import {v4 as uuid} from 'uuid';
import {validateUser} from '../validators/user.validator.js';
import EmailOTPService from '../services/emailOTPServices.js'; // Assuming EmailOTPService is set up for OTP generation
import sequelize from '../config/database.config.js';
import User from "../models/User.js";
import TempUser from "../models/tempUser.js";
import OTPStore from "../models/OTPStore.js";
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import Session from "../models/Session.js";
import RememberedDevice from "../models/RememberDevices.js";
import {Op} from "sequelize";



export const register = async (req, res) => {
    const transaction = await sequelize.transaction();

    try {
        // Validate input using Zod
        const validatedData = validateUser(req.body);

        // Check if email is already registered or pending in TempUser table
        const existingUser = await User.findOne({
            where: {email: validatedData.email},
            transaction // Ensure the transaction is passed to the query
        });

        if (existingUser) {
            return res.status(400).json({error: 'Email already registered'});
        }

        const tempUser = await TempUser.findOne({
            where: {email: validatedData.email},
            transaction // Ensure the transaction is passed to the query
        });

        if (tempUser) {
            return res.status(400).json({error: 'Email already exists in pending verification'});
        }

        // Create a new TempUser entry in the database with transaction handling
        const tempUserData = await TempUser.create(validatedData, {transaction});

        // Request OTP and send verification email
        const otp = EmailOTPService.generateOTP();
        // console.log(otp);

        // Store OTP in OTPStore table, ensuring the OTP is associated with the TempUser
        await OTPStore.create({
            otp,
            tempUserId: tempUserData.id, // Linking OTP to TempUser's ID
            email: tempUserData.email
        }, {transaction});

        // Send OTP via email
        await EmailOTPService.sendOTP(otp, validatedData.email);

        // Commit the transaction after all operations are successful
        await transaction.commit();

        res.status(200).json({message: 'Registration initiated. Please verify your email to complete registration.'});
    } catch (error) {
        // If an error occurs, rollback the transaction to maintain data integrity
        console.error(error);
        await transaction.rollback();
        res.status(500).json({error: 'Error registering user', details: error.message});
    }
};

// Verify OTP and Complete Registration
export const verifyEmailOTP = async (req, res) => {
    const {email, otp} = req.body; // Extract email and OTP from the request body

    // Check if email and OTP are provided
    if (!email || !otp) {
        return res.status(400).json({error: 'Email and OTP are required'});
    }

    try {
        // Step 1: Find the OTP in OTPStore based on the provided OTP
        const otpRecord = await OTPStore.findOne({
            where: {otp: otp, email: email} // Query both OTP and email to ensure validity
        });

        // If OTP does not exist or is invalid
        if (!otpRecord) {
            return res.status(400).json({error: 'Invalid OTP or email'});
        }

        // Step 2: Find the associated TempUser using the tempUserId from OTPStore
        const tempUser = await TempUser.findByPk(otpRecord.tempUserId);

        // If no TempUser is found
        if (!tempUser) {
            return res.status(400).json({error: 'No associated pending user found'});
        }
        const hashedPassword = await bcrypt.hash(tempUser.password, 10);

        // Step 3: Create the final User from the TempUser data
        const newUser = await User.create({
            username: tempUser.username, // Assuming TempUser stores username
            email: tempUser.email,
            password: hashedPassword, // Assuming TempUser stores password
            firstName: tempUser.firstName, // Assuming TempUser stores first name
            lastName: tempUser.lastName, // Assuming TempUser stores last name
        });

        // Step 4: Clean up: Delete the OTP and TempUser once the user is created
        await OTPStore.destroy({where: {otp, email}});
        await TempUser.destroy({where: {id: tempUser.id}});

        // Step 5: Send response back to client
        res.status(200).json({
            message: 'OTP verified successfully. User registration complete.',
            user: newUser, // Send back the new user data (optional)
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: 'Error verifying OTP',
            details: error.message,
        });
    }
};

// Login a user
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user by email
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email' });
        }

        const UserID = user.id;
        const UserEmail = user.email;
        console.log(UserEmail);

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Check if deviceId exists in cookies
        const deviceId = req.cookies.deviceId;
        console.log("Device ID from cookies:", deviceId);

        if (deviceId) {
            // Check if device is remembered and still valid
            const deviceRemembered = await RememberedDevice.findOne({
                where: {
                    userId: user.id,
                    deviceId,
                    expirationTime: { [Op.gt]: new Date() }, // Ensure token is still valid
                },
            });

            if (deviceRemembered) {
                // Device is remembered; Generate a session and token
                const sessionId = uuid();
                const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours expiry
                const newToken = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

                // Create a new session
                await Session.create({
                    id: sessionId,
                    userId: user.id,
                    token: newToken,
                    expiresAt,
                });

                // Set the session cookie
                res.set('Set-Cookie', `session=${sessionId}; HttpOnly; Path=/`);

                return res.status(200).json({ message: 'Login successful', newToken });
            }
        }

        // If no deviceId or unrecognized device, send OTP
        const otp = EmailOTPService.generateOTP();
        console.log("Generated OTP:", otp);

        // Save OTP in OTPStore with email for verification
        await OTPStore.create({
            otp,
            tempUserId: UserID,
            email: UserEmail,
        });

        // Send OTP to the user's email
        await EmailOTPService.sendOTP(otp, email);

        // Save the device info for future recognition
        if (!deviceId) {
            const newDeviceId = uuid(); // Generate a new deviceId
            const expirationTime = new Date();
            expirationTime.setDate(expirationTime.getDate() + 7); // Expiration set to 7 days

            await RememberedDevice.create({
                userId: user.id,
                deviceId: newDeviceId,
                expirationTime,
            });

            // Set the new deviceId in cookies
            res.cookie('deviceId', newDeviceId, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }); // 7 days
        }

        res.status(200).json({
            message: 'OTP sent to your email. Please verify to complete login.',
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({
            error: 'Error during login',
            details: error.message,
        });
    }
};

// Verify OTP during login
export const verifyLoginOTP = async (req, res) => {
    const transaction = await sequelize.transaction();

    try {
        const { email, otp } = req.body;

        // Validate input
        if (!email || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        // Find OTP record in OTPStore
        const otpRecord = await OTPStore.findOne({
            where: {
                email,
                otp,
                createdAt: { [Op.gt]: new Date(Date.now() - 5 * 60 * 1000) }, // OTP must be within 5 minutes
            },
        });

        if (!otpRecord) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // Find the user associated with this email
        const user = await User.findOne({
            where: { email },
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Remove OTP record after successful verification
        await OTPStore.destroy({
            where: { email, otp },
            transaction,
        });

        // Generate a session token and JWT
        const sessionId = uuid();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours expiry
        const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Save the session in the database
        await Session.create({
            id: sessionId,
            userId: user.id,
            token,
            expiresAt,
            transaction,
        });

        // Check if deviceId exists in cookies
        let deviceId = req.cookies.deviceId;

        if (!deviceId) {
            deviceId = uuid(); // Generate a new deviceId if not present
            res.cookie('deviceId', deviceId, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }); // Set cookie for 7 days
        }

        // Remember the device for future logins
        const expirationTime = new Date();
        expirationTime.setDate(expirationTime.getDate() + 7); // Remember for 7 days

        await RememberedDevice.upsert({
            userId: user.id,
            deviceId,
            expirationTime,
            transaction,
        });

        // Commit the transaction
        await transaction.commit();

        // Set the session cookie
        res.set('Set-Cookie', `session=${sessionId}; HttpOnly; Path=/`);

        res.status(200).json({
            message: 'OTP verified successfully. Login complete.',
            token, // Send JWT token
            user: {
                id: user.id,
                email: user.email,
                name: user.name, // Include additional user info as required
            },
        });
    } catch (error) {
        // Rollback the transaction in case of an error
        await transaction.rollback();
        console.error('Error during OTP verification:', error);
        res.status(500).json({
            error: 'Error during OTP verification',
            details: error.message,
        });
    }
};

// Logout a user

export const logout = async (req, res) => {
    try {
        // Extract the token from the Authorization header
        const authHeader = req.headers['authorization'];
        const token = authHeader?.split(' ')[1]; // Extract token after "Bearer "
        // const token = verifyToken(token)
        const sessionId = req.cookies?.session;

        if (!token && !sessionId) {
            return res.status(400).json({ error: 'No session or token found to logout.' });
        }

        // console.log('Token:', token);
        const databaseToken =await Session.findOne({where: {token:token}})
        if(!databaseToken) {
            console.error('No matching session found for token:', token);
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        // console.log(databaseToken.token)

        // Destroy the session by token
        if (token && databaseToken.token) {
            const decoded = jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
                if (err) {
                    console.error('Invalid token:', err.message);
                    return null;
                }
                console.log("Decoded Token:", decoded);
                return decoded;
            });


            if (decoded) {
                if(decoded.id === databaseToken.userId){
                    await Session.destroy({ where: { token } });
                }
                // console.log(`Session for token ${token} destroyed.`);
            }
        }

        // Destroy the session by session ID (if provided)
        if (sessionId) {
            await Session.destroy({ where: { id: sessionId } });
            console.log(`Session with ID ${sessionId} destroyed.`);
        }

        // Clear cookies
        res.clearCookie('session', { httpOnly: true, secure: true, sameSite: 'Strict' });

        // Optionally set cookies to expire immediately
        res.set('Set-Cookie', [
            'session=; Path=/; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        ]);

        return res.status(200).json({ message: 'Logged out successfully.' });
    } catch (error) {
        console.error('Error during logout:', error);
        return res.status(500).json({
            error: 'Error during logout',
            details: error.message,
        });
    }
};


// Homepage route
export const homepage = async (req, res) => {
    try {
        const sessionId = req.cookies.session;

        // Check if session exists
        const session = await Session.findOne({where: {id: sessionId}});
        console.log(session);
        if (!session) {
            return res.status(403).json({message: 'Unauthorized. Please log in.'});
        }

        // Check if the user is visiting for the first time
        const user = await User.findByPk(session.userId);
        if (user.firstVisit) {
            user.firstVisit = false;
            await user.save();
            res.json({message: `Welcome, ${user.username}. You are visiting for the first time.`});
        } else {
            res.json({message: `Welcome back, ${user.username}.`});
        }
    } catch (error) {
        res.status(500).json({error: 'Error accessing home page', details: error.message});
    }
};