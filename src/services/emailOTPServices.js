import nodemailer from 'nodemailer';
import otpGenerator from "otp-generator";

/**
 * Email OTP Service
 */


const EmailOTPService = {
    /**
     * Generate and store an OTP for a user
     * @returns {string} The generated OTP
     */
    generateOTP: function () {
        // Generate a 6-digit OTP
        return otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false,
            digits: true,
        });
    },


    /**
     * Send the OTP to the user's email
     * @param {string} userId - The user's ID
     * @param {string} email - The user's email address
     * @param {string} otp - The OTP to send
     */
    async sendOTP(otp, email) {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "gamagang982@gmail.com",
                pass: "psst nzmj bnwp wtrs",
            },
        });

        const mailOptions = {
            from: "gamagang982@gmail.com",
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP is: ${otp}. It will expire in 5 minutes.`,
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log(`OTP sent to ${email}`);
        } catch (error) {
            console.error('Error sending OTP email:', error);
            console.error('Error details:', error.response || error.message);
            throw new Error('Failed to send OTP email');
        }
    }
};

export default EmailOTPService;