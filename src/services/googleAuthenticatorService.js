import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import {fileURLToPath} from 'url';
import {dirname, join} from 'path';
import fs from 'fs';
import User from '../models/User.js';

// Mimic __dirname in ES modules
const __dirname = dirname(fileURLToPath(import.meta.url));

const generate2FA = {
    // Wrap the function in a Promise to handle async file writing
    async g_Author(email) {
        console.log("Email: " + email);

        // Generate the 2FA secret
        const secret = speakeasy.generateSecret({
            name: `Google_Authenticator (${email})`, // Application name with user email
        });
        console.log(secret)

        // Fetch the user document from the database
        const user = await User.findOne({
            where: {email: email} // Ensure proper filtering by email
        });

        if (!user) {
            throw new Error('User not found');
        }

        // Access the user's dataValues (plain data)
        const userData = user.dataValues;
        // console.log(userData)

        // Store the secret in the user's record (in production, encrypt this)
        userData.twoFASecret = secret.base32;

        const Data = userData.twoFASecret
        // user.twoFASecret = Data;
        console.log("secret:", Data)

        await User.update({twoFASecret: Data}, {where: {email}});

        // Generate a QR code for the secret
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Generate the <img> HTML tag with the base64 QR code
        const imgHtml = `<html>
                            <img src="${qrCodeUrl}">
                         </html>`;

        // Define the file path where you want to save the HTML file
        const filePath = join(__dirname, 'img.html');

        // Return a Promise to handle async fs.writeFile and resolve the file path
        return new Promise((resolve, reject) => {
            fs.writeFile(filePath, imgHtml, (err) => {
                if (err) {
                    console.error('Error saving the HTML file:', err);
                    reject(err); // Reject the promise if there's an error
                } else {
                    console.log(filePath);
                    resolve(filePath); // Resolve the promise with the filePath
                }
            });
        });
    }
};

export default generate2FA;
