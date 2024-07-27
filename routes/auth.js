// const express = require('express');
// const User = require('../models/user');
// const router = express.Router();

// // Login route
// router.post('/login', async (req, res) => {
//     const { username, email, password } = req.body;

//     try {
//         let user;
//         if (username) {
//             user = await User.findOne({ username });
//         } else if (email) {
//             user = await User.findOne({ email });
//         }

//         if (!user) {
//             return res.status(400).json({ message: 'User not found' });
//         }

//         const isMatch = await user.comparePassword(password);

//         if (!isMatch) {
//             return res.status(400).json({ message: 'Invalid credentials' });
//         }

//         res.status(200).json({ message: 'Login successful', user });
//     } catch (err) {
//         res.status(500).json({ message: err.message });
//     }
// });

// module.exports = router;

const bcrypt = require('bcrypt');
const express = require('express');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const User = require('../models/user');
const router = express.Router();

// Register route
router.post('/register', async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    // Check if passwords match
    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Create and save a new user
        const user = new User({ username, email, password });
        await user.save();
        res.status(201).json({ message: 'User registered successfully', user });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Login route
router.post('/login', async (req, res) => {
    const { usernameOrEmail, password } = req.body;

    try {
        let user;
        if (usernameOrEmail.includes('@')) {
            // If the input looks like an email
            user = await User.findOne({ email: usernameOrEmail });
        } else {
            // If the input looks like a username
            user = await User.findOne({ username: usernameOrEmail });
        }

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        const isMatch = await user.comparePassword(password);

        if (!isMatch) {
            console.log('Password mismatch for user:', usernameOrEmail);
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', user, token });
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ message: err.message });
    }
});
// console.log('JWT_SECRET:', process.env.JWT_SECRET);


// Send password reset email
// router.post('/request-password-reset', async (req, res) => {
//     const { email } = req.body;

//     try {
//         const user = await User.findOne({ email });
//         if (!user) {
//             return res.status(404).json({ message: 'User not found' });
//         }

//         // Generate a reset token
//         const token = crypto.randomBytes(32).toString('hex');

//         // Set token expiration (e.g., 1 hour from now)
//         const tokenExpiry = Date.now() + 3600000;

//         // Save token and expiration in the database
//         user.resetPasswordToken = token;
//         user.resetPasswordExpires = tokenExpiry;
//         await user.save();

//         // Send reset email
//         const resetUrl = `http://localhost:5500/reset-password/${token}`;
//         await sendPasswordResetEmail(user.email, resetUrl);

//         res.json({ message: 'Password reset email sent' });
//     } catch (err) {
//         console.error('Error sending password reset email:', err);
//         res.status(500).json({ message: err.message });
//     }
// });
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Generate a reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

        user.resetPasswordToken = resetPasswordToken;
        user.resetPasswordExpire = resetPasswordExpire;
        await user.save();

        // Send email with the reset link
        const resetUrl = `http://localhost:5500/reset-password/${resetToken}`;
        await sendPasswordResetEmail(user.email, resetUrl);
        try {
            await sendPasswordResetEmail(user.email, resetUrl);
        } 
        catch (emailError) {
            console.error('Error sending email:', emailError);
            return res.status(500).json({ message: 'Error sending password reset email' });
        }
        res.status(200).json({ message: 'Password reset email sent' });
    } catch (err) {
        console.error('Error in forgot-password route:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reset password
// router.post('/reset-password/:token', async (req, res) => {
//     const { token } = req.params;
//     const { password, confirmPassword } = req.body;

//     // Check if passwords match
//     if (password !== confirmPassword) {
//         return res.status(400).json({ message: 'Passwords do not match' });
//     }

//     try {
//         const user = await User.findOne({
//             resetPasswordToken: token,
//             resetPasswordExpires: { $gt: Date.now() }
//         });

//         if (!user) {
//             return res.status(400).json({ message: 'Password reset token is invalid or has expired' });
//         }

//         // Update the password
//         user.password = await bcrypt.hash(password, 10);
//         user.resetPasswordToken = undefined;
//         user.resetPasswordExpires = undefined;
//         await user.save();

//         res.json({ message: 'Password has been reset successfully' });
//     } catch (err) {
//         console.error('Error resetting password:', err);
//         res.status(500).json({ message: err.message });
//     }
// });
router.post('/reset-password/:resetToken', async (req, res) => {
    const { resetToken } = req.params;
    const { newPassword, confirmNewPassword } = req.body;

    if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        // Hash the token and find the user by reset token and ensure the token has not expired
        const resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        // Update user's password
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successful' });
    } catch (err) {
        console.error('Error in reset-password route:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

async function sendPasswordResetEmail(to, resetUrl) {
    const transporter = nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: to,
        subject: 'Password Reset',
        text: `Click the link to reset your password: ${resetUrl}`
    };

    await transporter.sendMail(mailOptions);
}

module.exports = router;
