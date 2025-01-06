import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../model/userModel.js';
import transporter from '../config/nodemailer.js';

// Register user
export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Please fill in all fields' });
    }

    try {

        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 1 * 7 * 24 * 60 * 60 * 1000,
        });

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to ksh',
            text: `Hello ${name},\n\nWelcome to ksh. Your account has been created with email id : ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: 'Register successful' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// Login user
export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: 'Email and password are required' });
    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'Invalid email' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 1 * 7 * 24 * 60 * 60 * 1000,
        })

        return res.json({ success: true, message: 'Login successful' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }

}

// Logout user
export const logout = async (req, res) => {

    try {

        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 1 * 7 * 24 * 60 * 60 * 1000,
        });

        return res.json({ success: true, message: 'Logout successful' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }

}

// Send OTP to user
export const sendVerifyOtp = async (req, res) => {
    try {

        const { userId } = req.body;
        const user = await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.json({ success: false, message: 'Account already verified' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${otp}. Verify your account using this OTP.`
        }

        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Verification OTP sent on Email.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// Verify OTP
export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({ success: false, message: 'User ID and OTP are required' });
    }

    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: 'Invalid user ID' });
        }

        if (!user.verifyOtp || user.verifyOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP expired' });
        }

        user.isAccountVerified = true;
        user.verifyOtp = null; // Use `null` for clarity
        user.verifyOtpExpireAt = null; // Reset expiration timestamp

        await user.save();

        return res.json({
            success: true,
            message: 'Email verified successfully.'
        });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

// Check if user is authenticated
export const isAuthenticated = async (req, res) => {

    try {

        return res.json({ success: true })

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// Send OTP to user for password reset
export const sentResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: 'Email is required' });
    }

    try {

        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'password reset OTP',
            text: `Your OTP is ${otp}. Use this OTP to reset your password.`
        }

        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'OTP sent on Email.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// Reset password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: 'Email, OTP and new password are required' });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if (!user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP expired' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = null; // Use `null` for clarity
        user.resetOtpExpireAt = null; // Reset expiration timestamp

        await user.save();

        return res.json({ success: true, message: 'Password reset successfully.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}