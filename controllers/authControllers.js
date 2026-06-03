const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { createHmac } = require('node:crypto')
const crypto = require('crypto')
const { generateAccessToken, generateRefreshToken } = require('../utils/generateTokens');


const signup = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({ email, password: hashedPassword });

        res.status(200).json({ message: 'User created successfully', newUser });

    } catch (error) {
        console.log('Error code : ', error.code);
        console.log('Error message : ', error.message);

        if (error.code === 11000 //duplicate key error code for MongoDB
            || error.message.includes("already exists")
            || error.message.includes("duplicate key")
            || error.message.includes("already registered")) {
            res.status(400).json({ message: "Email already exists" });
        }
        else {
            console.error('Error signing up user : ', error);
            res.status(500).json({ message: 'Error signing up user' });
        }

    }
}

const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshToken = refreshToken;
        await user.save();

        res.cookie('token', accessToken, { // Sends token as an HTTP-only cookie
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 15, // 15mins
        });

        res.cookie('refreshToken', refreshToken, { // Sends refresh token as an HTTP-only cookie
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
        });

        res.status(200).json({ message: 'Login successful', accessToken, refreshToken });
    } catch (error) {
        console.log('Error code : ', error.code);
        console.log('Error message : ', error.message);
        console.error('Error logging in user : ', error);
        res.status(500).json({ message: 'Error logging in user' });
    }
}

const logOut = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(400).json({ message: "No refresh token provided" });
        }

        await User.findOneAndUpdate({ refreshToken }, { $unset: { refreshToken: "" } });//finds the user with the provided refresh token and removes it from the database

        res.clearCookie("token");
        res.clearCookie("refreshToken");

        res.status(200).json({ message: "Logged out" });
    } catch (error) {
        console.error("Error logging out user: ", error);
        res.status(500).json({ message: "Error logging out user" });
    }


}

const getUsers = async (req, res) => {
    try {
        const allUsers = await User.find({})

        //allUsers return array so check length
        if (allUsers.length === 0) {
            return res.status(404).json({ message: "no user exists" })
        }

        res.status(200).json({ message: "all users: ", allUsers })

    } catch (error) {
        console.error("Error code: ", error.code)
        console.error("Error msg: ", error.message)
        res.status(500).json({ message: "failed to fetch all users" })
    }
}

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body

        if (!email) {
            return res.status(400).json({ message: "email is required" })
        }

        const user = await User.findOne({ email })

        if (!user) {
            return res.status(400).json({ message: "no user was found" })
        }

        // const rawToken =  crypto.randomBytes(32).toString('hex')
        const rawToken = crypto.randomBytes(32).toString('base64url')

        // const hashedToken = crypto 
        // .createHash("sha256")
        // .update(rawToken)
        // .digest("hex");

        //password hash for db
        const hashedToken = createHmac("sha256", process.env.CRYPTO_kEY)
            .update(rawToken)
            .digest("hex");

        //db store
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 1000 * 60 * 15

        await user.save()

        const resetLink = `${process.env.LOCAL_URL}/api/auth/reset-password/${rawToken}`;

        res.status(200).json({ message: "sent token", resetLink })

        //mail transporter
        //     await transporter.sendMail({
        //     from: `APP Team <${process.env.EMAIL_USER}>`,
        //     to: `${email}`,
        //     subject: `Reset Password Link from APP`,
        //     html: `
        //     <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        //     <h2>Password Reset Request</h2>
        //     <p>Hi ${email},</p>
        //     <p>We received a request to reset your TruckRiser password. Click the link below to set a new password:</p>
        //     <a href="${resetLink}" style="display: inline-block; padding: 10px 20px; background-color: #ff7700; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
        //     <p>This link expires in <strong>15 minutes</strong>.</p>
        //     <p>If you didn't request this, you can safely ignore this email.</p>
        //     <p>— The TruckRiser Team</p>
        //     </div>`
        //   })

    }
    catch (error) {
        console.error("Error code: ", error.code)
        console.error("Error msg: ", error.message)
        res.status(500).json({ message: "failed to send reset token" })
    }
}

const getResetPassword = async (req, res) => {
    try {
        // const {id} = req.body;

        //hash the token from the URL to compare with DB
        const hashedToken = createHmac("sha256", process.env.CRYPTO_kEY).update(req.params.token).digest("hex")

        //looks up the user with the hashed token and checks if it's not expired (greater than now)
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token" })
        }

        res.status(200).json({ message: "rest page render" })

    } catch (error) {
        console.error("Error code: ", error.code)
        console.error("Error msg: ", error.message)
        res.status(500).json({ message: "failed to process reset token" })
    }
}

const changePassword = async (req, res) => {
    try {
        const { password } = req.body

        if (!password) {
            return res.status(400).json({ message: "password is required" })
        }

        if (password.length < 6) {
            return res.status(400).json({ message: "password must be greater 6" })
        }

        //hash the token from the URL to compare with DB
        const hashedToken = createHmac("sha256", process.env.CRYPTO_kEY).update(req.params.token).digest("hex")

        //looks up the user with the hashed token and checks if it's not expired (greater than now)
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token" })
        }

        //hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        user.password = hashedPassword

        // remove token (one-time use)
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save()

        res.status(200).json({ message: "Password reset successful. Please login." })

    } catch (error) {
        console.error("Error code: ", error.code)
        console.error("Error msg: ", error.message)
        res.status(500).json({ message: "failed to reset password" })
    }
}

const refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({ message: "No refresh token" });
        }

        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

        const user = await User.findById(decoded.userId);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const newAccessToken = generateAccessToken(user);

        res.cookie('token', newAccessToken, {
            httpOnly: true,
            maxAge: 1000 * 60 * 15,
        });

        res.status(200).json({ accessToken: newAccessToken });

    } catch (error) {
        return res.status(403).json({ message: "Refresh failed" });
    }
}

const getMe = async (req, res) => {
    res.status(200).json({ user: req.user });
}


module.exports = {
    signup,
    login,
    logOut,
    getUsers,
    forgotPassword,
    getResetPassword,
    changePassword,
    refreshAccessToken,
    getMe
};