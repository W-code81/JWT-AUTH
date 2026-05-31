const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { createHmac } = require('node:crypto')
const crypto = require('crypto')


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
        console.error('Error signing up user : ', error);
        res.status(500).json({ message: 'Error signing up user' });
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

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' }); // Generate JWT token

        res.cookie('token', token, { // Sends token as an HTTP-only cookie
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24, // 1 hour
        });

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.log('Error code : ', error.code);
        console.log('Error message : ', error.message);
        console.error('Error logging in user : ', error);
        res.status(500).json({ message: 'Error logging in user' });
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




module.exports = {
    signup,
    login,
    getUsers,
    forgotPassword,
    
};