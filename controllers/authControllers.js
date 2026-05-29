const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');


const signup = async (req, res) => {
    try {
        const {email, password} = req.body;

        if(!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const existingUser  =  await User.findOne({email});

        if (existingUser){
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({ email, password: hashedPassword });

        res.status(201).json({ message: 'User created successfully', newUser });

    } catch (error) {
        console.log('Error code : ', error.code);
        console.log('Error message : ', error.message);
        console.error('Error signing up user : ', error);
        res.status(500).json({ message: 'Error signing up user' });
    }
}

const login = async (req, res) => {
    try{
        const {email, password} = req.body;

        if(!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({email});

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token =  jwt.sign({userId: user._id}, process.env.JWT_SECRET, {expiresIn: '1h'}); // Generate JWT token

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

module.exports = {
  signup,
  login,
};