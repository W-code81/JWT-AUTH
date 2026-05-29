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
        res.status(500).json({ message: 'Error signing up user' });
    }
}

module.exports = signup;