require("dotenv").config();
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const connectDB = require('./config/db');
const cookieParser = require('cookie-parser');
const authRouter = require('./routes/authRoute');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
connectDB();


// Routes
app.use('/api/auth', authRouter);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});