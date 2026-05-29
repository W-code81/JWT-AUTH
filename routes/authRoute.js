const express = require("express");
const authRouter = express.Router();
const signup  = require('../controllers/authControllers');


authRouter.post('/signup', signup);

module.exports = authRouter;