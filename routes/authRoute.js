const express = require("express");
const authRouter = express.Router();
const { signup, login, getUsers, forgotPassword, getResetPassword, changePassword } = require('../controllers/authControllers');


authRouter.post('/signup', signup);
authRouter.post('/login', login);
authRouter.get('/all-users', getUsers)
authRouter.post('/forgot-password', forgotPassword)
authRouter.route('/reset-password/:token')
    .get(getResetPassword)
    .post(changePassword)
module.exports = authRouter;