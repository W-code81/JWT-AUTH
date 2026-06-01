const express = require("express");
const authRouter = express.Router();
const { signup, login, getUsers, forgotPassword, getResetPassword, changePassword, logOut } = require('../controllers/authControllers');
const protect = require('../middleware/authMiddleware')


authRouter.post('/signup', signup);
authRouter.post('/login', login);
authRouter.post('/logOut', logOut)
authRouter.get('/all-users', protect , getUsers)
authRouter.post('/forgot-password', forgotPassword)
authRouter.route('/reset-password/:token')
    .get(getResetPassword)
    .post(changePassword)
module.exports = authRouter;