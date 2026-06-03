const express = require("express");
const authRouter = express.Router();
const { signup, login, getUsers, forgotPassword, getResetPassword, changePassword, logOut ,refreshAccessToken, getMe } = require('../controllers/authControllers');
const {protect, authorize} = require('../middleware/authMiddleware')


authRouter.post('/signup', signup);
authRouter.post('/login', login);
authRouter.post('/logOut', logOut)
authRouter.get('/all-users', protect , authorize('admin'), getUsers) //protect checked if user is loged in and authorize validates role
authRouter.post('/refresh', refreshAccessToken);
authRouter.get('/me', protect, getMe);    
authRouter.post('/forgot-password', forgotPassword)
authRouter.route('/reset-password/:token')
    .get(getResetPassword)
    .post(changePassword)
module.exports = authRouter;