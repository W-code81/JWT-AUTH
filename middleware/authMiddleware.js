const jwt = require("jsonwebtoken");
const User = require("../models/User");


const protect = async (req, res, next) => {
    try {
        //get jwt token
        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({ message: "Not authorized" });
        }

        //verify's user token (if expired,modified or wrong it throws error)
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        //Find the user by their ID and retrieve the user's information while excluding the password field.
        const user = await User.findById(decoded.userId).select("-password");

        if (!user) {
            return res.status(401).json({
                message: "User not found",
            });
        }

        //attaches user to request
        req.user = user;

        next();

    } catch (error) {
        return res.status(401).json({
            message: "Invalid token",
        });
    }
}

module.exports = protect