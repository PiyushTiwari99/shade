const jwt = require("jsonwebtoken");

const authorization = (req, res, next) => {
    try {
        const token = req.cookies.access_token;

        if (!token)
            return res.status(400).json({ status: false, msg: "token is required" });

        const data = jwt.verify(token, `${process.env.SECRET_KEY}`);

        req.userId = data.userId;

        return next();

    } catch (err) {
        return res.status(500).json({ status: false, msg: err.message });
    }
};

module.exports = { authorization };