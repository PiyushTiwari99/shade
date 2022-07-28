const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const UserModel = require("../models/userModel");
const validator = require("../validation/valid");

/////////////////////////////
const register = async (req, res) => {
    try {
        if (!validator.isValidRequestBody(req.body))
            return res.status(400).json({
                status: false,
                msg: "Please provide Valid Details",
            });

        let { firstName, lastName, email, password } = req.body;

        if (!validator.isValid(firstName))
            return res
                .status(400)
                .json({ status: false, msg: "first name is require" });

        if (!validator.isValidFname(firstName))
            return res
                .status(400)
                .json({ status: false, msg: "first name like Mr and Miss" });

        if (!validator.isValid(lastName))
            return res
                .status(400)
                .json({ status: false, msg: "last name is required" });

        if (!/^[a-zA-Z]+$/.test(lastName))
            return res
                .status(400)
                .json({ status: false, msg: "last name string" });

        if (!validator.isValid(email))
            return res.status(400).json({ status: false, msg: "email is required" });

        let isEmailUsed = await UserModel.findOne({ email });

        if (isEmailUsed)
            return res
                .status(400)
                .json({ status: false, msg: `${email} already exists` });

        if (!/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email))
            return res
                .status(400)
                .json({ status: false, message: "invalid id" });

        if (!validator.isValid(password))
            return res
                .status(400)
                .json({ status: false, msg: "password is necessary" });

        if (password.length < 8 || password.length > 15)
            return res
                .status(400)
                .json({ status: false, msg: "password length be between 8-15" });

        let hasedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = {
            firstName,
            lastName,
            email,
            password: hasedPassword,
        };

        let user = await UserModel.create(newUser);
        return res
            .status(201)
            .send({ status: true, message: "User created successfully", data: user });
    } catch (err) {
        return res.status(500).json({ status: false, msg: err.message });
    }
};

///////////////////////////
const login = async (req, res) => {
    try {
        if (!validator.isValidRequestBody(req.body))
            return res.status(400).json({
                status: false,
                message: "please provide email and password",
            });

        let { email, password } = req.body;

        if (!validator.isValid(email))
            return res.status(400).json({
                status: false,
                message: "email is required",
            });

        if (!/^\w+([\.-]?\w+)@\w+([\.-]?\w+)(\.\w{2,3})+$/.test(email))
            return res.status(400).json({
                status: false,
                message: `valid email`,
            });

        if (!validator.isValid(password))
            return res
                .status(400)
                .json({ status: false, message: "password is required" });

        if (password.length < 8 || password.length > 15)
            return res
                .status(400)
                .json({ status: false, msg: "password length be btw 8-15" });

        if (email && password) {
            let User = await UserModel.findOne({ email: email });
            if (!User)
                return res
                    .status(400)
                    .json({ status: false, msg: "email does not exist" });

            let decryppasss = await bcrypt.compare(password, User.password);

            if (decryppasss) {
                const Token = jwt.sign(
                    {
                        userId: User._id
                    },
                    `${process.env.SECRET_KEY}`
                );

                return res
                    .cookie("access_token", Token, {
                        httpOnly: true,
                    })
                    .status(200)
                    .json({
                        message: "logged in successfully",
                        data: { userId: User._id, token: Token },
                    });
            } else
                return res.status(400).json({ status: false, Msg: "Invalid password" });
        }
    } catch (err) {
        return res.status(500).json({ status: false, message: err.message });
    }
};


///////////////////////////
const logout = (req, res) => {
    return res
        .clearCookie("access_token")
        .status(200)
        .json({ message: "Successfully logged out" });
};


////////////////////////////////////////////
const passwordChange = async (req, res) => {
    try {
        if (!validator.isValidObjectId(req.params.userId))
            return res
                .status(400)
                .json({ status: false, message: `${userId} is invalid` });

        const userFound = await UserModel.findOne({ _id: req.params.userId });

        if (!userFound)
            return res
                .status(404)
                .json({ status: false, message: `User do not exists` });

        if (req.params.userId.toString() !== req.userId)
            return res.status(401).json({
                status: false,
                message: `UnAuthorized access to user`,
            });

        if (!validator.isValidRequestBody(req.body))
            return res
                .status(400)
                .json({ status: false, message: "Please provide details to update" });

        let { password } = req.body;

        let updateUserData = {};

        if (password.length < 8 || password.length > 15)
            return res
                .status(400)
                .json({ status: false, msg: "password length be btw 8-15" });

        if (validator.isValid(password)) {
            const encryptPass = await bcrypt.hash(password, saltRounds);
            updateUserData["password"] = encryptPass;
        }

        const updatedUserData = await UserModel.findOneAndUpdate(
            { _id: req.params.userId },
            updateUserData,
            { new: true }
        );

        return res
            .status(201)
            .json({
                status: true,
                msg: "password changed successfully",
                data: updatedUserData,
            });
    } catch (error) {
        return res.status(500).json({ status: false, msg: error.message });
    }
};



module.exports = { register, login, logout, passwordChange };
