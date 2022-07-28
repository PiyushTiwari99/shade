const mongoose = require("mongoose");

const isValid = (value) => {
    if (typeof value === "undefined" || typeof value === null) return false;
    if (typeof value === "string" && value.trim().length === 0) return false;
    return true;
};

const isValidRequestBody = (requestBody) => {
    return Object.keys(requestBody).length !== 0;
};

const isValidObjectId = (objectId) => {
    return mongoose.Types.ObjectId.isValid(objectId);
};

const isValidFname = (status) => {
    return ["Mr", "Miss", "Mrs"].indexOf(status) !== -1;
};

module.exports = {
    isValid,
    isValidFname,
    isValidObjectId,
    isValidRequestBody,
};