const mongoose = require("mongoose")

const users = new mongoose.Schema({
    username: String,
    password: String
});

const usersModel = mongoose.connection.useDb("appVx").model("users", users);

module.exports = usersModel;