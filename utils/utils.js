const userModel = require('../database/models');

const verifyUser = async (username, password) => {
    if (!username || !password) return false;

    const user = await userModel.findOne({ username });

    if (!user) return false;

    return password == user.password;
}

module.exports = {
    verifyUser
}