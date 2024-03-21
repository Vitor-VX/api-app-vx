require("dotenv").config()
const mongoose = require("mongoose")

const stringDeConexao = process.env.USERNAME_DATA_BASE

async function connectDataBase() {
    try {
        if (mongoose.connection.readyState !== 1) {
            await mongoose.connect(stringDeConexao);
        }
    } catch (error) {
        console.log(error);
    }
}

module.exports = connectDataBase;