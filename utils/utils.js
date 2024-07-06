const { UserModel } = require('../database/models');
const axios = require("axios");

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRECT;

const tokenGenerate = (payload) => {
    return jwt.sign(payload, JWT_SECRET);
}

const generateRandomSessionId = () => {
    return crypto.randomBytes(16).toString('hex');
}

const verifyUser = async (username, password) => {
    if (!username || !password) return false;

    const user = await UserModel.findOne({ username });

    if (!user) return false;

    return password == user.password;
}

const verifyDateLogin = (user) => {
    const now = new Date();
    const expirationDate = new Date(user.expirationDate);

    if (now > expirationDate) {
        return -1; // Token expirado
    }
      
    const diffInMilliseconds = expirationDate.getTime() - now.getTime();
    const diffInMinutes = Math.ceil(diffInMilliseconds / (1000 * 60));
    const diffInHours = diffInMinutes / 60;
    const diffInDays = diffInHours / 24;

    if (diffInDays >= 1) {
        return Math.floor(diffInDays);
    } else {
        return diffInMinutes + " min";
    }
};

async function makeRequest() {
    try {
        const url = 'https://api-bot-vx.glitch.me/verific';

        const response = await axios.get(url);

        console.log('Requisição feita com sucesso:', response.data);
    } catch (error) {
        console.error('Erro ao fazer a requisição:', error.message);
    }
}

function generateRandomUsername() {
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const usernameLength = 8;
    let username = '';

    for (let i = 0; i < usernameLength; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        username += characters[randomIndex];
    }

    return username;
}

function generateRandomPassword() {
    const min = 1000;
    const max = 9999;

    return Math.floor(Math.random() * (max - min + 1)) + min;
}

module.exports = {
    verifyUser,
    verifyDateLogin,
    makeRequest,
    tokenGenerate,
    generateRandomUsername,
    generateRandomPassword,
    generateRandomSessionId
}