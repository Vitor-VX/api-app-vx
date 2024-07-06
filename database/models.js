const mongoose = require("mongoose");

function getData(valorDias) {
    const currentDate = new Date();
    const expirationDate = new Date(currentDate.getTime() + valorDias * 24 * 60 * 60 * 1000);
    return expirationDate;
}

function getDataTrial(value) {
    const newExpirationDate = new Date();
    newExpirationDate.setMinutes(newExpirationDate.getMinutes() + value);
    return newExpirationDate;
}

const userSessionSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    sessionId: { type: String, required: true },
    username: { type: String, default: 'unknown' },
    createdAt: { type: Date, default: Date.now },
    language: { type: String, default: 'pt-br' }
});

const ipClientsSchema = new mongoose.Schema({
    ip: {
        type: String,
        required: true
    },
    authorization: {
        type: String
    },
    initTime: {
        type: Date,
        default: Date.now
    },
    finalizeTime: {
        type: Date
    }
});

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    deviceId: {
        type: String,
        default: ''
    },
    deviceBuildID: {
        type: String,
        default: ''
    },
    isLoginBlock: {
        type: Boolean,
        default: false
    },
    isDeviceReset: {
        type: Boolean,
        default: true
    },
    tokenAccount: {
        type: String,
        default: null
    },
    lastLogin: {
        type: Date,
        default: null
    },
    key: {
        type: String
    },
    architectureDevice: {
        type: String
    },
    createDate: {
        type: Date,
        default: Date.now
    },
    expirationDate: {
        type: Date
    },
    levelAccount: {
        type: String,
        default: 'client'
    },
    typeAccount: {
        type: String,
        default: 'free'
    },
    resetCount: {
        type: Number,
        default: 0
    },
    firstLogin: {
        type: Boolean,
        default: true
    }
});

userSchema.pre('save', function(next) {
    if (!this.expirationDate) {
        this.expirationDate = getDataTrial(10);
    }
    next();
});

const RevokedTokenSchema = new mongoose.Schema({
    user: { type: String, required: true },
    token: { type: String, required: true, unique: true }
});

const RevokedTokenModel = mongoose.connection.useDb("appVx").model('RevokedToken', RevokedTokenSchema);

const UserModel = mongoose.connection.useDb("appVx").model("users", userSchema);

const UserSession = mongoose.connection.useDb("appVx").model("sessions", userSessionSchema);

const ipClients = mongoose.connection.useDb("appVx").model("ip", ipClientsSchema);

module.exports = {
    UserModel,
    RevokedTokenModel,
    ipClients,
    UserSession
};
