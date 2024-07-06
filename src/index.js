require('dotenv').config()
const express = require('express');
const app = express();

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

// connectDataBase
require('../database/database')();

const PORT = 4000;
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRECT;

const { verifyUser,
    verifyDateLogin,
    tokenGenerate,
    generateRandomUsername,
    generateRandomPassword,
    generateRandomSessionId
} = require('../utils/utils');

const { UserModel,
    RevokedTokenModel,
    ipClients,
    UserSession
} = require('../database/models');

const {
    convertTo,
    getClientInfo,
    verifyToken,
    isTokenValid
} = require('./utilities/utilities');

const serverIsManutence = false;

app.get('/session-id', async (req, res) => {
    const { username, password, language } = req.query;
    const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const ipClient = ip.split(",")[0].trim();
    const tongue = getMessages(language);

    try {
        let userSession = await UserSession.findOne({ ip: ipClient });

        if (userSession) {
            if (username) {
                const authenticated = await verifyUser(username, password);
                if (!authenticated) {
                    return res.status(401).json({ success: false, message: tongue.credentialsInvalid });
                }

                await UserSession.updateOne({ ip: ipClient }, { $set: { username: username, language: language } } ); 
            } else {
                await UserSession.updateOne({ ip: ipClient }, { $set: { username: '', language: language } } );
            }
          
            console.log("aqui: " + language)

            return res.status(200).json({ success: true, message: tongue.sessionExists, session: userSession.sessionId });
        }

        if (!language) {
            return res.status(400).json({ success: false, message: tongue.languageNotDefined });
        }

        const newSessionId = generateRandomSessionId();
        await UserSession.create({
            ip: ipClient,
            sessionId: newSessionId,
            username: username || 'unknown',
            language: language
        });

        return res.status(200).json({ success: true, message: 'New session ID generated.', session: newSessionId });

    } catch (error) {
        console.error("Error in session-id route:", error);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password, deviceId, deviceBuildID, architectureDevice, version } = req.body;
    const { language } = await getClientInfo(req, res);

    if (process.env.version != version) {
        return res.status(401).json({ success: true, message: `${language.versionAppOutdated} ${version}` })
    }

    if (!username || !password || !deviceId || !deviceBuildID || !architectureDevice) {
        return res.status(400).json({ success: false, message: language.invalidFields });
    }

    try {
        const user = await UserModel.findOne({ username });
        const currentDate = new Date();
        currentDate.setTime(currentDate.getTime() - 3 * 60 * 60 * 1000);

        if (!user) {
            return res.status(401).json({ success: false, message: language.userNotFound });
        }

        const authenticated = await verifyUser(username, password);
        if (!authenticated) {
            return res.status(401).json({ success: false, message: language.credentialsInvalid });
        }

        if (user.isDeviceReset) {
            await UserModel.updateOne(
                { username },
                { $set: { lastLogin: currentDate, isLoginBlock: false, isDeviceReset: false, deviceId: '', deviceBuildID: '', firstLogin: true } }
            );

            return res.status(401).json({ success: false, message: language.loginReset });
        }

        if (user.isLoginBlock) {
            return res.status(401).json({ success: false, message: language.loginBlocked });
        }

        if ((!user.firstLogin && user.deviceId !== deviceId) || (!user.firstLogin && user.deviceBuildID !== deviceBuildID)) {
            return res.status(401).json({ success: false, message: language.deviceUnauthorized });
        }

        if (serverIsManutence && !(user.levelAccount == 'admin')) {
            return res.status(401).json({ success: false, message: language.serverMaintenance });
        }

        const verifyLogin = verifyDateLogin(user);

        if (verifyLogin == -1) {
            return res.status(401).json({ success: false, message: language.loginExpired });
        }

        await UserModel.updateOne(
            { username },
            { $set: { lastLogin: currentDate, deviceId: deviceId, deviceBuildID: deviceBuildID, architectureDevice: architectureDevice, firstLogin: false } }
        );

        const payload = {
            access: true,
            username: username,
            created_at: convertTo(user.createDate),
            expires_at: convertTo(user.expirationDate),
            time_remaining: verifyLogin,
            architecture: architectureDevice
        };

        let token = tokenGenerate(payload);

        const existToken = await RevokedTokenModel.findOne({ token });

        if (existToken) {
            token = tokenGenerate(payload);
        }

        await RevokedTokenModel.create({ token, user: username });
        await UserModel.updateOne(
            { username },
            { $set: { key: token } }
        );

        return res.status(200).json({
            success: true,
            data: [token]
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: language.internalServerError });
    }
});

app.get('/authorization-token', async (req, res) => {
    try {
        const { detect } = req.query;
        const { ipClient, language } = await getClientInfo(req, res);
        const user = await ipClients.findOne({ ip: ipClient });

        let token = jwt.sign({ success: true }, JWT_SECRET);

        if (detect) {
            const userAccount = await UserModel.findOne({ tokenAccount: detect });

            const decoded = jwt.decode(token);
            if (userAccount && !isTokenValid(decoded)) {
                token = jwt.sign({ success: true, userExist: true, username: userAccount.username, password: userAccount.password }, JWT_SECRET);

                res.cookie('authorization_token', token, { httpOnly: true, secure: true });
                return res.redirect('https://suaads.com/aa9192');
            }
        }

        if (!user) {
            await ipClients.create({
                ip: ipClient,
                authorization: token,
                initTime: Date.now()
            });
            res.cookie('authorization_token', token, { httpOnly: true, secure: true });
            return res.redirect('https://suaads.com/aa9192');
        }

        if (!user.authorization || user.authorization.length === 0) {
            user.authorization = token;
            user.initTime = Date.now();
            await user.save();
            res.cookie('authorization_token', token, { httpOnly: true, secure: true });
            return res.redirect('https://suaads.com/aa9192');
        } else {
            user.authorization = '';
            user.initTime = null;
            user.finalizeTime = null;
            await user.save();

            return res.redirect('/authorization-token');
        }
    } catch (error) {
        console.log("Error cookie authorization: " + error);
        return res.status(500).json({ success: false, message: 'Erro interno no servidor' });
    }
});

app.get('/verify-router', async (req, res) => {
    try {
        const { ipClient, language } = await getClientInfo(req, res);
        const user = await ipClients.findOne({ ip: ipClient });

        if (!user || !req.cookies.authorization_token) {
            return res.redirect('/authorization-token');
        }

        if (!verifyToken(req.cookies.authorization_token)) {
            res.clearCookie('authorization_token');
            return res.redirect('/authorization-token');
        }

        const currentTime = Date.now();
        const timeDifference = (currentTime - user.initTime) / 1000;

        if (timeDifference < 60) {
            res.clearCookie('authorization_token');
            return res.redirect('/authorization-token');
        }

        user.finalizeTime = currentTime;
        await user.save();

        const tokenExist = jwt.decode(req.cookies.authorization_token);

        if (!tokenExist.userExist) {
            const username = generateRandomUsername();
            const password = generateRandomPassword();
            const validUntil = Date.now() + 5 * 60 * 1000;

            const payload = { username, password, validUntil };
            const accountToken = jwt.sign(payload, JWT_SECRET);

            res.cookie('account_token', accountToken, { httpOnly: true, secure: true });
            return res.redirect('/page-login');
        } else {
            const user = await UserModel.findOne({ username: tokenExist.username, password: tokenExist.password });

            if (!user) {
                return res.json({ message: "Error" });
            }
            const validUntil = Date.now() + 5 * 60 * 1000;
            const payload = { username: user.username, password: user.password };

            const accountToken = jwt.sign(payload, JWT_SECRET);

            user.tokenAccount = accountToken;
            await user.save();

            res.cookie('account_token', accountToken, { httpOnly: true, secure: true });
            return res.redirect('/page-login');
        }
    } catch (error) {
        console.error('Erro ao verificar o verify-router:', error);
        return res.status(500).json({ success: false, message: "Error internal server." });
    }
});

app.get('/page-login', (req, res) => {
    try {
        res.sendFile(path.join(__dirname, "../public/html/index.html"));
    } catch (error) {
        console.log(error);
    }
});

app.get('/login-access', async (req, res) => {
    try {
        const { ipClient, language } = await getClientInfo(req, res);
        const user = await ipClients.findOne({ ip: ipClient });

        if (!req.cookies.account_token) {
            return res.redirect('/authorization-token');
        }

        if (!verifyToken(req.cookies.authorization_token)) {
            res.clearCookie('authorization_token');
            return res.redirect('/authorization-token');
        }

        const currentTime = Date.now();
        const timeDifference = (currentTime - user.initTime) / 1000;

        if (timeDifference < 60) {
            res.clearCookie('authorization_token');
            res.clearCookie('account_token');
            return res.redirect('/authorization-token');
        }

        const tokenUser = req.cookies.account_token;

        user.authorization = '';
        user.initTime = null;
        user.finalizeTime = null;
        await user.save();

        res.clearCookie('account_token');
        res.clearCookie('authorization_token');

        return res.redirect(`vxinjector://login-success?token=${tokenUser}`)
    } catch (error) {
        console.error('Erro ao verificar o login-access:', error);
        return res.status(500).json({ success: false, message: 'Erro interno do servidor' });
    }
});

app.post('/create-user', async (req, res) => {
    try {
        const { token } = req.body;
        const { ipClient, language } = await getClientInfo(req, res);

        if (!token) {
            return res.status(400).json({ success: false, message: language.missingToken });
        }

        const user = jwt.decode(token);

        if (!user || !user.username || !user.password) {
            return res.status(400).json({ success: false, message: language.invalidTokenData });
        }

        const existingUser = await UserModel.findOne({ tokenAccount: token });

        if (existingUser) {

            existingUser.username = user.username;
            existingUser.password = user.password;
            existingUser.lastModified = Date.now();

            const newExpirationDate = new Date();
            newExpirationDate.setMinutes(newExpirationDate.getMinutes() + 7);
            existingUser.expirationDate = newExpirationDate;

            await existingUser.save();

            return res.status(200).json({
                success: true,
                message: language.userDetailsUpdated,
                data: {
                    user: existingUser.username,
                    password: existingUser.password
                }
            });
        }

        if (!isTokenValid(token)) {
            return res.status(401).json({ success: false, message: language.invalidTokenAccount });
        }

        const createAccount = await UserModel.create({
            username: user.username,
            password: user.password,
            tokenAccount: token
        });

        if (createAccount) {
            return res.status(200).json({
                success: true,
                message: language.userCreatedSuccessfully,
                data: {
                    user: createAccount.username,
                    password: createAccount.password
                }
            });
        } else {
            return res.status(500).json({ success: false, message: language.accountCreationFailed });
        }
    } catch (error) {
        console.error('Erro ao verificar o create-user:', error);
        return res.status(500).json({ success: false, message: "Error internal server" });
    }
});

const createAccount = async (username, password, type) => {
    await UserModel.create({
        username: username,
        password: password,
        typeAccount: type,
        resetCount: 4
    });
}

const loginReset = async (username, password) => {
    const authenticated = await verifyUser(username, password);

    if (!authenticated) {
        return;
    }

    await UserModel.updateOne(
        { username },
        { $set: { isLoginBlock: false, isDeviceReset: false, deviceId: '', deviceBuildID: '' } }
    );
}

const setVipLogin = async (username, password) => {
    const authenticated = await verifyUser(username, password);

    if (!authenticated) {
        return;
    }

    await UserModel.updateOne(
        { username },
        { $set: { typeAccount: 'VIP', resetCount: 4 } }
    );
}

// createAccount("jc", "12345", "VIP")
// loginReset('yuan', 2295)

app.get('/check-server', async (req, res) => {
    const { ipClient, language } = await getClientInfo(req, res);

    if (!serverIsManutence) {
        return res.status(200).json({ success: true, message: 'Server ON' });
    } else {
        return res.status(401).json({ success: false, message: language.checkServerFail });
    }
});


app.get('/user-info', async (req, res) => {
    const { username, password } = req.query;
    const { ipClient, language } = await getClientInfo(req, res);
    const user = await UserModel.findOne({ username, password });

    if (!user) {
        return res.status(400).json({
            success: false, message: language.userNotFound, infos: {
                username: "null",
                password: "null",
                account: "null",
                isResetDevice: "null",
                resetCount: "null",
                validityLogin: convertTo(Date())
            }
        });
    }

    const data = {
        username: user.username,
        password: user.password,
        account: user.typeAccount,
        isResetDevice: user.isDeviceReset,
        resetCount: user.resetCount,
        validityLogin: convertTo(user.expirationDate.toISOString())
    }

    return res.status(200).json({ success: true, message: 'Get infor for users.', infos: data });
});

app.post('/reset-login', async (req, res) => {
    const { username, password, sessionId } = req.body;
    const { ipClient, language } = await getClientInfo(req, res);

    if (!sessionId) {
        return res.status(400).json({ success: false, message: language.unauthorizedAccessReset });
    }

    const user = await UserModel.findOne({ username, password });

    if (!user) {
        return res.status(400).json({ success: false, message: language.unauthorizedAccessReset });
    }

    if (user.resetCount > 0) {
        let resets = user.resetCount - 1;

        await UserModel.updateOne(
            { username: user.username, password: user.password },
            { $set: { isDeviceReset: true, deviceId: '', deviceBuildID: '', resetCount: resets } }
        );
    }

    return res.status(200).json({ success: true, message: language.deviceResetSuccess });
});

app.get('/library', async (req, res) => {
    const { v, deviceId } = req.query;

    const user = await UserModel.findOne({ key: v, deviceId });

    if (!user) {
        return res.status(401).json({ success: false, message: "Usuário não encontrado ou acesso inválido" });
    }

    if (user.deviceId !== '' && user.deviceId !== deviceId) {
        return res.status(401).json({ success: false, message: "Dispositivo não autorizado." });
    }

    const userToken = jwt.decode(v);

    if (!userToken || !userToken.username || !userToken.architecture) {
        return res.status(400).json({ success: false, message: 'Dados do token de criação de conta inválidos!' });
    }

    let message = "";
    let linkLibraryAtt = "";

    if (userToken.architecture == "Emulador") {
        linkLibraryAtt = "https://cdn.glitch.global/7f919d82-9fa3-434c-8144-a92f44c44834/libmain.so?v=1719815036158";
        message = "Emulator detect."
    } else {
        linkLibraryAtt = "https://cdn.glitch.global/7f919d82-9fa3-434c-8144-a92f44c44834/libmain.so?v=1720185057434";
        message = "Mobile detect."
    }

    return res.status(200).json({ success: true, message, link: linkLibraryAtt });
});

app.post('/verific', async (req, res) => {
    const { v, deviceBuildID } = req.body;

    try {
        const isTokenRevoked = await RevokedTokenModel.findOne({ token: v });
        if (!isTokenRevoked) {
            return res.status(401).json({ message: "Token inválido." });
        }

        const decoded = jwt.verify(v, JWT_SECRET);

        if (decoded.access) {
            const usernameAccess = decoded.username;
            const deviceBuild = decoded.deviceBuildID;

            const userExist = await UserModel.findOne({ username: usernameAccess, key: v, deviceBuildID: deviceBuildID });

            if (!userExist) {
                return res.status(401).json({ message: 'Username não existe!' });
            }

            await RevokedTokenModel.deleteOne({ token: v });
            await UserModel.updateOne({ key: v }, { $set: { key: '' } });

            return res.status(200).json({ success: true });
        }

        return res.status(401).json({ success: false, message: 'Acesso não autorizado' });
    } catch (error) {
        console.error('Erro ao verificar o token JWT:', error);
        return res.status(500).json({ success: false, message: 'Erro interno do servidor' });
    }
});

app.listen(PORT, console.log(`Servidor iniciado, port: ${PORT}`));