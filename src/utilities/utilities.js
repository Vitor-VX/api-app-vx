const { UserSession } = require('../../database/models');
const moment = require('moment');
require('moment-timezone');

const getMessages = (language) => {
    const messages = {
        'en-us': {
            credentialsInvalid: 'Invalid credentials!',
            sessionExists: 'Session ID exists.',
            newSessionGenerated: 'New session ID generated.',
            languageNotDefined: 'Language not defined.',
            internalServerError: 'Internal server error',
            userNotFound: 'User not found.',
            invalidFields: 'Invalid fields!',
            loginReset: 'Your login has been reset, please login again!',
            loginBlocked: 'Your login is blocked!',
            deviceUnauthorized: 'Unauthorized device.',
            deviceResetSuccess: 'Login reset.',
            serverMaintenance: 'Server under maintenance!',
            loginExpired: 'Login expired! Generate a new token.',
            userUpdated: 'User details updated successfully!',
            accountCreationFailed: 'Failed to create your account, please try again!',
            checkServerSuccess: 'Server is running.',
            checkServerFail: 'Server is under maintenance!',
            userCreatedSuccessfully: 'User created successfully!',
            invalidToken: 'Invalid token!',
            invalidTokenAccount: 'Invalid or expired account creation token!',
            invalidTokenData: 'Invalid account creation token data!',
            missingToken: 'Account Creation Token Not Provided!',
            unauthorizedAccess: 'Unauthorized access',
            unauthorizedAccessReset: 'Token unavailable.',
            versionAppUpdate: 'App updated, version:',
            versionAppOutdated: 'The app is on the old version, update by logging into discord! Version:',
        },
        'pt-br': {
            credentialsInvalid: 'Credenciais inválidas!',
            sessionExists: 'Session ID existe.',
            newSessionGenerated: 'Novo session ID gerado.',
            languageNotDefined: 'Idioma não definido.',
            internalServerError: 'Erro interno do servidor',
            userNotFound: 'Usuário não encontrado.',
            invalidFields: 'Campos inválidos!',
            loginReset: 'Seu login foi resetado, faça o login novamente!',
            loginBlocked: 'Seu login está bloqueado!',
            deviceUnauthorized: 'Dispositivo não autorizado.',
            deviceResetSuccess: 'Login resetado.',
            serverMaintenance: 'Servidor em manutenção!',
            loginExpired: 'Login expirado! Gere um novo token novamente.',
            userUpdated: 'Detalhes do usuário atualizados com sucesso!',
            accountCreationFailed: 'Erro ao tentar criar a sua conta, tente novamente!',
            checkServerSuccess: 'Servidor em funcionamento.',
            checkServerFail: 'Servidor em manutenção!',
            invalidToken: 'Token inválido!',
            invalidTokenAccount: 'Token de criação de conta inválido ou expirado!',
            userCreatedSuccessfully: 'Usuário criado com sucesso!',
            invalidTokenData: 'Dados do token de criação de conta inválidos!',
            missingToken: 'Token de criação de conta não fornecido!',
            unauthorizedAccess: 'Acesso não autorizado',
            unauthorizedAccessReset: 'Token indisponivel.',
            versionAppUpdate: 'App atualizado, version:',
            versionAppOutdated: 'O app está na versão antiga, atualize entrando no discord! Version:',
        }
    };
    return messages[language] || messages['pt-br'];
}

const convertTo = (time) => {
    let date = new Date(time);

    let offset = -3;
    date.setHours(date.getHours() + offset);

    let day = ("0" + date.getDate()).slice(-2);
    let month = ("0" + (date.getMonth() + 1)).slice(-2);
    let year = date.getFullYear();

    return `${day}/${month}/${year}`;
}

const getClientInfo = async (req, res) => {
    const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const ipClient = ip.split(",")[0].trim();
    const userSession = await UserSession.findOne({ ip: ipClient });

    if (!userSession) {
        const language = getMessages('pt-br');
        return { ipClient, language };
    }

    return res.status(400).json({ success: false, message: 'ip not found, erro set language.', data: [] });
};

const verifyToken = (token) => {
    try {
        jwt.verify(token, JWT_SECRET);
        return true;
    } catch (error) {
        console.error('Erro ao verificar o token:', error);
        return false;
    }
}

const isTokenValid = (token) => {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.validUntil) {
        return false;
    }
    const currentTime = Date.now();
    return currentTime < decoded.validUntil;
}

module.exports = {
    convertTo,
    getClientInfo,
    verifyToken,
    isTokenValid
}