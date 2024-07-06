require('dotenv').config();
const axios = require('axios');
const jwt = require('jsonwebtoken');

function decompileJwtToken(token) {
    try {
        const decoded = jwt.decode(token);
        return decoded;
    } catch (error) {
        console.error('Error decoding JWT token:', error);
        return null;
    }
}

const jwtSecret = process.env.JWT_SECRET;

async function TestApi(username, password, deviceId, deviceBuildID, architectureDevice, version) {
    try {
        const res = await axios.post('http://localhost:4000/login', {
            username, password, deviceId, deviceBuildID, architectureDevice, version
        });

        const token = res.data.data[0];

        return token;
    } catch (error) {
        throw error;
    }
}

TestApi('jv', '1', 'bfde6e548ba3b6f6', 'NMF26X', 'x86_64', '2.0.0')
    .then((token) => {
        const decodedToken = decompileJwtToken(token);
        console.log(decodedToken);
    })
    .catch((err) => {
        console.error('Error in API call:', err.response.data);
    });
