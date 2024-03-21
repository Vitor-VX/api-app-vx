const express = require('express');
const app = express();

// connectDataBase
require('../database/database')();

const PORT = 4000;
const { verifyUser } = require('../utils/utils');

app.use(express.json());

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ message: 'invalid fields!' });

    const authenticated = await verifyUser(username, password);
    
    if (!authenticated) {
        return res.status(401).json({ message: 'username or password incorrect!' });
    }

    return res.status(200).json({ message: 'login success!' });
});

app.listen(PORT, () => console.log(`Server init port: ${PORT}`));