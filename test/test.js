const axios = require('axios');

async function TestApi(username, password) {
    const res = await axios.post('http://localhost:4000/login', {
        username,
        password
    });

    return res;
}

TestApi('victor', 12345).then((res) => console.log(res)).catch((err) => console.log(err.response.data));