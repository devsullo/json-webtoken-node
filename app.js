const express = require('express');
const app = express();
const port = 3000;
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const bodyParser = require('body-parser');
const cors = require('cors');
const refreshTokens = {};
const randtoken = require('rand-token');

const TOKEN_SECRET = dotenv.config().parsed.TOKEN_SECRET;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.raw());


function authenticateToken(req, res, next) {
    // Gather the jwt access token from the request header
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401) // if there isn't any token
    jwt.verify(token, TOKEN_SECRET, (err, user) => {
        console.log(typeof(err), err)
        if (err) return res.sendStatus(403)
        req.user = user
        next() // pass the execution off to whatever request the client intended
    })
}

function createToken(username) {
    const user = {
        'username': username,
    }
    return jwt.sign(user, TOKEN_SECRET, { expiresIn: '20s' })
}

app.post('/login', function(req, res, next) {
    const username = req.body.username
    const token = createToken(username);
    const refreshToken = randtoken.uid(256)
    refreshTokens[refreshToken] = username
    res.json({ token: token, refreshToken: refreshToken })
});

app.post('/refresh-token', function(req, res, next) {
    const refreshToken = req.body.refreshToken
    if ((refreshToken in refreshTokens)) {
        token = createToken(refreshTokens[refreshToken]);
        res.json({ token: token, refreshToken: refreshToken })
    } else {
        res.send(401)
    }
})

app.get('/getUser', authenticateToken, (req, res) => {
    // executes after authenticateToken
    res.json(req.user);
})

app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`));