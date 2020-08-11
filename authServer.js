require("dotenv").config();

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

app.use(express.json());

let refreshTokens = [];

const users = [
  {
    username: "Alex",
    password: "password"
  },
  {
    username: "Brad",
    password: "123456"
  }
];

let usersHashed = [];

(() => {
  // encoding user passwords. generally done during user creation
  try {
    usersHashed = users.map((user) => {
      const hashedPassword = bcrypt.hashSync(user.password, 10);
      user.password = hashedPassword;
      return user;
    });

    // generate secret tokens during initialize rather than default in .env
    // require('crypto').randomBytes(64).toString('hex')
    process.env.ACCESS_TOKEN_SECRET = crypto.randomBytes(64).toString("hex");
    process.env.REFRESH_TOKEN_SECRET = crypto.randomBytes(64).toString("hex");
  } catch (e) {
    console.log(e);
  }
})();

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!password) {
      return res.status(400).send("password is required");
    }
    const user = usersHashed.find((user) => {
      return user.username === username;
    });
    if (!user) {
      return res.status(400).send("Cannot find user");
    }
    // authenticate user
    if (await bcrypt.compare(password, user.password)) {
      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      refreshTokens.push(refreshToken);
      console.log(username + " has been authenticated!");
      res.json({ accessToken, refreshToken });
    } else {
      res.status(403).send("Not allowed!");
    }
  } catch (e) {
    console.log(e);
    res.status(500).send("Server error!");
  }
});

app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken });
  });
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "30s" });
}

app.listen(4000);
