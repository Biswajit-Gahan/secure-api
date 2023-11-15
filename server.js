const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { db, userSchema } = require("./db").db;
const {
  uuid,
  decryptData,
  encryptData,
  getDecryptedData,
  getEncryptedData,
  getAutoEncryptedData,
  jwtEncode,
} = require("./utils");

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());
dotenv.config();

app.post("/login", (req, res, next) => {
  if (/^\/login$/.test(req.url)) {
    if (!req.body?.data) {
      return next();
    }
    const decryptedData = JSON.parse(getDecryptedData(req.body.data));

    if (!decryptedData) {
      return next();
    }

    const requestedEmail = decryptedData?.email;
    const requestedPassword = decryptedData?.password;

    if (!requestedEmail || !requestedPassword) {
      return next();
    }

    const foundUser = db.find((user) => user.email === requestedEmail);

    if (!foundUser) {
      const encryptedData = getAutoEncryptedData({
        status: 401,
        message: "Invalid Credentials",
      });
      return res.status(401).json({ data: encryptedData });
    }

    const verifyUser = foundUser.password === requestedPassword;

    if (!verifyUser) {
      const encryptedData = getAutoEncryptedData({
        status: 401,
        message: "Invalid Credentials",
      });
      return res.status(401).json({ data: encryptedData });
    }

    const token = jwtEncode({
      uid: foundUser.uid,
      name: foundUser.name,
      email: foundUser.email,
    });

    const encrypedToken = getAutoEncryptedData(token);

    const encryptedData = getAutoEncryptedData({
      status: 200,
      message: "Login Successful",
    });

    foundUser.token = token;

    return res.status(200).json({ token: encrypedToken, data: encryptedData });
  }

  return next();
});

app.post("/register", (req, res, next) => {
  if (/^\/register$/.test(req.url)) {
    if (!req.body?.data) {
      return next();
    }

    const decryptedData = JSON.parse(getDecryptedData(req.body.data));

    if (!decryptedData) {
      return next();
    }

    const requestedEmail = decryptedData?.email;
    const requestedPassword = decryptedData?.password;
    const requestedName = decryptedData?.name;

    if (!requestedEmail || !requestedPassword || !requestedName) {
      return next();
    }

    const checkUser = db.find((user) => user.email === requestedEmail);

    if (checkUser) {
      const encryptedData = getAutoEncryptedData({
        status: 401,
        message: "Email duplication found.",
      });
      return res.status(401).json({ data: encryptedData });
    }

    const uid = uuid().substring(0, 16);

    db.push({ ...decryptedData, uid });

    const encryptedData = getAutoEncryptedData({
      status: 200,
      message: "You're Successfully Registered.",
    });
    return res.status(200).json({ data: encryptedData });
  }

  return next();
});

app.get("/randomId", (req, res, next) => {
  if (/^\/randomId$/.test(req.url)) {
    const key = uuid().substring(0, 32);
    const iv = uuid().substring(0, 16);
    return res.status(200).json({ randomId: key + iv });
  }

  return next();
});

app.all("*", (req, res, next) => {
  return res
    .status(401)
    .send(
      "<h3 style='color: red'>You're restricted to access this domain.</h3>"
    );
});

app.use((err, req, res, next) => {
  console.log(err);
  return res
    .status(500)
    .json({ status: 500, message: "Something went wrong." });
});

app.listen(port, () => {
  console.log("server: http://localhost:5000");
});
