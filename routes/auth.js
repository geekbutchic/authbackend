const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");

dotenv.config();

router.get("/hello-auth", (req, res) => {
  res.json({ message: "Hello from auth" });
});

const createUser = async (username, passwordHash) => {
  try {
    const collection = await blogsDB().collection("users");
    const user = {
      username: username,
      password: passwordHash,
      uid: uuid(),
    };
    await collection.insertOne(user);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
};

router.post("/register-user", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const saltRounds = 5;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    const userSaveSuccess = await createUser(username, hash);
    res.status({ success: userSaveSuccess }).status(200);
  } catch (e) {
    console.log(e);
    res.json({ success: e }).status(500);
  }
});

router.post("/login-user", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const collection = await blogsDB().collection("users");
    const user = await collection.findOne({
      username: username,
    });
    if (!user) {
      res.json({ success: false }).status(204);
      return;
    }
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      const jwtSecretKey = process.env.JWT_SECRET_KEY;
      const data = {
        time: new Date(),
        userId: user.uid,
        // Note: Double check this line of code to be sure that user.uid is coming from your fetched mongo user
      };
      const token = jwt.sign(data, jwtSecretKey);
      res.json({ success: match, token: token }).status(200);
      return;
    }
    res.json({ success: false }).status(204);
  } catch (error) {
    res.json({ success: error }).status(500);
  }
});

router.get("/auth/validate-token", (req, res) => {
  const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
  const jwtSecretKey = process.env.JWT_SECRET_KEY;

  try {
    const token = req.header(tokenHeaderKey);

    const verified = jwt.verify(token, jwtSecretKey);
    if (verified) {
      return res.json({ success: true });
    } else {
      // Access Denied
      throw Error("Access Denied");
    }
  } catch (error) {
    // Access Denied
    return res.status(401).json({ success: true, message: String(error) });
  }
});

module.exports = router;
