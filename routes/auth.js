const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");

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
    const salt = await bcrypt.genSalt(saltRounds)
    const hash = await bcrypt.hash(password, salt)
    const userSaveSuccess = await createUser(username, hash);
    res
    .status(200)
    .json({success: userSaveSuccess})
  } catch (e) {
    res
    .status(500)
    .json({ message: `Failed to Save User ${e}`, success: false })
  }
});

router.post("/login-user", async (req, res) => {
    
})

module.exports = router;
