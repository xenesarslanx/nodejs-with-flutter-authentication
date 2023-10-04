const express = require("express");
const bcryptjs = require("bcryptjs");
const User = require("../models/user");
const authRouter = express.Router();
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");

// Sign Up
authRouter.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {//email databasede varsa hata döndür
      return res
        .status(400)
        .json({ msg: "User with same email already exists!" });
    }

    const hashedPassword = await bcryptjs.hash(password, 8);//şifreyi hashler

    let user = new User({
      email,
      password: hashedPassword,
      name,
    });
    user = await user.save();
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Sign In

authRouter.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {//boyle bi email yoksa
      return res
        .status(400)
        .json({ msg: "User with this email does not exist!" });
    }
//şifreleri kıyasla databasedeki
    const isMatch = await bcryptjs.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Incorrect password." });
    }
//ilk parametre kullanıcının databasedekı idsi 2.si anahtar
    const token = jwt.sign({ id: user._id }, "passwordKey");
    res.json({ token, ...user._doc });//user._doc kullanıcının MongoDB veritabanında saklanan verilerini temsil eder. 
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

authRouter.post("/tokenIsValid", async (req, res) => {
  try {
    const token = req.header("x-auth-token");//gelen isteğin başlığından "x-auth-token" adlı bir token alır
    if (!token) return res.json(false);
    const verified = jwt.verify(token, "passwordKey");//token'ın geçerliliği doğrulanır
    if (!verified) return res.json(false);

    //Eğer token geçerli ise, kullanıcının kimliği 
    //(verified.id) kullanılarak veritabanında ilgili kullanıcı belgesi (user) alınır
    const user = await User.findById(verified.id);
    if (!user) return res.json(false);
    res.json(true);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// get user data
authRouter.get("/", auth, async (req, res) => {
  const user = await User.findById(req.user);
  res.json({ ...user._doc, token: req.token });
});

module.exports = authRouter;