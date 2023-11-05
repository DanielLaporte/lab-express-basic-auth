const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const saltRounds = 10;
const User = require("../models/User.model");
const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");
const session = require('express-session');



// GET /auth/signup
router.get("/signup", isLoggedOut, (req, res) => {
  res.render("auth/signup");
});

// POST /auth/signup
router.post("/signup", isLoggedOut, (req, res, next) => {
  let { username, password, passwordRepeat } = req.body;

  if (!username || !password || !passwordRepeat) {
    res.status(400).render("auth/signup", {
      errorMessage: "All fields are mandatory. Please provide username and both passwords.",
    });
    return;
  }

  if (password !== passwordRepeat) {
    res.status(400).render("auth/signup", {
      errorMessage: "Passwords do not match.",
    });
    return;
  }

  User.find({ username })
    .then((result) => {
      if (result.length !== 0) {
        res.render("auth/signup", {
          errorMessage: "The user already exists, please choose another one.",
        });
        return;
      }

      bcrypt
        .genSalt(saltRounds)
        .then((salt) => bcrypt.hash(password, salt))
        .then((hashedPassword) => {
          return User.create({ username, password: hashedPassword });
        })
        .then((user) => {
          res.redirect("/auth/login");
        })
        .catch((error) => {
          if (error instanceof mongoose.Error.ValidationError) {
            res.status(500).render("auth/signup", { errorMessage: error.message });
          } else if (error.code === 11000) {
            res.status(500).render("auth/signup", {
              errorMessage: "Username needs to be unique. Provide a valid username.",
            });
          } else {
            next(error);
          }
        });
    })
    .catch((error) => {
      next(error);
    });
});

// GET /auth/login
router.get("/login", isLoggedOut, (req, res) => {
  res.render("auth/login");
});

// POST /auth/login
router.post("/login", isLoggedOut, (req, res, next) => {
  const { username, password } = req.body;


   if (!username || !password) {
    res.status(400).render("auth/login", {
      errorMessage: "All fields are mandatory. Please provide username and password.",
    });
    return;
  }
  
  User.findOne({ username })
    .then((user) => {
      if (!user) {
        res.status(400).render("auth/login", { errorMessage: "Wrong credentials." });
        return;
      }

      bcrypt
        .compare(password, user.password)
        .then((isSamePassword) => {
          if (!isSamePassword) {
            res
              .status(400)
              .render("auth/login", { errorMessage: "Wrong credentials." });
            return;
          }

         
          req.session.currentUser = user.toObject();
          
          delete req.session.currentUser.password;

          res.redirect("/dashboard");
        })
        
        .catch((err) => next(err)); 
    })
    .catch((err) => next(err));
    
});

// GET /auth/logout
router.get("/logout", isLoggedIn, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).render("auth/logout", { errorMessage: err.message });
      return;
    }

    res.redirect("/"); 
  });
});

module.exports = router;
