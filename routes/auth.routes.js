const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const saltRounds = 10;
const User = require("../models/User.model");
const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");

// GET /auth/signup
router.get("/signup", isLoggedOut, (req, res) => {
  res.render("auth/signup");
});

router.post("/login", isLoggedOut, (req, res, next) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      res.status(400).render("auth/login", {
        errorMessage:
          "All fields are mandatory. Please provide username and password.",
      });
      return;
    }
  
    if (password.length < 6) {
      res.status(400).render("auth/login", {
        errorMessage: "Your password needs to be at least 6 characters long.",
      });
      return;
    }
  
    User.findOne({ username })
      .then((user) => {
        if (!user) {
          throw new Error("Wrong credentials.");
        }
  
        // Store the user object to use it later
        const foundUser = user;
  
        return bcrypt.compare(password, user.password);
      })
      .then((isSamePassword) => {
        if (!isSamePassword) {
          throw new Error("Wrong credentials.");
        }
  
        // Now you can use the 'foundUser' variable here
        req.session.userId = foundUser._id;
        res.redirect('/dashboard'); // Cambia '/dashboard' a la ruta correcta
      })
      .catch((error) => {
        res.status(400).render("auth/login", { errorMessage: error.message });
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
      errorMessage:
        "All fields are mandatory. Please provide username and password.",
    });
    return;
  }

  if (password.length < 6) {
    res.status(400).render("auth/login", {
      errorMessage: "Your password needs to be at least 6 characters long.",
    });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        throw new Error("Wrong credentials.");
      }

      return bcrypt.compare(password, user.password);
    })
    .then((isSamePassword) => {
      if (!isSamePassword) {
        throw new Error("Wrong credentials.");
      }

      req.session.userId = user._id;
      res.redirect('/dashboard'); // Cambia '/dashboard' a la ruta correcta
    })
    .catch((error) => {
      res.status(400).render("auth/login", { errorMessage: error.message });
    });
});

// GET /auth/logout
router.get("/logout", isLoggedIn, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).render("auth/logout", { errorMessage: err.message });
    } else {
      res.redirect("/");
    }
  });
});

module.exports = router;