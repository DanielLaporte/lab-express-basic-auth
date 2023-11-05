const express = require("express");
const router = require("express").Router();
const isAuthenticated = require("../middleware/isAuthenticated");


router.get("/", isAuthenticated, (req, res, next) => {
  res.render("main",{ currentUser: req.session.currentUser });
});




module.exports = router;
