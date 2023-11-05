const router = require("express").Router();
const bcrypt = require('bcrypt');

const mongoose = require("mongoose");

const session = require('express-session');
const MongoStore = require('connect-mongo');


/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});




module.exports = router;
