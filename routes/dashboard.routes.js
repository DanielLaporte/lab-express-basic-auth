const router = require("express").Router();


router.get("/", (req, res, next) => {
  res.render("dashboard");
});




module.exports = router;
