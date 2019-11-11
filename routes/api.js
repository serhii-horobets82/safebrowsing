var express = require("express");
var validate = require("../lib/validate");
let urlHash = require("../lib/urlHash");

var router = express.Router();

/* GET users listing. */
router.get("/", function(req, res, next) {
  res.send("API echo");
});

router.post("/validate", function(req, res, next) {
  var siteUrl = req.body.siteUrl;

  let hashes = [];
  let hash = urlHash.canonicalizeAndHashExpressions(siteUrl);
  for (let j in hash) {
    hashes.push({ hash: hash[j][1] });
  }

  validate.hashCheck(hashes, (err, validateRes) => {
    if (validateRes) {
      console.log(validateRes.matches);
      res.render('result', {data : validateRes.matches, siteUrl});
    }
  });
});

module.exports = router;
