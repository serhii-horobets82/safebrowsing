const express = require("express");
const validate = require("../lib/validate");
const urlHash = require("../lib/urlHash");

const router = express.Router();

router.get("/validate", async (req, res) => {
  const siteUrl = req.query.url;
  const result = await validate.isUrlSafe(siteUrl);
  res.json(result);
});

router.post("/validate", async (req, res) => {
  const siteUrl = req.body.siteUrl;

  let hashes = [];
  const hash = urlHash.canonicalizeAndHashExpressions(siteUrl);
  for (let j in hash) {
    hashes.push({ hash: hash[j][1] });
  }
  const validateRes = await validate.hashCheckAsync(hashes);

  res.render("result", { data: validateRes.matches, siteUrl });
});

module.exports = router;
