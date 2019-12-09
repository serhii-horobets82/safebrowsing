const express = require("express");
const validate = require("../lib/validate");
const urlHash = require("../lib/urlHash");
const RiceDecoder = require("../lib/riceDecoder")
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
  const validateRes = await validate.hashCheck(hashes);

  res.render("result", { data: validateRes.matches, siteUrl });
});

router.get("/updatedb", async (req, res) => {
  const result = await validate.updateThreatList();
  res.sendStatus(200);
});

router.get("/updatedbbin", async (req, res) => {
  const result = await validate.updateThreatListBin();
  res.send(200);
});

router.get("/viewdb", async (req, res) => {
  const result = await validate.getLocalThreatList();
  res.json(result);
});

validate.updateThreatListBin();

module.exports = router;
