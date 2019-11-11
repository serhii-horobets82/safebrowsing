var express = require('express');
var router = express.Router();
var lib = require('../lib/validate');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Safe Browsing' });
});

module.exports = router;
