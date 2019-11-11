var Canonicalize = require('./lib/getCanonicalizedURL');

//  tests to help validate a canonicalization implementation (from https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization)
console.log("Canonicalization:");
console.log("01: %s", Canonicalize("http://host/%25%32%35") == "http://host/%25");
console.log("02: %s", Canonicalize("http://host/%25%32%35%25%32%35") == "http://host/%25%25");
console.log("03: %s", Canonicalize("http://host/%2525252525252525") == "http://host/%25");
console.log("04: %s", Canonicalize("http://host/asdf%25%32%35asd") == "http://host/asdf%25asd");
console.log("05: %s", Canonicalize("http://host/%%%25%32%35asd%%") == "http://host/%25%25%25asd%25%25");
console.log("06: %s", Canonicalize("http://www.google.com/") == "http://www.google.com/");
console.log("07: %s", Canonicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/") == "http://168.188.99.26/.secure/www.ebay.com/");
console.log("08: %s", Canonicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/") == "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/");
console.log("09: %s", Canonicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B") == "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+");
console.log("10: %s", Canonicalize("http://3279880203/blah") == "http://195.127.0.11/blah");
console.log("11: %s", Canonicalize("http://www.google.com/blah/..") == "http://www.google.com/");
console.log("12: %s", Canonicalize("www.google.com/") == "http://www.google.com/");
console.log("13: %s", Canonicalize("www.google.com") == "http://www.google.com/");
console.log("14: %s", Canonicalize("http://www.evil.com/blah#frag") == "http://www.evil.com/blah");
console.log("15: %s", Canonicalize("http://www.GOOgle.com/") == "http://www.google.com/");
console.log("16: %s", Canonicalize("http://www.google.com.../") == "http://www.google.com/");
console.log("17: %s", Canonicalize("http://www.google.com/foo\tbar\rbaz\n2") =="http://www.google.com/foobarbaz2");
console.log("18: %s", Canonicalize("http://www.google.com/q?") == "http://www.google.com/q?");
console.log("19: %s", Canonicalize("http://www.google.com/q?r?") == "http://www.google.com/q?r?");
console.log("20: %s", Canonicalize("http://www.google.com/q?r?s") == "http://www.google.com/q?r?s");
console.log("21: %s", Canonicalize("http://evil.com/foo#bar#baz") == "http://evil.com/foo");
console.log("22: %s", Canonicalize("http://evil.com/foo;") == "http://evil.com/foo;");
console.log("23: %s", Canonicalize("http://evil.com/foo?bar;") == "http://evil.com/foo?bar;");
console.log("24: %s", Canonicalize("http://\x01\x80.com/") == "http://%01%80.com/");
console.log("25: %s", Canonicalize("http://notrailingslash.com") == "http://notrailingslash.com/");
console.log("26: %s", Canonicalize("http://www.gotaport.com:1234/") == "http://www.gotaport.com/");
console.log("27: %s", Canonicalize("  http://www.google.com/  ") == "http://www.google.com/");
console.log("28: %s", Canonicalize("http:// leadingspace.com/") == "http://%20leadingspace.com/");
console.log("29: %s", Canonicalize("http://%20leadingspace.com/") == "http://%20leadingspace.com/");
console.log("30: %s", Canonicalize("%20leadingspace.com/") == "http://%20leadingspace.com/");
console.log("31: %s", Canonicalize("https://www.securesite.com/") == "https://www.securesite.com/");
console.log("32: %s", Canonicalize("http://host.com/ab%23cd") == "http://host.com/ab%23cd");
console.log("33: %s", Canonicalize("http://host.com//twoslashes?more//slashes") == "http://host.com/twoslashes?more//slashes");


/* https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions */
var LookupExpressions = require('./lib/getLookupExpressions');
console.log(LookupExpressions("http://a.b.c/1/2.html?param=1"));

/* https://developers.google.com/safe-browsing/v4/urls-hashing#hash-computations */
let cryptoHash = require("./lib/cryptoHash");

console.log(cryptoHash.getHashObject("abc"));
console.log(cryptoHash.getNormalizedPrefix("abc"));

let urlHash = require("./lib/urlHash");
console.log(urlHash.canonicalizeAndHashExpressions('http://testsafebrowsing.appspot.com/s/malware.html'));