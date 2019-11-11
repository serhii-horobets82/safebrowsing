var request = require("request");
var package = require("../package.json");

function hashCheck(hashlist, callback) {
  var reqdata = {
    client: {
      clientId: package.name,
      clientVersion: package.version
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: hashlist
    }
  };
  var options = {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    method: "POST",
    url:
      "https://safebrowsing.googleapis.com/v4/fullHashes:find?key=" +
      process.env.GOOGLE_API_KEY,
    json: reqdata
  };
  request(options, (err, httpResponse, body) => {
    if (err) {
      callback(err, null);
    } else {
      callback(err, body);
    }
  });
}

function urlCheck(threatlist, callback) {
  var reqdata = {
    client: {
      clientId: "firewalla",
      clientVersion: "1.0"
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: threatlist
    }
  };

  var options = {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    method: "POST",
    url:
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
      process.env.GOOGLE_API_KEY,
    json: reqdata
  };

  request(options, (err, httpResponse, body) => {
    if (err) {
      callback(err, null);
    } else {
      callback(err, body);
    }
  });
}

function isUrlSafe(url){
  

}

module.exports = {
  urlCheck: urlCheck,
  hashCheck: hashCheck
};
