const package = require("../package.json");
const request = require("request");
const urlHash = require("./urlHash");
const { promisify } = require("util");
const rp = promisify(request);

const hashCheckAsync = async hashList => {
  var reqData = {
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
      threatEntries: hashList
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
    json: reqData
  };

  const { body } = await rp(options);
  return body;
};

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

async function isUrlSafe(url) {
  let hashes = [];
  let hash = urlHash.canonicalizeAndHashExpressions(url);
  for (let j in hash) {
    hashes.push({ hash: hash[j][1] });
  }
  const result = await hashCheckAsync(hashes);
  // check for matches array
  const isSafe = result && !result.matches;
  return isSafe;
}

module.exports = {
  isUrlSafe: isUrlSafe,
  urlCheck: urlCheck,
  hashCheckAsync: hashCheckAsync
};
