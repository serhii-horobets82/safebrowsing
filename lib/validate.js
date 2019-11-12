const package = require("../package.json");
const request = require("request");
const urlHash = require("./urlHash");
const { DefaultLists } = require("./constants");
const { promisify } = require("util");
const { writeFile, readFile, readFileSync } = require("fs");
const rp = promisify(request);
const writeFilePromise = promisify(writeFile);
const readFilePromise = promisify(readFile);

const threatListUpdatesAsync = async hashList => {
  var reqData = {
    client: {
      clientId: package.name,
      clientVersion: package.version
    },
    listUpdateRequests: DefaultLists
  };
  var options = {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    method: "POST",
    url:
      "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key=" +
      process.env.GOOGLE_API_KEY,
    json: reqData
  };

  const { body } = await rp(options);
  return body;
};

const hashCheck = async hashList => {
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

const urlCheck = async threatList => {
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
      threatEntries: threatList
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
    json: reqData
  };

  const { body } = await rp(options);
  return body;
};

async function isUrlSafe(url) {
  let hashes = [];
  let hash = urlHash.canonicalizeAndHashExpressions(url);
  console.log(hash);
  for (let j in hash) {
    hashes.push({ hash: hash[j][1] });
  }
  const result = await hashCheck(hashes);
  // check for matches array
  const isSafe = result && !result.matches;
  return isSafe;
}

async function updateThreatList() {
  const result = await threatListUpdatesAsync();

  await writeFilePromise("./db/update.json", JSON.stringify(result));

  return result;
}

function getLocalThreatList() {
  return JSON.parse(readFileSync("./db/update.json"));
}

module.exports = {
  isUrlSafe: isUrlSafe,
  urlCheck: urlCheck,
  hashCheck: hashCheck,
  updateThreatList: updateThreatList,
  getLocalThreatList: getLocalThreatList
};
