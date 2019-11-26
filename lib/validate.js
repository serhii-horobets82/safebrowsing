const package = require("../package.json");
const request = require("request");
const urlHash = require("./urlHash");
const {
  ThreatType,
  PlatformType,
  ThreatEntryType,
  CompressionType,
  ClientInfo,
  FetchThreatListUpdatesRequest
} = require("../proto/safebrowsing_pb");
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

const threatListUpdatesProtoAsync = async hashList => {
  var request = new FetchThreatListUpdatesRequest();
  // client info
  var clientInfo = new ClientInfo();
  clientInfo.setClientId("navclient-auto-ffox");
  request.setClient(clientInfo);

  var listUpdateRequest = [];
  listUpdateRequest.push(createRequest(ThreatType.SOCIAL_ENGINEERING));
  listUpdateRequest.push(createRequest(ThreatType.MALWARE_THREAT));
  listUpdateRequest.push(createRequest(ThreatType.UNWANTED_SOFTWARE));
  listUpdateRequest.push(createRequest(ThreatType.MALICIOUS_BINARY));
  listUpdateRequest.push(createRequest(ThreatType.CSD_DOWNLOAD_WHITELIST));

  request.setListUpdateRequestsList(listUpdateRequest);

  var bytes = request.serializeBinary();
  var requestB64 = Buffer.from(bytes).toString("base64");

  var queryObject = {
    key: 'AIzaSyCtenHHBZ3mEuaDU5tyFf0MVMQLd6SRi7M',//process.env.GOOGLE_API_KEY,
    $ct: "application/x-protobuf",
    $req: requestB64
  };
  console.log('queryObject', queryObject)
  var options = {
    method: "POST",
    url: "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch",
    qs: queryObject
  };

  const { body } = await rp(options);

  // var response = new safebrowsing.FetchThreatListUpdatesResponse();
  // console.log('response', response);
  // var message2 = safebrowsing.FetchThreatListUpdatesResponse.deserializeBinary(body)
  // console.log(message2);
  return body;
};

const createRequest = (
  threatType = ThreatType.SOCIAL_ENGINEERING,
  platformType = PlatformType.WINDOWS_PLATFORM,
  threatEntryType = ThreatEntryType.URL
) => {
  const lur = new FetchThreatListUpdatesRequest.ListUpdateRequest();
  lur.setThreatType(threatType);
  lur.setPlatformType(platformType);
  lur.setThreatEntryType(threatEntryType);
  const constraints = new FetchThreatListUpdatesRequest.ListUpdateRequest.Constraints();
  constraints.addSupportedCompressions(CompressionType.RICE);
  lur.setConstraints(constraints);

  return lur;
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

async function updateThreatListBin() {
  const result = await threatListUpdatesProtoAsync();

  await writeFilePromise("./db/update.bin", result);

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
  updateThreatListBin: updateThreatListBin,
  getLocalThreatList: getLocalThreatList
};
