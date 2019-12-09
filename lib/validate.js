const package = require("../package.json");
const request = require("request");
const urlHash = require("./urlHash");
const RiceDecoder = require("./riceDecoder");
const {
  ThreatType,
  PlatformType,
  ThreatEntryType,
  CompressionType,
  ClientInfo,
  FetchThreatListUpdatesRequest,
  FetchThreatListUpdatesResponse
} = require("../proto/safebrowsing_pb");
const { DefaultLists } = require("./constants");
const { promisify } = require("util");
const { writeFile, readFile, readFileSync, createWriteStream } = require("fs");
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
  var reqData = new FetchThreatListUpdatesRequest();
  // client info
  var clientInfo = new ClientInfo();
  clientInfo.setClientId("navclient-auto-ffox");
  reqData.setClient(clientInfo);

  var listUpdateRequest = [];
  listUpdateRequest.push(createRequest(ThreatType.SOCIAL_ENGINEERING));
  listUpdateRequest.push(createRequest(ThreatType.MALWARE_THREAT));
  listUpdateRequest.push(createRequest(ThreatType.UNWANTED_SOFTWARE));
  listUpdateRequest.push(createRequest(ThreatType.MALICIOUS_BINARY));
  listUpdateRequest.push(createRequest(ThreatType.CSD_DOWNLOAD_WHITELIST));

  reqData.setListUpdateRequestsList(listUpdateRequest);

  var bytes = reqData.serializeBinary();
  var requestB64 = Buffer.from(bytes).toString("base64");
  console.log("requestB64", requestB64);
  var queryObject = {
    $ct: "application/x-protobuf",
    key: "AIzaSyCtenHHBZ3mEuaDU5tyFf0MVMQLd6SRi7M", //process.env.GOOGLE_API_KEY,
    $httpMethod: "POST",
    $req: requestB64
  };
  var options = {
    method: "POST",
    url: "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch",
    qs: queryObject
  };
  var chunks = [];
  request(options, (err, httpResponse, body) => {})
    .on("data", function(data) {
      chunks.push(data);
    })
    .on("end", function() {
      var buffer = Buffer.concat(chunks);
      var resp = FetchThreatListUpdatesResponse.deserializeBinary(buffer);
      //console.log(resp.toObject());
      var luel = resp.getListUpdateResponsesList();
      for (var item of luel) {
        var threatType = item.getThreatType();

        // console.log("item", item.toObject());
        var additionalList = item.getAdditionsList();

        var hashes = additionalList[0].getRawHashes();

        for (var addList of additionalList) {
          var compressionType = addList.getCompressionType();
          console.log("threatType", threatType, compressionType);
          var hashes = null;
          if (compressionType == CompressionType.RICE) {
            var riseHashes = addList.getRiceHashes();
            hashes = riseHashes;
            const numEntries = riseHashes.getNumEntries();
            const firstValue = riseHashes.getFirstValue();
            const EncodedData = riseHashes.getEncodedData();
            const riceParameter = riseHashes.getRiceParameter();
            encodedData = [...EncodedData];

            console.log("numEntries", numEntries);
            console.log("firstValue", firstValue);
            console.log("riceParameter", riceParameter);

            let values = [];
            values.push(firstValue);
            console.log("start", values);
            var riceDecoder = new RiceDecoder(encodedData, riceParameter);
            for (var i = 0; i < numEntries; i++) {
              const delta = riceDecoder.readValue();
              values.push(values[i] + delta);
            }
            console.log("finish");
          } else {
            var rawHashes = addList.getRawHashes();
            hashes = rawHashes;
          }

          writeFile(
            `./db/threat${threatType}.json`,
            JSON.stringify(hashes.toObject()),
            err => {
              if (err) throw err;
              console.log("The file has been saved!");
            }
          );
        }

        //console.log("additionalList", additionalList);
      }
    })
    .on("response", function(response) {
      // var ws = createWriteStream("./db/response.");
      // ws.on("finish", function() {
      //   console.log("finish");
      //   var bytes = readFileSync("./db/response.log");
      //   var responseBody = FetchThreatListUpdatesResponse.deserializeBinary(
      //     bytes
      //   );
      //   console.log("2::", bytes.length);
      //   //console.log(responseBody.toObject());
      // });
      // response.pipe(ws);
    })
    .pipe(createWriteStream("./db/full_response.bin"));

  return {};

  const { body } = await rp(options);
  var bodyBytes = Buffer.from(body);
  console.log(bodyBytes);

  var response = new FetchThreatListUpdatesResponse();
  // console.log('response', response);
  //var responseBody = FetchThreatListUpdatesResponse.deserializeBinary(body)
  //console.log(responseBody.toObject());
  return bodyBytes;
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
  return result;
}

async function updateThreatListBin3() {
  const result = null; //await threatListUpdatesProtoAsync();
  let encodedData = readFileSync("./db/hash30036_17_119888.bin");

  let values = [];
  values.push(119888);
  var riceDecoder = new RiceDecoder(encodedData, 17);
  for (var i = 0; i < 30036; i++) {
    let delta = riceDecoder.readValue();
    values.push(values[i] + delta);
  }
  console.log(values);
  await writeFilePromise("./db/hash30036.num", JSON.stringify(values));

  return result;
}

async function updateThreatListBin2() {
  const result = null; //await threatListUpdatesProtoAsync();
  let content = readFileSync("./db/hash.b64", "utf8");

  let encodedData = Buffer.from(content, "base64");
  let values = [];
  var riceDecoder = new RiceDecoder(encodedData, 17);
  for (var i = 0; i < 30245; i++) {
    values.push(riceDecoder.readValue());
  }
  console.log(values);
  await writeFilePromise("./db/hash.num", JSON.stringify(values));
  //await writeFilePromise("./db/update.bin", result);

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
