const RiceDecoder = require("../lib/riceDecoder");
const { readFileSync, writeFileSync } = require("fs");
const _ = require("lodash");

let h = 122405958;
let buf = Buffer.alloc(4);
buf.writeUInt32LE(h);
console.log("h= [", h, "]");
console.log("  buf=[", [...buf], "]");
console.log("  hash=[", buf.toString('base64'), "]");

const testsData = [
  {
    riceParameter: 2,
    hexEncodedData: "f702",
    expectedValues: [15, 9]
  },
  {
    riceParameter: 5,
    hexEncodedData: "00",
    expectedValues: [0]
  },
  {
    riceParameter: 10,
    hexEncodedData: "",
    expectedValues: []
  },
  {
    riceParameter: 28,
    hexEncodedData: "54607be70a5fc1dcee69defe583ca3d6a5f2108c4a595600",
    expectedValues: [
      62763050,
      1046523781,
      192522171,
      1800511020,
      4442775,
      582142548
    ]
  },
  {
    riceParameter: 28,
    hexEncodedData: "54607be70a5fc1dcee69defe583ca3d6a5f2108c4a595600",
    expectedValues: [
      62763050,
      1046523781,
      192522171,
      1800511020,
      4442775,
      582142548
    ]
  },
  {
    riceParameter: 28,
    hexEncodedData:
      "06861b2314cb46f2af0708c988541f4104d51a03ebe63a8013917bbf83f3b785f12918b36109",
    expectedValues: [
      26067715,
      344823336,
      8420095,
      399843890,
      95029378,
      731622412,
      35811335,
      1047558127,
      1117722715,
      78698892
    ]
  },
  {
    riceParameter: 27,
    hexEncodedData:
      "8998d875bc4491eb390c3e309a78f36ad4d9b19ffb703e443ea3086742c22b46698e3cebd9105a439a32a52d4e770f877820b6ab7198480c9e9ed7230c13432ca901",
    expectedValues: [
      225846818,
      328287420,
      166748623,
      29117720,
      552397365,
      350353215,
      558267528,
      4738273,
      567093445,
      28563065,
      55077698,
      73091685,
      339246010,
      98242620,
      38060941,
      63917830,
      206319759,
      137700744
    ]
  },
  {
    riceParameter: 28,
    hexEncodedData:
      "21c50291f982d757b8e93cf0c84fe8648d776204d6853f1c9700041b17c6",
    expectedValues: [
      339784008,
      263128563,
      63871877,
      69723256,
      826001074,
      797300228,
      671166008,
      207712688
    ]
  },
  {
    riceParameter: 28,
    hexEncodedData:
      "959c7db08fe8d9bdfe8c7f81530d75dc4e40180c9a453da8dcfa2659409e16084377c34e0401a4e65d00",
    expectedValues: [
      471820069,
      196333855,
      855579133,
      122737976,
      203433838,
      85354544,
      1307949392,
      165938578,
      195134475,
      553930435,
      49231136
    ]
  },
  {
    riceParameter: 27,
    hexEncodedData:
      "1a4f692a639af6c62eaf73d06fd731eb771d43e32b93ce678b59f998d4da4f3c6fb0e8a5788d623618fe081e78d814322484611cf33763c4a0887b74cb64c85cba05",
    expectedValues: [
      87336845,
      129291033,
      30906211,
      433549264,
      30899891,
      53207875,
      11959529,
      354827862,
      82919275,
      489637251,
      53561020,
      336722992,
      408117728,
      204506246,
      188216092,
      9047110,
      479817359,
      230317256
    ]
  },
  {
    riceParameter: 28,
    hexEncodedData:
      "f1940a876c5f9690e3abf7c0cb2de976dbf85963c16f7c99e3875fc704deb9468e54c0ac4a030d6c8f00",
    expectedValues: [
      297968956,
      19709657,
      259702329,
      76998112,
      1023176123,
      29296013,
      1602741145,
      393745181,
      177326295,
      55225536,
      75194472
    ]
  },
  {
    riceParameter: 28,
    hexEncodedData:
      "412ce4fe06dc0dbd31a504d56edd9b43b73f11245210804f964bd48067b2dd52c94e02c6d760de0692521edd356471262cfecf8146b27901",
    expectedValues: [
      532220688,
      780594691,
      436816483,
      163436269,
      573044456,
      1069604,
      39629436,
      211410997,
      227714491,
      381562898,
      75610008,
      196754597,
      40310339,
      15204118,
      99010842
    ]
  },
  {
    riceParameter: 28,
    hexEncodedData:
      "b22c263acd669cdb5f072e6fe6f9211052d594f4822248f99d24f6ff2ffc6d3f21651b363456eac42100",
    expectedValues: [
      219354713,
      389598618,
      750263679,
      554684211,
      87381124,
      4523497,
      287633354,
      801308671,
      424169435,
      372520475,
      277287849
    ]
  }
];

let counter = 0;
let values = [];
for (let t of testsData) {
  values = [];
  let encodedData = Buffer.from(t.hexEncodedData, "hex");
  var riceDecoder = new RiceDecoder(encodedData, t.riceParameter);
  for (var i = 0; i < t.expectedValues.length; i++) {
    values.push(riceDecoder.readValue());
  }
  // compare
  const isEqual = _.isEqual(values, t.expectedValues);
  console.log(`Test ${counter++} result: `, isEqual);
  if (!isEqual) {
    console.log(`** got  [${values}]`);
    console.log(`** want [${t.expectedValues}]`);
  }
}

/*  Tests with binary files */

const testFilesData = [
  {
    fileName: "h19919_171176_17.bin",
    firstValue: 171176,
    riceParameter: 17,
    numEntries: 19919
  },
  {
    fileName: "h29953_119888_17.bin",
    firstValue: 119888,
    riceParameter: 17,
    numEntries: 29953
  },
  {
    fileName: "h70642_20625_15.bin",
    firstValue: 20625,
    riceParameter: 15,
    numEntries: 70642
  },
  {
    fileName: "h3176613_994_10.bin",
    firstValue: 994,
    riceParameter: 10,
    numEntries: 3176613
  },
  {
    fileName: "h3176532_994_10.bin",
    firstValue: 994,
    riceParameter: 10,
    numEntries: 3176532
  }
];

for (let t of testFilesData) {
  console.time("start");
  values = [];
  let encodedData = readFileSync(`./data/${t.fileName}`);
  values.push(t.firstValue);
  var riceDecoder = new RiceDecoder(encodedData, t.riceParameter);
  for (var i = 0; i < t.numEntries; i++) {
    let delta = riceDecoder.readValue();
    values.push(values[i] + delta);
  }
  writeFileSync(`./data/${t.fileName}.num`, JSON.stringify(values));
  console.timeEnd("start");
  console.log("Test for ", t.fileName, "done!");
}
