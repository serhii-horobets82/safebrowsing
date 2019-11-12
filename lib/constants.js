const DefaultLists = [
  {
    threatType: "MALWARE",
    platformType: "ANY_PLATFORM",
    threatEntryType: "URL"
  },
  {
    threatType: "SOCIAL_ENGINEERING",
    platformType: "ANY_PLATFORM",
    threatEntryType: "URL"
  },
  {
    threatType: "POTENTIALLY_HARMFUL_APPLICATION",
    platformType: "ANDROID",
    threatEntryType: "URL"
  },
  {
    threatType: "POTENTIALLY_HARMFUL_APPLICATION",
    platformType: "IOS",
    threatEntryType: "URL"
  },
  {
    threatType: "UNWANTED_SOFTWARE",
    platformType: "ANY_PLATFORM",
    threatEntryType: "URL"
  }
];

const ThreatTypes = {
  MALWARE: 1,
  SOCIAL_ENGINEERING: 2,
  POTENTIALLY_HARMFUL_APPLICATION: 3,
  UNWANTED_SOFTWARE: 4
};

const PlatformTypes = {
  ANY_PLATFORM: 1,
  WINDOWS: 2,
  LINUX: 3,
  OSX: 4,
  ALL_PLATFORMS: 5,
  CHROME: 6,
  ANDROID: 7,
  IOS: 8
};

const ThreatEntryTypes = {
  URL: 1,
  IP_RANGE: 2
};

module.exports = { DefaultLists, ThreatTypes, PlatformTypes, ThreatEntryTypes };
