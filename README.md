# Safe Browsing API NodeJS Client

## Set up an API key 
You need an API key to access the Safe Browsing APIs. 
See instructions [here](https://developers.google.com/safe-browsing/v4/get-started)
Put API key in `.env` file
```
GOOGLE_API_KEY=XXXXX
```

# Using
## Check site with GET request

```
/api/validate/?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/
/api/validate/?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/
/api/validate/?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/UNWANTED_SOFTWARE/URL/
/api/validate/?url=http://www.google.com/
/api/validate/?url=https://skinfast.net
/api/validate/?url=http://steamgotrade.com

```
## Module 
```
  const validate = require("../lib/validate");
  const siteUrl = "http://testsafebrowsing.appspot.com/s/malware.html";
  const result = await validate.isUrlSafe(siteUrl); // true\false
```
