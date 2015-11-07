## 0.9.7 (11/06/2015)

### Changes

* Accept either "accounts.google.com" or "https://accounts.google.com" as the issuer of the ID token issued by Google. ([@mcduan][])
* Update to prevent status code 200 messages from being flagged as errors. ([@ryan-devrel][])
* Update async & request ([@josephpage][])
* Update oauthclient2.js ([@riblee][])
* Update README.md ([@ofrobots][])

## 0.9.6 (05/21/2015)

### Changes

* Corrects return value in getRequestMetadata ([@tbetbetbe][])
* Fixed error code not being parsed correctly ([@fiznool][])

## 0.9.5 (05/07/2015)

### Changes

* Corrects usage of refresh token in jwtclient ([@tbetbetbe][])
* Adds an implementation of JWT Access authorization ([@tbetbetbe][])
* Adds getRequestMetadata() to the API surface ([@tbetbetbe][])
* Adds an implementation of IAM authorization ([@tbetbetbe][])

## 0.9.4 (03/04/2015)

### Changes

* Obtains the instance email and key from gtoken ([@stephenplusplus][])
* Switches from GAPIToken to gtoken ([@stephenplusplus][])
* Updates the sample ([@jasonall][])

[@fiznool]: https://github.com/fiznool
[@jasonall]: https://github.com/jasonall
[@josephpage]: https://github.com/josephpage
[@mcduan]: https://github.com/mcduan
[@ofrobots]: https://github.com/ofrobots
[@riblee]: https://github.com/riblee
[@ryan-devrel]: https://github.com/ryan-devrel
[@stephenplusplus]: https://github.com/stephenplusplus
[@tbetbetbe]: https://github.com/tbetbetbe
