# Google APIs Node.js Client

[![Build Status][travisimg]][travis]
[![Code Coverage][coverallsimg]][coveralls]

This is Google's officially supported [node.js][node] client library for using
OAuth 2.0 authorization and authentication with Google APIs.

### Alpha

This library is in Alpha. We will make an effort to support the library, but we reserve the right to make incompatible changes when necessary.

### Questions/problems?

* Ask your development related questions on [![Ask a question on Stackoverflow][overflowimg]][stackoverflow]
* If you've found an bug/issue, please [file it on GitHub][bugs].

## Installation

This library is distributed on `npm`. To add it as a dependency,
run the following command:

``` sh
$ npm install google-auth-library --save
```

## License

This library is licensed under Apache 2.0. Full license text is
available in [COPYING][copying].

## Example Usage

``` js
var google = require('googleapis');

// Get the environment configured authorization
google.auth.getApplicationDefault(function(err, authClient) {
  if (err === null) {
    // Inject scopes if they have not been injected by the environment
    if (authClient.createScopedRequired && authClient.createScopedRequired()) {
      var scopes = [
        'https://www.googleapis.com/auth/cloud-platform',
        'https://www.googleapis.com/auth/compute'
      ];
      authClient = authClient.createScoped(scopes)
    }

    // Fetch the access token
    var _ = require(lodash);
    var optionalUri = null;  // optionally specify the URI being authorized
    var reqHeaders = {};
    authClient.getRequestMetadata(optionalUri, function(err, headers)) {
      if (err === null) {
        // Use authorization headers
        reqHeaders = _.merge(allHeaders, headers);
      }
    });
  }
});
```

## Application Default Credentials
This library provides an implementation of application default credentials for Node.js.

The Application Default Credentials provide a simple way to get authorization credentials for use
in calling Google APIs.

They are best suited for cases when the call needs to have the same identity and authorization
level for the application independent of the user. This is the recommended approach to authorize
calls to Cloud APIs, particularly when you're building an application that uses Google Compute
Engine.

## Contributing

See [CONTRIBUTING][contributing].

[travisimg]: https://api.travis-ci.org/google/google-auth-library-nodejs.svg
[bugs]: https://github.com/google/google-auth-library-nodejs/issues
[node]: http://nodejs.org/
[travis]: https://travis-ci.org/google/google-auth-library-nodejs
[stackoverflow]: http://stackoverflow.com/questions/tagged/google-auth-library-nodejs
[apiexplorer]: https://developers.google.com/apis-explorer
[urlshort]: https://developers.google.com/url-shortener/
[usingkeys]: https://developers.google.com/console/help/#UsingKeys
[contributing]: https://github.com/google/google-auth-library-nodejs/tree/master/CONTRIBUTING.md
[copying]: https://github.com/google/google-auth-library-nodejs/tree/master/COPYING
[authdocs]: https://developers.google.com/accounts/docs/OAuth2Login
[request]: https://github.com/mikeal/request
[requestopts]: https://github.com/mikeal/request#requestoptions-callback
[stream]: http://nodejs.org/api/stream.html#stream_class_stream_readable
[stability]: http://nodejs.org/api/stream.html#stream_stream
[overflowimg]: https://googledrive.com/host/0ByfSjdPVs9MZbkhjeUhMYzRTeEE/stackoveflow-tag.png
[devconsole]: https://console.developer.google.com
[oauth]: https://developers.google.com/accounts/docs/OAuth2
[options]: https://github.com/google/google-auth-library-nodejs/tree/master#options
[gcloud]: https://github.com/GoogleCloudPlatform/gcloud-node
[cloudplatform]: https://developers.google.com/cloud/
[coveralls]: https://coveralls.io/r/google/google-auth-library-nodejs?branch=master
[coverallsimg]: https://img.shields.io/coveralls/google/google-auth-library-nodejs.svg
