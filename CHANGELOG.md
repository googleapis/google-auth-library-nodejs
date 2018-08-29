# Changelog

[npm history][1]

[1]: https://www.npmjs.com/package/google-auth-library-nodejs?activeTab=versions

## v2.0.0

Well hello 2.0 🎉  **This release has multiple breaking changes**.   It also has a lot of bug fixes.

### Breaking Changes

#### Support for node.js 4.x and 9.x has been dropped
These versions of node.js are no longer supported.

#### The `getRequestMetadata` method has been deprecated
The `getRequestMetadata` method has been deprecated on the `IAM`, `OAuth2`, `JWT`, and `JWTAccess` classes.  The `getRequestHeaders` method should be used instead.  The methods have a subtle difference:  the `getRequestMetadata` method returns an object with a headers property, which contains the authorization header.  The `getRequestHeaders` method simply returns the headers.

##### Old code
```js
const client = await auth.getClient();
const res = await client.getRequestMetadata();
const headers = res.headers;
```

##### New code
```js
const client = await auth.getClient();
const headers = await client.getRequestHeaders();
```

#### The `createScopedRequired` method has been deprecated
The `createScopedRequired` method has been deprecated on multiple classes.  The `createScopedRequired` and `createScoped` methods on the `JWT` class were largely in place to help inform clients when scopes were required in an application default credential scenario.  Instead of checking if scopes are required after creating the client, instead scopes should just be passed either into the `GoogleAuth.getClient` method, or directly into the `JWT` constructor.

##### Old code
```js
auth.getApplicationDefault(function(err, authClient) {
   if (err) {
     return callback(err);
   }
  if (authClient.createScopedRequired && authClient.createScopedRequired()) {
    authClient = authClient.createScoped([
      'https://www.googleapis.com/auth/cloud-platform'
    ]);
  }
  callback(null, authClient);
});
```

##### New code
```js
const client = await auth.getClient({
  scopes: ['https://www.googleapis.com/auth/cloud-platform']
});
```

#### The `refreshAccessToken` method has been deprecated
The `OAuth2.refreshAccessToken` method has been deprecated.  The `getAccessToken`, `getRequestMetadata`, and `request` methods will all refresh the token if needed automatically.   There is no need to ever manually refresh the token.

As always, if you run into any problems... please let us know!

### Features
- Set private_key_id in JWT access token header like other google auth libraries. (#450)

### Bug Fixes
- fix: support HTTPS proxies (#405)
- fix: export missing interfaces (#437)
- fix: Use new auth URIs (#434)
- docs: Fix broken link (#423)
- fix: surface file read streams (#413)
- fix: prevent unhandled rejections by avoid .catch (#404)
- fix: use gcp-metadata for compute credentials (#409)
- Add Code of Conduct
- fix: Warn when using user credentials from the Cloud SDK (#399)
- fix: use `Buffer.from` instead of `new Buffer` (#400)
- fix: Fix link format in README.md (#385)

### Breaking changes
- chore: deprecate getRequestMetadata (#414)
- fix: deprecate the `createScopedRequired` methods (#410)
- fix: drop support for node.js 4.x and 9.x (#417)
- fix: deprecate the `refreshAccessToken` methods (#411)
- fix: deprecate the `getDefaultProjectId` method (#402)
- fix: drop support for node.js 4 (#401)

### Build / Test changes
- Run synth to make build tools consistent (#455)
- Add a package.json for samples and cleanup README (#454)
- chore(deps): update dependency typedoc to ^0.12.0 (#453)
- chore: move examples => samples + synth (#448)
- chore(deps): update dependency nyc to v13 (#452)
- chore(deps): update dependency pify to v4 (#447)
- chore(deps): update dependency assert-rejects to v1 (#446)
- chore: ignore package-lock.json (#445)
- chore: update renovate config (#442)
- chore(deps): lock file maintenance (#443)
- chore: remove greenkeeper badge (#440)
- test: throw on deprecation
- chore: add intelli-espower-loader for running tests (#430)
- chore(deps): update dependency typescript to v3 (#432)
- chore(deps): lock file maintenance (#431)
- test: use strictEqual in tests (#425)
- chore(deps): lock file maintenance (#428)
- chore: Configure Renovate (#424)
- chore: Update gts to the latest version 🚀 (#422)
- chore: update gcp-metadata for isAvailable fix (#420)
- refactor: use assert.reject in the tests (#415)
- refactor: cleanup types for certificates (#412)
- test: run tests with hard-rejection (#397)
- cleanup: straighten nested try-catch (#394)
- test: getDefaultProjectId should prefer config (#388)
- chore(package): Update gts to the latest version 🚀 (#387)
- chore(package): update sinon to version 6.0.0 (#386)

