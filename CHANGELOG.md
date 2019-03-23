# Changelog

[npm history][1]

[1]: https://www.npmjs.com/package/google-auth-library-nodejs?activeTab=versions

## v3.1.2

03-22-2019 15:38 PDT

### Implementation Changes
- fix: getCredential(): load credentials with getClient() ([#648](https://github.com/google/google-auth-library-nodejs/pull/648))

### Internal / Testing Changes
- chore: publish to npm using wombat ([#645](https://github.com/google/google-auth-library-nodejs/pull/645))

## v3.1.1

03-18-2019 08:32 PDT

### Bug Fixes
- fix: Avoid loading fast-text-encoding if not in browser environment ([#627](https://github.com/google/google-auth-library-nodejs/pull/627))

### Dependencies
- fix(deps): update dependency gcp-metadata to v1 ([#632](https://github.com/google/google-auth-library-nodejs/pull/632))

### Documentation
- docs: update links in contrib guide ([#630](https://github.com/google/google-auth-library-nodejs/pull/630))

### Internal / Testing Changes
- build: use per-repo publish token ([#641](https://github.com/google/google-auth-library-nodejs/pull/641))
- build: Add docuploader credentials to node publish jobs ([#639](https://github.com/google/google-auth-library-nodejs/pull/639))
- build: use node10 to run samples-test, system-test etc ([#638](https://github.com/google/google-auth-library-nodejs/pull/638))
- build: update release configuration
- chore(deps): update dependency @types/lru-cache to v5 ([#635](https://github.com/google/google-auth-library-nodejs/pull/635))
- chore(deps): update dependency mocha to v6
- chore: fix lint ([#631](https://github.com/google/google-auth-library-nodejs/pull/631))
- build: use linkinator for docs test ([#628](https://github.com/google/google-auth-library-nodejs/pull/628))
- chore(deps): update dependency @types/tmp to ^0.0.34 ([#629](https://github.com/google/google-auth-library-nodejs/pull/629))
- build: create docs test npm scripts ([#625](https://github.com/google/google-auth-library-nodejs/pull/625))
- build: test using @grpc/grpc-js in CI ([#624](https://github.com/google/google-auth-library-nodejs/pull/624))

## v3.1.0

02-08-2019 08:29 PST

### Bug fixes
- fix: use key file when fetching project id ([#618](https://github.com/googleapis/google-auth-library-nodejs/pull/618))
- fix: Throw error if there is no refresh token despite the necessity of refreshing ([#605](https://github.com/googleapis/google-auth-library-nodejs/pull/605))

### New Features
- feat: allow passing constructor options to getClient ([#611](https://github.com/googleapis/google-auth-library-nodejs/pull/611))

### Documentation
- docs: update contributing path in README ([#621](https://github.com/googleapis/google-auth-library-nodejs/pull/621))
- chore: move CONTRIBUTING.md to root ([#619](https://github.com/googleapis/google-auth-library-nodejs/pull/619))
- docs: add lint/fix example to contributing guide ([#615](https://github.com/googleapis/google-auth-library-nodejs/pull/615))
- docs: use the People API for samples ([#609](https://github.com/googleapis/google-auth-library-nodejs/pull/609))

### Internal / Testing Changes
- chore(deps): update dependency typescript to ~3.3.0 ([#612](https://github.com/googleapis/google-auth-library-nodejs/pull/612))
- chore(deps): update dependency eslint-config-prettier to v4 ([#604](https://github.com/googleapis/google-auth-library-nodejs/pull/604))
- build: ignore googleapis.com in doc link check ([#602](https://github.com/googleapis/google-auth-library-nodejs/pull/602))
- chore(deps): update dependency karma to v4 ([#603](https://github.com/googleapis/google-auth-library-nodejs/pull/603))

## v3.0.1

01-16-2019 21:04 PST

### Bug Fixes
- fix(deps): upgrade to the latest gaxios ([#596](https://github.com/googleapis/google-auth-library-nodejs/pull/596))

## v3.0.0

01-16-2019 10:00 PST

Welcome to 3.0 🎉  This release has it all.  New features, bug fixes, breaking changes, performance improvements - something for everyone!  The biggest addition to this release is support for the browser via Webpack.

**This release has breaking changes.**  This release has a few breaking changes. These changes are unlikely to affect most clients.

#### BREAKING: Migration from `axios` to `gaxios`
The 2.0 version of this library used the [axios](https://github.com/axios/axios) library for making HTTP requests. In the 3.0 release, this has been replaced by a *mostly* API compatible library [gaxios](https://github.com/JustinBeckwith/gaxios). The new request library natively supports proxies, and comes with a smaller dependency chain. While this is mostly an implementation detail, the `request` method was directly exposed via the `GoogleAuth.request` and `OAuth2Client.request` methods.  The gaxios library aims to provide an API compatible implementation of axios, but that can never be 100% promised.  If you run into bugs or differences that cause issues - please do let us know.

#### BREAKING: `generateCodeVerifier` is now `generateCodeVerifierAsync`
The `OAuth2Client.generateCodeVerifier` method has been replaced by the `OAuth2Client.generateCodeVerifierAsync` method.  It has changed from a synchronous method to an asynchronous method to support async browser crypto APIs required for Webpack support.

#### BREAKING: `generateCodeVerifier` is now `generateCodeVerifierAsync`
The `OAuth2Client.verifySignedJwtWithCerts` method has been replaced by the `OAuth2Client.verifySignedJwtWithCerts` method.  It has changed from a synchronous method to an asynchronous method to support async browser crypto APIs required for Webpack support.


### New Features
- feat: make it webpackable ([#371](https://github.com/google/google-auth-library-nodejs/pull/371))

### Bug Fixes
- fix: accept lowercase env vars ([#578](https://github.com/google/google-auth-library-nodejs/pull/578))

### Dependencies
- chore(deps): update gtoken ([#592](https://github.com/google/google-auth-library-nodejs/pull/592))
- fix(deps): upgrade to gcp-metadata v0.9.3 ([#586](https://github.com/google/google-auth-library-nodejs/pull/586))

### Documentation
- docs: update bug report link ([#585](https://github.com/google/google-auth-library-nodejs/pull/585))
- docs: clarify access and refresh token docs ([#577](https://github.com/google/google-auth-library-nodejs/pull/577))

### Internal / Testing Changes
- refactor(deps): use `gaxios` for HTTP requests instead of `axios` ([#593](https://github.com/google/google-auth-library-nodejs/pull/593))
- fix: some browser fixes ([#590](https://github.com/google/google-auth-library-nodejs/pull/590))
- chore(deps): update dependency ts-loader to v5 ([#588](https://github.com/google/google-auth-library-nodejs/pull/588))
- chore(deps): update dependency karma to v3 ([#587](https://github.com/google/google-auth-library-nodejs/pull/587))
- build: check broken links in generated docs ([#579](https://github.com/google/google-auth-library-nodejs/pull/579))
- chore(deps): drop unused dep on typedoc ([#583](https://github.com/google/google-auth-library-nodejs/pull/583))
- build: add browser test running on Kokoro ([#584](https://github.com/google/google-auth-library-nodejs/pull/584))
- test: improve samples and add tests ([#576](https://github.com/google/google-auth-library-nodejs/pull/576))

## v2.0.2

12-16-2018 10:48 PST

### Fixes
- fix(types): export GCPEnv type ([#569](https://github.com/google/google-auth-library-nodejs/pull/569))
- fix: use post for token revocation ([#524](https://github.com/google/google-auth-library-nodejs/pull/524))

### Dependencies
- fix(deps): update dependency lru-cache to v5 ([#541](https://github.com/google/google-auth-library-nodejs/pull/541))

### Documentation
- docs: add ref docs again ([#553](https://github.com/google/google-auth-library-nodejs/pull/553))
- docs: clean up the readme ([#554](https://github.com/google/google-auth-library-nodejs/pull/554))

### Internal / Testing Changes
- chore(deps): update dependency @types/sinon to v7 ([#568](https://github.com/google/google-auth-library-nodejs/pull/568))
- refactor: use execa for install tests, run eslint on samples ([#559](https://github.com/google/google-auth-library-nodejs/pull/559))
- chore(build): inject yoshi automation key ([#566](https://github.com/google/google-auth-library-nodejs/pull/566))
- chore: update nyc and eslint configs ([#565](https://github.com/google/google-auth-library-nodejs/pull/565))
- chore: fix publish.sh permission +x ([#563](https://github.com/google/google-auth-library-nodejs/pull/563))
- fix(build): fix Kokoro release script ([#562](https://github.com/google/google-auth-library-nodejs/pull/562))
- build: add Kokoro configs for autorelease ([#561](https://github.com/google/google-auth-library-nodejs/pull/561))
- chore: always nyc report before calling codecov ([#557](https://github.com/google/google-auth-library-nodejs/pull/557))
- chore: nyc ignore build/test by default ([#556](https://github.com/google/google-auth-library-nodejs/pull/556))
- chore(build): update the prettier and renovate config ([#552](https://github.com/google/google-auth-library-nodejs/pull/552))
- chore: update license file ([#551](https://github.com/google/google-auth-library-nodejs/pull/551))
- fix(build): fix system key decryption ([#547](https://github.com/google/google-auth-library-nodejs/pull/547))
- chore(deps): update dependency typescript to ~3.2.0 ([#546](https://github.com/google/google-auth-library-nodejs/pull/546))
- chore(deps): unpin sinon ([#544](https://github.com/google/google-auth-library-nodejs/pull/544))
- refactor: drop non-required modules ([#542](https://github.com/google/google-auth-library-nodejs/pull/542))
- chore: add synth.metadata ([#537](https://github.com/google/google-auth-library-nodejs/pull/537))
- fix: Pin @types/sinon to last compatible version ([#538](https://github.com/google/google-auth-library-nodejs/pull/538))
- chore(deps): update dependency gts to ^0.9.0 ([#531](https://github.com/google/google-auth-library-nodejs/pull/531))
- chore: update eslintignore config ([#530](https://github.com/google/google-auth-library-nodejs/pull/530))
- chore: drop contributors from multiple places ([#528](https://github.com/google/google-auth-library-nodejs/pull/528))
- chore: use latest npm on Windows ([#527](https://github.com/google/google-auth-library-nodejs/pull/527))
- chore: update CircleCI config ([#523](https://github.com/google/google-auth-library-nodejs/pull/523))
- chore: include build in eslintignore ([#516](https://github.com/google/google-auth-library-nodejs/pull/516))

## v2.0.1

### Implementation Changes
- fix: verifyIdToken will never return null ([#488](https://github.com/google/google-auth-library-nodejs/pull/488))
- Update the url to application default credentials ([#470](https://github.com/google/google-auth-library-nodejs/pull/470))
- Update omitted parameter 'hd' ([#467](https://github.com/google/google-auth-library-nodejs/pull/467))

### Dependencies
- chore(deps): update dependency nock to v10 ([#501](https://github.com/google/google-auth-library-nodejs/pull/501))
- chore(deps): update dependency sinon to v7 ([#502](https://github.com/google/google-auth-library-nodejs/pull/502))
- chore(deps): update dependency typescript to v3.1.3 ([#503](https://github.com/google/google-auth-library-nodejs/pull/503))
- chore(deps): update dependency gh-pages to v2 ([#499](https://github.com/google/google-auth-library-nodejs/pull/499))
- chore(deps): update dependency typedoc to ^0.13.0 ([#497](https://github.com/google/google-auth-library-nodejs/pull/497))

### Documentation
- docs: Remove code format from Application Default Credentials ([#483](https://github.com/google/google-auth-library-nodejs/pull/483))
- docs: replace google/ with googleapis/ in URIs ([#472](https://github.com/google/google-auth-library-nodejs/pull/472))
- Fix typo in readme ([#469](https://github.com/google/google-auth-library-nodejs/pull/469))
- Update samples and docs for 2.0 ([#459](https://github.com/google/google-auth-library-nodejs/pull/459))

### Internal / Testing Changes
- chore: update issue templates ([#509](https://github.com/google/google-auth-library-nodejs/pull/509))
- chore: remove old issue template ([#507](https://github.com/google/google-auth-library-nodejs/pull/507))
- build: run tests on node11 ([#506](https://github.com/google/google-auth-library-nodejs/pull/506))
- chore(build): drop hard rejection and update gts in the kitchen test ([#504](https://github.com/google/google-auth-library-nodejs/pull/504))
- chores(build): do not collect sponge.xml from windows builds ([#500](https://github.com/google/google-auth-library-nodejs/pull/500))
- chores(build): run codecov on continuous builds ([#495](https://github.com/google/google-auth-library-nodejs/pull/495))
- chore: update new issue template ([#494](https://github.com/google/google-auth-library-nodejs/pull/494))
- build: fix codecov uploading on Kokoro ([#490](https://github.com/google/google-auth-library-nodejs/pull/490))
- test: move kitchen sink tests to system-test ([#489](https://github.com/google/google-auth-library-nodejs/pull/489))
- Update kokoro config ([#482](https://github.com/google/google-auth-library-nodejs/pull/482))
- fix: export additional typescript types ([#479](https://github.com/google/google-auth-library-nodejs/pull/479))
- Don't publish sourcemaps ([#478](https://github.com/google/google-auth-library-nodejs/pull/478))
- test: remove appveyor config ([#477](https://github.com/google/google-auth-library-nodejs/pull/477))
- Enable prefer-const in the eslint config ([#473](https://github.com/google/google-auth-library-nodejs/pull/473))
- Enable no-var in eslint ([#471](https://github.com/google/google-auth-library-nodejs/pull/471))
- Update CI config ([#468](https://github.com/google/google-auth-library-nodejs/pull/468))
- Retry npm install in CI ([#465](https://github.com/google/google-auth-library-nodejs/pull/465))
- Update Kokoro config ([#462](https://github.com/google/google-auth-library-nodejs/pull/462))

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

## Upgrading to 1.x
The `1.x` release includes a variety of bug fixes, new features, and breaking changes. Please take care, and see [the release notes](https://github.com/googleapis/google-auth-library-nodejs/releases/tag/v1.0.0) for a list of breaking changes, and the upgrade guide.
