# Contributing

Before making any contributions, please sign one of the contributor
license agreements below.

Fork the repo, develop and test your code changes.

Install all dependencies including development requirements by running:

``` sh
$ npm install -d
```

Tests are run using mocha. To run all tests just run:

``` sh
$ npm test
```

which looks for tests in the `test/` directory.

In addition, you must run the [google-api-nodejs-client][client-repo] tests, which depend upon this
library. Clone a copy of the [google-api-nodejs-client][client-repo] repo, update the dependency
to point to your local copy of the google-auth-library-nodejs repo, and ensure that the client
tests still pass.

Your code should honor the [Google JavaScript Style Guide][js-guide].
You can use [Closure Linter][c-linter] to detect style issues.

Submit a pull request. The repo owner will review your request. If it is
approved, the change will be merged. If it needs additional work, the repo
owner will respond with useful comments.

## Generating Documentation

You can generate the documentation for the APIs by running:

``` sh
npm run generate-docs
```

Documentation will be generated in `docs/`.

## Preparing for release

Before releasing a new version, you should run tests,
bump the version in `package.json` and create a git tag for the release. You
can automate all this with a patch version bump (version += 0.0.1) by running:

``` sh
npm run prepare
```

## Contributor License Agreements

Before creating a pull request, please fill out either the individual or
corporate Contributor License Agreement.

* If you are an individual writing original source code and you're sure you
own the intellectual property, then you'll need to sign an
[individual CLA][indv-cla].
* If you work for a company that wants to allow you to contribute your work
to this client library, then you'll need to sign a
[corporate CLA][corp-cla].

Follow either of the two links above to access the appropriate CLA and
instructions for how to sign and return it. Once we receive it, we'll add you
to the official list of contributors and be able to accept your patches.

[js-guide]: https://google-styleguide.googlecode.com/svn/trunk/javascriptguide.xml
[c-linter]: https://code.google.com/p/closure-linter/
[indv-cla]: https://developers.google.com/open-source/cla/individual
[corp-cla]: https://developers.google.com/open-source/cla/corporate
[client-repo]: https://github.com/google/google-api-nodejs-client
