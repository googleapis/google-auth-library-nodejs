const path = require('path');

module.exports = {
  entry: './build/browser-test/test.oauth2.js',
  resolve: {
    extensions: ['.ts', '.js', '.json'],
    alias: {
      '../../package.json': path.resolve(__dirname, 'package.json'),
    },
  },
  output: {
    filename: 'google-auth-library-tests.js',
    path: path.resolve(__dirname, 'dist'),
  },
  node: {
    child_process: 'empty',
    fs: 'empty',
    crypto: 'empty',
  },
  module: {
    rules: [
      {
        test: /node_modules\/gtoken\//,
        use: 'null-loader',
      },
      {
        test: /node_modules\/pkginfo\//,
        use: 'null-loader',
      },
      {
        test: /node_modules\/https-proxy-agent\//,
        use: 'null-loader',
      },
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  mode: 'production',
  plugins: [],
};
