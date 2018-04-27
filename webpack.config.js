const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: './build/src/index.js',
  resolve: {
    extensions: [ '.js', '.json' ]
  },
  output: {
    library: 'GoogleAuth',
    filename: 'google-auth-library.min.js',
    path: path.resolve(__dirname, 'dist')
  },
  node: {
    'child_process': 'empty',
    'fs': 'empty'
  },
  module: {
    rules: [
      {
        test: /node_modules\/(?:gtoken|elliptic)\//,
        use: 'null-loader'
      }
    ]
  },
  mode: 'production',
  plugins: [
    new webpack.DefinePlugin({
      'process.env': {
        'WEBPACK': 'true',
      }
    })
  ]
};
