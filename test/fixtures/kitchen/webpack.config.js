const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: './build/src/index.js',
  resolve: {
    extensions: [ '.js', '.json' ]
  },
  output: {
    filename: 'bundle.min.js',
    path: path.resolve(__dirname, 'dist')
  },
  node: {
    'child_process': 'empty',
    'fs': 'empty',
    'crypto': 'empty'
  },
  module: {
    rules: [
      {
        test: /node_modules\/gtoken\//,
        use: 'null-loader'
      }
    ]
  },
  mode: 'production'
};
