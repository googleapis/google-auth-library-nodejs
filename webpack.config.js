const path = require('path');
const webpack = require('webpack');
// const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;

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
    'fs': 'empty',
    'crypto': 'empty'
  },
  module: {
    rules: [
      {
        test: /node_modules\/gtoken\//,
        use: 'null-loader'
      },
      {
        test: /node_modules\/text-encoding\/lib\/encoding-indexes.js/,
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
//  , new BundleAnalyzerPlugin()
  ]
};
