// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Shows API key usage in GCP libraries
 *
 * @param {string} googleApiKey - API key value you want to use.
 */
function main(googleApiKey) {
  // [START auth_cloud_api_key]
  /**
   * TODO(developer):
   *  1. Uncomment and replace these variables before running the sample.
   *  2. Create an API key as described in https://cloud.google.com/docs/authentication/api-keys
   */
  // const googleApiKey = 'YOUR_API_KEY';

  const language = require('@google-cloud/language');

  async function authenticateWithApiKey() {
    // This snippet demonstrates how to analyze sentiment.
    const client = new language.LanguageServiceClient({apiKey: googleApiKey});

    const text = 'Hello, World';
    const document = {type: 'PLAIN_TEXT', content: text};
    const analyzeSentimentRequest = {document: document, encodingType: 'UTF8'};

    const [response] = await client.analyzeSentiment(analyzeSentimentRequest);
    const sentiment = response.documentSentiment;
    console.log(`Text: ${text}`);
    console.log(`Sentiment score: ${sentiment.score}`);
    console.log(`Sentiment magnitude: ${sentiment.magnitude}`);
  }

  authenticateWithApiKey();
  // [END auth_cloud_api_key]
}

process.on('unhandledRejection', err => {
  console.error(err.message);
  process.exitCode = 1;
});

main(...process.argv.slice(2));
