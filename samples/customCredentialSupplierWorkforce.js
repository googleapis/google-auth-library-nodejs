const {IdentityPoolClient} = require('google-auth-library');
const fs = require('fs/promises');
// const path = require('path');

/**
 * A custom SubjectTokenSupplier that reads a JSON file, finds the
 * 'subject_token' field, and returns its value.
 *
 * This is useful when the token is stored in a structured file alongside
 * other data, a scenario the built-in file supplier doesn't handle.
 */
class CustomFileSupplier {
  /**
   * @param {string} filePath The absolute path to the JSON token file.
   */
  constructor(filePath) {
    this.filePath = filePath;
    console.log(`[Supplier] Initialized to read from file: "${this.filePath}"`);
  }

  /**
   * This method is called by the IdentityPoolClient when it needs a subject token.
   * @param {object} context Context from the calling client. We'll log it for demonstration.
   * @returns {Promise<string>} A promise that resolves with the subject token.
   */
  async getSubjectToken(context) {
    console.log('[Supplier] getSubjectToken called.');
    console.log(`[Supplier] Audience from context: ${context.audience}`);

    try {
      // 1. Read and parse the JSON file.
      const fileContent = await fs.readFile(this.filePath, 'utf-8');
      const tokenData = JSON.parse(fileContent);

      // 2. Extract the token from the 'subject_token' field.
      //    This is the "custom logic" part.
      const token = tokenData.subject_token;

      if (
        !token ||
        typeof token !== 'string' ||
        token === 'PASTE_YOUR_THIRD_PARTY_TOKEN_HERE'
      ) {
        throw new Error(
          `'subject_token' field not found, is not a string, or still has the placeholder value in ${this.filePath}`,
        );
      }

      console.log('[Supplier] Successfully extracted subject token from file.');
      return token;
    } catch (err) {
      if (err.code === 'ENOENT') {
        throw new Error(
          `[Supplier] The token file was not found at ${this.filePath}`,
        );
      }
      throw new Error(
        `[Supplier] Failed to read or parse token file: ${err.message}`,
      );
    }
  }
}

/**
 * Main function to demonstrate the custom supplier in a live environment.
 */
async function main() {
  console.log(
    '--- Running Live Custom Subject Token Supplier for Workforce Pool Example ---',
  );

  // The audience for your Workforce Pool Provider and the user project are required
  // command-line argument.
  const audience = process.argv[2];
  const workforcePoolUserProject = process.argv[3];
  const tokenFilePathArg = process.argv[4];

  if (!audience || !workforcePoolUserProject) {
    console.error(
      '\nError: Please provide the audience and workforce pool user project as command-line arguments.',
    );
    console.error(
      'Usage: node customCredentialSupplierWorkforce.js "AUDIENCE" "WORKFORCE_POOL_USER_PROJECT" [TOKEN_FILE_PATH]',
    );
    console.error(
      'Example: node customCredentialSupplierWorkforce.js "//iam.googleapis.com/locations/global/workforcePools/..." "123456789" token.json',
    );
    throw new Error('Audience or workforce_pool_user_project not provided.');
  }

  // The token file path can be provided as the second argument.
  // If not, it defaults to 'token.json' in the current directory.
  const tokenFilePath = tokenFilePathArg
    ? path.resolve(tokenFilePathArg)
    : path.join(__dirname, 'token.json');

  try {
    console.log(`[Test] Using token file path: "${tokenFilePath}"`);
    // 1. Create an instance of our custom supplier.
    const customSupplier = new CustomFileSupplier(tokenFilePath);

    // 2. Create the IdentityPoolClient for a workforce pool, passing the custom supplier.
    //    This client will now use our custom logic to get the subject token.
    const client = new IdentityPoolClient({
      audience,
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt', // Or another appropriate type like id_token
      workforce_pool_user_project: workforcePoolUserProject,
      subject_token_supplier: customSupplier,
    });
    console.log('[Test] IdentityPoolClient created with custom supplier.');

    // 3. Call getAccessToken(). This will trigger our supplier's logic to fetch
    //    the third-party token and exchange it for a Google Cloud access token.
    console.log('[Test] Calling client.getAccessToken()...');
    const {token} = await client.getAccessToken();

    console.log('\n--- Result ---');
    console.log('✅ Successfully retrieved GCP Access Token!');
    console.log('Token:', token ? `${token.substring(0, 30)}...` : 'undefined');
  } catch (error) {
    console.error('\n--- Result ---');
    console.error('❌ Failed to retrieve GCP Access Token:', error.message);
  }
}

main();
