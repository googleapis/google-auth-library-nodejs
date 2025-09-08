// const {AwsClient} = require('google-auth-library');
// const {fromNodeProviderChain} = require('@aws-sdk/credential-provider-node');

// /**
//  * A custom AwsSecurityCredentialsSupplier that uses the AWS SDK's default
//  * credential provider chain to find credentials.
//  *
//  * This is useful for authenticating from any AWS environment supported by
//  * the AWS SDK, including EC2, ECS, EKS, Fargate, or local setups using
//  * environment variables or shared credential files.
//  */
// class CustomAwsSupplier {
//   /**
//    * @param {string} region The AWS region to use for signing requests.
//    */
//   constructor(region) {
//     this.region = region;
//     // The provider chain can be initialized once and reused.
//     // It will automatically handle credential refreshing.
//     this.provider = fromNodeProviderChain();
//     console.log(
//       '[Supplier] Initialized with AWS SDK default credential provider chain.',
//     );
//   }

//   /**
//    * Returns the configured AWS region.
//    * @param {object} context Context from the calling AwsClient. We'll log it for demonstration.
//    * @returns {Promise<string>} A promise that resolves with the AWS region.
//    */
//   async getAwsRegion(context) {
//     console.log('[Supplier] getAwsRegion called.');
//     console.log(`[Supplier] Audience from context: ${context.audience}`);
//     return this.region;
//   }

//   /**
//    * Retrieves AWS credentials using the AWS SDK's default provider chain.
//    * @param {object} context Context from the calling AwsClient.
//    * @returns {Promise<object>} A promise that resolves with the AWS security credentials.
//    */
//   async getAwsSecurityCredentials(context) {
//     console.log('[Supplier] getAwsSecurityCredentials called.');
//     try {
//       const awsCredentials = await this.provider();
//       if (!awsCredentials.accessKeyId || !awsCredentials.secretAccessKey) {
//         throw new Error(
//           'AWS credentials missing accessKeyId or secretAccessKey',
//         );
//       }

//       console.log(
//         '[Supplier] Successfully retrieved credentials from AWS SDK provider chain.',
//       );

//       // The google-auth-library AwsClient expects this specific format.
//       return {
//         accessKeyId: awsCredentials.accessKeyId,
//         secretAccessKey: awsCredentials.secretAccessKey,
//         token: awsCredentials.sessionToken, // This may be undefined for permanent credentials
//       };
//     } catch (err) {
//       throw new Error(
//         `[Supplier] Failed to get credentials from AWS provider chain: ${err.message}`,
//       );
//     }
//   }
// }

// /**
//  * Main function to demonstrate the custom AWS supplier in a live environment.
//  */
// async function main() {
//   console.log(
//     '--- Running Live Custom AWS Security Credentials Supplier Example ---',
//   );

//   const audience = process.argv[2];
//   const awsRegion = process.argv[3];

//   if (!audience || !awsRegion) {
//     console.error(
//       '\nError: Please provide the GCP audience and AWS region as command-line arguments.',
//     );
//     console.error(
//       'Usage: node custom_aws_supplier_example.js "//iam.googleapis.com/..." "us-east-2"',
//     );

//     throw new Error('Audience or AWS region not provided.');
//   }

//   try {
//     // 1. Create an instance of our custom AWS supplier.
//     const customAwsSupplier = new CustomAwsSupplier(awsRegion);

//     // 2. Create the AwsClient, passing our custom supplier.
//     //    This client will now use our custom logic to get AWS credentials.
//     const client = new AwsClient({
//       audience,
//       subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
//       aws_security_credentials_supplier: customAwsSupplier,
//     });
//     console.log('[Test] AwsClient created with custom supplier.');

//     // 3. Call getAccessToken(). This will trigger our supplier's logic to fetch
//     //    the AWS credentials, sign a request to AWS STS, and exchange it for a
//     //    Google Cloud access token.
//     console.log('[Test] Calling client.getAccessToken()...');
//     const {token} = await client.getAccessToken();

//     console.log('\n--- Result ---');
//     console.log('✅ Successfully retrieved GCP Access Token!');
//     console.log('Token:', token ? `${token.substring(0, 30)}...` : 'undefined');
//   } catch (error) {
//     console.error('\n--- Result ---');
//     console.error('❌ Failed to retrieve GCP Access Token:', error.message);
//   }
// }

// main();
