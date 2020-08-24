// Copyright 2020 Google LLC
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

import * as assert from 'assert';
import {describe, it, afterEach, beforeEach} from 'mocha';
import * as sinon from 'sinon';
import {AwsRequestSigner} from '../src/auth/awsrequestsigner';
import {GaxiosOptions} from 'gaxios';

/** Defines the interface to facilitate testing of AWS request signing. */
interface AwsRequestSignerTest {
  // Test description.
  description: string;
  // AWS request signer instance.
  instance: AwsRequestSigner;
  // The raw input request.
  originalRequest: GaxiosOptions;
  // The expected signed output request.
  getSignedRequest: () => GaxiosOptions;
}

describe('AwsRequestSigner', () => {
  let clock: sinon.SinonFakeTimers;
  // Load AWS credentials from a sample security_credentials response.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const awsSecurityCredentials = require('../../test/fixtures/aws-security-credentials.json');
  const referenceDate = new Date('2020-08-11T06:55:22.345Z');
  const amzDate = '20200811T065522Z';
  const dateStamp = '20200811';
  const awsRegion = 'us-east-2';
  const accessKeyId = awsSecurityCredentials.AccessKeyId;
  const secretAccessKey = awsSecurityCredentials.SecretAccessKey;
  const token = awsSecurityCredentials.Token;

  beforeEach(() => {
    clock = sinon.useFakeTimers(referenceDate);
  });

  afterEach(() => {
    if (clock) {
      clock.restore();
    }
  });

  describe('getRequestOptions()', () => {
    const awsError = new Error('Error retrieving AWS security credentials');
    // Successful AWS credentials retrieval.
    // In this case, temporary credentials are returned.
    const getCredentials = async () => {
      return {
        accessKeyId,
        secretAccessKey,
        token,
      };
    };
    // Successful AWS credentials retrieval.
    // In this case, permanent credentials are returned (no session token).
    const getCredentialsWithoutToken = async () => {
      return {
        accessKeyId,
        secretAccessKey,
      };
    };
    // Failing AWS credentials retrieval.
    const getCredentialsUnsuccessful = async () => {
      throw awsError;
    };
    // Sample request parameters.
    const requestParams = {
      KeySchema: [
        {
          KeyType: 'HASH',
          AttributeName: 'Id',
        },
      ],
      TableName: 'TestTable',
      AttributeDefinitions: [
        {
          AttributeName: 'Id',
          AttributeType: 'S',
        },
      ],
      ProvisionedThroughput: {
        WriteCapacityUnits: 5,
        ReadCapacityUnits: 5,
      },
    };
    // List of various requests and their expected signatures.
    // Examples source:
    // https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    const getRequestOptionsTests: AwsRequestSignerTest[] = [
      {
        description: 'signed GET request',
        instance: new AwsRequestSigner(getCredentials, awsRegion),
        originalRequest: {
          url:
            'https://ec2.us-east-2.amazonaws.com?' +
            'Action=DescribeRegions&Version=2013-10-15',
        },
        getSignedRequest: () => {
          const signature =
            '631ea80cddfaa545fdadb120dc92c9f18166e38a5c47b50fab9fce476e022855';
          return {
            url:
              'https://ec2.us-east-2.amazonaws.com?' +
              'Action=DescribeRegions&Version=2013-10-15',
            method: 'GET',
            headers: {
              Authorization:
                `AWS4-HMAC-SHA256 Credential=${accessKeyId}/` +
                `${dateStamp}/${awsRegion}/ec2/aws4_request, SignedHeaders=host;` +
                `x-amz-date;x-amz-security-token, Signature=${signature}`,
              host: 'ec2.us-east-2.amazonaws.com',
              'x-amz-date': amzDate,
              'x-amz-security-token': token,
            },
          };
        },
      },
      {
        description: 'signed POST request',
        instance: new AwsRequestSigner(getCredentials, awsRegion),
        originalRequest: {
          url:
            'https://sts.us-east-2.amazonaws.com' +
            '?Action=GetCallerIdentity&Version=2011-06-15',
          method: 'POST',
        },
        getSignedRequest: () => {
          const signature =
            '73452984e4a880ffdc5c392355733ec3f5ba310d5e0609a89244440cadfe7a7a';
          return {
            url:
              'https://sts.us-east-2.amazonaws.com' +
              '?Action=GetCallerIdentity&Version=2011-06-15',
            method: 'POST',
            headers: {
              'x-amz-date': amzDate,
              Authorization:
                `AWS4-HMAC-SHA256 Credential=${accessKeyId}/` +
                `${dateStamp}/${awsRegion}/sts/aws4_request, SignedHeaders=host;` +
                `x-amz-date;x-amz-security-token, Signature=${signature}`,
              host: 'sts.us-east-2.amazonaws.com',
              'x-amz-security-token': token,
            },
          };
        },
      },
      {
        description: 'signed request when AWS credentials have no token',
        instance: new AwsRequestSigner(getCredentialsWithoutToken, awsRegion),
        originalRequest: {
          url:
            'https://sts.us-east-2.amazonaws.com' +
            '?Action=GetCallerIdentity&Version=2011-06-15',
          method: 'POST',
        },
        getSignedRequest: () => {
          const signature =
            'd095ba304919cd0d5570ba8a3787884ee78b860f268ed040ba23831d55536d56';
          return {
            url:
              'https://sts.us-east-2.amazonaws.com' +
              '?Action=GetCallerIdentity&Version=2011-06-15',
            method: 'POST',
            headers: {
              'x-amz-date': amzDate,
              Authorization:
                `AWS4-HMAC-SHA256 Credential=${accessKeyId}/` +
                `${dateStamp}/${awsRegion}/sts/aws4_request, SignedHeaders=host;` +
                `x-amz-date, Signature=${signature}`,
              host: 'sts.us-east-2.amazonaws.com',
            },
          };
        },
      },
      {
        description: 'signed POST request with additional headers/body',
        instance: new AwsRequestSigner(getCredentials, awsRegion),
        originalRequest: {
          url: 'https://dynamodb.us-east-2.amazonaws.com/',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-amz-json-1.0',
            'x-amz-target': 'DynamoDB_20120810.CreateTable',
          },
          body: JSON.stringify(requestParams),
        },
        getSignedRequest: () => {
          const signature =
            'fdaa5b9cc9c86b80fe61eaf504141c0b3523780349120f2bd8145448456e0385';
          return {
            url: 'https://dynamodb.us-east-2.amazonaws.com/',
            method: 'POST',
            headers: {
              Authorization:
                `AWS4-HMAC-SHA256 Credential=${accessKeyId}/` +
                `${dateStamp}/${awsRegion}/dynamodb/aws4_request, SignedHeaders=` +
                'content-type;host;x-amz-date;x-amz-security-token;x-amz-target' +
                `, Signature=${signature}`,
              'Content-Type': 'application/x-amz-json-1.0',
              host: 'dynamodb.us-east-2.amazonaws.com',
              'x-amz-date': amzDate,
              'x-amz-security-token': token,
              'x-amz-target': 'DynamoDB_20120810.CreateTable',
            },
            body: JSON.stringify(requestParams),
          };
        },
      },
      {
        description: 'signed POST request with additional headers/data',
        instance: new AwsRequestSigner(getCredentials, awsRegion),
        originalRequest: {
          url: 'https://dynamodb.us-east-2.amazonaws.com/',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-amz-json-1.0',
            'x-amz-target': 'DynamoDB_20120810.CreateTable',
          },
          data: requestParams,
        },
        getSignedRequest: () => {
          const signature =
            'fdaa5b9cc9c86b80fe61eaf504141c0b3523780349120f2bd8145448456e0385';
          return {
            url: 'https://dynamodb.us-east-2.amazonaws.com/',
            method: 'POST',
            headers: {
              Authorization:
                `AWS4-HMAC-SHA256 Credential=${accessKeyId}/` +
                `${dateStamp}/${awsRegion}/dynamodb/aws4_request, SignedHeaders=` +
                'content-type;host;x-amz-date;x-amz-security-token;x-amz-target' +
                `, Signature=${signature}`,
              'Content-Type': 'application/x-amz-json-1.0',
              host: 'dynamodb.us-east-2.amazonaws.com',
              'x-amz-date': amzDate,
              'x-amz-security-token': token,
              'x-amz-target': 'DynamoDB_20120810.CreateTable',
            },
            body: JSON.stringify(requestParams),
          };
        },
      },
    ];

    getRequestOptionsTests.forEach(test => {
      it(`should resolve with the expected ${test.description}`, async () => {
        const actualSignedRequest = await test.instance.getRequestOptions(
          test.originalRequest
        );
        assert.deepStrictEqual(actualSignedRequest, test.getSignedRequest());
      });
    });

    it('should reject with underlying getCredentials error', async () => {
      const awsRequestSigner = new AwsRequestSigner(
        getCredentialsUnsuccessful,
        awsRegion
      );
      const options: GaxiosOptions = {
        url:
          `https://sts.${awsRegion}.amazonaws.com` +
          '?Action=GetCallerIdentity&Version=2011-06-15',
        method: 'POST',
      };

      await assert.rejects(
        awsRequestSigner.getRequestOptions(options),
        awsError
      );
    });

    it('should reject when no URL is available', async () => {
      const invalidOptionsError = new Error(
        '"url" is required in "amzOptions"'
      );
      const awsRequestSigner = new AwsRequestSigner(getCredentials, awsRegion);

      await assert.rejects(
        awsRequestSigner.getRequestOptions({}),
        invalidOptionsError
      );
    });
  });
});
