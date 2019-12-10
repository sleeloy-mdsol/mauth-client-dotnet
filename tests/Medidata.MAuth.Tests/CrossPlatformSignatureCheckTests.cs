using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Models;
using Newtonsoft.Json;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class CrossPlatformSignatureCheckTests
    {
        [Fact]
        public async Task Signature_Check_Valid_V1()
        {
            // Arrange
            var testData = ReadCrossPlatformSignatureValues();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = new Guid(testData["attributes_for_signing"]["app_uuid"].ToString()),
                SignedTime = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(testData["attributes_for_signing"]["time"])),
                PrivateKey = testData["private_key"].ToString()
            };

            // Act
            var result = await new MAuthCore().CalculatePayload(CreateRequest(testData), authInfo);

            // Assert
            var expectedResult = testData["signatures"]["v1"].ToString();

            Assert.Equal(expectedResult, result.ToString());
        }

        [Fact]
        public async Task Signature_Check_Valid_V2()
        {
            // Arrange
            var testData = ReadCrossPlatformSignatureValues();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = new Guid(testData["attributes_for_signing"]["app_uuid"].ToString()),
                SignedTime = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(testData["attributes_for_signing"]["time"])),
                PrivateKey = testData["private_key"].ToString()
            };

            // Act
            var result = await new MAuthCoreV2().CalculatePayload(CreateRequest(testData, MAuthVersion.MWSV2), authInfo);

            // Assert
            var expectedResult = testData["signatures"]["v2"].ToString();

            Assert.Equal(expectedResult, result.ToString());

        }

        private HttpRequestMessage CreateRequest(dynamic testData, MAuthVersion version = MAuthVersion.MWS,
            bool emptyBody = false)
        {
            var requestUri = testData["attributes_for_signing"]["request_url"].ToString() +
                             "?"+ testData["attributes_for_signing"]["query_string"].ToString();
            var request = new HttpRequestMessage(new HttpMethod(
                testData["attributes_for_signing"]["verb"].ToString()), new Uri(requestUri))
            {
                Content = emptyBody ? null : new ByteArrayContent(GetBinaryFileBody())
            };

            var mAuthCore = MAuthCoreFactory.Instantiate(version);
            var headerKeys = mAuthCore.GetHeaderKeys();
            var mauthHeader = version == MAuthVersion.MWS
                ? $"{version} {testData["attributes_for_signing"]["app_uuid"]}:{testData["signatures"]["v1"]}"
                : $"{version} {testData["attributes_for_signing"]["app_uuid"]}:{testData["signatures"]["v2"]};";

            request.Headers.Add(headerKeys.mAuthHeaderKey, mauthHeader);
            request.Headers.Add(headerKeys.mAuthTimeHeaderKey, testData["attributes_for_signing"]["time"].ToString());

            return request;
        }


        private static dynamic ReadCrossPlatformSignatureValues()
        {
            return JsonConvert.DeserializeObject(
                File.ReadAllText(@"Mocks/Fixtures/mauth_signature_testing.json"));
        }

        private static byte[] GetBinaryFileBody()
        {
            var binaryFileData = File.ReadAllBytes(@"Mocks/Fixtures/blank.jpeg");
            return binaryFileData;
        }

    }
}
