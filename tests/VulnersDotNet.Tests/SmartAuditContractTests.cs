using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using VulnersDotNet.Extensions;

namespace VulnersDotNet.Tests;

/// <summary>
/// Credential-free wire-contract tests for the Smart Audit preview endpoint.
/// </summary>
public class SmartAuditContractTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }

        public string? RequestBody { get; private set; }

        public string? ApiKey { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken
        )
        {
            RequestUri = request.RequestUri;
            ApiKey = request.Headers.GetValues("X-Api-Key").Single();
            RequestBody = await request
                .Content!.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);

            const string body = """
                {
                  "result": [
                    {
                      "input": "OpenSSL 1.0.1",
                      "cpe": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
                      "purls": ["pkg:generic/openssl@1.0.1"],
                      "confidence": 0.93,
                      "vulnerabilities": [
                        {
                          "id": "CVE-2014-0160",
                          "reasons": [
                            {
                              "config": "nvd",
                              "criterias": [[{
                                "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                                "vulnerable": true,
                                "versionEndIncluding": "1.0.1f"
                              }]]
                            }
                          ],
                          "title": "CVE-2014-0160",
                          "short_description": "Heartbleed",
                          "type": "cve",
                          "href": "https://vulners.com/cve/CVE-2014-0160",
                          "published": "2014-04-07T00:00:00Z",
                          "modified": "2025-04-03T00:00:00Z",
                          "ai_score": { "value": 9.8, "uncertainty": 0.1 },
                          "future_field": true
                        }
                      ],
                      "preview_field": "preserved"
                    }
                  ]
                }
                """;

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
        }
    }

    [Fact]
    public async Task AuditSmartAsync_SendsContractAndDeserializesTypedResult()
    {
        var handler = new StubHandler();
        var services = new ServiceCollection();
        services.AddVulners(options =>
        {
            options.ApiKey = "test-key";
        });
        services.ConfigureHttpClientDefaults(builder =>
            builder.ConfigurePrimaryHttpMessageHandler(() => handler)
        );

        using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IVulnersClient>();

        var results = await client.Audit.AuditSmartAsync(
            new[] { "OpenSSL 1.0.1" },
            catalog: "extended",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.Equal("https://vulners.com/api/v4/audit/smart", handler.RequestUri?.ToString());
        Assert.Equal("test-key", handler.ApiKey);

        using var request = JsonDocument.Parse(Assert.IsType<string>(handler.RequestBody));
        Assert.Equal("OpenSSL 1.0.1", request.RootElement.GetProperty("software")[0].GetString());
        Assert.Equal("extended", request.RootElement.GetProperty("catalog").GetString());

        var result = Assert.Single(results);
        Assert.Equal("OpenSSL 1.0.1", result.Input);
        Assert.Equal("pkg:generic/openssl@1.0.1", Assert.Single(result.Purls));
        Assert.Equal(0.93, result.Confidence);
        Assert.NotNull(result.AdditionalFields);
        Assert.True(result.AdditionalFields.ContainsKey("preview_field"));

        var vulnerability = Assert.Single(result.Vulnerabilities);
        Assert.Equal("CVE-2014-0160", vulnerability.Id);
        Assert.Equal(9.8, vulnerability.AiScore?.Value);
        Assert.NotNull(vulnerability.AdditionalFields);
        Assert.True(vulnerability.AdditionalFields.ContainsKey("future_field"));

        var reason = Assert.Single(vulnerability.Reasons);
        var criteriaGroup = Assert.Single(reason.CriteriaGroups);
        var criterion = Assert.Single(criteriaGroup);
        Assert.True(criterion.Vulnerable);
        Assert.Equal("1.0.1f", criterion.VersionEndIncluding);
    }
}
