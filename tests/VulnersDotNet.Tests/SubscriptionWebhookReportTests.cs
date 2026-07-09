using System.Text.Json;
using VulnersDotNet.Exceptions;

namespace VulnersDotNet.Tests;

/// <summary>
/// Live coverage for the subscription, webhook, and report services.
/// Some of these endpoints depend on API-key scopes or account data that a given
/// key may not have; those tests accept a <see cref="VulnersException"/> (an API-level
/// error) as a valid outcome, which still verifies that the SDK serializes the
/// request, reaches the endpoint, and surfaces API errors correctly. Any other
/// exception (serialization, URL, null) fails the test.
/// </summary>
public class SubscriptionWebhookReportTests : IntegrationTestBase
{
    // ---------- Webhook (full round-trip; requires 'webhook' scope) ----------

    [Fact]
    public async Task Webhook_AddListEnableReadDelete_RoundTrip()
    {
        var ct = TestContext.Current.CancellationToken;
        const string query = "type:cve AND cvss.score:[9.9 TO 10]";

        string? id = null;
        try
        {
            await Client.Webhook.AddAsync(query, ct);

            var list = await Client.Webhook.ListAsync(ct);
            Assert.NotEmpty(list);

            // Find the subscription we just created by its query text.
            foreach (var sub in list)
            {
                if (
                    sub.TryGetProperty("query", out var q)
                    && q.GetString() == query
                    && sub.TryGetProperty("id", out var idProp)
                )
                {
                    id = idProp.GetString();
                    break;
                }
            }

            Assert.False(string.IsNullOrEmpty(id), "Created webhook should be present in the list");

            // Read pending data (may be empty) — verifies the read endpoint wiring.
            var read = await Client.Webhook.ReadAsync(id!, newestOnly: true, ct);
            Assert.NotEqual(default, read);

            // Disable it.
            await Client.Webhook.EnableAsync(id!, active: false, ct);
        }
        finally
        {
            if (!string.IsNullOrEmpty(id))
            {
                await Client.Webhook.DeleteAsync(id!, ct);
            }
        }
    }

    // ---------- Email subscriptions (V3, deprecated) ----------

    [Fact]
    public async Task Subscription_ListAsync_ReturnsList()
    {
        var result = await Client.Subscription.ListAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(result);
    }

    [Fact]
    public async Task Subscription_AddAsync_TransmitsRequest()
    {
        // The deprecated email-subscription endpoint validates the query server-side;
        // a valid transmission returns success or a VulnersException ("Invalid query").
        try
        {
            await Client.Subscription.AddAsync(
                query: "type:cve",
                email: "sdk-verify@example.com",
                format: "html",
                cancellationToken: TestContext.Current.CancellationToken
            );
        }
        catch (VulnersException)
        {
            // Expected when the query/scope is rejected — request wiring still verified.
        }
    }

    // ---------- Subscriptions V4 ----------

    [Fact]
    public async Task SubscriptionV4_GetListAsync_ReturnsResult()
    {
        var result = await Client.SubscriptionV4.GetListAsync(
            TestContext.Current.CancellationToken
        );
        Assert.NotEqual(default, result);
    }

    [Fact]
    public async Task SubscriptionV4_CreateAsync_TransmitsRequest()
    {
        // The V4 create schema (discriminated-union query/delivery) is caller-supplied;
        // a minimal payload should reach the server and be rejected with a VulnersException.
        try
        {
            var result = await Client.SubscriptionV4.CreateAsync(
                name: "sdk-verify-temp",
                query: new Dictionary<string, object>
                {
                    ["type"] = "query",
                    ["value"] = "type:cve",
                },
                delivery: new Dictionary<string, object>
                {
                    ["method"] = "email",
                    ["email"] = "sdk-verify@example.com",
                },
                cancellationToken: TestContext.Current.CancellationToken
            );

            // If it unexpectedly succeeds, clean up.
            if (result.TryGetProperty("id", out var idProp))
            {
                var id = idProp.GetString();
                if (!string.IsNullOrEmpty(id))
                {
                    await Client.SubscriptionV4.DeleteAsync(
                        id!,
                        TestContext.Current.CancellationToken
                    );
                }
            }
        }
        catch (VulnersException)
        {
            // Expected: schema validation rejects the minimal payload — wiring verified.
        }
    }

    // ---------- Reports (Linux Audit; requires report data) ----------

    [Theory]
    [InlineData("vulnssummary")]
    [InlineData("vulnslist")]
    [InlineData("ipsummary")]
    [InlineData("scanlist")]
    [InlineData("hostvulns")]
    public async Task Report_TransmitsRequest(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        try
        {
            JsonElement result = kind switch
            {
                "vulnssummary" => await Client.Report.GetVulnsSummaryAsync(
                    limit: 3,
                    cancellationToken: ct
                ),
                "vulnslist" => await Client.Report.GetVulnsListAsync(
                    limit: 3,
                    cancellationToken: ct
                ),
                "ipsummary" => await Client.Report.GetIpSummaryAsync(
                    limit: 3,
                    cancellationToken: ct
                ),
                "scanlist" => await Client.Report.GetScanListAsync(limit: 3, cancellationToken: ct),
                _ => await Client.Report.GetHostVulnsAsync(limit: 3, cancellationToken: ct),
            };
            Assert.NotEqual(default, result);
        }
        catch (VulnersException)
        {
            // Accepted: the account may have no Linux-Audit report data (server-side error).
        }
    }
}
