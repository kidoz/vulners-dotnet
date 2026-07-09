using System.Net;
using System.Text.Json;
using VulnersDotNet;
using VulnersDotNet.Exceptions;
using VulnersDotNet.Models;
using VulnersDotNet.Services;

namespace VulnersDotNet.Tests;

/// <summary>
/// Credential-hygiene tests that do not require an API key: they verify the API key is
/// never echoed into exception messages and is not serialized into request bodies on the
/// endpoints that authenticate via the X-Api-Key header.
/// </summary>
public class SecurityTests
{
    private const string SecretKey = "SECRET-KEY-ABC123XYZ";

    /// <summary>Captures the outgoing request and returns a canned response.</summary>
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;

        public string? CapturedBody { get; private set; }

        public StubHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken
        )
        {
            if (request.Content is not null)
            {
                CapturedBody = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
            }

            return new HttpResponseMessage(_status) { Content = new StringContent(_body) };
        }
    }

    /// <summary>Minimal concrete <see cref="BaseApiService"/> exposing the protected helpers.</summary>
    private sealed class TestService : BaseApiService
    {
        public TestService(HttpClient client, VulnersOptions options)
            : base(client, options) { }

        public Task<T> Get<T>(string url, CancellationToken ct) => GetAsync<T>(url, ct);

        public Task<object> Post<TReq>(string url, TReq req, CancellationToken ct) =>
            PostAsync<TReq, object>(url, req, ct);
    }

    private static (TestService svc, StubHandler handler) Make(HttpStatusCode status, string body)
    {
        var handler = new StubHandler(status, body);
        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://vulners.com/api/v3/"),
        };
        var svc = new TestService(client, new VulnersOptions { ApiKey = SecretKey });
        return (svc, handler);
    }

    [Fact]
    public async Task ErrorBody_RedactsApiKeyAndTokens()
    {
        var (svc, _) = Make(
            HttpStatusCode.InternalServerError,
            $"{{\"error\":\"request apiKey={SecretKey} failed\",\"token\":\"{SecretKey}\"}}"
        );

        var ex = await Assert.ThrowsAsync<VulnersException>(() =>
            svc.Get<JsonElement>("boom", TestContext.Current.CancellationToken)
        );

        Assert.DoesNotContain(SecretKey, ex.Message, StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ErrorBody_IsTruncated()
    {
        var (svc, _) = Make(HttpStatusCode.BadGateway, new string('A', 5000));

        var ex = await Assert.ThrowsAsync<VulnersException>(() =>
            svc.Get<JsonElement>("boom", TestContext.Current.CancellationToken)
        );

        Assert.Contains("[truncated]", ex.Message, StringComparison.Ordinal);
        Assert.True(ex.Message.Length < 5000, "Error body should be truncated");
    }

    [Fact]
    public async Task EmailSubscriptionRequest_BodyOmitsApiKey()
    {
        var (svc, handler) = Make(HttpStatusCode.OK, "{\"result\":\"OK\",\"data\":{}}");

        // The request the SubscriptionService builds for add — with no ApiKey set.
        var request = new AddEmailSubscriptionRequest
        {
            Query = "type:cve",
            Email = "user@example.com",
            Format = "html",
        };

        await svc.Post(
            "subscriptions/addEmailSubscription/",
            request,
            TestContext.Current.CancellationToken
        );

        Assert.NotNull(handler.CapturedBody);
        Assert.DoesNotContain("apiKey", handler.CapturedBody!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(SecretKey, handler.CapturedBody!, StringComparison.Ordinal);
    }
}
