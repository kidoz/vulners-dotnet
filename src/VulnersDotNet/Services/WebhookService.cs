using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the webhook service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class WebhookService : BaseApiService, IWebhookService
{
    public WebhookService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    public async Task<IReadOnlyList<JsonElement>> ListAsync(
        CancellationToken cancellationToken = default
    )
    {
        // Authenticated via the X-Api-Key header on the configured HttpClient — the key
        // is deliberately not placed in the query string.
        var response = await GetAsync<WebhookListResponseData>(
                "subscriptions/listWebhookSubscriptions/",
                cancellationToken
            )
            .ConfigureAwait(false);
        return response.Subscriptions;
    }

    /// <inheritdoc />
    public async Task AddAsync(string query, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(query);
#else
        if (string.IsNullOrEmpty(query))
            throw new ArgumentException("Value cannot be null or empty.", nameof(query));
#endif

        // LEGACY EXCEPTION: addWebhookSubscription rejects header-only auth with
        // errorCode 103 ("Missing parameters: ['apiKey']"), so the key must be sent in
        // the body here. The key is also present in the X-Api-Key header.
        var request = new AddWebhookRequest { ApiKey = ApiKey, Query = query };
        await PostAsync<AddWebhookRequest, object>(
                "subscriptions/addWebhookSubscription/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task EnableAsync(
        string subscriptionId,
        bool active,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(subscriptionId);
#else
        if (string.IsNullOrEmpty(subscriptionId))
            throw new ArgumentException("Value cannot be null or empty.", nameof(subscriptionId));
#endif

        // Key travels in the X-Api-Key header; not serialized into the request body.
        var request = new EditWebhookRequest
        {
            SubscriptionId = subscriptionId,
            Active = active ? "true" : "false",
        };
        await PostAsync<EditWebhookRequest, object>(
                "subscriptions/editWebhookSubscription/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(
        string subscriptionId,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(subscriptionId);
#else
        if (string.IsNullOrEmpty(subscriptionId))
            throw new ArgumentException("Value cannot be null or empty.", nameof(subscriptionId));
#endif

        // Key travels in the X-Api-Key header; not serialized into the request body.
        var request = new RemoveWebhookRequest { SubscriptionId = subscriptionId };
        await PostAsync<RemoveWebhookRequest, object>(
                "subscriptions/removeWebhookSubscription/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public async Task<JsonElement> ReadAsync(
        string subscriptionId,
        bool newestOnly = true,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(subscriptionId);
#else
        if (string.IsNullOrEmpty(subscriptionId))
            throw new ArgumentException("Value cannot be null or empty.", nameof(subscriptionId));
#endif

        // LEGACY EXCEPTION: the webhook read endpoint rejects header-only auth with
        // errorCode 103 ("Missing parameters: ['apiKey']") and requires apiKey as a query
        // parameter. The key is also present in the X-Api-Key header.
        var url =
            $"subscriptions/webhook?apiKey={Uri.EscapeDataString(ApiKey)}&subscriptionid={Uri.EscapeDataString(subscriptionId)}&newest_only={(newestOnly ? "true" : "false")}";
        return await GetAsync<JsonElement>(url, cancellationToken).ConfigureAwait(false);
    }
}
