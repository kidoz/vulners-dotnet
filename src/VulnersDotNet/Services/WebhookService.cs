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
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public async Task<IReadOnlyList<JsonElement>> ListAsync(
        CancellationToken cancellationToken = default
    )
    {
        var url = $"subscriptions/listWebhookSubscriptions/?apiKey={Uri.EscapeDataString(ApiKey)}";
        var response = await GetAsync<WebhookListResponseData>(url, cancellationToken)
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

        var request = new EditWebhookRequest
        {
            ApiKey = ApiKey,
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

        var request = new RemoveWebhookRequest { ApiKey = ApiKey, SubscriptionId = subscriptionId };
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

        var url =
            $"subscriptions/webhook?apiKey={Uri.EscapeDataString(ApiKey)}&subscriptionid={Uri.EscapeDataString(subscriptionId)}&newest_only={(newestOnly ? "true" : "false")}";
        return await GetAsync<JsonElement>(url, cancellationToken).ConfigureAwait(false);
    }
}
