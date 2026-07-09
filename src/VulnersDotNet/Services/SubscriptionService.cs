using System.Diagnostics.CodeAnalysis;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the email subscription service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class SubscriptionService : BaseApiService, ISubscriptionService
{
    public SubscriptionService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    public async Task<IReadOnlyList<EmailSubscription>> ListAsync(
        CancellationToken cancellationToken = default
    )
    {
        var url = $"subscriptions/listEmailSubscriptions/?apiKey={Uri.EscapeDataString(ApiKey)}";
        var response = await GetAsync<SubscriptionListResponseData>(url, cancellationToken)
            .ConfigureAwait(false);
        return response.Subscriptions;
    }

    /// <inheritdoc />
    public async Task AddAsync(
        string query,
        string email,
        string? format = null,
        string? crontab = null,
        string? queryType = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(query);
        ArgumentException.ThrowIfNullOrEmpty(email);
#else
        if (string.IsNullOrEmpty(query))
            throw new ArgumentException("Value cannot be null or empty.", nameof(query));
        if (string.IsNullOrEmpty(email))
            throw new ArgumentException("Value cannot be null or empty.", nameof(email));
#endif

        var request = new AddEmailSubscriptionRequest
        {
            ApiKey = ApiKey,
            Query = query,
            Email = email,
            Format = format,
            Crontab = crontab,
            QueryType = queryType,
        };

        await PostAsync<AddEmailSubscriptionRequest, object>(
                "subscriptions/addEmailSubscription/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task EditAsync(
        string subscriptionId,
        string? format = null,
        string? crontab = null,
        string? active = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(subscriptionId);
#else
        if (string.IsNullOrEmpty(subscriptionId))
            throw new ArgumentException("Value cannot be null or empty.", nameof(subscriptionId));
#endif

        var request = new EditEmailSubscriptionRequest
        {
            ApiKey = ApiKey,
            SubscriptionId = subscriptionId,
            Format = format,
            Crontab = crontab,
            Active = active,
        };

        await PostAsync<EditEmailSubscriptionRequest, object>(
                "subscriptions/editEmailSubscription/",
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

        var request = new RemoveEmailSubscriptionRequest
        {
            ApiKey = ApiKey,
            SubscriptionId = subscriptionId,
        };

        await PostAsync<RemoveEmailSubscriptionRequest, object>(
                "subscriptions/removeEmailSubscription/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }
}
