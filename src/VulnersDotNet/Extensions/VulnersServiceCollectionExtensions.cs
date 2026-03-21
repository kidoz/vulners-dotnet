using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using VulnersDotNet.Services;

namespace VulnersDotNet.Extensions;

/// <summary>
/// Extension methods for configuring the Vulners API client in an <see cref="IServiceCollection"/>.
/// </summary>
public static class VulnersServiceCollectionExtensions
{
    /// <summary>
    /// Adds the Vulners API client and its dependencies to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">An action to configure the <see cref="VulnersOptions"/>.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddVulners(
        this IServiceCollection services,
        Action<VulnersOptions> configureOptions
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);
#else
        if (services == null)
            throw new ArgumentNullException(nameof(services));
        if (configureOptions == null)
            throw new ArgumentNullException(nameof(configureOptions));
#endif

        var options = new VulnersOptions();
        configureOptions(options);
        options.Validate();

        // Replace any pre-existing registration so HttpClient and services share the same instance
        services.RemoveAll<VulnersOptions>();
        services.AddSingleton(options);

        services.AddHttpClient<ISearchService, SearchService>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<IAuditService, AuditService>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<IArchiveService, ArchiveService>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<ISubscriptionService, SubscriptionService>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<IMiscService, MiscService>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<IWebhookService, WebhookService>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<ISubscriptionV4Service, SubscriptionV4Service>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<IReportService, ReportService>(client =>
            ConfigureHttpClient(client, options)
        );
        services.AddHttpClient<IStixService, StixService>(client =>
            ConfigureHttpClient(client, options)
        );

        services.TryAddTransient<IVulnersClient, VulnersClient>();

        return services;
    }

    private static void ConfigureHttpClient(HttpClient client, VulnersOptions options)
    {
        client.BaseAddress = new Uri(options.BaseUrl);
        client.Timeout = options.Timeout;
        client.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"VulnersDotNet/{typeof(VulnersServiceCollectionExtensions).Assembly.GetName().Version}"
        );

        if (!string.IsNullOrWhiteSpace(options.ApiKey))
        {
            client.DefaultRequestHeaders.Add("X-Api-Key", options.ApiKey);
        }
    }
}
