using VulnersDotNet.Services;

namespace VulnersDotNet;

/// <summary>
/// Defines the main entry point for the Vulners API client.
/// </summary>
public interface IVulnersClient
{
    /// <summary>
    /// Gets the search service.
    /// </summary>
    ISearchService Search { get; }

    /// <summary>
    /// Gets the audit service.
    /// </summary>
    IAuditService Audit { get; }

    /// <summary>
    /// Gets the archive/collection service.
    /// </summary>
    IArchiveService Archive { get; }

    /// <summary>
    /// Gets the email subscription service (V3, deprecated).
    /// </summary>
    ISubscriptionService Subscription { get; }

    /// <summary>
    /// Gets the miscellaneous service (suggestions, AI scoring).
    /// </summary>
    IMiscService Misc { get; }

    /// <summary>
    /// Gets the webhook subscription service.
    /// </summary>
    IWebhookService Webhook { get; }

    /// <summary>
    /// Gets the V4 subscription service.
    /// </summary>
    ISubscriptionV4Service SubscriptionV4 { get; }

    /// <summary>
    /// Gets the report service.
    /// </summary>
    IReportService Report { get; }

    /// <summary>
    /// Gets the STIX service.
    /// </summary>
    IStixService Stix { get; }
}
