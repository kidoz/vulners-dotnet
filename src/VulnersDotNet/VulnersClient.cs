using System.Diagnostics.CodeAnalysis;
using VulnersDotNet.Services;

namespace VulnersDotNet;

/// <summary>
/// The main client for interacting with the Vulners API.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class VulnersClient : IVulnersClient
{
    /// <summary>
    /// Initializes a new instance of the <see cref="VulnersClient"/> class.
    /// </summary>
    public VulnersClient(
        ISearchService search,
        IAuditService audit,
        IArchiveService archive,
        ISubscriptionService subscription,
        IMiscService misc,
        IWebhookService webhook,
        ISubscriptionV4Service subscriptionV4,
        IReportService report,
        IStixService stix
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(search);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(subscription);
        ArgumentNullException.ThrowIfNull(misc);
        ArgumentNullException.ThrowIfNull(webhook);
        ArgumentNullException.ThrowIfNull(subscriptionV4);
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(stix);
        Search = search;
        Audit = audit;
        Archive = archive;
        Subscription = subscription;
        Misc = misc;
        Webhook = webhook;
        SubscriptionV4 = subscriptionV4;
        Report = report;
        Stix = stix;
#else
        Search = search ?? throw new ArgumentNullException(nameof(search));
        Audit = audit ?? throw new ArgumentNullException(nameof(audit));
        Archive = archive ?? throw new ArgumentNullException(nameof(archive));
        Subscription = subscription ?? throw new ArgumentNullException(nameof(subscription));
        Misc = misc ?? throw new ArgumentNullException(nameof(misc));
        Webhook = webhook ?? throw new ArgumentNullException(nameof(webhook));
        SubscriptionV4 = subscriptionV4 ?? throw new ArgumentNullException(nameof(subscriptionV4));
        Report = report ?? throw new ArgumentNullException(nameof(report));
        Stix = stix ?? throw new ArgumentNullException(nameof(stix));
#endif
    }

    /// <inheritdoc />
    public ISearchService Search { get; }

    /// <inheritdoc />
    public IAuditService Audit { get; }

    /// <inheritdoc />
    public IArchiveService Archive { get; }

    /// <inheritdoc />
    public ISubscriptionService Subscription { get; }

    /// <inheritdoc />
    public IMiscService Misc { get; }

    /// <inheritdoc />
    public IWebhookService Webhook { get; }

    /// <inheritdoc />
    public ISubscriptionV4Service SubscriptionV4 { get; }

    /// <inheritdoc />
    public IReportService Report { get; }

    /// <inheritdoc />
    public IStixService Stix { get; }
}
