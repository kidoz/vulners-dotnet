using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the report service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class ReportService : BaseApiService, IReportService
{
    public ReportService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    public Task<JsonElement> GetVulnsSummaryAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    )
    {
        return GetReportAsync("vulnssummary", limit, offset, filter, sort, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> GetVulnsListAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    )
    {
        return GetReportAsync("vulnslist", limit, offset, filter, sort, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> GetIpSummaryAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    )
    {
        return GetReportAsync("ipsummary", limit, offset, filter, sort, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> GetScanListAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    )
    {
        return GetReportAsync("scanlist", limit, offset, filter, sort, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> GetHostVulnsAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    )
    {
        return GetReportAsync("hostvulns", limit, offset, filter, sort, cancellationToken);
    }

    private async Task<JsonElement> GetReportAsync(
        string reportType,
        int limit,
        int offset,
        Dictionary<string, object>? filter,
        string sort,
        CancellationToken cancellationToken
    )
    {
        var request = new ReportRequest
        {
            ReportType = reportType,
            Skip = offset,
            Size = limit,
            Filter = filter ?? new Dictionary<string, object>(),
            Sort = sort,
        };

        var response = await PostAsync<ReportRequest, ReportResponseData>(
                "reports/vulnsreport",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);

        return response.Report;
    }
}
