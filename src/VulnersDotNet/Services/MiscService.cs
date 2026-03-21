using System.Diagnostics.CodeAnalysis;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the miscellaneous service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class MiscService : BaseApiService, IMiscService
{
    public MiscService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetSuggestionAsync(
        string fieldName,
        string type = "distinct",
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(fieldName);
#else
        if (string.IsNullOrEmpty(fieldName))
            throw new ArgumentException("Value cannot be null or empty.", nameof(fieldName));
#endif

        var request = new SuggestionRequest { FieldName = fieldName, Type = type };
        var response = await PostAsync<SuggestionRequest, SuggestionResponseData>(
                "search/suggest/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
        return response.Suggest;
    }

}
