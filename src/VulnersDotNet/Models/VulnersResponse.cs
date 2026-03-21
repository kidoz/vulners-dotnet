using System.Text.Json.Serialization;

namespace VulnersDotNet.Models;

/// <summary>
/// Represents a standard response from the Vulners API.
/// </summary>
/// <typeparam name="T">The type of the data payload.</typeparam>
public record VulnersResponse<T>
{
    /// <summary>
    /// Gets the result status (e.g., "OK", "ERROR").
    /// </summary>
    [JsonPropertyName("result")]
    public string Result { get; init; } = string.Empty;

    /// <summary>
    /// Gets the actual data payload.
    /// </summary>
    [JsonPropertyName("data")]
    public T? Data { get; init; }

    /// <summary>
    /// Gets the error message, if any.
    /// </summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }

    /// <summary>
    /// Gets a value indicating whether the request was successful.
    /// </summary>
    [JsonIgnore]
    public bool IsSuccess => string.Equals(Result, "OK", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Represents a V4 API response where the result field contains the actual data directly.
/// </summary>
/// <typeparam name="T">The type of the result payload.</typeparam>
public record VulnersV4Response<T>
{
    /// <summary>
    /// Gets the result payload.
    /// </summary>
    [JsonPropertyName("result")]
    public T? Result { get; init; }
}
