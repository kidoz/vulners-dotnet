using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using VulnersDotNet.Exceptions;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Base class for all Vulners API services.
/// </summary>
public abstract class BaseApiService
{
    /// <summary>
    /// Gets the configured HTTP client.
    /// </summary>
    protected HttpClient HttpClient { get; }

    private readonly Uri _v4BaseUri;

    /// <summary>
    /// Gets the configured API key.
    /// </summary>
    protected string ApiKey { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="BaseApiService"/> class.
    /// </summary>
    /// <param name="httpClient">The configured HTTP client.</param>
    /// <param name="options">The Vulners API options.</param>
    protected BaseApiService(HttpClient httpClient, VulnersOptions options)
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        HttpClient = httpClient;
#else
        HttpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        if (options == null)
            throw new ArgumentNullException(nameof(options));
#endif
        _v4BaseUri = new Uri(options.V4BaseUrl);
        ApiKey = options.ApiKey;
    }

    private const int MaxErrorBodyLength = 2048;

    private static readonly Regex CredentialPattern = new Regex(
        "(?i)(\"?(?:api[_-]?key|x-api-key|token|secret)\"?\\s*[:=]\\s*\"?)([^\"&\\s,}]+)",
        RegexOptions.Compiled
    );

    /// <summary>
    /// Redacts credentials from an HTTP error body and truncates it before it is placed
    /// into an exception message, so API keys or sensitive request context echoed by the
    /// server (or a proxy) do not leak into application logs.
    /// </summary>
    [SuppressMessage(
        "Globalization",
        "CA1307:Specify StringComparison for clarity",
        Justification = "Ordinal replacement of an exact secret value; the StringComparison overload is unavailable on netstandard2.0."
    )]
    [SuppressMessage(
        "Performance",
        "CA1845:Use span-based 'string.Concat'",
        Justification = "Cold error path; the span-based Concat overload is unavailable on netstandard2.0."
    )]
    private string SanitizeError(string? content)
    {
        if (string.IsNullOrEmpty(content))
        {
            return string.Empty;
        }

        var sanitized = content!;

        // Redact the exact configured key wherever it appears.
        if (!string.IsNullOrEmpty(ApiKey))
        {
            sanitized = sanitized.Replace(ApiKey, "[REDACTED]");
        }

        // Redact common credential patterns (apiKey=..., "apiKey":"...", token, secret).
        sanitized = CredentialPattern.Replace(sanitized, "$1[REDACTED]");

        if (sanitized.Length > MaxErrorBodyLength)
        {
            sanitized = sanitized.Substring(0, MaxErrorBodyLength) + "… [truncated]";
        }

        return sanitized;
    }

    /// <summary>
    /// Throws a <see cref="VulnersException"/> with a redacted, truncated copy of the
    /// response body when <paramref name="response"/> does not indicate success.
    /// </summary>
    private async Task ThrowOnErrorAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken
    )
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

#if NET8_0_OR_GREATER
        var errorContent = await response
            .Content.ReadAsStringAsync(cancellationToken)
            .ConfigureAwait(false);
#else
        var errorContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#endif
        throw new VulnersException(
            $"HTTP error {(int)response.StatusCode}: {SanitizeError(errorContent)}",
            response.StatusCode
        );
    }

    /// <summary>
    /// Materializes a collection argument and validates its element count falls within the
    /// inclusive range documented by the endpoint, throwing before any network call.
    /// </summary>
    private protected static IReadOnlyList<T> ValidateCount<T>(
        IEnumerable<T> items,
        string paramName,
        int min,
        int max
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(items, paramName);
#else
        if (items is null)
            throw new ArgumentNullException(paramName);
#endif

        var list = items as IReadOnlyList<T> ?? items.ToList();
        if (list.Count < min || list.Count > max)
        {
            throw new ArgumentException(
                $"Expected between {min} and {max} items, but got {list.Count}.",
                paramName
            );
        }

        return list;
    }

    /// <summary>
    /// Validates a collection of string arguments for count, and that no item is null,
    /// empty, or longer than <paramref name="maxItemLength"/> (when non-zero).
    /// </summary>
    private protected static IReadOnlyList<string> ValidateStringItems(
        IEnumerable<string> items,
        string paramName,
        int min,
        int max,
        int maxItemLength = 0
    )
    {
        var list = ValidateCount(items, paramName, min, max);
        for (var i = 0; i < list.Count; i++)
        {
            if (string.IsNullOrEmpty(list[i]))
            {
                throw new ArgumentException(
                    $"Item at index {i} must not be null or empty.",
                    paramName
                );
            }

            if (maxItemLength > 0 && list[i].Length > maxItemLength)
            {
                throw new ArgumentException(
                    $"Item at index {i} exceeds the maximum length of {maxItemLength}.",
                    paramName
                );
            }
        }

        return list;
    }

    /// <summary>
    /// Sends a POST request and deserializes the response.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    protected async Task<TResponseData> PostAsync<TRequest, TResponseData>(
        string url,
        TRequest request,
        CancellationToken cancellationToken
    )
    {
        using var response = await HttpClient
            .PostAsJsonAsync(url, request, cancellationToken)
            .ConfigureAwait(false);

        return await ProcessResponseAsync<TResponseData>(response, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a GET request and deserializes the response.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    [SuppressMessage(
        "Usage",
        "CA2234:Pass system uri objects instead of strings",
        Justification = "HttpClient accepts strings"
    )]
    protected async Task<TResponseData> GetAsync<TResponseData>(
        string url,
        CancellationToken cancellationToken
    )
    {
        using var response = await HttpClient
            .GetAsync(url, cancellationToken)
            .ConfigureAwait(false);

        return await ProcessResponseAsync<TResponseData>(response, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a GET request and returns the response as a stream (for binary downloads).
    /// The returned stream takes ownership of the HTTP response and disposes it on close.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    [SuppressMessage(
        "Usage",
        "CA2234:Pass system uri objects instead of strings",
        Justification = "HttpClient accepts strings"
    )]
    protected async Task<Stream> GetStreamAsync(string url, CancellationToken cancellationToken)
    {
        var response = await HttpClient
            .GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            await ThrowOnErrorAsync(response, cancellationToken).ConfigureAwait(false);

#if NET8_0_OR_GREATER
            var stream = await response
                .Content.ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(false);
#else
            var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
            return new ResponseOwningStream(stream, response);
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Sends a POST request and deserializes a V4 response (result field contains data directly).
    /// The URL is resolved as a relative path against the configured V4 base URL.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    protected async Task<TResponseData> PostV4Async<TRequest, TResponseData>(
        string url,
        TRequest request,
        CancellationToken cancellationToken
    )
    {
        var absoluteUrl = new Uri(_v4BaseUri, url).ToString();
        using var response = await HttpClient
            .PostAsJsonAsync(absoluteUrl, request, cancellationToken)
            .ConfigureAwait(false);
        return await ProcessV4ResponseAsync<TResponseData>(response, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a GET request and deserializes a V4 response (result field contains data directly).
    /// The URL is resolved as a relative path against the configured V4 base URL.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    [SuppressMessage(
        "Usage",
        "CA2234:Pass system uri objects instead of strings",
        Justification = "HttpClient accepts strings"
    )]
    protected async Task<TResponseData> GetV4Async<TResponseData>(
        string url,
        CancellationToken cancellationToken
    )
    {
        var absoluteUrl = new Uri(_v4BaseUri, url).ToString();
        using var response = await HttpClient
            .GetAsync(absoluteUrl, cancellationToken)
            .ConfigureAwait(false);
        return await ProcessV4ResponseAsync<TResponseData>(response, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a PUT request and deserializes a V4 response.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    protected async Task<TResponseData> PutV4Async<TRequest, TResponseData>(
        string url,
        TRequest request,
        CancellationToken cancellationToken
    )
    {
        var absoluteUrl = new Uri(_v4BaseUri, url).ToString();
        using var response = await HttpClient
            .PutAsJsonAsync(absoluteUrl, request, cancellationToken)
            .ConfigureAwait(false);
        return await ProcessV4ResponseAsync<TResponseData>(response, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a DELETE request and deserializes a V4 response.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    [SuppressMessage(
        "Usage",
        "CA2234:Pass system uri objects instead of strings",
        Justification = "HttpClient accepts strings"
    )]
    protected async Task DeleteV4Async(string url, CancellationToken cancellationToken)
    {
        var absoluteUrl = new Uri(_v4BaseUri, url).ToString();
        using var response = await HttpClient
            .DeleteAsync(absoluteUrl, cancellationToken)
            .ConfigureAwait(false);

        await ThrowOnErrorAsync(response, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a POST request with multipart form data and deserializes a V4 response.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    [SuppressMessage(
        "Usage",
        "CA2234:Pass system uri objects instead of strings",
        Justification = "HttpClient accepts strings"
    )]
    protected async Task<TResponseData> PostV4MultipartAsync<TResponseData>(
        string url,
        HttpContent content,
        CancellationToken cancellationToken
    )
    {
        var absoluteUrl = new Uri(_v4BaseUri, url).ToString();
        using var response = await HttpClient
            .PostAsync(absoluteUrl, content, cancellationToken)
            .ConfigureAwait(false);
        return await ProcessV4ResponseAsync<TResponseData>(response, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a POST request with a raw text body and deserializes a V4 response.
    /// The URL is resolved as a relative path against the configured V4 base URL.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    [SuppressMessage(
        "Usage",
        "CA2234:Pass system uri objects instead of strings",
        Justification = "HttpClient accepts strings"
    )]
    protected async Task<TResponseData> PostV4RawAsync<TResponseData>(
        string url,
        string body,
        string mediaType,
        CancellationToken cancellationToken
    )
    {
        var absoluteUrl = new Uri(_v4BaseUri, url).ToString();
        using var content = new StringContent(body, Encoding.UTF8, mediaType);
        using var response = await HttpClient
            .PostAsync(absoluteUrl, content, cancellationToken)
            .ConfigureAwait(false);
        return await ProcessV4ResponseAsync<TResponseData>(response, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a GET request to a V4 endpoint that streams a gzip-compressed JSON array
    /// (the archive collection/family download endpoints), decompresses it, and
    /// deserializes the result. These endpoints return a bare JSON document, not the
    /// standard <c>{"result": ...}</c> envelope.
    /// The URL is resolved as a relative path against the configured V4 base URL.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "HttpClient extension methods accept strings"
    )]
    [SuppressMessage(
        "Usage",
        "CA2234:Pass system uri objects instead of strings",
        Justification = "HttpClient accepts strings"
    )]
    protected async Task<TResponseData> GetV4GzipJsonAsync<TResponseData>(
        string url,
        CancellationToken cancellationToken
    )
    {
        var absoluteUrl = new Uri(_v4BaseUri, url).ToString();
        using var response = await HttpClient
            .GetAsync(absoluteUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        await ThrowOnErrorAsync(response, cancellationToken).ConfigureAwait(false);

#if NET8_0_OR_GREATER
        var networkStream = await response
            .Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
#else
        var networkStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif

        using var _ = networkStream;
        using var gzip = new GZipStream(networkStream, CompressionMode.Decompress);
        var result = await JsonSerializer
            .DeserializeAsync<TResponseData>(gzip, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        if (result is null)
        {
            throw new VulnersException(
                "Failed to deserialize the gzip-compressed archive response."
            );
        }

        return result;
    }

    private async Task<TResponseData> ProcessV4ResponseAsync<TResponseData>(
        HttpResponseMessage response,
        CancellationToken cancellationToken
    )
    {
        await ThrowOnErrorAsync(response, cancellationToken).ConfigureAwait(false);

        var apiResponse = await response
            .Content.ReadFromJsonAsync<VulnersV4Response<TResponseData>>(
                cancellationToken: cancellationToken
            )
            .ConfigureAwait(false);

        if (apiResponse is null || apiResponse.Result is null)
        {
            throw new VulnersException(
                "Failed to deserialize the V4 API response or result was null."
            );
        }

        return apiResponse.Result;
    }

    private async Task<TResponseData> ProcessResponseAsync<TResponseData>(
        HttpResponseMessage response,
        CancellationToken cancellationToken
    )
    {
        await ThrowOnErrorAsync(response, cancellationToken).ConfigureAwait(false);

        var apiResponse = await response
            .Content.ReadFromJsonAsync<VulnersResponse<TResponseData>>(
                cancellationToken: cancellationToken
            )
            .ConfigureAwait(false);

        if (apiResponse is null)
        {
            throw new VulnersException(
                "Failed to deserialize the API response or response was empty."
            );
        }

        if (!apiResponse.IsSuccess)
        {
            throw new VulnersException(
                apiResponse.Error is null
                    ? "The API returned an error without a specific error message."
                    : SanitizeError(apiResponse.Error)
            );
        }

        if (apiResponse.Data is null)
        {
            throw new VulnersException(
                "The API request was successful, but the data payload was null."
            );
        }

        return apiResponse.Data;
    }

    /// <summary>
    /// A stream wrapper that disposes the underlying <see cref="HttpResponseMessage"/>
    /// when the stream itself is disposed.
    /// </summary>
    private sealed class ResponseOwningStream : Stream
    {
        private readonly Stream _inner;
        private readonly HttpResponseMessage _response;

        public ResponseOwningStream(Stream inner, HttpResponseMessage response)
        {
            _inner = inner;
            _response = response;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            _inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

        public override void SetLength(long value) => _inner.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) =>
            _inner.Write(buffer, offset, count);

        public override void Flush() => _inner.Flush();

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken
        ) => _inner.ReadAsync(buffer, offset, count, cancellationToken);

#if NET8_0_OR_GREATER
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default
        ) => _inner.ReadAsync(buffer, cancellationToken);
#endif

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
                _response.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
