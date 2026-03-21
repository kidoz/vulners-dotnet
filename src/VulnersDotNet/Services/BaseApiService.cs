using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Json;
using System.Text.Json;
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
            if (!response.IsSuccessStatusCode)
            {
#if NET8_0_OR_GREATER
                var errorContent = await response
                    .Content.ReadAsStringAsync(cancellationToken)
                    .ConfigureAwait(false);
#else
                var errorContent = await response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false);
#endif
                throw new VulnersException(
                    $"HTTP error {(int)response.StatusCode}: {errorContent}",
                    response.StatusCode
                );
            }

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

        if (!response.IsSuccessStatusCode)
        {
#if NET8_0_OR_GREATER
            var errorContent = await response
                .Content.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);
#else
            var errorContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#endif
            throw new VulnersException(
                $"HTTP error {(int)response.StatusCode}: {errorContent}",
                response.StatusCode
            );
        }
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

    private static async Task<TResponseData> ProcessV4ResponseAsync<TResponseData>(
        HttpResponseMessage response,
        CancellationToken cancellationToken
    )
    {
        if (!response.IsSuccessStatusCode)
        {
#if NET8_0_OR_GREATER
            var errorContent = await response
                .Content.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);
#else
            var errorContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#endif
            throw new VulnersException(
                $"HTTP error {(int)response.StatusCode}: {errorContent}",
                response.StatusCode
            );
        }

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

    private static async Task<TResponseData> ProcessResponseAsync<TResponseData>(
        HttpResponseMessage response,
        CancellationToken cancellationToken
    )
    {
        if (!response.IsSuccessStatusCode)
        {
#if NET8_0_OR_GREATER
            var errorContent = await response
                .Content.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);
#else
            var errorContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#endif
            throw new VulnersException(
                $"HTTP error {(int)response.StatusCode}: {errorContent}",
                response.StatusCode
            );
        }

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
                apiResponse.Error ?? "The API returned an error without a specific error message."
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

        public override long Seek(long offset, SeekOrigin origin) =>
            _inner.Seek(offset, origin);

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
