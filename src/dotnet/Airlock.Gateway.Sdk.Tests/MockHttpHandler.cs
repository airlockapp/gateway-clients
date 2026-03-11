using System.Net;
using System.Text;
using System.Text.Json;

namespace Airlock.Gateway.Sdk.Tests;

/// <summary>
/// A mock HttpMessageHandler that returns pre-configured responses.
/// Used to test AirlockGatewayClient without making real HTTP calls.
/// </summary>
public class MockHttpHandler : HttpMessageHandler
{
    private readonly Queue<MockResponse> _responses = new();

    /// <summary>
    /// Enqueue a response to be returned by the next HTTP call.
    /// </summary>
    public void Enqueue(HttpStatusCode statusCode, object? body = null)
    {
        var json = body is string s ? s : (body != null ? JsonSerializer.Serialize(body, JsonOpts) : "");
        _responses.Enqueue(new MockResponse(statusCode, json));
    }

    /// <summary>
    /// Enqueue a raw string response.
    /// </summary>
    public void EnqueueRaw(HttpStatusCode statusCode, string body)
    {
        _responses.Enqueue(new MockResponse(statusCode, body));
    }

    /// <summary>
    /// All captured requests in order.
    /// </summary>
    public List<CapturedRequest> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var bodyContent = request.Content != null
            ? await request.Content.ReadAsStringAsync()
            : null;

        Requests.Add(new CapturedRequest(
            request.Method,
            request.RequestUri!,
            bodyContent,
            request.Headers.Authorization?.ToString()));

        if (_responses.Count == 0)
            throw new InvalidOperationException(
                $"MockHttpHandler: No response enqueued for {request.Method} {request.RequestUri}");

        var mock = _responses.Dequeue();
        return new HttpResponseMessage(mock.StatusCode)
        {
            Content = new StringContent(mock.Body, Encoding.UTF8, "application/json")
        };
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public record MockResponse(HttpStatusCode StatusCode, string Body);
    public record CapturedRequest(HttpMethod Method, Uri Uri, string? Body, string? Authorization);
}
