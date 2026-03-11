using System.Net;
using Xunit;

namespace Airlock.Gateway.Sdk.Tests;

/// <summary>
/// Tests for AirlockGatewayException error classification.
/// </summary>
public class ErrorHandlingTests
{
    [Fact]
    public void IsQuotaExceeded_TrueFor429()
    {
        var ex = new AirlockGatewayException("Quota", (HttpStatusCode)429);
        Assert.True(ex.IsQuotaExceeded);
    }

    [Fact]
    public void IsQuotaExceeded_TrueForQuotaExceededCode()
    {
        var ex = new AirlockGatewayException("Quota", HttpStatusCode.OK, "quota_exceeded");
        Assert.True(ex.IsQuotaExceeded);
    }

    [Fact]
    public void IsQuotaExceeded_TrueForWorkspaceLimitExceeded()
    {
        var ex = new AirlockGatewayException("Quota", HttpStatusCode.OK, "workspace_limit_exceeded");
        Assert.True(ex.IsQuotaExceeded);
    }

    [Fact]
    public void IsQuotaExceeded_FalseForOtherErrors()
    {
        var ex = new AirlockGatewayException("Other", HttpStatusCode.BadRequest, "bad_request");
        Assert.False(ex.IsQuotaExceeded);
    }

    [Fact]
    public void IsPairingRevoked_TrueForPairingRevokedCode()
    {
        var ex = new AirlockGatewayException("Revoked", HttpStatusCode.Forbidden, "pairing_revoked");
        Assert.True(ex.IsPairingRevoked);
    }

    [Fact]
    public void IsPairingRevoked_FalseForOtherForbidden()
    {
        var ex = new AirlockGatewayException("Forbidden", HttpStatusCode.Forbidden, "access_denied");
        Assert.False(ex.IsPairingRevoked);
    }

    [Fact]
    public void IsExpired_TrueFor410()
    {
        var ex = new AirlockGatewayException("Gone", HttpStatusCode.Gone);
        Assert.True(ex.IsExpired);
    }

    [Fact]
    public void IsExpired_TrueForExpiredCode()
    {
        var ex = new AirlockGatewayException("Expired", HttpStatusCode.UnprocessableEntity, "expired");
        Assert.True(ex.IsExpired);
    }

    [Fact]
    public void IsConflict_TrueFor409()
    {
        var ex = new AirlockGatewayException("Conflict", HttpStatusCode.Conflict);
        Assert.True(ex.IsConflict);
    }

    [Fact]
    public void ExceptionPreservesAllFields()
    {
        var ex = new AirlockGatewayException(
            "Test message",
            HttpStatusCode.UnprocessableEntity,
            errorCode: "test_code",
            responseBody: "{\"error\":true}",
            requestId: "req-123");

        Assert.Equal("Test message", ex.Message);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, ex.StatusCode);
        Assert.Equal("test_code", ex.ErrorCode);
        Assert.Equal("{\"error\":true}", ex.ResponseBody);
        Assert.Equal("req-123", ex.RequestId);
    }

    [Fact]
    public void ExceptionWithInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new AirlockGatewayException("outer", inner);

        Assert.Equal("outer", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }
}
