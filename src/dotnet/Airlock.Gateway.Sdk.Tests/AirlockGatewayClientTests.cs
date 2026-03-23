using System.Net;
using Airlock.Gateway.Sdk.Crypto;
using Airlock.Gateway.Sdk.Models;
using Xunit;

namespace Airlock.Gateway.Sdk.Tests;

public class AirlockGatewayClientTests
{
    private static (AirlockGatewayClient client, MockHttpHandler handler) CreateClient()
    {
        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://gw.test") };
        return (new AirlockGatewayClient(httpClient), handler);
    }

    private static (AirlockGatewayClient client, MockHttpHandler handler) CreateClientWithCredentials()
    {
        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://gw.test") };
        httpClient.DefaultRequestHeaders.Add("X-Client-Id", "test-id");
        httpClient.DefaultRequestHeaders.Add("X-Client-Secret", "test-secret");
        return (new AirlockGatewayClient(httpClient), handler);
    }


    // ── Echo ─────────────────────────────────────────────────────

    [Fact]
    public async Task EchoAsync_ReturnsServerTime()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new
        {
            utc = "2025-01-01T00:00:00Z",
            local = "2025-01-01T03:00:00+03:00",
            timezone = "Europe/Istanbul",
            offsetMinutes = 180
        });

        var result = await client.EchoAsync();

        Assert.Equal("2025-01-01T00:00:00Z", result.Utc);
        Assert.Equal("Europe/Istanbul", result.Timezone);
        Assert.Equal(180, result.OffsetMinutes);
        Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal("/echo", handler.Requests[0].Uri.AbsolutePath);
    }

    // ── SubmitArtifact ───────────────────────────────────────────

    [Fact]
    public async Task SubmitArtifactAsync_PostsEnvelopeAndReturnsRequestId()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.Accepted, new
        {
            msgType = "artifact.accepted",
            requestId = "req-test123"
        });

        var requestId = await client.SubmitArtifactAsync(new ArtifactSubmitRequest
        {
            EnforcerId = "enforcer-1",
            ArtifactType = "command-approval",
            ArtifactHash = "abc123",
            Ciphertext = new EncryptedPayload
            {
                Alg = "aes-256-gcm",
                Data = "encrypted-data",
                Nonce = "nonce-1",
                Tag = "tag-1"
            },
            RequestId = "req-test123",
            Metadata = new() { ["routingToken"] = "rt-abc" }
        });

        Assert.Equal("req-test123", requestId);
        Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("/v1/artifacts", handler.Requests[0].Uri.AbsolutePath);
        Assert.Contains("artifact.submit", handler.Requests[0].Body);
        Assert.Contains("enforcer-1", handler.Requests[0].Body);
        Assert.Contains("routingToken", handler.Requests[0].Body);
    }

    [Fact]
    public async Task EncryptAndSubmitArtifactAsync_PostsCanonicalHashAndAesGcmCiphertext()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.Accepted, new { msgType = "artifact.accepted" });

        var keyBytes = new byte[32];
        Array.Fill(keyBytes, (byte)7);
        var keyB64 = CryptoHelpers.ToBase64Url(keyBytes);

        var requestId = await client.EncryptAndSubmitArtifactAsync(new EncryptedArtifactRequest
        {
            EnforcerId = "e1",
            PlaintextPayload = """{"value":42,"action":"test"}""",
            EncryptionKeyBase64Url = keyB64,
            RequestId = "req-enc",
        });

        Assert.Equal("req-enc", requestId);
        Assert.Single(handler.Requests);
        Assert.Contains(
            "d3c2d7effb479ffc5085aad2144df886a452a4863396060f4e0ea29a8409d0fd",
            handler.Requests[0].Body);
        Assert.Contains("AES-256-GCM", handler.Requests[0].Body);
    }

    [Fact]
    public async Task SubmitArtifactAsync_GeneratesRequestIdWhenNotProvided()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.Accepted, new { msgType = "artifact.accepted" });

        var requestId = await client.SubmitArtifactAsync(new ArtifactSubmitRequest
        {
            EnforcerId = "e1",
            ArtifactHash = "h1",
            Ciphertext = new EncryptedPayload { Alg = "aes-256-gcm", Data = "d" }
        });

        Assert.StartsWith("req-", requestId);
    }

    [Fact]
    public async Task SubmitArtifactAsync_ThrowsOnNoApprover()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.UnprocessableEntity, new
        {
            msgType = "error",
            body = new { code = "no_approver", message = "No approver available." }
        });

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.SubmitArtifactAsync(new ArtifactSubmitRequest
            {
                EnforcerId = "e1",
                ArtifactHash = "h1",
                Ciphertext = new EncryptedPayload { Alg = "aes-256-gcm", Data = "d" }
            }));

        Assert.Equal("no_approver", ex.ErrorCode);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, ex.StatusCode);
    }

    [Fact]
    public async Task SubmitArtifactAsync_ThrowsOnPairingRevoked()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.Forbidden, new
        {
            msgType = "error",
            body = new { code = "pairing_revoked", message = "The pairing has been revoked." }
        });

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.SubmitArtifactAsync(new ArtifactSubmitRequest
            {
                EnforcerId = "e1",
                ArtifactHash = "h1",
                Ciphertext = new EncryptedPayload { Alg = "aes-256-gcm", Data = "d" }
            }));

        Assert.True(ex.IsPairingRevoked);
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
    }

    [Fact]
    public async Task SubmitArtifactAsync_ThrowsOnQuotaExceeded()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue((HttpStatusCode)429, new
        {
            msgType = "error",
            body = new { code = "quota_exceeded", message = "Monthly approval quota exceeded (100/100)" }
        });

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.SubmitArtifactAsync(new ArtifactSubmitRequest
            {
                EnforcerId = "e1",
                ArtifactHash = "h1",
                Ciphertext = new EncryptedPayload { Alg = "aes-256-gcm", Data = "d" }
            }));

        Assert.True(ex.IsQuotaExceeded);
    }

    [Fact]
    public async Task SubmitArtifactAsync_ThrowsOnConflict()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.Conflict, new
        {
            msgType = "error",
            body = new { code = "AlreadyExistsConflict", message = "requestId used with different artifactHash" }
        });

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.SubmitArtifactAsync(new ArtifactSubmitRequest
            {
                EnforcerId = "e1",
                ArtifactHash = "h2",
                RequestId = "req-dup",
                Ciphertext = new EncryptedPayload { Alg = "aes-256-gcm", Data = "d" }
            }));

        Assert.True(ex.IsConflict);
    }

    // ── GetExchangeStatus ───────────────────────────────────────

    [Fact]
    public async Task GetExchangeStatusAsync_ReturnsStatus()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new
        {
            msgType = "exchange.status",
            requestId = "req-1",
            body = new
            {
                requestId = "req-1",
                state = "PendingApproval",
                artifactHash = "abc123"
            }
        });

        var result = await client.GetExchangeStatusAsync("req-1");

        Assert.Equal("exchange.status", result.MsgType);
        Assert.Equal("req-1", result.RequestId);
        Assert.Equal("PendingApproval", result.Body?.State);
    }

    [Fact]
    public async Task GetExchangeStatusAsync_ThrowsOnNotFound()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.NotFound, new
        {
            msgType = "error",
            body = new { code = "NotFound", message = "Exchange not found" }
        });

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.GetExchangeStatusAsync("req-nonexistent"));

        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
        Assert.Equal("NotFound", ex.ErrorCode);
    }

    // ── WaitForDecision ─────────────────────────────────────────

    [Fact]
    public async Task WaitForDecisionAsync_ReturnsDecision()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new
        {
            msgId = "msg-1",
            msgType = "decision.deliver",
            requestId = "req-1",
            body = new
            {
                artifactHash = "abc123",
                decision = "approve",
                reason = "Looks good",
                signerKeyId = "key-1",
                nonce = "n1",
                signature = "sig1"
            }
        });

        var result = await client.WaitForDecisionAsync("req-1", 30);

        Assert.NotNull(result);
        Assert.Equal("decision.deliver", result!.MsgType);
        Assert.Equal("approve", result.Body?.Decision);
        Assert.Equal("Looks good", result.Body?.Reason);
        Assert.True(result.Body?.IsApproved);
        Assert.False(result.Body?.IsRejected);
    }

    [Fact]
    public async Task WaitForDecisionAsync_ReturnsNullOn204()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.NoContent);

        var result = await client.WaitForDecisionAsync("req-1", 5);

        Assert.Null(result);
    }

    [Fact]
    public async Task WaitForDecisionAsync_ClampsTimeout()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.NoContent);

        await client.WaitForDecisionAsync("req-1", 200);

        Assert.Contains("timeout=60", handler.Requests[0].Uri.Query);
    }

    // ── WithdrawExchange ────────────────────────────────────────

    [Fact]
    public async Task WithdrawExchangeAsync_PostsToCorrectPath()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new { msgType = "exchange.withdrawn" });

        await client.WithdrawExchangeAsync("req-1");

        Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("/v1/exchanges/req-1/withdraw", handler.Requests[0].Uri.AbsolutePath);
    }

    [Fact]
    public async Task WithdrawExchangeAsync_ThrowsOnConflict()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.Conflict, new
        {
            msgType = "error",
            body = new { code = "already_resolved", message = "Exchange is already in state 'Decided'" }
        });

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.WithdrawExchangeAsync("req-1"));

        Assert.True(ex.IsConflict);
    }

    // ── Pairing ─────────────────────────────────────────────────

    [Fact]
    public async Task InitiatePairingAsync_ReturnsNonceAndCode()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.Created, new
        {
            pairingNonce = "nonce-abc",
            pairingCode = "ABC123",
            deviceId = "dev-1",
            expiresAt = "2025-01-01T00:05:00Z"
        });

        var result = await client.InitiatePairingAsync(new PairingInitiateRequest
        {
            DeviceId = "dev-1",
            EnforcerId = "enforcer-1",
            X25519PublicKey = "pubkey-base64"
        });

        Assert.Equal("nonce-abc", result.PairingNonce);
        Assert.Equal("ABC123", result.PairingCode);
        Assert.Equal("/v1/pairing/initiate", handler.Requests[0].Uri.AbsolutePath);
    }

    [Fact]
    public async Task GetPairingStatusAsync_ReturnsState()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new
        {
            pairingNonce = "nonce-abc",
            state = "Completed",
            routingToken = "rt-xyz"
        });

        var result = await client.GetPairingStatusAsync("nonce-abc");

        Assert.Equal("Completed", result.State);
        Assert.Equal("rt-xyz", result.RoutingToken);
    }

    [Fact]
    public async Task RevokePairingAsync_PostsRequest()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new
        {
            status = "revoked",
            enforcerId = "enforcer-1"
        });

        var result = await client.RevokePairingAsync("rt-xyz");

        Assert.Equal("revoked", result.Status);
        Assert.Equal("enforcer-1", result.EnforcerId);
        Assert.Equal("/v1/pairing/revoke", handler.Requests[0].Uri.AbsolutePath);
    }

    // ── Presence ────────────────────────────────────────────────

    [Fact]
    public async Task SendHeartbeatAsync_PostsCorrectBody()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new { status = "ok" });

        await client.SendHeartbeatAsync(new PresenceHeartbeatRequest
        {
            EnforcerId = "enforcer-1",
            WorkspaceName = "my-project",
            EnforcerLabel = "Cursor"
        });

        Assert.Single(handler.Requests);
        Assert.Equal("/v1/presence/heartbeat", handler.Requests[0].Uri.AbsolutePath);
        Assert.Contains("enforcer-1", handler.Requests[0].Body);
    }

    // ── DND Policies ────────────────────────────────────────────

    [Fact]
    public async Task GetEffectiveDndPoliciesAsync_ReturnsPolicies()
    {
        var (client, handler) = CreateClient();
        handler.Enqueue(HttpStatusCode.OK, new
        {
            msgType = "dnd.policy.effective",
            requestId = "dnd-effective-1",
            body = new[]
            {
                new
                {
                    requestId = "p1",
                    objectType = "airlock.dnd.workspace",
                    workspaceId = "ws-1",
                    enforcerId = "enf-1",
                    policyMode = "approve_all",
                    expiresAt = "2099-01-01T00:00:00Z"
                }
            }
        });

        var resp = await client.GetEffectiveDndPoliciesAsync("enf-1", "ws-1");

        Assert.Equal("dnd.policy.effective", resp.MsgType);
        Assert.Single(resp.Body);
        Assert.Equal("approve_all", resp.Body[0].PolicyMode);
    }

    // ── ClientId/Secret Auth ────────────────────────────────────

    [Fact]
    public async Task ClientWithCredentials_SetsClientIdAndSecretHeaders()
    {
        var (client, handler) = CreateClientWithCredentials();
        handler.Enqueue(HttpStatusCode.OK, new
        {
            utc = "2025-01-01T00:00:00Z",
            local = "2025-01-01T03:00:00+03:00",
            timezone = "UTC",
            offsetMinutes = 0
        });

        await client.EchoAsync();

        Assert.Single(handler.Requests);
        var req = handler.Requests[0];
        Assert.True(req.Headers.ContainsKey("X-Client-Id"), "X-Client-Id header missing");
        Assert.Equal("test-id", req.Headers["X-Client-Id"]);
        Assert.True(req.Headers.ContainsKey("X-Client-Secret"), "X-Client-Secret header missing");
        Assert.Equal("test-secret", req.Headers["X-Client-Secret"]);
    }

    // ── Error handling edge cases ───────────────────────────────

    [Fact]
    public async Task ThrowsOnNonJsonErrorBody()
    {
        var (client, handler) = CreateClient();
        handler.EnqueueRaw(HttpStatusCode.InternalServerError, "Internal Server Error");

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.EchoAsync());

        Assert.Equal(HttpStatusCode.InternalServerError, ex.StatusCode);
        Assert.Contains("Internal Server Error", ex.ResponseBody);
    }

    [Fact]
    public async Task ThrowsOnUnauthorized()
    {
        var (client, handler) = CreateClient();
        handler.EnqueueRaw(HttpStatusCode.Unauthorized, "");

        var ex = await Assert.ThrowsAsync<AirlockGatewayException>(() =>
            client.EchoAsync());

        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
    }
}
