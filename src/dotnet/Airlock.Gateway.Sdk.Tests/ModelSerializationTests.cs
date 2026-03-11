using System.Text.Json;
using Airlock.Gateway.Sdk.Models;
using Xunit;

namespace Airlock.Gateway.Sdk.Tests;

/// <summary>
/// Tests for JSON serialization round-trips of all model classes.
/// </summary>
public class ModelSerializationTests
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    [Fact]
    public void HarpEnvelope_RoundTrips()
    {
        var envelope = new HarpEnvelope
        {
            MsgId = "msg-1",
            MsgType = "artifact.submit",
            RequestId = "req-1",
            CreatedAt = DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
            Sender = new SenderInfo { EnforcerId = "e1" },
            Recipient = new RecipientInfo { ApproverId = "a1" }
        };

        var json = JsonSerializer.Serialize(envelope, Opts);
        var deserialized = JsonSerializer.Deserialize<HarpEnvelope>(json, Opts)!;

        Assert.Equal("msg-1", deserialized.MsgId);
        Assert.Equal("artifact.submit", deserialized.MsgType);
        Assert.Equal("req-1", deserialized.RequestId);
        Assert.Equal("e1", deserialized.Sender?.EnforcerId);
        Assert.Equal("a1", deserialized.Recipient?.ApproverId);
    }

    [Fact]
    public void ArtifactSubmitBody_SerializesAllFields()
    {
        var body = new ArtifactSubmitBody
        {
            ArtifactType = "command-approval",
            ArtifactHash = "hash123",
            Ciphertext = new CiphertextRef
            {
                Alg = "aes-256-gcm",
                Data = "encrypted",
                Nonce = "n1",
                Tag = "t1",
                Aad = "aad1"
            },
            ExpiresAt = DateTimeOffset.Parse("2025-01-01T00:10:00Z"),
            Metadata = new() { ["routingToken"] = "rt-1", ["workspaceName"] = "proj" }
        };

        var json = JsonSerializer.Serialize(body, Opts);
        var deserialized = JsonSerializer.Deserialize<ArtifactSubmitBody>(json, Opts)!;

        Assert.Equal("command-approval", deserialized.ArtifactType);
        Assert.Equal("hash123", deserialized.ArtifactHash);
        Assert.Equal("aes-256-gcm", deserialized.Ciphertext.Alg);
        Assert.Equal("encrypted", deserialized.Ciphertext.Data);
        Assert.Equal("n1", deserialized.Ciphertext.Nonce);
        Assert.Equal("t1", deserialized.Ciphertext.Tag);
        Assert.Equal("aad1", deserialized.Ciphertext.Aad);
        Assert.Equal("rt-1", deserialized.Metadata?["routingToken"]);
    }

    [Fact]
    public void ArtifactSubmitBody_NullableMetadata()
    {
        var body = new ArtifactSubmitBody
        {
            ArtifactType = "command-approval",
            ArtifactHash = "hash123",
            Ciphertext = new CiphertextRef { Alg = "aes-256-gcm", Data = "d" }
        };

        var json = JsonSerializer.Serialize(body, Opts);
        var deserialized = JsonSerializer.Deserialize<ArtifactSubmitBody>(json, Opts)!;

        Assert.Null(deserialized.Metadata);
    }

    [Fact]
    public void DecisionDeliverBody_HelperProperties()
    {
        var approve = new DecisionDeliverBody { Decision = "approve" };
        Assert.True(approve.IsApproved);
        Assert.False(approve.IsRejected);

        var reject = new DecisionDeliverBody { Decision = "reject" };
        Assert.False(reject.IsApproved);
        Assert.True(reject.IsRejected);

        // Case-insensitive
        var upper = new DecisionDeliverBody { Decision = "APPROVE" };
        Assert.True(upper.IsApproved);
    }

    [Fact]
    public void DecisionDeliverBody_RoundTrips()
    {
        var body = new DecisionDeliverBody
        {
            ArtifactHash = "hash1",
            Decision = "approve",
            Reason = "Looks safe",
            SignerKeyId = "key-1",
            Nonce = "n1",
            Signature = "sig1",
            DecisionHash = "dh1"
        };

        var json = JsonSerializer.Serialize(body, Opts);
        var deserialized = JsonSerializer.Deserialize<DecisionDeliverBody>(json, Opts)!;

        Assert.Equal("hash1", deserialized.ArtifactHash);
        Assert.Equal("approve", deserialized.Decision);
        Assert.Equal("Looks safe", deserialized.Reason);
        Assert.Equal("key-1", deserialized.SignerKeyId);
        Assert.Equal("sig1", deserialized.Signature);
    }

    [Fact]
    public void PairingInitiateRequest_RoundTrips()
    {
        var request = new PairingInitiateRequest
        {
            DeviceId = "dev-1",
            EnforcerId = "e-1",
            GatewayUrl = "https://gw.test",
            X25519PublicKey = "pubkey",
            EnforcerLabel = "Cursor",
            WorkspaceName = "my-project"
        };

        var json = JsonSerializer.Serialize(request, Opts);
        var deserialized = JsonSerializer.Deserialize<PairingInitiateRequest>(json, Opts)!;

        Assert.Equal("dev-1", deserialized.DeviceId);
        Assert.Equal("e-1", deserialized.EnforcerId);
        Assert.Equal("Cursor", deserialized.EnforcerLabel);
        Assert.Equal("my-project", deserialized.WorkspaceName);
    }

    [Fact]
    public void PairingStatusBatchResponse_Deserializes()
    {
        var json = """{"statuses":{"rt-1":"Completed","rt-2":"Revoked","rt-3":"Unknown"}}""";
        var deserialized = JsonSerializer.Deserialize<PairingStatusBatchResponse>(json, Opts)!;

        Assert.Equal(3, deserialized.Statuses.Count);
        Assert.Equal("Completed", deserialized.Statuses["rt-1"]);
        Assert.Equal("Revoked", deserialized.Statuses["rt-2"]);
    }

    [Fact]
    public void EchoResponse_Deserializes()
    {
        var json = """{"utc":"2025-01-01T00:00:00Z","local":"2025-01-01T03:00:00+03:00","timezone":"Europe/Istanbul","offsetMinutes":180}""";
        var deserialized = JsonSerializer.Deserialize<EchoResponse>(json, Opts)!;

        Assert.Equal("Europe/Istanbul", deserialized.Timezone);
        Assert.Equal(180, deserialized.OffsetMinutes);
    }

    [Fact]
    public void PresenceHeartbeatRequest_RoundTrips()
    {
        var request = new PresenceHeartbeatRequest
        {
            EnforcerId = "e-1",
            WorkspaceName = "proj",
            EnforcerLabel = "MyAgent"
        };

        var json = JsonSerializer.Serialize(request, Opts);
        Assert.Contains("enforcerId", json);
        Assert.Contains("workspaceName", json);

        var deserialized = JsonSerializer.Deserialize<PresenceHeartbeatRequest>(json, Opts)!;
        Assert.Equal("e-1", deserialized.EnforcerId);
    }

    [Fact]
    public void EnforcerPresenceRecord_Deserializes()
    {
        var json = """{"enforcerDeviceId":"e1","status":"online","workspaceName":"proj","enforcerLabel":"Cursor","transport":"websocket","capabilities":{"hooks":"true"}}""";
        var deserialized = JsonSerializer.Deserialize<EnforcerPresenceRecord>(json, Opts)!;

        Assert.Equal("e1", deserialized.EnforcerDeviceId);
        Assert.Equal("online", deserialized.Status);
        Assert.Equal("Cursor", deserialized.EnforcerLabel);
        Assert.NotNull(deserialized.Capabilities);
        Assert.Equal("true", deserialized.Capabilities?["hooks"]);
    }
}
