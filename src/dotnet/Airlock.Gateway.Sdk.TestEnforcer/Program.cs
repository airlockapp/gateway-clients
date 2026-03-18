using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Airlock.Gateway.Sdk;
using Airlock.Gateway.Sdk.Models;
using Spectre.Console;

namespace Airlock.Gateway.Sdk.TestEnforcer;

// ── Persistent Configuration ────────────────────────────────────────────
class EnforcerConfig
{
    public string GatewayUrl { get; set; } = "https://igw.airlocks.io";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string EnforcerId { get; set; } = "enf-test";
    public string WorkspaceName { get; set; } = "default";
    public string RoutingToken { get; set; } = "";
    public string EncryptionKey { get; set; } = "";
    public string AccessToken { get; set; } = "";
    public string RefreshToken { get; set; } = "";
    public DateTimeOffset TokenExpiresAt { get; set; }
}

// ── Debug HTTP Logging Handler ──────────────────────────────────────────
class DebugLoggingHandler : DelegatingHandler
{
    public DebugLoggingHandler(HttpMessageHandler inner) : base(inner) { }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        AnsiConsole.MarkupLine($"  [dim]{request.Method} {request.RequestUri}[/]");
        var response = await base.SendAsync(request, ct);
        var color = response.IsSuccessStatusCode ? "green" : "red";
        AnsiConsole.MarkupLine($"  [{color}]=> {(int)response.StatusCode} {response.ReasonPhrase}[/]");
        return response;
    }
}

// ── Main Program ────────────────────────────────────────────────────────
class Program
{
    static readonly string ConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".airlock", "test-enforcer.json");

    static EnforcerConfig _config = new();
    static AirlockAuthClient? _authClient;
    static AirlockGatewayClient? _gwClient;
    static CancellationTokenSource? _heartbeatCts;
    static string? _lastRequestId;
    static string _keycloakUrl = "";

    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    static async Task Main(string[] args)
    {
        AnsiConsole.Write(new FigletText("Airlock").Color(Color.Aqua));
        AnsiConsole.MarkupLine("[bold]Test Enforcer CLI[/]\n");

        // Load or create config
        await LoadConfig();
        DiscoverGateway();

        if (string.IsNullOrEmpty(_config.ClientId))
        {
            await RunSetupWizard();
            DiscoverGateway();
        }

        // Initialize SDK clients
        InitClients();

        // Startup: try restoring session
        await TryRestoreSession();

        // Show initial status
        PrintStatus();

        // Main loop
        while (true)
        {
            var choices = BuildMenuChoices();
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("\n[bold cyan]Choose action:[/]")
                    .PageSize(12)
                    .AddChoices(choices));

            try
            {
                switch (choice)
                {
                    case "> Sign In": await DoSignIn(); break;
                    case "> Pair Device": await DoPair(); break;
                    case "> Submit Artifact": await DoSubmit(); break;
                    case "> Withdraw": await DoWithdraw(); break;
                    case "> Unpair": await DoUnpair(); break;
                    case "> Sign Out": await DoSignOut(); break;
                    case "> Reconfigure": await RunSetupWizard(); DiscoverGateway(); InitClients(); break;
                    case "x Exit":
                        _heartbeatCts?.Cancel();
                        AnsiConsole.MarkupLine("[dim]Goodbye![/]");
                        return;
                }
            }
            catch (AirlockGatewayException ex)
            {
                AnsiConsole.Write(new Panel(
                    $"[red]{Markup.Escape(ex.ErrorCode ?? "error")}[/]\n{Markup.Escape(ex.Message)}")
                    .Header("[red]Gateway Error[/]")
                    .BorderColor(Color.Red));
            }
            catch (AirlockAuthException ex)
            {
                AnsiConsole.Write(new Panel($"[red]{Markup.Escape(ex.Message)}[/]")
                    .Header("[red]Auth Error[/]")
                    .BorderColor(Color.Red));
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
            }
        }
    }

    // ── Menu ─────────────────────────────────────────────────────────────
    static string[] BuildMenuChoices()
    {
        var isSignedIn = _authClient?.IsLoggedIn == true;
        var isPaired = !string.IsNullOrEmpty(_config.RoutingToken);

        return isSignedIn
            ? isPaired
                ? ["> Submit Artifact", "> Withdraw", "─────────", "> Unpair", "> Sign Out", "> Reconfigure", "x Exit"]
                : ["> Pair Device", "─────────", "> Sign Out", "> Reconfigure", "x Exit"]
            : ["> Sign In", "> Reconfigure", "x Exit"];
    }

    // ── Status ───────────────────────────────────────────────────────────
    static void PrintStatus()
    {
        var table = new Table().Border(TableBorder.Rounded).BorderColor(Color.Grey);
        table.AddColumn("[bold]Property[/]");
        table.AddColumn("[bold]Value[/]");

        table.AddRow("Gateway", Markup.Escape(_config.GatewayUrl));
        table.AddRow("Client ID", Markup.Escape(_config.ClientId));
        table.AddRow("Client Secret", MaskSecret(_config.ClientSecret));
        table.AddRow("Enforcer ID", Markup.Escape(_config.EnforcerId));
        table.AddRow("Workspace", Markup.Escape(_config.WorkspaceName));

        var signedIn = _authClient?.IsLoggedIn == true;
        table.AddRow("Auth", signedIn ? "[green]Signed in[/]" : "[dim]Not signed in[/]");

        if (!string.IsNullOrEmpty(_config.RoutingToken))
            table.AddRow("Paired", $"[green]{Markup.Escape(_config.RoutingToken[..Math.Min(16, _config.RoutingToken.Length)])}...[/]");
        else
            table.AddRow("Paired", "[dim]Not paired[/]");

        AnsiConsole.Write(table);
    }

    // ── Sign In (Device Auth Grant) ─────────────────────────────────────
    static async Task DoSignIn()
    {
        var tokenResponse = await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("cyan"))
            .StartAsync("Discovering OIDC endpoints...", async ctx =>
            {
                await _authClient!.DiscoverAsync();

                ctx.Status("Requesting device code...");
                TokenResponse? token = null;

                token = await _authClient.LoginAsync(deviceCode =>
                {
                    ctx.Status("Waiting for user authorization...");
                    AnsiConsole.WriteLine();
                    AnsiConsole.Write(new Panel(
                        $"[bold yellow]Open this URL:[/]\n{Markup.Escape(deviceCode.VerificationUriComplete ?? deviceCode.VerificationUri ?? "")}\n\n" +
                        $"[bold]Enter code:[/] [cyan]{Markup.Escape(deviceCode.UserCode ?? "")}[/]")
                        .Header("Device Authorization Required")
                        .BorderColor(Color.Yellow));
                });

                return token;
            });

        AnsiConsole.MarkupLine($"\n[green]:check_mark: Signed in successfully[/]");

        // Save tokens
        var (access, refresh, exp) = _authClient!.GetTokenState();
        _config.AccessToken = access ?? "";
        _config.RefreshToken = refresh ?? "";
        _config.TokenExpiresAt = exp;
        await SaveConfig();

        // Set bearer on gateway client
        _gwClient!.SetBearerToken(access);

        // Check consent
        await CheckConsent();
    }

    // ── Consent Check ───────────────────────────────────────────────────
    static async Task CheckConsent()
    {
        try
        {
            var status = await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Checking consent...", async _ =>
                    await _gwClient!.CheckConsentAsync());

            AnsiConsole.MarkupLine($"[green]:check_mark: Consent status: {Markup.Escape(status)}[/]");
        }
        catch (AirlockGatewayException ex) when (ex.ErrorCode is "app_consent_required" or "app_consent_pending")
        {
            AnsiConsole.Write(new Panel(
                $"[yellow]{Markup.Escape(ex.Message)}[/]\n\n" +
                "A consent request has been sent to your mobile device.\n" +
                "Please approve it in the Airlock mobile app.")
                .Header($"Consent: {ex.ErrorCode}")
                .BorderColor(Color.Yellow));
        }
    }

    // ── Pair Device ─────────────────────────────────────────────────────
    static async Task DoPair()
    {
        if (string.IsNullOrEmpty(_config.DeviceId))
        {
            _config.DeviceId = AnsiConsole.Prompt(
                new TextPrompt<string>("Device ID:")
                    .DefaultValue($"dev-{Environment.MachineName.ToLowerInvariant()}")
                    .AllowEmpty());
            if (string.IsNullOrEmpty(_config.DeviceId))
                _config.DeviceId = $"dev-{Environment.MachineName.ToLowerInvariant()}";
        }

        // Generate X25519 keypair for ECDH key agreement
        var x25519KeyPair = Airlock.Gateway.Sdk.Crypto.CryptoHelpers.GenerateX25519KeyPair();

        var req = new PairingInitiateRequest
        {
            DeviceId = _config.DeviceId,
            EnforcerId = _config.EnforcerId,
            EnforcerLabel = "Test Enforcer CLI",
            WorkspaceName = _config.WorkspaceName,
            X25519PublicKey = x25519KeyPair.publicKeyBase64Url,
        };

        var res = await _gwClient!.InitiatePairingAsync(req);

        AnsiConsole.Write(new Panel(
            $"[bold]Pairing Code:[/] [cyan]{Markup.Escape(res.PairingCode ?? "N/A")}[/]\n" +
            $"[bold]Nonce:[/] {Markup.Escape(res.PairingNonce ?? "N/A")}\n\n" +
            "Enter this code in the Airlock mobile app to complete pairing.")
            .Header("Pairing Initiated")
            .BorderColor(Color.Yellow));

        // Poll for completion
        var completedStatus = await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("yellow"))
            .StartAsync("Waiting for pairing approval...", async ctx =>
            {
                for (int i = 0; i < 60; i++) // 5 minutes max
                {
                    await Task.Delay(5000);
                    var status = await _gwClient.GetPairingStatusAsync(res.PairingNonce!);
                    var state = status.State?.ToLowerInvariant() ?? "";

                    ctx.Status($"Pairing status: [bold]{state}[/] ({i * 5}s)");

                    if (state is "completed")
                    {
                        return status;
                    }
                    if (state is "revoked" or "expired")
                    {
                        AnsiConsole.MarkupLine($"[red]Pairing {state}[/]");
                        return null;
                    }
                }
                return null;
            });

        if (completedStatus is not null)
        {
            _config.RoutingToken = completedStatus.RoutingToken ?? "";

            // Extract approver's X25519 public key from responseJson and derive shared key
            if (!string.IsNullOrEmpty(completedStatus.ResponseJson))
            {
                try
                {
                    using var doc = JsonDocument.Parse(completedStatus.ResponseJson);
                    if (doc.RootElement.TryGetProperty("x25519PublicKey", out var approverKeyProp))
                    {
                        var approverPubKey = approverKeyProp.GetString();
                        if (!string.IsNullOrEmpty(approverPubKey))
                        {
                            _config.EncryptionKey = Airlock.Gateway.Sdk.Crypto.CryptoHelpers.DeriveSharedKey(
                                x25519KeyPair.privateKeyBase64Url, approverPubKey);
                            AnsiConsole.MarkupLine("[green]:check_mark: X25519 ECDH key agreement completed — E2E encryption enabled[/]");
                        }
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[yellow]⚠ Failed to derive encryption key: {Markup.Escape(ex.Message)}[/]");
                }
            }

            if (string.IsNullOrEmpty(_config.EncryptionKey))
            {
                AnsiConsole.MarkupLine("[yellow]⚠ No approver X25519 key received — encryption will use random test keys[/]");
            }

            await SaveConfig();

            AnsiConsole.MarkupLine($"[green]:check_mark: Paired! Routing token saved.[/]");
            StartHeartbeat();
        }
        else
        {
            AnsiConsole.MarkupLine("[red]Pairing timed out or was rejected.[/]");
        }
    }

    // ── Submit Artifact ─────────────────────────────────────────────────
    static async Task DoSubmit()
    {
        // Ensure fresh token
        await EnsureFreshToken();

        // Build a plaintext payload (this is what gets encrypted)
        var plaintext = JsonSerializer.Serialize(new
        {
            requestLabel = $"Test approval request from .NET enforcer",
            command = "dotnet test --filter Category=Integration",
            workspaceName = _config.WorkspaceName,
            enforcerId = _config.EnforcerId,
            timestamp = DateTimeOffset.UtcNow.ToString("O")
        });

        // Use stored encryption key or a test key
        var encKey = _config.EncryptionKey;
        if (string.IsNullOrEmpty(encKey))
        {
            // Generate a test key if not paired yet
            encKey = Airlock.Gateway.Sdk.Crypto.CryptoHelpers.ToBase64Url(
                RandomNumberGenerator.GetBytes(32));
            AnsiConsole.MarkupLine("[yellow]⚠ No encryption key from pairing — using random test key[/]");
        }

        var req = new EncryptedArtifactRequest
        {
            EnforcerId = _config.EnforcerId,
            ArtifactType = "command-approval",
            PlaintextPayload = plaintext,
            EncryptionKeyBase64Url = encKey,
            Metadata = new Dictionary<string, string>
            {
                ["routingToken"] = _config.RoutingToken,
                ["workspaceName"] = _config.WorkspaceName,
                ["requestLabel"] = "Test approval request from .NET enforcer",
            },
        };

        AnsiConsole.MarkupLine($"[dim]Submitting encrypted artifact...[/]");

        var submittedId = await _gwClient!.EncryptAndSubmitArtifactAsync(req);
        _lastRequestId = submittedId;

        AnsiConsole.MarkupLine($"[green]:check_mark: Submitted:[/] {Markup.Escape(_lastRequestId)} [dim](AES-256-GCM encrypted)[/]");

        // Long-poll for decision
        var decision = await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("cyan"))
            .StartAsync("Waiting for decision...", async ctx =>
            {
                var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
                int poll = 0;

                while (DateTimeOffset.UtcNow < deadline)
                {
                    poll++;
                    var elapsed = (int)(DateTimeOffset.UtcNow - deadline.AddMinutes(2)).TotalSeconds * -1;
                    ctx.Status($"Waiting for decision... ({poll * 25}s elapsed)");

                    try
                    {
                        var envelope = await _gwClient.WaitForDecisionAsync(_lastRequestId, 25);
                        if (envelope?.Body is not null)
                        {
                            return envelope;
                        }
                    }
                    catch (AirlockGatewayException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // Exchange expired or withdrawn
                        return null;
                    }
                }
                return null;
            });

        if (decision?.Body is not null)
        {
            var d = decision.Body;
            var isApproved = d.Decision?.Equals("approve", StringComparison.OrdinalIgnoreCase) == true;
            var color = isApproved ? Color.Green : Color.Red;
            var icon = isApproved ? ":check_mark_button:" : ":cross_mark:";

            AnsiConsole.Write(new Panel(
                $"[bold]{icon} {Markup.Escape(d.Decision?.ToUpperInvariant() ?? "UNKNOWN")}[/]\n" +
                (string.IsNullOrEmpty(d.Reason) ? "" : $"Reason: {Markup.Escape(d.Reason)}\n") +
                (string.IsNullOrEmpty(d.SignerKeyId) ? "" : $"Signer: {Markup.Escape(d.SignerKeyId)}"))
                .Header($"[bold]Decision[/]")
                .BorderColor(color));
        }
        else
        {
            AnsiConsole.MarkupLine("[yellow]:hourglass_not_done: Timed out waiting for decision.[/]");
            // Auto-withdraw
            await DoWithdraw();
        }
    }

    // ── Withdraw ─────────────────────────────────────────────────────────
    static async Task DoWithdraw()
    {
        var id = _lastRequestId;
        if (string.IsNullOrEmpty(id))
        {
            id = AnsiConsole.Prompt(new TextPrompt<string>("Request ID to withdraw:"));
        }

        try
        {
            await _gwClient!.WithdrawExchangeAsync(id);
            AnsiConsole.MarkupLine($"[green]:check_mark: Withdrawn:[/] {Markup.Escape(id)}");
            _lastRequestId = null;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[yellow]Withdraw failed (non-fatal): {Markup.Escape(ex.Message)}[/]");
        }
    }

    // ── Unpair ───────────────────────────────────────────────────────────
    static async Task DoUnpair()
    {
        if (string.IsNullOrEmpty(_config.RoutingToken))
        {
            AnsiConsole.MarkupLine("[dim]Not paired.[/]");
            return;
        }

        var confirm = AnsiConsole.Confirm("Revoke pairing?", defaultValue: false);
        if (!confirm) return;

        try
        {
            await _gwClient!.RevokePairingAsync(_config.RoutingToken);
        }
        catch (Exception ex)
        {
            // Token may be stale (DB reset, expired session) — clear locally regardless
            AnsiConsole.MarkupLine($"[dim]Server revoke failed (token may be stale): {ex.Message}[/]");
        }

        _config.RoutingToken = "";
        _config.DeviceId = "";
        _heartbeatCts?.Cancel();
        await SaveConfig();

        AnsiConsole.MarkupLine("[green]:check_mark: Unpaired.[/]");
    }

    // ── Sign Out ─────────────────────────────────────────────────────────
    static async Task DoSignOut()
    {
        try { await _authClient!.LogoutAsync(); } catch { /* best effort */ }

        _config.AccessToken = "";
        _config.RefreshToken = "";
        _config.TokenExpiresAt = default;
        _gwClient!.SetBearerToken(null);
        _heartbeatCts?.Cancel();
        await SaveConfig();

        AnsiConsole.MarkupLine("[green]:check_mark: Signed out.[/]");
    }

    // ── Session Restore ─────────────────────────────────────────────────
    static async Task TryRestoreSession()
    {
        if (string.IsNullOrEmpty(_config.RefreshToken)) return;

        _authClient!.RestoreTokens(
            _config.AccessToken, _config.RefreshToken, _config.TokenExpiresAt);

        try
        {
            var refreshed = await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Refreshing session...", async _ =>
                    await _authClient.RefreshTokenAsync());

            var (access, refresh, exp) = _authClient.GetTokenState();
            _config.AccessToken = access ?? "";
            _config.RefreshToken = refresh ?? "";
            _config.TokenExpiresAt = exp;
            await SaveConfig();

            _gwClient!.SetBearerToken(access);
            AnsiConsole.MarkupLine("[green]:check_mark: Session restored[/]");

            // Check consent
            await CheckConsent();

            // Start heartbeat if paired
            if (!string.IsNullOrEmpty(_config.RoutingToken))
            {
                StartHeartbeat();
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[yellow]Session expired: {Markup.Escape(ex.Message)}[/]");
            _config.AccessToken = "";
            _config.RefreshToken = "";
            _config.TokenExpiresAt = default;
            await SaveConfig();
        }
    }

    // ── Token Refresh ───────────────────────────────────────────────────
    static async Task EnsureFreshToken()
    {
        if (_authClient?.IsTokenExpired == true && !string.IsNullOrEmpty(_config.RefreshToken))
        {
            await _authClient.RefreshTokenAsync();
            var (access, refresh, exp) = _authClient.GetTokenState();
            _config.AccessToken = access ?? "";
            _config.RefreshToken = refresh ?? "";
            _config.TokenExpiresAt = exp;
            _gwClient!.SetBearerToken(access);
            await SaveConfig();
        }
    }

    // ── Background Heartbeat ────────────────────────────────────────────
    static void StartHeartbeat()
    {
        _heartbeatCts?.Cancel();
        _heartbeatCts = new CancellationTokenSource();
        var ct = _heartbeatCts.Token;

        _ = Task.Run(async () =>
        {
            AnsiConsole.MarkupLine("[dim]:red_heart: Heartbeat started (every 10s)[/]");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await _gwClient!.SendHeartbeatAsync(new PresenceHeartbeatRequest
                    {
                        EnforcerId = _config.EnforcerId,
                        EnforcerLabel = "Test Enforcer CLI",
                        WorkspaceName = _config.WorkspaceName,
                    });
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[dim yellow]:red_heart: Heartbeat failed: {Markup.Escape(ex.Message)}[/]");
                }

                try { await Task.Delay(10_000, ct); } catch (TaskCanceledException) { break; }
            }
            AnsiConsole.MarkupLine("[dim]:red_heart: Heartbeat stopped[/]");
        }, ct);
    }

    // ── Setup Wizard ────────────────────────────────────────────────────
    static async Task RunSetupWizard()
    {
        AnsiConsole.Write(new Rule("[yellow]Setup[/]").RuleStyle("grey"));

        _config.GatewayUrl = AnsiConsole.Prompt(
            new TextPrompt<string>("Gateway URL:")
                .DefaultValue(_config.GatewayUrl));

        _config.ClientId = AnsiConsole.Prompt(
            new TextPrompt<string>("Client ID:")
                .DefaultValue(string.IsNullOrEmpty(_config.ClientId) ? "" : _config.ClientId));

        _config.ClientSecret = AnsiConsole.Prompt(
            new TextPrompt<string>("Client Secret:")
                .DefaultValue(string.IsNullOrEmpty(_config.ClientSecret) ? "" : _config.ClientSecret)
                .Secret('*'));

        _config.EnforcerId = AnsiConsole.Prompt(
            new TextPrompt<string>("Enforcer ID:")
                .DefaultValue(_config.EnforcerId));

        _config.WorkspaceName = AnsiConsole.Prompt(
            new TextPrompt<string>("Workspace Name:")
                .DefaultValue(_config.WorkspaceName));

        await SaveConfig();
        AnsiConsole.MarkupLine("[green]:check_mark: Configuration saved[/]");
    }

    // ── Client Initialization ───────────────────────────────────────────
    // ── Gateway Discovery ────────────────────────────────────────────
    static void DiscoverGateway()
    {
        try
        {
            using var http = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            })
            { Timeout = TimeSpan.FromSeconds(5) };

            var resp = http.GetAsync($"{_config.GatewayUrl.TrimEnd('/')}/v1/integrations/discovery").Result;
            if (resp.IsSuccessStatusCode)
            {
                var json = resp.Content.ReadAsStringAsync().Result;
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("idp", out var idp) &&
                    idp.TryGetProperty("baseUrl", out var baseUrl) &&
                    !string.IsNullOrEmpty(baseUrl.GetString()))
                {
                    _keycloakUrl = baseUrl.GetString()!;
                    AnsiConsole.MarkupLine($"[dim]Keycloak: {Markup.Escape(_keycloakUrl)}[/]");
                    return;
                }
            }
            AnsiConsole.MarkupLine("[yellow]⚠ Discovery did not return a valid Keycloak URL. Sign In will be unavailable until reconfigured.[/]");
        }
        catch
        {
            AnsiConsole.MarkupLine($"[yellow]⚠ Could not reach gateway at {Markup.Escape(_config.GatewayUrl)} — Sign In will be unavailable until reconfigured.[/]");
        }
    }

    static void InitClients()
    {
        // HTTP handler with self-signed cert bypass + debug logging
        var innerHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        var loggingHandler = new DebugLoggingHandler(innerHandler);

        // Auth client
        var authHttp = new HttpClient(loggingHandler, disposeHandler: false)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _authClient = new AirlockAuthClient(
            new AirlockAuthOptions
            {
                KeycloakRealmUrl = _keycloakUrl,
                OidcClientId = "airlock-integrations",
            },
            authHttp);

        // Gateway client with client credentials + debug logging
        var gwHttp = new HttpClient(loggingHandler, disposeHandler: false)
        {
            BaseAddress = new Uri(_config.GatewayUrl.TrimEnd('/')),
            Timeout = TimeSpan.FromSeconds(120)
        };
        gwHttp.DefaultRequestHeaders.Add("X-Client-Id", _config.ClientId);
        gwHttp.DefaultRequestHeaders.Add("X-Client-Secret", _config.ClientSecret);
        _gwClient = new AirlockGatewayClient(gwHttp);
    }

    // ── Config Persistence ──────────────────────────────────────────────
    static async Task LoadConfig()
    {
        if (File.Exists(ConfigPath))
        {
            var json = await File.ReadAllTextAsync(ConfigPath);
            _config = JsonSerializer.Deserialize<EnforcerConfig>(json) ?? new EnforcerConfig();
        }
    }

    static async Task SaveConfig()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        await File.WriteAllTextAsync(ConfigPath, JsonSerializer.Serialize(_config, JsonOpts));
    }
    static string MaskSecret(string? secret)
    {
        if (string.IsNullOrEmpty(secret)) return "[dim]not set[/]";
        if (secret.Length <= 8) return new string('*', secret.Length);
        return $"{secret[..4]}{"…"}{secret[^4..]}";
    }
}
