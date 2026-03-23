package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/airlockapp/gateway-clients/src/go/airlock"
	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
)

// ── Persistent Configuration ────────────────────────────────────────────
type Config struct {
	GatewayURL     string    `json:"gatewayUrl"`
	ClientID       string    `json:"clientId"`
	ClientSecret   string    `json:"clientSecret"`
	EnforcerID     string    `json:"enforcerId"`
	WorkspaceName  string    `json:"workspaceName"`
	DeviceID       string    `json:"deviceId"`
	RoutingToken   string    `json:"routingToken"`
	EncryptionKey  string    `json:"encryptionKey"`
	Pat            string    `json:"pat"`
	AccessToken    string    `json:"accessToken"`
	RefreshToken   string    `json:"refreshToken"`
	TokenExpiresAt time.Time `json:"tokenExpiresAt"`
}

// ── Discovery ───────────────────────────────────────────────────────────
type DiscoveryResponse struct {
	IDP struct {
		BaseURL  string `json:"baseUrl"`
		ClientID string `json:"clientId"`
	} `json:"idp"`
}

var (
	cfg             Config
	configPath      string
	authClient      *airlock.AirlockAuthClient
	gwClient        *airlock.Client
	keycloakURL     string
	lastReqID       string
	heartbeatMu     sync.Mutex
	heartbeatCtx    context.Context
	heartbeatCancel context.CancelFunc

	cyan   = color.New(color.FgCyan, color.Bold)
	green  = color.New(color.FgGreen)
	red    = color.New(color.FgRed)
	yellow = color.New(color.FgYellow)
	dim    = color.New(color.Faint)
	bold   = color.New(color.Bold)
)

func main() {
	homeDir, _ := os.UserHomeDir()
	configPath = filepath.Join(homeDir, ".airlock", "test-enforcer-go.json")

	// Banner
	cyan.Println("╔═══════════════════════════════════════╗")
	cyan.Println("║       Airlock Test Enforcer (Go)      ║")
	cyan.Println("╚═══════════════════════════════════════╝")
	fmt.Println()

	loadConfig()
	discoverGateway()

	if cfg.ClientID == "" {
		runSetupWizard()
		discoverGateway()
	}

	initClients()
	tryRestoreSession()
	printStatus()

	// Main loop
	for {
		choices := buildMenuChoices()
		prompt := promptui.Select{
			Label: cyan.Sprint("Choose action"),
			Items: choices,
			Size:  12,
		}

		_, choice, err := prompt.Run()
		if err != nil {
			if err == promptui.ErrInterrupt || err == promptui.ErrEOF {
				stopHeartbeat()
				dim.Println("Goodbye!")
				return
			}
			continue
		}

		if err := handleChoice(choice); err != nil {
			handleError(err)
		}
	}
}

func handleChoice(choice string) error {
	switch choice {
	case "▸ Set PAT (recommended)":
		return doSetPat()
	case "▸ Sign In (OAuth)":
		return doSignIn()
	case "▸ Pair Device":
		return doPair()
	case "▸ Submit Artifact":
		return doSubmit()
	case "▸ Withdraw":
		return doWithdraw()
	case "▸ Unpair":
		return doUnpair()
	case "▸ Sign Out":
		return doSignOut()
	case "▸ Reconfigure":
		runSetupWizard()
		discoverGateway()
		initClients()
		reapplyAuth()
		return nil
	case "✕ Exit":
		stopHeartbeat()
		dim.Println("Goodbye!")
		os.Exit(0)
	}
	return nil
}

// ── Menu ─────────────────────────────────────────────────────────────
func buildMenuChoices() []string {
	isSignedIn := (authClient != nil && authClient.IsLoggedIn()) || cfg.Pat != ""
	isPaired := cfg.RoutingToken != ""

	if isSignedIn {
		if isPaired {
			return []string{"▸ Submit Artifact", "▸ Withdraw", "─────────", "▸ Unpair", "▸ Sign Out", "▸ Reconfigure", "✕ Exit"}
		}
		return []string{"▸ Pair Device", "─────────", "▸ Sign Out", "▸ Reconfigure", "✕ Exit"}
	}
	return []string{"▸ Set PAT (recommended)", "▸ Sign In (OAuth)", "▸ Reconfigure", "✕ Exit"}
}

// ── Status ───────────────────────────────────────────────────────────
func printStatus() {
	fmt.Println()
	fmt.Println("┌──────────────────────────────────────────────┐")
	fmt.Printf("│ %-14s │ %-28s │\n", "Gateway", cfg.GatewayURL)
	fmt.Printf("│ %-14s │ %-28s │\n", "Client ID", cfg.ClientID)
	fmt.Printf("│ %-14s │ %-28s │\n", "Client Secret", maskSecret(cfg.ClientSecret))
	fmt.Printf("│ %-14s │ %-28s │\n", "Enforcer ID", cfg.EnforcerID)
	fmt.Printf("│ %-14s │ %-28s │\n", "Workspace", cfg.WorkspaceName)

	if cfg.Pat != "" {
		fmt.Printf("│ %-14s │ %s │\n", "Auth", green.Sprint("PAT (airpat_…)"))
	} else if authClient != nil && authClient.IsLoggedIn() {
		fmt.Printf("│ %-14s │ %s │\n", "Auth", green.Sprint("Signed in"))
	} else {
		fmt.Printf("│ %-14s │ %s │\n", "Auth", dim.Sprint("Not authenticated"))
	}

	if cfg.RoutingToken != "" {
		truncated := cfg.RoutingToken
		if len(truncated) > 16 {
			truncated = truncated[:16] + "..."
		}
		fmt.Printf("│ %-14s │ %s │\n", "Paired", green.Sprint(truncated))
	} else {
		fmt.Printf("│ %-14s │ %s │\n", "Paired", dim.Sprint("Not paired"))
	}
	fmt.Println("└──────────────────────────────────────────────┘")
	fmt.Println()
}

// ── Set PAT (recommended flow) ───────────────────────────────────────
func doSetPat() error {
	prompt := promptui.Prompt{
		Label: "Paste your Personal Access Token (airpat_…)",
		Mask:  '*',
	}
	pat, err := prompt.Run()
	if err != nil || pat == "" {
		return nil
	}
	if !strings.HasPrefix(pat, "airpat_") {
		red.Println("Invalid PAT. Tokens must start with 'airpat_'.")
		return nil
	}
	cfg.Pat = pat
	gwClient.SetPat(pat)
	saveConfig()
	green.Println("✓ PAT set. You can now pair and submit artifacts without OAuth sign-in.")
	checkConsent()
	return nil
}

// ── Sign In (Device Auth Grant) ─────────────────────────────────────
func doSignIn() error {
	dim.Println("Discovering OIDC endpoints...")
	_, err := authClient.Discover(context.Background())
	if err != nil {
		return fmt.Errorf("OIDC discovery failed: %w", err)
	}

	dim.Println("Requesting device code...")
	_, err = authClient.Login(context.Background(), func(info *airlock.DeviceCodeInfo) {
		fmt.Println()
		yellow.Println("┌─ Device Authorization Required ─────────────────┐")
		url := info.VerificationURIComplete
		if url == "" {
			url = info.VerificationURI
		}
		yellow.Printf("│ Open this URL: %s\n", url)
		cyan.Printf("│ Enter code:    %s\n", info.UserCode)
		yellow.Println("└─────────────────────────────────────────────────┘")
		dim.Println("Waiting for user authorization...")
	})
	if err != nil {
		return err
	}

	green.Println("✓ Signed in successfully")

	// Save tokens
	acc, ref, exp := authClient.GetTokenState()
	cfg.AccessToken = acc
	cfg.RefreshToken = ref
	cfg.TokenExpiresAt = exp
	saveConfig()

	gwClient.SetBearerToken(acc)

	// Check consent
	checkConsent()
	return nil
}

// ── Consent Check ───────────────────────────────────────────────────
func checkConsent() {
	dim.Println("Checking consent...")
	status, err := gwClient.CheckConsent()
	if err != nil {
		var gwErr *airlock.GatewayError
		if errors.As(err, &gwErr) {
			consentErr := airlock.ParseConsentError(gwErr.StatusCode, []byte(gwErr.ResponseBody))
			if consentErr != nil {
				yellow.Println("┌─ Consent Required ──────────────────────────────┐")
				yellow.Printf("│ %s\n", consentErr.Message)
				yellow.Println("│ A consent request has been sent to your mobile.")
				yellow.Println("│ Please approve it in the Airlock mobile app.")
				yellow.Println("└─────────────────────────────────────────────────┘")
				return
			}
		}
		yellow.Printf("Consent check failed: %v\n", err)
		return
	}
	green.Printf("✓ Consent status: %s\n", status)
}

// ── Pair Device ─────────────────────────────────────────────────────
func doPair() error {
	if cfg.DeviceID == "" {
		hn, _ := os.Hostname()
		defaultID := fmt.Sprintf("dev-%s", strings.ToLower(hn))
		prompt := promptui.Prompt{
			Label:   "Device ID",
			Default: defaultID,
		}
		result, err := prompt.Run()
		if err != nil {
			return nil
		}
		if result == "" {
			result = defaultID
		}
		cfg.DeviceID = result
	}

	// Choose: new pairing or claim pre-generated code
	modePrompt := promptui.Select{
		Label: "Pairing mode",
		Items: []string{"Initiate new pairing", "Claim a pre-generated code"},
	}
	_, mode, err := modePrompt.Run()
	if err != nil {
		return nil
	}

	// Generate X25519 keypair for ECDH key agreement
	x25519kp, err := airlock.GenerateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("generate x25519 keypair: %w", err)
	}

	var pairingNonce string

	if mode == "Claim a pre-generated code" {
		codePrompt := promptui.Prompt{Label: "Enter the pre-generated pairing code"}
		code, err := codePrompt.Run()
		if err != nil || code == "" {
			return nil
		}

		claimReq := airlock.PairingClaimRequest{
			PairingCode:     code,
			DeviceID:        cfg.DeviceID,
			EnforcerID:      cfg.EnforcerID,
			EnforcerLabel:   "Test Enforcer Go",
			WorkspaceName:   cfg.WorkspaceName,
			GatewayURL:      cfg.GatewayURL,
			X25519PubKey:    x25519kp.PublicKey,
		}

		claimRes, err := gwClient.ClaimPairing(claimReq)
		if err != nil {
			return err
		}
		pairingNonce = claimRes.PairingNonce
		green.Printf("✓ Code claimed. Nonce: %s\n", pairingNonce)
	} else {
		req := airlock.PairingInitiateRequest{
			DeviceID:        cfg.DeviceID,
			EnforcerID:      cfg.EnforcerID,
			EnforcerLabel:   "Test Enforcer Go",
			WorkspaceName:   cfg.WorkspaceName,
			X25519PublicKey: x25519kp.PublicKey,
		}

		res, err := gwClient.InitiatePairing(req)
		if err != nil {
			return err
		}
		pairingNonce = res.PairingNonce

		yellow.Println("┌─ Pairing Initiated ─────────────────────────────┐")
		bold.Printf("│ Pairing Code: %s\n", cyan.Sprint(res.PairingCode))
		fmt.Printf("│ Nonce:        %s\n", res.PairingNonce)
		yellow.Println("│ Enter this code in the Airlock mobile app.")
		yellow.Println("└─────────────────────────────────────────────────┘")
	}

	// Poll for completion
	dim.Println("Waiting for the approver to complete pairing in the mobile app...")
	for i := 0; i < 60; i++ { // 5 min max
		time.Sleep(5 * time.Second)
		status, err := gwClient.GetPairingStatus(pairingNonce)
		if err != nil {
			return err
		}

		state := strings.ToLower(status.State)
		dim.Printf("  Pairing status: %s (%ds)\n", state, (i+1)*5)

		if state == "completed" {
			cfg.RoutingToken = status.RoutingToken

			// Extract approver's X25519 public key from responseJson and derive shared key
			if status.ResponseJSON != "" {
				var respData map[string]interface{}
				if err := json.Unmarshal([]byte(status.ResponseJSON), &respData); err == nil {
					if approverPubKey, ok := respData["x25519PublicKey"].(string); ok && approverPubKey != "" {
						derivedKey, err := airlock.DeriveSharedKey(x25519kp.PrivateKey, approverPubKey)
						if err != nil {
							yellow.Printf("⚠ Failed to derive encryption key: %v\n", err)
						} else {
							cfg.EncryptionKey = derivedKey
							green.Println("✓ X25519 ECDH key agreement completed — E2E encryption enabled")
						}
					}
				}
			}

			if cfg.EncryptionKey == "" {
				yellow.Println("⚠ No approver X25519 key received — encryption will use random test keys")
			}

			saveConfig()
			green.Println("✓ Paired! Routing token saved.")
			startHeartbeat()
			return nil
		}
		if state == "revoked" || state == "expired" {
			red.Printf("Pairing %s\n", state)
			return nil
		}
	}

	red.Println("Pairing timed out.")
	return nil
}

// ── Submit Artifact ─────────────────────────────────────────────────
func doSubmit() error {
	ensureFreshToken()

	// Build plaintext payload
	plaintext, _ := json.Marshal(map[string]string{
		"requestLabel":  "Test approval request from Go enforcer",
		"command":       "go test ./...",
		"workspaceName": cfg.WorkspaceName,
		"enforcerId":    cfg.EnforcerID,
		"timestamp":     time.Now().Format(time.RFC3339),
	})

	// Use stored encryption key or generate a test key
	encKey := cfg.EncryptionKey
	if encKey == "" {
		testKey := make([]byte, 32)
		rand.Read(testKey)
		encKey = airlock.ToBase64URL(testKey)
		yellow.Println("⚠ No encryption key from pairing — using random test key")
	}

	// Canonicalize and hash
	canonical, err := airlock.CanonicalizeJSON(string(plaintext))
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	artifactHash := airlock.SHA256Hex(canonical)

	// Encrypt with AES-256-GCM
	ciphertext, err := airlock.AesGcmEncrypt(encKey, canonical)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	reqID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	req := airlock.ArtifactSubmitRequest{
		EnforcerID:   cfg.EnforcerID,
		ArtifactType: "command-approval",
		ArtifactHash: artifactHash,
		Ciphertext:   *ciphertext,
		Metadata: map[string]string{
			"routingToken":  cfg.RoutingToken,
			"workspaceName": cfg.WorkspaceName,
			"requestLabel":  "Test approval request from Go enforcer",
		},
		RequestID: reqID,
	}

	dim.Println("Submitting encrypted artifact...")
	submittedID, err := gwClient.SubmitArtifact(req)
	if err != nil {
		return err
	}
	if submittedID != "" {
		lastReqID = submittedID
	} else {
		lastReqID = reqID
	}

	green.Printf("✓ Submitted: %s (AES-256-GCM encrypted)\n", lastReqID)

	// Long-poll for decision
	dim.Println("Waiting for decision...")
	deadline := time.Now().Add(2 * time.Minute)
	poll := 0

	for time.Now().Before(deadline) {
		poll++
		dim.Printf("  Waiting for decision... (%ds elapsed)\n", poll*25)

		env, err := gwClient.WaitForDecision(lastReqID, 25)
		if err != nil {
			var gwErr *airlock.GatewayError
			if errors.As(err, &gwErr) && gwErr.StatusCode == 404 {
				return nil // Exchange expired or withdrawn
			}
			return err
		}

		if env != nil && env.Body != nil {
			isApproved := strings.EqualFold(env.Body.Decision, "approve")
			if isApproved {
				green.Println("┌─ Decision ──────────────────────────────────────┐")
				green.Printf("│ ✓ %s\n", strings.ToUpper(env.Body.Decision))
			} else {
				red.Println("┌─ Decision ──────────────────────────────────────┐")
				red.Printf("│ ✗ %s\n", strings.ToUpper(env.Body.Decision))
			}
			if env.Body.Reason != "" {
				fmt.Printf("│ Reason: %s\n", env.Body.Reason)
			}
			if env.Body.SignerKeyID != "" {
				fmt.Printf("│ Signer: %s\n", env.Body.SignerKeyID)
			}
			fmt.Println("└─────────────────────────────────────────────────┘")
			return nil
		}
	}

	yellow.Println("⏳ Timed out waiting for decision.")
	doWithdraw()
	return nil
}

// ── Withdraw ────────────────────────────────────────────────────────
func doWithdraw() error {
	id := lastReqID
	if id == "" {
		prompt := promptui.Prompt{Label: "Request ID to withdraw"}
		var err error
		id, err = prompt.Run()
		if err != nil || id == "" {
			return nil
		}
	}

	err := gwClient.WithdrawExchange(id)
	if err != nil {
		yellow.Printf("Withdraw failed (non-fatal): %v\n", err)
		return nil
	}
	green.Printf("✓ Withdrawn: %s\n", id)
	lastReqID = ""
	return nil
}

// ── Unpair ──────────────────────────────────────────────────────────
func doUnpair() error {
	if cfg.RoutingToken == "" {
		dim.Println("Not paired.")
		return nil
	}

	prompt := promptui.Prompt{
		Label:     "Revoke pairing",
		IsConfirm: true,
	}
	_, err := prompt.Run()
	if err != nil {
		return nil // User said no
	}

	_, revokeErr := gwClient.RevokePairing(cfg.RoutingToken)
	if revokeErr != nil {
		dim.Printf("Server revoke failed (token may be stale): %v\n", revokeErr)
	}

	cfg.RoutingToken = ""
	cfg.DeviceID = ""
	stopHeartbeat()
	saveConfig()

	green.Println("✓ Unpaired.")
	return nil
}

// ── Sign Out ────────────────────────────────────────────────────────
func doSignOut() error {
	_ = authClient.Logout(context.Background()) // best effort

	cfg.AccessToken = ""
	cfg.RefreshToken = ""
	cfg.Pat = ""
	cfg.TokenExpiresAt = time.Time{}
	gwClient.SetBearerToken("")
	gwClient.SetPat("")
	stopHeartbeat()
	saveConfig()

	green.Println("✓ Signed out.")
	return nil
}

// ── Session Restore ─────────────────────────────────────────────────
func tryRestoreSession() {
	// PAT takes priority — no need for token refresh
	if cfg.Pat != "" {
		gwClient.SetPat(cfg.Pat)
		green.Println("✓ PAT restored")

		// Validate PAT is still active — handle revoked tokens gracefully
		dim.Println("Checking consent...")
		_, err := gwClient.CheckConsent()
		if err != nil {
			var gwErr *airlock.GatewayError
			if errors.As(err, &gwErr) && gwErr.StatusCode == 401 {
				yellow.Println("⚠ PAT has been revoked or expired. Please set a new PAT.")
				cfg.Pat = ""
				gwClient.SetPat("")
				saveConfig()
				return
			}
			// Non-401 errors — handle consent prompts or log
			if errors.As(err, &gwErr) {
				consentErr := airlock.ParseConsentError(gwErr.StatusCode, []byte(gwErr.ResponseBody))
				if consentErr != nil {
					yellow.Println("┌─ Consent Required ──────────────────────────────┐")
					yellow.Printf("│ %s\n", consentErr.Message)
					yellow.Println("│ A consent request has been sent to your mobile.")
					yellow.Println("│ Please approve it in the Airlock mobile app.")
					yellow.Println("└─────────────────────────────────────────────────┘")
				} else {
					yellow.Printf("⚠ PAT validation failed: %v\n", err)
				}
			} else {
				yellow.Printf("⚠ PAT validation failed: %v\n", err)
			}
		} else {
			green.Println("✓ Consent OK")
		}

		if cfg.RoutingToken != "" {
			startHeartbeat()
		}
		return
	}

	if cfg.RefreshToken == "" {
		return
	}

	authClient.RestoreTokens(cfg.AccessToken, cfg.RefreshToken, cfg.TokenExpiresAt)

	dim.Println("Refreshing session...")
	_, err := authClient.RefreshToken(context.Background())
	if err != nil {
		yellow.Printf("Session expired: %v\n", err)
		cfg.AccessToken = ""
		cfg.RefreshToken = ""
		cfg.TokenExpiresAt = time.Time{}
		saveConfig()
		return
	}

	acc, ref, exp := authClient.GetTokenState()
	cfg.AccessToken = acc
	cfg.RefreshToken = ref
	cfg.TokenExpiresAt = exp
	saveConfig()

	gwClient.SetBearerToken(acc)
	green.Println("✓ Session restored")

	checkConsent()

	if cfg.RoutingToken != "" {
		startHeartbeat()
	}
}

// ── Re-apply Auth After Reconfigure ─────────────────────────────────
func reapplyAuth() {
	if cfg.Pat != "" {
		gwClient.SetPat(cfg.Pat)
		green.Println("✓ PAT re-applied after reconfigure")
	} else if cfg.AccessToken != "" {
		gwClient.SetBearerToken(cfg.AccessToken)
		green.Println("✓ Bearer token re-applied after reconfigure")
	}
}

// ── Token Refresh ───────────────────────────────────────────────────
func ensureFreshToken() {
	if authClient == nil {
		return
	}
	if authClient.IsTokenExpired() && cfg.RefreshToken != "" {
		_, _ = authClient.RefreshToken(context.Background())
		acc, ref, exp := authClient.GetTokenState()
		cfg.AccessToken = acc
		cfg.RefreshToken = ref
		cfg.TokenExpiresAt = exp
		gwClient.SetBearerToken(acc)
		saveConfig()
	}
}

// ── Background Heartbeat ────────────────────────────────────────────
func startHeartbeat() {
	stopHeartbeat()

	heartbeatMu.Lock()
	heartbeatCtx, heartbeatCancel = context.WithCancel(context.Background())
	heartbeatMu.Unlock()

	go func() {
		dim.Println("❤ Heartbeat started (every 10s)")

		// Send an immediate heartbeat so the enforcer shows online right away
		sendBeat := func() {
			err := gwClient.SendHeartbeat(airlock.PresenceHeartbeatRequest{
				EnforcerID:    cfg.EnforcerID,
				EnforcerLabel: "Test Enforcer Go",
				WorkspaceName: cfg.WorkspaceName,
			})
			if err != nil {
				dim.Printf("❤ Heartbeat failed: %v\n", err)
			}
		}

		sendBeat()

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-heartbeatCtx.Done():
				dim.Println("❤ Heartbeat stopped")
				return
			case <-ticker.C:
				sendBeat()
			}
		}
	}()
}

func stopHeartbeat() {
	heartbeatMu.Lock()
	defer heartbeatMu.Unlock()
	if heartbeatCancel != nil {
		heartbeatCancel()
		heartbeatCancel = nil
	}
}

// ── Setup Wizard ────────────────────────────────────────────────────
func runSetupWizard() {
	yellow.Println("─── Setup ──────────────────────────────────────")

	prompts := []struct {
		label    string
		current  *string
		fallback string
		secret   bool
	}{
		{"Gateway URL", &cfg.GatewayURL, "https://igw.airlocks.io", false},
		{"Client ID", &cfg.ClientID, "", false},
		{"Client Secret", &cfg.ClientSecret, "", true},
		{"Enforcer ID", &cfg.EnforcerID, "enf-test", false},
		{"Workspace Name", &cfg.WorkspaceName, "default", false},
	}

	for _, p := range prompts {
		def := *p.current
		if def == "" {
			def = p.fallback
		}
		prompt := promptui.Prompt{
			Label:   p.label,
			Default: def,
		}
		if p.secret {
			prompt.Mask = '*'
		}
		result, err := prompt.Run()
		if err != nil {
			continue
		}
		if result != "" {
			*p.current = result
		} else if *p.current == "" {
			*p.current = p.fallback
		}
	}

	saveConfig()
	green.Println("✓ Configuration saved")
}

// ── Client Initialization ───────────────────────────────────────────
func discoverGateway() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	debugTransport := &debugRoundTripper{inner: transport}
	httpClient := &http.Client{Transport: debugTransport, Timeout: 5 * time.Second}

	discoveryURL := strings.TrimRight(cfg.GatewayURL, "/") + "/v1/integrations/discovery"
	resp, err := httpClient.Get(discoveryURL)
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var disc DiscoveryResponse
		if json.Unmarshal(body, &disc) == nil && disc.IDP.BaseURL != "" {
			keycloakURL = disc.IDP.BaseURL
			dim.Printf("Keycloak: %s\n", keycloakURL)
			return
		}
		yellow.Printf("⚠ Discovery did not return a valid Keycloak URL. Sign In will be unavailable until reconfigured.\n")
		return
	}
	if err != nil {
		yellow.Printf("⚠ Could not reach gateway at %s — Sign In will be unavailable until reconfigured.\n", cfg.GatewayURL)
	} else {
		yellow.Printf("⚠ Gateway discovery returned status %d — Sign In will be unavailable until reconfigured.\n", resp.StatusCode)
	}
}

func initClients() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	debugTransport := &debugRoundTripper{inner: transport}
	httpClient := &http.Client{Transport: debugTransport, Timeout: 120 * time.Second}

	// Auth client
	authClient = airlock.NewAirlockAuthClient(airlock.AirlockAuthOptions{
		KeycloakRealmURL: keycloakURL,
		OIDCClientID:     "airlock-integrations",
		HTTPClient:       httpClient,
	})

	// Gateway client
	gwClient = airlock.NewClientWithCredentials(
		cfg.GatewayURL, cfg.ClientID, cfg.ClientSecret,
	).WithHTTPClient(httpClient)
}

// ── Error Handling ──────────────────────────────────────────────────
func handleError(err error) {
	var gwErr *airlock.GatewayError
	if errors.As(err, &gwErr) {
		red.Println("┌─ Gateway Error ─────────────────────────────────┐")
		red.Printf("│ %s\n", gwErr.ErrorCode)
		red.Printf("│ %s\n", gwErr.Message)
		red.Println("└─────────────────────────────────────────────────┘")

		consentErr := airlock.ParseConsentError(gwErr.StatusCode, []byte(gwErr.ResponseBody))
		if consentErr != nil {
			yellow.Println("┌─ Consent Required ──────────────────────────────┐")
			yellow.Printf("│ %s\n", consentErr.Message)
			yellow.Println("│ Approve in the Airlock mobile app.")
			yellow.Println("└─────────────────────────────────────────────────┘")
		}
	} else {
		red.Printf("[Error] %v\n", err)
	}
}

// ── Debug HTTP Logging ──────────────────────────────────────────────
type debugRoundTripper struct {
	inner http.RoundTripper
}

func (d *debugRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	dim.Printf("  %s %s\n", req.Method, req.URL)
	resp, err := d.inner.RoundTrip(req)
	if err != nil {
		red.Printf("  => ERROR: %v\n", err)
	} else if resp.StatusCode >= 400 {
		red.Printf("  => %d %s\n", resp.StatusCode, resp.Status)
	} else {
		green.Printf("  => %d %s\n", resp.StatusCode, resp.Status)
	}
	return resp, err
}

// ── Config Persistence ──────────────────────────────────────────────
func loadConfig() {
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &cfg)
	}
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = "https://igw.airlocks.io"
	}
	if cfg.EnforcerID == "" {
		cfg.EnforcerID = "enf-test"
	}
	if cfg.WorkspaceName == "" {
		cfg.WorkspaceName = "default"
	}
}

func saveConfig() {
	dir := filepath.Dir(configPath)
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configPath, data, 0644)
}

func maskSecret(secret string) string {
	if secret == "" {
		return "(not set)"
	}
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + "…" + secret[len(secret)-4:]
}
