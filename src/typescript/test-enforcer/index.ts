#!/usr/bin/env node
/**
 * Airlock Test Enforcer CLI (TypeScript) — Full TUI with @inquirer/prompts + chalk
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { select, input, password, confirm, Separator } from '@inquirer/prompts';
import chalk from 'chalk';
import { AirlockGatewayClient, AirlockAuthClient, AirlockGatewayError } from '@airlock/gateway-sdk';
import type { AirlockAuthOptions, DeviceCodeInfo } from '@airlock/gateway-sdk';

// Allow self-signed certificates in development
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// ── Persistent Configuration ────────────────────────────────────────
interface Config {
    gatewayUrl: string;
    clientId: string;
    clientSecret: string;
    enforcerId: string;
    workspaceName: string;
    deviceId: string;
    routingToken: string;
    encryptionKey: string;
    pat: string;
    accessToken: string;
    refreshToken: string;
    tokenExpiresAt: number;
}

const CONFIG_PATH = path.join(os.homedir(), '.airlock', 'test-enforcer-typescript.json');

let cfg: Config = {
    gatewayUrl: 'https://igw.airlocks.io',
    clientId: '',
    clientSecret: '',
    enforcerId: 'enf-test',
    workspaceName: 'default',
    deviceId: '',
    routingToken: '',
    encryptionKey: '',
    pat: '',
    accessToken: '',
    refreshToken: '',
    tokenExpiresAt: 0,
};

let authClient: AirlockAuthClient;
let gwClient: AirlockGatewayClient;
let keycloakUrl = '';
let lastRequestId = '';
let heartbeatInterval: ReturnType<typeof setInterval> | null = null;

// ── Helpers ──────────────────────────────────────────────────────────
function maskSecret(s: string): string {
    if (!s) return '(not set)';
    if (s.length <= 8) return '*'.repeat(s.length);
    return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function loadConfig(): void {
    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const data = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
            cfg = { ...cfg, ...data };
        }
    } catch {
        // use defaults
    }
}

function saveConfig(): void {
    const dir = path.dirname(CONFIG_PATH);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

// ── Debug Fetch ─────────────────────────────────────────────────────
const debugFetch: typeof globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const method = init?.method || 'GET';
    console.log(chalk.dim(`  ${method} ${url}`));
    const response = await globalThis.fetch(input, init);
    if (response.ok) {
        console.log(chalk.green(`  => ${response.status} ${response.statusText}`));
    } else {
        console.log(chalk.red(`  => ${response.status} ${response.statusText}`));
    }
    return response;
};

// ── Gateway Discovery ───────────────────────────────────────────────
async function discoverGateway(): Promise<void> {
    try {
        const url = `${cfg.gatewayUrl.replace(/\/$/, '')}/v1/integrations/discovery`;
        const resp = await fetch(url);
        if (resp.ok) {
            const data = await resp.json() as any;
            if (data?.idp?.baseUrl) {
                keycloakUrl = data.idp.baseUrl;
                console.log(chalk.dim(`Keycloak: ${keycloakUrl}`));
                return;
            }
        }
        console.log(chalk.yellow('⚠ Discovery did not return a valid Keycloak URL. Sign In will be unavailable until reconfigured.'));
    } catch {
        console.log(chalk.yellow(`⚠ Could not reach gateway at ${cfg.gatewayUrl} — Sign In will be unavailable until reconfigured.`));
    }
}

// ── Client Init ─────────────────────────────────────────────────────
function initClients(): void {
    const authOptions: AirlockAuthOptions = {
        keycloakRealmUrl: keycloakUrl,
        oidcClientId: 'airlock-integrations',
        fetch: debugFetch,
    };
    authClient = new AirlockAuthClient(authOptions);

    gwClient = new AirlockGatewayClient({
        baseUrl: cfg.gatewayUrl,
        clientId: cfg.clientId,
        clientSecret: cfg.clientSecret,
        fetch: debugFetch,
    });
}

// ── Status Display ──────────────────────────────────────────────────
function printStatus(): void {
    console.log();
    console.log('┌──────────────────────────────────────────────┐');
    console.log(`│ ${'Gateway'.padEnd(14)} │ ${cfg.gatewayUrl.padEnd(28)} │`);
    console.log(`│ ${'Client ID'.padEnd(14)} │ ${cfg.clientId.padEnd(28)} │`);
    console.log(`│ ${'Client Secret'.padEnd(14)} │ ${maskSecret(cfg.clientSecret).padEnd(28)} │`);
    console.log(`│ ${'Enforcer ID'.padEnd(14)} │ ${cfg.enforcerId.padEnd(28)} │`);
    console.log(`│ ${'Workspace'.padEnd(14)} │ ${cfg.workspaceName.padEnd(28)} │`);

    const signedIn = authClient?.isLoggedIn || Boolean(cfg.pat);
    const authLabel = cfg.pat
        ? chalk.green('PAT (airpat_…)')
        : signedIn
            ? chalk.green('OAuth signed in')
            : chalk.dim('Not authenticated');
    const authPlain = cfg.pat ? 'PAT (airpat_…)' : signedIn ? 'OAuth signed in' : 'Not authenticated';
    const padLen = Math.max(0, 28 - authPlain.length);
    console.log(`│ ${'Auth'.padEnd(14)} │ ${authLabel}${' '.repeat(padLen)} │`);

    if (cfg.routingToken) {
        const truncated = cfg.routingToken.length > 16 ? cfg.routingToken.slice(0, 16) + '...' : cfg.routingToken;
        console.log(`│ ${'Paired'.padEnd(14)} │ ${chalk.green(truncated)}${' '.repeat(Math.max(0, 28 - truncated.length))} │`);
    } else {
        console.log(`│ ${'Paired'.padEnd(14)} │ ${chalk.dim('Not paired')}${' '.repeat(18)} │`);
    }
    console.log('└──────────────────────────────────────────────┘');
    console.log();
}

// ── Menu ─────────────────────────────────────────────────────────────
type MenuEntry = { name: string; value: string } | Separator;

function buildMenuChoices(): MenuEntry[] {
    const signedIn = authClient?.isLoggedIn || Boolean(cfg.pat);
    const paired = Boolean(cfg.routingToken);

    if (signedIn) {
        if (paired) {
            return [
                { name: '> Submit Artifact', value: 'submit' },
                { name: '> Withdraw', value: 'withdraw' },
                new Separator(),
                { name: '> Unpair', value: 'unpair' },
                { name: '> Sign Out', value: 'signout' },
                { name: '> Reconfigure', value: 'reconfig' },
                { name: 'x Exit', value: 'exit' },
            ];
        }
        return [
            { name: '> Pair Device', value: 'pair' },
            new Separator(),
            { name: '> Sign Out', value: 'signout' },
            { name: '> Reconfigure', value: 'reconfig' },
            { name: 'x Exit', value: 'exit' },
        ];
    }
    return [
        { name: '> Set PAT (recommended)', value: 'setpat' },
        { name: '> Sign In (OAuth)', value: 'signin' },
        { name: '> Reconfigure', value: 'reconfig' },
        { name: 'x Exit', value: 'exit' },
    ];
}

// ── Set PAT (recommended flow) ───────────────────────────────────────
async function doSetPat(): Promise<void> {
    const pat = await password({ message: 'Paste your Personal Access Token (airpat_…):', mask: '*' });
    if (!pat) return;
    if (!pat.startsWith('airpat_')) {
        console.log(chalk.red('Invalid PAT. Tokens must start with \'airpat_\'.'));
        return;
    }
    cfg.pat = pat;
    gwClient.setPat(pat);
    saveConfig();
    console.log(chalk.green('✓ PAT set. You can now pair and submit artifacts without OAuth sign-in.'));
    await checkConsent();
}

// ── Sign In (Device Auth Grant) ─────────────────────────────────────
async function doSignIn(): Promise<void> {
    console.log(chalk.dim('Discovering OIDC endpoints...'));
    await authClient.discover();

    console.log(chalk.dim('Requesting device code...'));
    await authClient.login((dc: DeviceCodeInfo) => {
        const url = dc.verification_uri_complete ?? dc.verification_uri;
        console.log();
        console.log(chalk.yellow('┌─ Device Authorization Required ─────────────────┐'));
        console.log(`│ Open this URL: ${chalk.bold(url)}`);
        console.log(`│ Enter code:    ${chalk.cyan.bold(dc.user_code)}`);
        console.log(chalk.yellow('└─────────────────────────────────────────────────┘'));
        console.log(chalk.dim('Waiting for user authorization...'));
    });

    console.log(chalk.green('✓ Signed in successfully'));

    const state = authClient.getTokenState();
    cfg.accessToken = state.accessToken ?? '';
    cfg.refreshToken = state.refreshToken ?? '';
    cfg.tokenExpiresAt = state.expiresAt;
    saveConfig();

    gwClient.setBearerToken(state.accessToken ?? undefined);
    await checkConsent();
}

// ── Consent Check ───────────────────────────────────────────────────
async function checkConsent(): Promise<void> {
    try {
        console.log(chalk.dim('Checking consent...'));
        const status = await gwClient.checkConsent();
        console.log(chalk.green(`✓ Consent status: ${status}`));
    } catch (ex: any) {
        if (ex instanceof AirlockGatewayError) {
            const code = ex.errorCode;
            if (code === 'app_consent_required' || code === 'app_consent_pending') {
                console.log(chalk.yellow('┌─ Consent Required ──────────────────────────────┐'));
                console.log(chalk.yellow(`│ ${ex.message}`));
                console.log(chalk.yellow('│ A consent request has been sent to your mobile device.'));
                console.log(chalk.yellow('│ Please approve it in the Airlock mobile app.'));
                console.log(chalk.yellow('└─────────────────────────────────────────────────┘'));
                return;
            }
        }
        throw ex;
    }
}

// ── Pair Device ─────────────────────────────────────────────────────
async function doPair(): Promise<void> {
    if (!cfg.deviceId) {
        const defaultId = `dev-${os.hostname().toLowerCase()}`;
        cfg.deviceId = await input({ message: 'Device ID:', default: defaultId }) || defaultId;
    }

    // Choose: new pairing or claim pre-generated code
    const mode = await select({
        message: 'How do you want to pair?',
        choices: [
            { name: 'New pairing (generate code)', value: 'initiate' },
            { name: 'Claim a pre-generated code', value: 'claim' },
        ],
    });

    // Generate X25519 keypair for ECDH key agreement (libsodium — matches harp-samples)
    const sodium = require('libsodium-wrappers-sumo');
    await sodium.ready;
    const x25519kp = sodium.crypto_box_keypair();
    const x25519PubB64Url = Buffer.from(x25519kp.publicKey).toString('base64url');

    let pairingNonce: string;

    if (mode === 'claim') {
        const code = await input({ message: 'Enter the pre-generated pairing code:' });
        if (!code) return;

        const claimRes = await gwClient.claimPairing({
            pairingCode: code.trim(),
            deviceId: cfg.deviceId,
            enforcerId: cfg.enforcerId,
            enforcerLabel: 'Test Enforcer CLI',
            workspaceName: cfg.workspaceName,
            gatewayUrl: cfg.gatewayUrl,
            x25519PublicKey: x25519PubB64Url,
        });
        pairingNonce = claimRes.pairingNonce;
        console.log(chalk.green(`✓ Code claimed. Nonce: ${pairingNonce}`));
        console.log(chalk.dim('Waiting for the approver to complete pairing in the mobile app...'));
    } else {
        const res = await gwClient.initiatePairing({
            deviceId: cfg.deviceId,
            enforcerId: cfg.enforcerId,
            enforcerLabel: 'Test Enforcer CLI',
            workspaceName: cfg.workspaceName,
            x25519PublicKey: x25519PubB64Url,
        });
        pairingNonce = res.pairingNonce;

        console.log(chalk.yellow('┌─ Pairing Initiated ─────────────────────────────┐'));
        console.log(`│ Pairing Code: ${chalk.cyan.bold(res.pairingCode)}`);
        console.log(`│ Nonce:        ${res.pairingNonce}`);
        console.log('│ Enter this code in the Airlock mobile app to complete pairing.');
        console.log(chalk.yellow('└─────────────────────────────────────────────────┘'));
    }

    if (mode !== 'claim') {
        console.log(chalk.dim('Waiting for the approver to complete pairing in the mobile app...'));
    }
    for (let i = 0; i < 60; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const status = await gwClient.getPairingStatus(pairingNonce);
        const state = (status.state || '').toLowerCase();
        console.log(chalk.dim(`  Pairing status: ${state} (${(i + 1) * 5}s)`));

        if (state === 'completed') {
            cfg.routingToken = (status as any).routingToken || '';

            // Extract approver's X25519 public key from responseJson and derive shared key
            const respJson = (status as any).responseJson;
            if (respJson) {
                try {
                    const respData = JSON.parse(respJson);
                    const approverPubKeyB64 = respData.x25519PublicKey;
                    if (approverPubKeyB64) {
                        const approverPubRaw = Buffer.from(approverPubKeyB64, 'base64url');
                        // X25519 ECDH via libsodium scalar multiplication (matches harp-samples)
                        const sharedSecret = sodium.crypto_scalarmult(
                            x25519kp.privateKey,
                            new Uint8Array(approverPubRaw),
                        );
                        // HKDF-SHA256 to derive AES-256 key
                        const derived = crypto.hkdfSync('sha256', Buffer.from(sharedSecret),
                            Buffer.alloc(0), Buffer.from('HARP-E2E-AES256GCM', 'utf8'), 32);
                        cfg.encryptionKey = Buffer.from(derived).toString('base64url');
                        console.log(chalk.green('✓ X25519 ECDH key agreement completed — E2E encryption enabled'));
                    }
                } catch (ex: any) {
                    console.log(chalk.yellow(`⚠ Failed to derive encryption key: ${ex.message}`));
                }
            }

            if (!cfg.encryptionKey) {
                console.log(chalk.yellow('⚠ No approver X25519 key received — encryption will use random test keys'));
            }

            saveConfig();
            console.log(chalk.green('✓ Paired! Routing token saved.'));
            startHeartbeat();
            return;
        }
        if (state === 'revoked' || state === 'expired') {
            console.log(chalk.red(`Pairing ${state}`));
            return;
        }
    }
    console.log(chalk.red('Pairing timed out or was rejected.'));
}

// ── Submit Artifact ─────────────────────────────────────────────────
async function doSubmit(): Promise<void> {
    await ensureFreshToken();

    const requestLabel = 'Test approval request from TypeScript enforcer';
    const plaintextPayload = JSON.stringify({
        requestLabel,
        command: 'dotnet test --filter Category=Integration',
        workspaceName: cfg.workspaceName,
        enforcerId: cfg.enforcerId,
        timestamp: new Date().toISOString(),
    });

    let encKey = cfg.encryptionKey;
    if (!encKey) {
        encKey = crypto.randomBytes(32).toString('base64url');
        console.log(chalk.yellow('⚠ No encryption key from pairing — using random test key'));
    }

    console.log(chalk.dim('Submitting encrypted artifact...'));
    const submittedId = await gwClient.encryptAndSubmitArtifact({
        enforcerId: cfg.enforcerId,
        artifactType: 'command-approval',
        plaintextPayload,
        encryptionKeyBase64Url: encKey,
        metadata: {
            routingToken: cfg.routingToken,
            workspaceName: cfg.workspaceName,
            requestLabel,
        },
    });

    lastRequestId = submittedId;
    console.log(chalk.green(`✓ Submitted: ${lastRequestId} (AES-256-GCM encrypted)`));

    // Long-poll for decision
    console.log(chalk.dim('Waiting for decision...'));
    const deadline = Date.now() + 120_000;
    let poll = 0;

    while (Date.now() < deadline) {
        poll++;
        console.log(chalk.dim(`  Waiting for decision... (${poll * 25}s elapsed)`));

        try {
            const env = await gwClient.waitForDecision(lastRequestId, 25);
            if (env?.body) {
                const isApproved = (env.body.decision || '').toLowerCase() === 'approve';
                const icon = isApproved ? '✓' : '✗';
                const color = isApproved ? chalk.green : chalk.red;

                console.log(color('┌─ Decision ──────────────────────────────────────┐'));
                console.log(color(`│ ${icon} ${(env.body.decision || 'UNKNOWN').toUpperCase()}`));
                if (env.body.reason) console.log(`│ Reason: ${env.body.reason}`);
                if (env.body.signerKeyId) console.log(`│ Signer: ${env.body.signerKeyId}`);
                console.log(color('└─────────────────────────────────────────────────┘'));
                return;
            }
        } catch (ex: any) {
            if (ex instanceof AirlockGatewayError && ex.statusCode === 404) {
                return;
            }
            throw ex;
        }
    }

    console.log(chalk.yellow('⏳ Timed out waiting for decision.'));
    await doWithdraw();
}

// ── Withdraw ────────────────────────────────────────────────────────
async function doWithdraw(): Promise<void> {
    let reqId = lastRequestId;
    if (!reqId) {
        reqId = await input({ message: 'Request ID to withdraw:' });
        if (!reqId) return;
    }

    try {
        await gwClient.withdrawExchange(reqId);
        console.log(chalk.green(`✓ Withdrawn: ${reqId}`));
        lastRequestId = '';
    } catch (ex: any) {
        console.log(chalk.yellow(`Withdraw failed (non-fatal): ${ex.message || ex}`));
    }
}

// ── Unpair ──────────────────────────────────────────────────────────
async function doUnpair(): Promise<void> {
    if (!cfg.routingToken) {
        console.log(chalk.dim('Not paired.'));
        return;
    }

    const yes = await confirm({ message: 'Revoke pairing?', default: false });
    if (!yes) return;

    try {
        await gwClient.revokePairing(cfg.routingToken);
    } catch (ex: any) {
        console.log(chalk.dim(`Server revoke failed (token may be stale): ${ex.message || ex}`));
    }

    cfg.routingToken = '';
    cfg.deviceId = '';
    stopHeartbeat();
    saveConfig();
    console.log(chalk.green('✓ Unpaired.'));
}

// ── Sign Out ────────────────────────────────────────────────────────
async function doSignOut(): Promise<void> {
    try {
        await authClient.logout();
    } catch {
        // best effort
    }

    cfg.accessToken = '';
    cfg.refreshToken = '';
    cfg.pat = '';
    cfg.tokenExpiresAt = 0;
    gwClient.setBearerToken(undefined);
    gwClient.setPat(undefined);
    stopHeartbeat();
    saveConfig();
    console.log(chalk.green('✓ Signed out.'));
}

// ── Session Restore ─────────────────────────────────────────────────
async function tryRestoreSession(): Promise<void> {
    // PAT takes priority — no need for token refresh
    if (cfg.pat) {
        gwClient.setPat(cfg.pat);
        console.log(chalk.green('✓ PAT restored'));

        // Validate PAT is still active — handle revoked tokens gracefully
        try {
            await checkConsent();
        } catch (ex: any) {
            if (ex instanceof AirlockGatewayError && ex.statusCode === 401) {
                console.log(chalk.red('✗ PAT is invalid or revoked.'));
                console.log(chalk.yellow('Please set a new PAT or sign in with OAuth.'));
                cfg.pat = '';
                gwClient.setPat(undefined);
                saveConfig();
                return;
            }
            // Non-401 errors — log but don't crash
            console.log(chalk.yellow(`⚠ PAT validation failed: ${ex.message || ex}`));
        }

        if (cfg.routingToken) startHeartbeat();
        return;
    }

    if (!cfg.refreshToken) return;

    authClient.restoreTokens(cfg.accessToken, cfg.refreshToken, cfg.tokenExpiresAt);

    try {
        console.log(chalk.dim('Refreshing session...'));
        await authClient.refreshTokenAsync();

        const state = authClient.getTokenState();
        cfg.accessToken = state.accessToken ?? '';
        cfg.refreshToken = state.refreshToken ?? '';
        cfg.tokenExpiresAt = state.expiresAt;
        saveConfig();

        gwClient.setBearerToken(state.accessToken ?? undefined);
        console.log(chalk.green('✓ Session restored'));

        await checkConsent();

        if (cfg.routingToken) {
            startHeartbeat();
        }
    } catch (ex: any) {
        console.log(chalk.yellow(`Session expired: ${ex.message || ex}`));
        cfg.accessToken = '';
        cfg.refreshToken = '';
        cfg.tokenExpiresAt = 0;
        saveConfig();
    }
}

// ── Re-apply Auth After Reconfigure ─────────────────────────────────
function reapplyAuth(): void {
    if (cfg.pat) {
        gwClient.setPat(cfg.pat);
        console.log(chalk.green('✓ PAT re-applied'));
    } else if (cfg.accessToken) {
        gwClient.setBearerToken(cfg.accessToken);
        console.log(chalk.green('✓ Bearer token re-applied'));
    }
}

// ── Token Refresh ───────────────────────────────────────────────────
async function ensureFreshToken(): Promise<void> {
    if (authClient?.isTokenExpired && cfg.refreshToken) {
        await authClient.refreshTokenAsync();
        const state = authClient.getTokenState();
        cfg.accessToken = state.accessToken ?? '';
        cfg.refreshToken = state.refreshToken ?? '';
        cfg.tokenExpiresAt = state.expiresAt;
        gwClient.setBearerToken(state.accessToken ?? undefined);
        saveConfig();
    }
}

// ── Background Heartbeat ────────────────────────────────────────────
function startHeartbeat(): void {
    stopHeartbeat();
    console.log(chalk.dim('❤ Heartbeat started (every 10s)'));

    const sendBeat = async () => {
        try {
            await gwClient.sendHeartbeat({
                enforcerId: cfg.enforcerId,
                enforcerLabel: 'Test Enforcer CLI',
                workspaceName: cfg.workspaceName,
            });
        } catch (ex: any) {
            console.log(chalk.yellow(`❤ Heartbeat failed: ${ex.message || ex}`));
        }
    };

    // Send an immediate heartbeat so the enforcer shows online right away
    sendBeat();

    heartbeatInterval = setInterval(sendBeat, 10_000);
}

function stopHeartbeat(): void {
    if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
        heartbeatInterval = null;
        console.log(chalk.dim('❤ Heartbeat stopped'));
    }
}

// ── Setup Wizard ────────────────────────────────────────────────────
async function runSetupWizard(): Promise<void> {
    stopHeartbeat();
    console.log(chalk.yellow('─── Setup ──────────────────────────────────────'));

    cfg.gatewayUrl = await input({ message: 'Gateway URL:', default: cfg.gatewayUrl }) || cfg.gatewayUrl;
    cfg.clientId = await input({ message: 'Client ID:', default: cfg.clientId }) || cfg.clientId;
    cfg.clientSecret = await password({ message: 'Client Secret:', mask: '*' }) || cfg.clientSecret;
    cfg.enforcerId = await input({ message: 'Enforcer ID:', default: cfg.enforcerId }) || cfg.enforcerId;
    cfg.workspaceName = await input({ message: 'Workspace Name:', default: cfg.workspaceName }) || cfg.workspaceName;

    saveConfig();
    console.log(chalk.green('✓ Configuration saved'));
}

// ── Error Handling ──────────────────────────────────────────────────
function handleError(ex: unknown): void {
    if (ex instanceof AirlockGatewayError) {
        console.log(chalk.red('┌─ Gateway Error ─────────────────────────────────┐'));
        if (ex.errorCode) console.log(chalk.red(`│ ${ex.errorCode}`));
        console.log(chalk.red(`│ ${ex.message}`));
        console.log(chalk.red('└─────────────────────────────────────────────────┘'));

        const consent = AirlockAuthClient.parseConsentError(ex.statusCode ?? 0, ex.responseBody || '');
        if (consent) {
            console.log(chalk.yellow('┌─ Consent Required ──────────────────────────────┐'));
            console.log(chalk.yellow(`│ ${consent.message}`));
            console.log(chalk.yellow('│ A consent request has been sent to your mobile device.'));
            console.log(chalk.yellow('│ Please approve it in the Airlock mobile app.'));
            console.log(chalk.yellow('└─────────────────────────────────────────────────┘'));
        }
    } else {
        console.log(chalk.red(`[Error] ${(ex as Error)?.message || ex}`));
    }
}

// ── Main ─────────────────────────────────────────────────────────────
async function main(): Promise<void> {
    console.log(chalk.cyan.bold('╔═══════════════════════════════════════════╗'));
    console.log(chalk.cyan.bold('║    Airlock Test Enforcer (TypeScript)      ║'));
    console.log(chalk.cyan.bold('╚═══════════════════════════════════════════╝'));
    console.log();

    loadConfig();
    await discoverGateway();

    if (!cfg.clientId) {
        await runSetupWizard();
        await discoverGateway();
    }

    initClients();
    await tryRestoreSession();
    printStatus();

    while (true) {
        const choices = buildMenuChoices();
        let choice: string;
        try {
            choice = await select({
                message: chalk.cyan.bold('Choose action'),
                choices,
            });
        } catch {
            stopHeartbeat();
            console.log(chalk.dim('Goodbye!'));
            process.exit(0);
        }

        try {
            switch (choice) {
                case 'setpat': await doSetPat(); break;
                case 'signin': await doSignIn(); break;
                case 'pair': await doPair(); break;
                case 'submit': await doSubmit(); break;
                case 'withdraw': await doWithdraw(); break;
                case 'unpair': await doUnpair(); break;
                case 'signout': await doSignOut(); break;
                case 'reconfig':
                    await runSetupWizard();
                    await discoverGateway();
                    initClients();
                    reapplyAuth();
                    break;
                case 'exit':
                    stopHeartbeat();
                    console.log(chalk.dim('Goodbye!'));
                    process.exit(0);
            }
        } catch (ex: any) {
            handleError(ex);
        }
    }
}

main().catch((err) => {
    console.error(chalk.red(err.message || err));
    process.exit(1);
});
