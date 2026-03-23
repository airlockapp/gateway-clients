// ── HARP Envelope ────────────────────────────────────────────────

export interface SenderInfo {
    enforcerId?: string;
    approverId?: string;
    gatewayId?: string;
}

export interface RecipientInfo {
    enforcerId?: string;
    approverId?: string;
}

export interface HarpEnvelope<T = unknown> {
    msgId?: string;
    msgType: string;
    requestId: string;
    createdAt?: string;
    expiresAt?: string;
    sender?: SenderInfo;
    recipient?: RecipientInfo;
    body?: T;
}

// ── Artifact Submit ─────────────────────────────────────────────

export interface CiphertextRef {
    alg: string;
    data: string;
    nonce?: string;
    tag?: string;
    aad?: string;
}

export interface ArtifactSubmitBody {
    artifactType: string;
    artifactHash: string;
    ciphertext: CiphertextRef;
    expiresAt: string;
    metadata?: Record<string, string>;
}

export interface ArtifactSubmitRequest {
    enforcerId: string;
    artifactType?: string;
    artifactHash: string;
    ciphertext: CiphertextRef;
    expiresAt?: string;
    metadata?: Record<string, string>;
    requestId?: string;
}

// ── Decision ────────────────────────────────────────────────────

export interface DecisionDeliverBody {
    artifactHash: string;
    decision: string;
    reason?: string;
    signerKeyId?: string;
    nonce?: string;
    signature?: string;
    decisionHash?: string;
}

export interface DecisionDeliverEnvelope {
    msgId?: string;
    msgType: string;
    requestId: string;
    body?: DecisionDeliverBody;
}

// ── Exchange Status ─────────────────────────────────────────────

export interface ExchangeStatusBody {
    requestId: string;
    state: string;
    createdAt?: string;
    expiresAt?: string;
    artifactHash?: string;
    decision?: unknown;
}

export interface ExchangeStatusResponse {
    msgType: string;
    requestId: string;
    body?: ExchangeStatusBody;
}

// ── Pairing ─────────────────────────────────────────────────────

export interface PairingInitiateRequest {
    deviceId: string;
    enforcerId: string;
    gatewayUrl?: string;
    x25519PublicKey?: string;
    enforcerLabel?: string;
    workspaceName?: string;
}

export interface PairingInitiateResponse {
    pairingNonce: string;
    pairingCode: string;
    deviceId: string;
    gatewayUrl?: string;
    expiresAt?: string;
}

export interface PairingStatusResponse {
    pairingNonce: string;
    state: string;
    responseJson?: string;
    routingToken?: string;
    expiresAt?: string;
}

export interface PairingRevokeResponse {
    status: string;
    enforcerId?: string;
}

// ── Pairing Claim (Pre-generated) ──────────────────────────────

export interface PairingClaimRequest {
    pairingCode: string;
    deviceId: string;
    enforcerId: string;
    enforcerLabel: string;
    workspaceName: string;
    gatewayUrl?: string;
    x25519PublicKey?: string;
}

export interface PairingClaimResponse {
    pairingNonce: string;
    expiresAt: string;
}

// ── Presence ────────────────────────────────────────────────────

export interface PresenceHeartbeatRequest {
    enforcerId: string;
    workspaceName?: string;
    enforcerLabel?: string;
}

// ── Echo ────────────────────────────────────────────────────────

export interface EchoResponse {
    utc: string;
    local: string;
    timezone: string;
    offsetMinutes: number;
}

// ── DND (Do Not Disturb) Policies ─────────────────────────────────

export interface DndPolicyWire {
    requestId: string;
    objectType: string;
    workspaceId: string;
    sessionId?: string;
    enforcerId: string;
    policyMode: string;
    targetArtifactType?: string;
    actionSelector?: Record<string, unknown>;
    selectorHash?: string;
    createdAt?: string;
    expiresAt: string;
}

export interface DndEffectiveResponse {
    msgType: string;
    requestId: string;
    body: DndPolicyWire[];
}
