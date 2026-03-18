//! HARP cryptographic primitives: AES-256-GCM, X25519, HKDF, Ed25519, Base64url, SHA-256.
//! Adapted from the HARP reference implementation (harp-samples).

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PubKey, StaticSecret};

const AES_KEY_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;

/// Encrypted payload (AES-256-GCM) with base64-encoded fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub alg: String,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

// ── Base64url ────────────────────────────────────────────────

/// Encode bytes to base64url (no padding).
pub fn to_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url (with or without padding).
pub fn from_base64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))
}

// ── SHA-256 ──────────────────────────────────────────────────

/// Compute lowercase hex SHA-256 of a UTF-8 string.
pub fn sha256_hex(s: &str) -> String {
    let hash = Sha256::digest(s.as_bytes());
    hex::encode(hash)
}

// ── HKDF-SHA256 ──────────────────────────────────────────────

/// Derive a key using HKDF-SHA256 (RFC 5869).
pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let hkdf = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).map_err(|e| format!("hkdf expand: {e}"))?;
    Ok(okm)
}

// ── X25519 ECDH Key Exchange ─────────────────────────────────

/// X25519 keypair for ECDH key agreement.
pub struct X25519KeyPair {
    pub public_key: String,  // base64url (raw 32 bytes)
    pub private_key: String, // base64url (raw 32 bytes)
}

/// Generate an X25519 keypair for ECDH key agreement.
pub fn generate_x25519_keypair() -> X25519KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PubKey::from(&secret);
    X25519KeyPair {
        public_key: to_base64url(public.as_bytes()),
        private_key: to_base64url(secret.as_bytes()),
    }
}

/// Derive a shared AES-256 key from X25519 ECDH + HKDF-SHA256.
pub fn derive_shared_key(my_private_base64url: &str, peer_public_base64url: &str) -> Result<String, String> {
    let priv_bytes = from_base64url(my_private_base64url).map_err(|e| format!("decode privkey: {e}"))?;
    let pub_bytes = from_base64url(peer_public_base64url).map_err(|e| format!("decode pubkey: {e}"))?;

    let mut priv_arr = [0u8; 32];
    let mut pub_arr = [0u8; 32];
    if priv_bytes.len() != 32 || pub_bytes.len() != 32 {
        return Err("keys must be 32 bytes".into());
    }
    priv_arr.copy_from_slice(&priv_bytes);
    pub_arr.copy_from_slice(&pub_bytes);

    let secret = StaticSecret::from(priv_arr);
    let public = X25519PubKey::from(pub_arr);
    let shared_secret = secret.diffie_hellman(&public);

    let info = b"HARP-E2E-AES256GCM";
    let derived = hkdf_derive(shared_secret.as_bytes(), &[], info, AES_KEY_SIZE)?;
    Ok(to_base64url(&derived))
}

// ── AES-256-GCM Encrypt/Decrypt ──────────────────────────────

/// Encrypt plaintext with AES-256-GCM.
pub fn aes_gcm_encrypt(key_base64url: &str, plaintext: &str) -> Result<EncryptedPayload, String> {
    let key = from_base64url(key_base64url).map_err(|e| format!("decode key: {e}"))?;
    if key.len() != AES_KEY_SIZE {
        return Err(format!("key must be {AES_KEY_SIZE} bytes, got {}", key.len()));
    }

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("new cipher: {e}"))?;

    let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
    use rand::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).map_err(|e| format!("encrypt: {e}"))?;

    // AES-GCM appends the 16-byte tag
    let ct_len = ciphertext.len() - 16;
    let ct = &ciphertext[..ct_len];
    let tag = &ciphertext[ct_len..];

    Ok(EncryptedPayload {
        alg: "AES-256-GCM".into(),
        data: base64::engine::general_purpose::STANDARD.encode(ct),
        nonce: Some(base64::engine::general_purpose::STANDARD.encode(nonce_bytes)),
        tag: Some(base64::engine::general_purpose::STANDARD.encode(tag)),
        aad: None,
    })
}

/// Decrypt an AES-256-GCM encrypted payload.
pub fn aes_gcm_decrypt(key_base64url: &str, payload: &EncryptedPayload) -> Result<String, String> {
    let key = from_base64url(key_base64url).map_err(|e| format!("decode key: {e}"))?;
    let data = base64::engine::general_purpose::STANDARD.decode(&payload.data)
        .map_err(|e| format!("decode data: {e}"))?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(payload.nonce.as_deref().unwrap_or(""))
        .map_err(|e| format!("decode nonce: {e}"))?;
    let tag = base64::engine::general_purpose::STANDARD.decode(payload.tag.as_deref().unwrap_or(""))
        .map_err(|e| format!("decode tag: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("new cipher: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut sealed = data;
    sealed.extend_from_slice(&tag);
    let plaintext = cipher.decrypt(nonce, sealed.as_ref()).map_err(|e| format!("decrypt: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| format!("utf8: {e}"))
}

// ── Ed25519 Signing & Verification ───────────────────────────

/// Ed25519 keypair.
pub struct Ed25519KeyPair {
    pub public_key: String,  // base64url (raw 32 bytes)
    pub private_key: String, // base64url (raw 32 bytes)
}

/// Generate an Ed25519 signing keypair.
pub fn generate_ed25519_keypair() -> Ed25519KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ed25519KeyPair {
        public_key: to_base64url(verifying_key.as_bytes()),
        private_key: to_base64url(signing_key.as_bytes()),
    }
}

/// Sign a message with Ed25519. Returns base64url signature.
pub fn ed25519_sign(private_key_base64url: &str, message: &[u8]) -> Result<String, String> {
    let priv_bytes = from_base64url(private_key_base64url).map_err(|e| format!("decode key: {e}"))?;
    let mut key_arr = [0u8; 32];
    if priv_bytes.len() != 32 {
        return Err("private key must be 32 bytes".into());
    }
    key_arr.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes(&key_arr);
    let sig = signing_key.sign(message);
    Ok(to_base64url(&sig.to_bytes()))
}

/// Verify an Ed25519 signature. Returns true if valid.
pub fn ed25519_verify(public_key_base64url: &str, message: &[u8], signature_base64url: &str) -> Result<bool, String> {
    let pub_bytes = from_base64url(public_key_base64url).map_err(|e| format!("decode key: {e}"))?;
    let sig_bytes = from_base64url(signature_base64url).map_err(|e| format!("decode sig: {e}"))?;

    let mut key_arr = [0u8; 32];
    if pub_bytes.len() != 32 { return Err("public key must be 32 bytes".into()); }
    key_arr.copy_from_slice(&pub_bytes);

    let mut sig_arr = [0u8; 64];
    if sig_bytes.len() != 64 { return Err("signature must be 64 bytes".into()); }
    sig_arr.copy_from_slice(&sig_bytes);

    let verifying_key = VerifyingKey::from_bytes(&key_arr).map_err(|e| format!("import key: {e}"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    Ok(verifying_key.verify(message, &signature).is_ok())
}
