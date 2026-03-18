package airlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	aesKeySize   = 32
	aesNonceSize = 12
	aesTagSize   = 16
)

// EncryptedPayload represents an AES-256-GCM encrypted payload.
// Wire-compatible with the CiphertextRef schema in the HARP Gateway spec.
type EncryptedPayload struct {
	Alg   string `json:"alg"`
	Data  string `json:"data"`
	Nonce string `json:"nonce,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Aad   string `json:"aad,omitempty"`
}

// ── Base64url ────────────────────────────────────────────────

// ToBase64URL encodes bytes to a base64url string (no padding).
func ToBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// FromBase64URL decodes a base64url string (with or without padding).
func FromBase64URL(s string) ([]byte, error) {
	// Try without padding first, then with
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
	}
	return data, err
}

// ── SHA-256 ──────────────────────────────────────────────────

// SHA256Hex computes the lowercase hex SHA-256 of a string.
func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ── HKDF-SHA256 ──────────────────────────────────────────────

// HKDFDerive derives a key using HKDF-SHA256 (RFC 5869).
func HKDFDerive(ikm, salt, info []byte, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return out, nil
}

// ── X25519 ECDH Key Exchange ─────────────────────────────────

// X25519KeyPair holds an X25519 keypair for ECDH key agreement.
type X25519KeyPair struct {
	PublicKey  string // base64url (raw 32 bytes)
	PrivateKey string // base64url (raw 32 bytes)
}

// GenerateX25519KeyPair generates an X25519 keypair for ECDH.
func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &X25519KeyPair{
		PublicKey:  ToBase64URL(privKey.PublicKey().Bytes()),
		PrivateKey: ToBase64URL(privKey.Bytes()),
	}, nil
}

// DeriveSharedKey derives a shared AES-256 key from X25519 ECDH + HKDF-SHA256.
// Uses info string "HARP-E2E-AES256GCM" to match the enforcer extension pattern.
func DeriveSharedKey(myPrivateKeyBase64URL, peerPublicKeyBase64URL string) (string, error) {
	privBytes, err := FromBase64URL(myPrivateKeyBase64URL)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	pubBytes, err := FromBase64URL(peerPublicKeyBase64URL)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}

	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return "", fmt.Errorf("import private key: %w", err)
	}
	pubKey, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("import public key: %w", err)
	}

	sharedSecret, err := privKey.ECDH(pubKey)
	if err != nil {
		return "", fmt.Errorf("ecdh: %w", err)
	}

	info := []byte("HARP-E2E-AES256GCM")
	derived, err := HKDFDerive(sharedSecret, nil, info, aesKeySize)
	if err != nil {
		return "", err
	}

	return ToBase64URL(derived), nil
}

// ── AES-256-GCM Encrypt/Decrypt ──────────────────────────────

// AesGcmEncrypt encrypts plaintext with AES-256-GCM (detached nonce+tag).
func AesGcmEncrypt(keyBase64URL, plaintext string) (*EncryptedPayload, error) {
	key, err := FromBase64URL(keyBase64URL)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != aesKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", aesKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// GCM appends the tag to the ciphertext
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	ctLen := len(sealed) - gcm.Overhead()
	ciphertext := sealed[:ctLen]
	tag := sealed[ctLen:]

	return &EncryptedPayload{
		Alg:   "AES-256-GCM",
		Data:  base64.StdEncoding.EncodeToString(ciphertext),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Tag:   base64.StdEncoding.EncodeToString(tag),
	}, nil
}

// AesGcmDecrypt decrypts an AES-256-GCM encrypted payload.
func AesGcmDecrypt(keyBase64URL string, payload *EncryptedPayload) (string, error) {
	key, err := FromBase64URL(keyBase64URL)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return "", fmt.Errorf("decode data: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(payload.Tag)
	if err != nil {
		return "", fmt.Errorf("decode tag: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	// GCM expects ciphertext+tag concatenated
	sealed := append(data, tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// ── Ed25519 Signing & Verification ───────────────────────────

// GenerateEd25519KeyPair generates an Ed25519 signing keypair.
func GenerateEd25519KeyPair() (publicKeyBase64URL, privateKeyBase64URL string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	return ToBase64URL(pub), ToBase64URL(priv), nil
}

// Ed25519Sign signs a message with Ed25519. Returns base64url signature.
func Ed25519Sign(privateKeyBase64URL string, message []byte) (string, error) {
	privBytes, err := FromBase64URL(privateKeyBase64URL)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), message)
	return ToBase64URL(sig), nil
}

// Ed25519Verify verifies an Ed25519 signature. Returns true if valid.
func Ed25519Verify(publicKeyBase64URL string, message []byte, signatureBase64URL string) (bool, error) {
	pubBytes, err := FromBase64URL(publicKeyBase64URL)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}
	sig, err := FromBase64URL(signatureBase64URL)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, errors.New("invalid public key size")
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), message, sig), nil
}
