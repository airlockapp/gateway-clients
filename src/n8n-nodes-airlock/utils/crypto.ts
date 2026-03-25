import * as crypto from 'node:crypto';

export interface X25519KeyPair {
    publicKey: string;   // base64url
    privateKey: string;  // base64url
}

/**
 * Generate an ephemeral X25519 keypair for ECDH key agreement.
 */
export function generateX25519KeyPair(): X25519KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    return {
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url'),
    };
}

/**
 * Derive a shared AES-256-GCM key from ECDH key agreement.
 */
export function deriveSharedKey(
    localPrivateKeyBase64Url: string,
    remotePublicKeyBase64Url: string
): string {
    const privKey = crypto.createPrivateKey({
        key: Buffer.from(localPrivateKeyBase64Url, 'base64url'),
        format: 'der',
        type: 'pkcs8',
    });

    let remotePubBuf = Buffer.from(remotePublicKeyBase64Url, 'base64url');
    if (remotePubBuf.length === 32) {
        // Wrap raw 32-byte key in X25519 SPKI DER header
        const X25519_SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex');
        remotePubBuf = Buffer.concat([X25519_SPKI_HEADER, remotePubBuf]);
    }
    const pubKey = crypto.createPublicKey({
        key: remotePubBuf,
        format: 'der',
        type: 'spki',
    });

    // ECDH shared secret
    const sharedSecret = crypto.diffieHellman({
        publicKey: pubKey,
        privateKey: privKey,
    });

    // HKDF-SHA256 to derive 256-bit AES key
    const derivedKey = crypto.hkdfSync(
        'sha256',
        sharedSecret,
        Buffer.alloc(0), // no salt (both sides must agree)
        Buffer.from('HARP-E2E-AES256GCM', 'utf-8'), // info string per HARP context
        32
    );

    return Buffer.from(derivedKey).toString('base64url');
}
