import { createCipheriv, createHash, randomBytes } from "node:crypto";
import type { CiphertextRef } from "./models.js";

const AES_KEY_SIZE = 32;
const AES_NONCE_SIZE = 12;
const AES_TAG_SIZE = 16;

function fromBase64Url(s: string): Buffer {
    let b = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b.length % 4;
    if (pad === 2) b += "==";
    else if (pad === 3) b += "=";
    return Buffer.from(b, "base64");
}

/** Lowercase hex SHA-256 of a UTF-8 string. */
export function sha256Hex(utf8: string): string {
    return createHash("sha256").update(utf8, "utf8").digest("hex");
}

/**
 * AES-256-GCM with detached nonce and tag (base64 fields), matching other SDKs.
 */
export function aesGcmEncrypt(keyBase64Url: string, plaintext: string): CiphertextRef {
    const key = fromBase64Url(keyBase64Url);
    if (key.length !== AES_KEY_SIZE) {
        throw new Error(`Key must be ${AES_KEY_SIZE} bytes, got ${key.length}`);
    }
    const nonce = randomBytes(AES_NONCE_SIZE);
    const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: AES_TAG_SIZE });
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        alg: "AES-256-GCM",
        data: ciphertext.toString("base64"),
        nonce: nonce.toString("base64"),
        tag: tag.toString("base64"),
    };
}
