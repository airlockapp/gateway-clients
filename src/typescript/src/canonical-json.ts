/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 * Object key ordering and whole-number handling match the Go/Rust gateway SDKs.
 * Whole numbers in JSON (including values like 42.0) in [-1e15, 1e15] serialize as decimal integers.
 * Other numeric values use JavaScript `toExponential` (uppercase E); exponent formatting may differ
 * slightly from Go's `strconv.FormatFloat` — use integer-only payloads for bit-identical hashes across SDKs.
 */

export function canonicalizeJson(input: string): string {
    let parsed: unknown;
    try {
        parsed = JSON.parse(input) as unknown;
    } catch {
        throw new Error("canonicalize: invalid json");
    }
    return canonicalValue(parsed);
}

function canonicalValue(v: unknown): string {
    if (v === null) return "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "number") return canonicalNumber(v);
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v)) {
        const parts = v.map((elem) => canonicalValue(elem));
        return `[${parts.join(",")}]`;
    }
    if (typeof v === "object") {
        const obj = v as Record<string, unknown>;
        const keys = Object.keys(obj).sort();
        const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalValue(obj[k])}`);
        return `{${parts.join(",")}}`;
    }
    throw new Error(`canonicalize: unsupported type ${typeof v}`);
}

function canonicalNumber(f: number): string {
    if (!Number.isFinite(f)) {
        throw new Error("canonicalize: non-finite number");
    }
    if (Object.is(f, -0)) f = 0;
    const t = Math.trunc(f);
    if (t === f && f >= -1e15 && f <= 1e15) {
        return String(t);
    }
    return f.toExponential().replace(/e(?=[+-])/i, "E");
}
