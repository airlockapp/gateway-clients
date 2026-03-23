import { describe, it, expect } from "vitest";
import { canonicalizeJson } from "../src/canonical-json.js";
import { sha256Hex } from "../src/crypto.js";

describe("canonicalizeJson", () => {
    it("matches other SDKs for integer-only reorder payload", () => {
        const c = canonicalizeJson('{"value":42,"action":"test"}');
        expect(c).toBe('{"action":"test","value":42}');
        expect(sha256Hex(c)).toBe(
            "d3c2d7effb479ffc5085aad2144df886a452a4863396060f4e0ea29a8409d0fd",
        );
    });
});
