"""
RFC 8785 JSON Canonicalization Scheme (JCS).
Produces deterministic JSON surface for hashing and signing.
"""

import json
from typing import Any

from .crypto_helpers import sha256_hex


def canonicalize(json_str: str) -> str:
    """Canonicalize a JSON string per RFC 8785 (JCS)."""
    parsed = json.loads(json_str)
    return _canonical_value(parsed)


def canonical_serialize(obj: Any) -> str:
    """Serialize an object to canonical JSON (RFC 8785 JCS)."""
    json_str = json.dumps(obj, ensure_ascii=False, default=str)
    return canonicalize(json_str)


def hash_canonical(obj: Any) -> str:
    """Compute the canonical JSON hash (SHA-256) of an object."""
    canonical = canonical_serialize(obj)
    return sha256_hex(canonical)


def _canonical_value(v: Any) -> str:
    """Recursively canonicalize a JSON value per RFC 8785."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # RFC 8785: integers should not have decimal points
        if v == int(v) and abs(v) <= 1e15:
            return str(int(v))
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        parts = [_canonical_value(elem) for elem in v]
        return "[" + ",".join(parts) + "]"
    if isinstance(v, dict):
        # Sort keys lexicographically (by Unicode code point)
        sorted_keys = sorted(v.keys())
        parts = [json.dumps(k, ensure_ascii=False) + ":" + _canonical_value(v[k]) for k in sorted_keys]
        return "{" + ",".join(parts) + "}"
    # Fallback: use json.dumps
    return json.dumps(v, ensure_ascii=False, default=str)
