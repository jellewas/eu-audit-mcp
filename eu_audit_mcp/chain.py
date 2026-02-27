from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any


GENESIS_HASH = "0" * 64


def generate_secret() -> str:
    return secrets.token_hex(32)


def compute_hash(event_data: dict[str, Any], previous_hash: str, secret: str) -> str:
    """Compute HMAC-SHA256 over canonical event data chained to the previous hash."""
    canonical = json.dumps(event_data, sort_keys=True, default=str)
    message = f"{previous_hash}:{canonical}"
    return hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()


def verify_event(
    event_data: dict[str, Any],
    expected_hash: str,
    previous_hash: str,
    secret: str,
) -> bool:
    """Verify a single event's hash against its predecessor."""
    computed = compute_hash(event_data, previous_hash, secret)
    return hmac.compare_digest(computed, expected_hash)
