import pytest

from eu_audit_mcp.chain import GENESIS_HASH, compute_hash, generate_secret, verify_event


def test_generate_secret_is_64_hex_chars():
    secret = generate_secret()
    assert len(secret) == 64
    int(secret, 16)  # must be valid hex


def test_compute_hash_deterministic():
    data = {"id": "1", "event_type": "test"}
    secret = "abc123"
    h1 = compute_hash(data, GENESIS_HASH, secret)
    h2 = compute_hash(data, GENESIS_HASH, secret)
    assert h1 == h2


def test_compute_hash_changes_with_data():
    secret = "abc123"
    h1 = compute_hash({"id": "1"}, GENESIS_HASH, secret)
    h2 = compute_hash({"id": "2"}, GENESIS_HASH, secret)
    assert h1 != h2


def test_compute_hash_changes_with_previous_hash():
    data = {"id": "1"}
    secret = "abc123"
    h1 = compute_hash(data, GENESIS_HASH, secret)
    h2 = compute_hash(data, "a" * 64, secret)
    assert h1 != h2


def test_compute_hash_changes_with_secret():
    data = {"id": "1"}
    h1 = compute_hash(data, GENESIS_HASH, "secret_a")
    h2 = compute_hash(data, GENESIS_HASH, "secret_b")
    assert h1 != h2


def test_verify_event_passes_valid():
    data = {"id": "1", "event_type": "test"}
    secret = "mysecret"
    h = compute_hash(data, GENESIS_HASH, secret)
    assert verify_event(data, h, GENESIS_HASH, secret) is True


def test_verify_event_fails_tampered():
    data = {"id": "1", "event_type": "test"}
    secret = "mysecret"
    h = compute_hash(data, GENESIS_HASH, secret)
    data["event_type"] = "tampered"
    assert verify_event(data, h, GENESIS_HASH, secret) is False


def test_chain_of_three():
    secret = generate_secret()
    events = [
        {"id": "1", "event_type": "a"},
        {"id": "2", "event_type": "b"},
        {"id": "3", "event_type": "c"},
    ]
    prev = GENESIS_HASH
    hashes = []
    for evt in events:
        h = compute_hash(evt, prev, secret)
        hashes.append(h)
        prev = h

    prev = GENESIS_HASH
    for evt, expected_hash in zip(events, hashes):
        assert verify_event(evt, expected_hash, prev, secret)
        prev = expected_hash
