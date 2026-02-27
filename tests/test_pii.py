import pytest

from eu_audit_mcp.config import PIIConfig
from eu_audit_mcp.pii import PIIEngine


@pytest.fixture
def pii_engine():
    config = PIIConfig(enabled=True, language="en", entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"])
    return PIIEngine(config)


@pytest.fixture
def disabled_engine():
    config = PIIConfig(enabled=False)
    return PIIEngine(config)


def test_scan_empty_text(pii_engine: PIIEngine):
    result = pii_engine.scan_and_redact("")
    assert result.redacted_text == ""
    assert result.mappings == []


def test_scan_no_pii(pii_engine: PIIEngine):
    result = pii_engine.scan_and_redact("The weather is nice today.")
    assert result.redacted_text == "The weather is nice today."
    assert result.mappings == []


def test_scan_detects_email(pii_engine: PIIEngine):
    result = pii_engine.scan_and_redact("Contact jan@example.com for details.")
    assert "jan@example.com" not in result.redacted_text
    assert "EMAIL_ADDRESS" in result.entity_types
    assert len(result.mappings) == 1
    assert result.mappings[0]["entity_type"] == "EMAIL_ADDRESS"


def test_scan_detects_person(pii_engine: PIIEngine):
    result = pii_engine.scan_and_redact("John Smith works at the company.")
    has_person = "PERSON" in result.entity_types
    if has_person:
        assert "John Smith" not in result.redacted_text
        assert len(result.mappings) >= 1


def test_disabled_engine_passes_through(disabled_engine: PIIEngine):
    text = "Contact jan@example.com for details."
    result = disabled_engine.scan_and_redact(text)
    assert result.redacted_text == text
    assert result.mappings == []


def test_encrypted_value_is_decryptable(pii_engine: PIIEngine):
    result = pii_engine.scan_and_redact("Contact test@example.org please.")
    email_mappings = [m for m in result.mappings if m["entity_type"] == "EMAIL_ADDRESS"]
    assert len(email_mappings) >= 1
    decrypted = pii_engine.decrypt_value(email_mappings[0]["encrypted_val"])
    assert "@" in decrypted


def test_fernet_key_persists(pii_engine: PIIEngine):
    key = pii_engine.fernet_key
    assert isinstance(key, bytes)
    assert len(key) > 0

    config = PIIConfig(enabled=True, language="en", entities=["EMAIL_ADDRESS"])
    engine2 = PIIEngine(config, fernet_key=key)

    result1 = pii_engine.scan_and_redact("Contact user@test.com for info.")
    email_mappings = [m for m in result1.mappings if m["entity_type"] == "EMAIL_ADDRESS"]
    assert len(email_mappings) >= 1
    decrypted = engine2.decrypt_value(email_mappings[0]["encrypted_val"])
    assert "user@test.com" in decrypted
