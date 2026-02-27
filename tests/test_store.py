import asyncio
import os
import tempfile

import pytest
import pytest_asyncio

from eu_audit_mcp.config import AuditConfig
from eu_audit_mcp.store import AuditStore


@pytest_asyncio.fixture
async def store(tmp_path):
    db_path = str(tmp_path / "test_audit.db")
    config = AuditConfig(database_path=db_path)
    s = AuditStore(config)
    await s.open()
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_append_and_query(store: AuditStore):
    result = await store.append_event(
        event_type="test_event",
        content="hello world",
        metadata={"key": "value"},
        session_id="sess1",
    )
    assert "event_id" in result
    assert "chain_hash" in result

    events = await store.query_events(event_type="test_event")
    assert len(events) == 1
    assert events[0]["content"] == "hello world"
    assert events[0]["session_id"] == "sess1"


@pytest.mark.asyncio
async def test_query_by_session(store: AuditStore):
    await store.append_event(event_type="a", session_id="s1")
    await store.append_event(event_type="b", session_id="s2")
    await store.append_event(event_type="c", session_id="s1")

    events = await store.query_events(session_id="s1")
    assert len(events) == 2
    assert all(e["session_id"] == "s1" for e in events)


@pytest.mark.asyncio
async def test_chain_integrity(store: AuditStore):
    for i in range(5):
        await store.append_event(event_type="test", content=f"event {i}")

    result = await store.verify_chain()
    assert result["intact"] is True
    assert result["total_events"] == 5


@pytest.mark.asyncio
async def test_stats(store: AuditStore):
    await store.append_event(event_type="llm_inference", metadata={
        "model": "mistral-large",
        "tokens_in": 100,
        "tokens_out": 50,
        "cost_eur": 0.005,
    })
    await store.append_event(event_type="data_access")
    await store.append_event(event_type="data_access")

    stats = await store.get_stats()
    assert stats["total_events"] == 3
    assert stats["by_type"]["llm_inference"] == 1
    assert stats["by_type"]["data_access"] == 2
    assert stats["total_cost_eur"] == 0.005
    assert stats["total_tokens_in"] == 100


@pytest.mark.asyncio
async def test_pii_vault(store: AuditStore):
    result = await store.append_event(event_type="test", content="redacted")
    await store.store_pii_mapping(
        event_id=result["event_id"],
        placeholder="[PERSON_1]",
        entity_type="PERSON",
        encrypted_val="enc_value",
    )

    summary = await store.get_pii_summary()
    assert summary["PERSON"] == 1


@pytest.mark.asyncio
async def test_erasure(store: AuditStore):
    result = await store.append_event(
        event_type="test", content="Contains personal data"
    )
    await store.store_pii_mapping(
        event_id=result["event_id"],
        placeholder="[PERSON_1]",
        entity_type="PERSON",
        encrypted_val="enc_jan",
    )

    erasure = await store.erase_entity("PERSON", "PERSON_1")
    assert erasure["events_redacted"] == 1

    events = await store.query_events(event_type="test")
    assert events[0]["content"] == "[REDACTED — GDPR Art. 17 erasure]"

    erasure_events = await store.query_events(event_type="gdpr_erasure")
    assert len(erasure_events) == 1


@pytest.mark.asyncio
async def test_event_type_exists(store: AuditStore):
    assert await store.event_type_exists("nonexistent") is False
    await store.append_event(event_type="special")
    assert await store.event_type_exists("special") is True


@pytest.mark.asyncio
async def test_oldest_event_timestamp(store: AuditStore):
    assert await store.oldest_event_timestamp() is None
    await store.append_event(event_type="first")
    ts = await store.oldest_event_timestamp()
    assert ts is not None
