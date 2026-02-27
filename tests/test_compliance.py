import pytest
import pytest_asyncio

from eu_audit_mcp.compliance import run_compliance_check
from eu_audit_mcp.config import AuditConfig
from eu_audit_mcp.store import AuditStore


@pytest_asyncio.fixture
async def store(tmp_path):
    db_path = str(tmp_path / "test_compliance.db")
    config = AuditConfig(database_path=db_path)
    s = AuditStore(config)
    await s.open()
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_empty_db_fails_all_checks(store: AuditStore):
    report = await run_compliance_check(store)
    assert report.overall_pass is False
    assert any(not c.passed for c in report.checks)


@pytest.mark.asyncio
async def test_minimal_passing_audit(store: AuditStore):
    await store.append_event(
        event_type="llm_inference",
        metadata={"model": "mistral-large", "tokens_in": 10, "tokens_out": 5, "cost_eur": 0.001, "purpose": "summarization"},
    )
    await store.append_event(
        event_type="data_access",
        metadata={"source": "doc.pdf", "action": "retrieve", "purpose": "search"},
    )
    # Add a PII-flagged event so GDPR Art. 30 data categories check passes
    await store.append_event(
        event_type="user_query",
        content="test",
        pii_types=["PERSON"],
    )
    await store.store_pii_mapping(
        event_id=(await store.query_events(event_type="user_query"))[0]["id"],
        placeholder="[PERSON_1]",
        entity_type="PERSON",
        encrypted_val="enc",
    )

    report = await run_compliance_check(store)
    assert report.overall_pass is True
    for check in report.checks:
        assert check.passed, f"Failed: {check.article} — {check.title}: {check.detail}"


@pytest.mark.asyncio
async def test_missing_inference_events(store: AuditStore):
    await store.append_event(event_type="data_access", metadata={"purpose": "test"})
    await store.append_event(event_type="user_query", pii_types=["PERSON"])
    await store.store_pii_mapping(
        event_id=(await store.query_events(event_type="user_query"))[0]["id"],
        placeholder="[PERSON_1]",
        entity_type="PERSON",
        encrypted_val="enc",
    )

    report = await run_compliance_check(store)
    inference_checks = [c for c in report.checks if "inference" in c.title.lower()]
    assert any(not c.passed for c in inference_checks)


@pytest.mark.asyncio
async def test_chain_integrity_in_compliance(store: AuditStore):
    await store.append_event(event_type="test")
    report = await run_compliance_check(store)
    chain_checks = [c for c in report.checks if "chain" in c.title.lower()]
    assert len(chain_checks) == 1
    assert chain_checks[0].passed is True


@pytest.mark.asyncio
async def test_report_to_dict(store: AuditStore):
    await store.append_event(event_type="test")
    report = await run_compliance_check(store)
    d = report.to_dict()
    assert "timestamp" in d
    assert "overall_pass" in d
    assert "checks" in d
    assert isinstance(d["checks"], list)
    for check in d["checks"]:
        assert "article" in check
        assert "passed" in check
