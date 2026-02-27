"""EU Audit Trail MCP Server.

Provides tamper-evident audit logging, PII scanning, GDPR erasure,
and EU AI Act compliance checking via the Model Context Protocol.

Regulatory coverage:
- EU AI Act (2024/1689) Art. 12 (Record-Keeping), Art. 19 (Log Retention)
- GDPR (2016/679) Art. 17 (Right to Erasure), Art. 30 (Processing Records)
"""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .compliance import run_compliance_check
from .config import AuditConfig
from .pii import PIIEngine
from .store import AuditStore

mcp = FastMCP("eu-audit")

_config: AuditConfig | None = None
_store: AuditStore | None = None
_pii: PIIEngine | None = None


async def _get_deps() -> tuple[AuditStore, PIIEngine, AuditConfig]:
    global _config, _store, _pii
    if _config is None:
        _config = AuditConfig.load()
    if _store is None:
        _store = AuditStore(_config)
        await _store.open()
    if _pii is None:
        stored_key = await _store.get_metadata("fernet_key")
        if stored_key:
            fernet_key = stored_key.encode()
        else:
            from cryptography.fernet import Fernet
            fernet_key = Fernet.generate_key()
            await _store.set_metadata("fernet_key", fernet_key.decode())
        _pii = PIIEngine(_config.pii, fernet_key=fernet_key)
    return _store, _pii, _config


# ---------------------------------------------------------------------------
# Logging tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def log_event(
    event_type: str,
    content: str | None = None,
    metadata: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Record an audit event. PII in content is automatically detected and redacted before storage.

    Args:
        event_type: Category of event (e.g. 'user_query', 'document_ingest', 'error').
        content: Free-text content to log. PII will be scanned and redacted.
        metadata: Arbitrary key-value metadata (purpose, source, etc.).
        session_id: Optional session identifier to group related events.

    Returns:
        event_id, timestamp, chain_hash, and list of PII types detected.
    """
    store, pii, _ = await _get_deps()

    pii_types: list[str] = []
    if content:
        result = pii.scan_and_redact(content)
        content = result.redacted_text
        pii_types = result.entity_types
        if result.mappings:
            event_result = await store.append_event(
                event_type=event_type,
                content=content,
                metadata=metadata,
                pii_types=pii_types or None,
                session_id=session_id,
            )
            for m in result.mappings:
                await store.store_pii_mapping(
                    event_id=event_result["event_id"],
                    placeholder=m["placeholder"],
                    entity_type=m["entity_type"],
                    encrypted_val=m["encrypted_val"],
                )
            event_result["pii_detected"] = pii_types
            return event_result

    event_result = await store.append_event(
        event_type=event_type,
        content=content,
        metadata=metadata,
        pii_types=pii_types or None,
        session_id=session_id,
    )
    event_result["pii_detected"] = pii_types
    return event_result


@mcp.tool()
async def log_inference(
    model: str,
    tokens_in: int,
    tokens_out: int,
    data_residency: str = "EU",
    cost_eur: float = 0.0,
    session_id: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    """Log an LLM inference call for audit purposes.

    Args:
        model: Model identifier (e.g. 'mistral-large').
        tokens_in: Number of input tokens.
        tokens_out: Number of output tokens.
        data_residency: Where inference was processed (e.g. 'EU-SE').
        cost_eur: Estimated cost in EUR.
        session_id: Optional session identifier.
        purpose: Processing purpose (recommended for GDPR Art. 30).

    Returns:
        event_id, timestamp, and chain_hash.
    """
    store, _, _ = await _get_deps()
    meta: dict[str, Any] = {
        "model": model,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "data_residency": data_residency,
        "cost_eur": cost_eur,
    }
    if purpose:
        meta["purpose"] = purpose
    return await store.append_event(
        event_type="llm_inference",
        metadata=meta,
        session_id=session_id,
    )


@mcp.tool()
async def log_data_access(
    source: str,
    action: str,
    chunks_retrieved: int = 0,
    session_id: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    """Log a document or data access event for audit purposes.

    Args:
        source: Document or data source identifier.
        action: What was done (e.g. 'ingest', 'retrieve', 'delete').
        chunks_retrieved: Number of chunks retrieved (for RAG queries).
        session_id: Optional session identifier.
        purpose: Processing purpose (recommended for GDPR Art. 30).

    Returns:
        event_id, timestamp, and chain_hash.
    """
    store, _, _ = await _get_deps()
    meta: dict[str, Any] = {
        "source": source,
        "action": action,
        "chunks_retrieved": chunks_retrieved,
    }
    if purpose:
        meta["purpose"] = purpose
    return await store.append_event(
        event_type="data_access",
        metadata=meta,
        session_id=session_id,
    )


# ---------------------------------------------------------------------------
# Query tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def query_log(
    event_type: str | None = None,
    session_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search the audit log with optional filters.

    Args:
        event_type: Filter by event type.
        session_id: Filter by session.
        since: ISO timestamp lower bound.
        until: ISO timestamp upper bound.
        limit: Max number of results (default 50, max 10000).

    Returns:
        List of matching audit events.
    """
    store, _, _ = await _get_deps()
    return await store.query_events(
        event_type=event_type,
        session_id=session_id,
        since=since,
        until=until,
        limit=limit,
    )


@mcp.tool()
async def get_session_trace(session_id: str) -> list[dict[str, Any]]:
    """Get the full ordered trace of a specific session.

    Args:
        session_id: The session to trace.

    Returns:
        All events for that session in chronological order.
    """
    store, _, _ = await _get_deps()
    return await store.query_events(session_id=session_id, limit=10000)


@mcp.tool()
async def get_stats(
    since: str | None = None, until: str | None = None
) -> dict[str, Any]:
    """Get summary statistics for the audit log.

    Args:
        since: ISO timestamp lower bound.
        until: ISO timestamp upper bound.

    Returns:
        Total events, breakdown by type, PII detection count, cost totals.
    """
    store, _, _ = await _get_deps()
    return await store.get_stats(since=since, until=until)


# ---------------------------------------------------------------------------
# Compliance tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def compliance_check() -> dict[str, Any]:
    """Run a technical compliance check against EU AI Act and GDPR.

    Checks:
    - EU AI Act Art. 12 — Record-keeping (event logging)
      https://artificialintelligenceact.eu/article/12/
    - EU AI Act Art. 19 — Automatically generated logs (retention, integrity)
      https://artificialintelligenceact.eu/article/19/
    - GDPR Art. 30 — Records of processing activities (purpose, PII categories)
      https://gdpr.eu/article-30-records-of-processing-activities/

    Returns:
        Overall pass/fail and per-article check results with details and reference URLs.
        This is a technical checklist, not legal advice.
    """
    store, _, config = await _get_deps()
    report = await run_compliance_check(store, config.retention_months)
    return report.to_dict()


@mcp.tool()
async def execute_erasure(
    entity_type: str, search_value: str
) -> dict[str, Any]:
    """Execute a GDPR Article 17 right-to-erasure request.

    Legal basis: GDPR Art. 17 — Right to erasure ("right to be forgotten")
    https://gdpr.eu/article-17-right-to-be-forgotten/

    Redacts event content and removes PII vault entries for the specified entity.
    The events themselves are kept (to preserve the hash chain for EU AI Act Art. 19
    integrity) but their content is replaced with a redaction notice. The erasure
    itself is logged as a gdpr_erasure event.

    Args:
        entity_type: PII type to erase (e.g. 'PERSON', 'EMAIL_ADDRESS').
        search_value: Placeholder pattern to match in the vault.

    Returns:
        Count of events redacted and vault entries removed.
    """
    store, _, _ = await _get_deps()
    return await store.erase_entity(entity_type, search_value)


@mcp.tool()
async def get_pii_summary() -> dict[str, int]:
    """Get a summary of PII types detected across all logged events.

    Returns only counts per entity type, never actual PII values.

    Returns:
        Dictionary mapping PII entity types to their occurrence counts.
    """
    store, _, _ = await _get_deps()
    return await store.get_pii_summary()


# ---------------------------------------------------------------------------
# Integrity tool
# ---------------------------------------------------------------------------


@mcp.tool()
async def verify_chain() -> dict[str, Any]:
    """Verify the HMAC-SHA256 hash chain integrity of the audit log.

    Returns:
        Whether the chain is intact, and if not, which event broke it.
    """
    store, _, _ = await _get_deps()
    return await store.verify_chain()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
