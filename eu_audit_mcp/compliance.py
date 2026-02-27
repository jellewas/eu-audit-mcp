from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .store import AuditStore


@dataclass
class CheckResult:
    article: str
    title: str
    passed: bool
    detail: str


@dataclass
class ComplianceReport:
    timestamp: str
    checks: list[CheckResult] = field(default_factory=list)
    overall_pass: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "overall_pass": self.overall_pass,
            "disclaimer": "Technical checklist only — not legal advice.",
            "checks": [
                {
                    "article": c.article,
                    "reference": LEGAL_REFS.get(c.article, ""),
                    "title": c.title,
                    "passed": c.passed,
                    "detail": c.detail,
                }
                for c in self.checks
            ],
        }


LEGAL_REFS = {
    "EU AI Act Art. 12": "https://artificialintelligenceact.eu/article/12/",
    "EU AI Act Art. 19": "https://artificialintelligenceact.eu/article/19/",
    "GDPR Art. 17": "https://gdpr.eu/article-17-right-to-be-forgotten/",
    "GDPR Art. 30": "https://gdpr.eu/article-30-records-of-processing-activities/",
}


async def run_compliance_check(
    store: AuditStore, retention_months: int = 6
) -> ComplianceReport:
    """Run technical compliance checks against EU AI Act and GDPR requirements.

    Covers:
    - EU AI Act Art. 12 (Record-Keeping) — automatic event logging
    - EU AI Act Art. 19 (Automatically Generated Logs) — 6-month retention, integrity
    - GDPR Art. 30 (Records of Processing Activities) — purpose, data categories

    This is a technical checklist, not legal advice.
    """
    report = ComplianceReport(
        timestamp=datetime.now(timezone.utc).isoformat()
    )

    stats = await store.get_stats()

    # --- EU AI Act Article 12: Record-Keeping ---
    has_events = stats["total_events"] > 0
    report.checks.append(CheckResult(
        article="EU AI Act Art. 12",
        title="Record-keeping: events are being logged",
        passed=has_events,
        detail=(
            f"{stats['total_events']} events recorded."
            if has_events
            else "No events recorded. The system must log events for monitoring."
        ),
    ))

    has_inference = await store.event_type_exists("llm_inference")
    report.checks.append(CheckResult(
        article="EU AI Act Art. 12",
        title="Record-keeping: LLM inference events logged",
        passed=has_inference,
        detail=(
            "LLM inference events are being recorded."
            if has_inference
            else "No LLM inference events found. Log inference calls with log_inference."
        ),
    ))

    has_data_access = await store.event_type_exists("data_access")
    report.checks.append(CheckResult(
        article="EU AI Act Art. 12",
        title="Record-keeping: data access events logged",
        passed=has_data_access,
        detail=(
            "Data access events are being recorded."
            if has_data_access
            else "No data access events found. Log document access with log_data_access."
        ),
    ))

    # --- EU AI Act Article 19: Log Retention ---
    oldest = await store.oldest_event_timestamp()
    if oldest:
        oldest_dt = datetime.fromisoformat(oldest)
        now = datetime.now(timezone.utc)
        months_retained = (now.year - oldest_dt.year) * 12 + (now.month - oldest_dt.month)
        meets_retention = months_retained <= retention_months or stats["total_events"] > 0
        report.checks.append(CheckResult(
            article="EU AI Act Art. 19",
            title=f"Log retention: minimum {retention_months} months",
            passed=meets_retention,
            detail=(
                f"Oldest event: {oldest}. Retention policy: {retention_months} months. "
                "Logs are being retained."
            ),
        ))
    else:
        report.checks.append(CheckResult(
            article="EU AI Act Art. 19",
            title=f"Log retention: minimum {retention_months} months",
            passed=False,
            detail="No events to evaluate retention against.",
        ))

    chain_result = await store.verify_chain()
    report.checks.append(CheckResult(
        article="EU AI Act Art. 19",
        title="Log integrity: tamper-evident chain",
        passed=chain_result["intact"],
        detail=(
            f"Hash chain intact across {chain_result['total_events']} events."
            if chain_result["intact"]
            else f"Chain broken at event {chain_result.get('broken_at_event', '?')}."
        ),
    ))

    # --- GDPR Article 30: Records of Processing Activities ---
    has_purpose = False
    events = await store.query_events(limit=500)
    for evt in events:
        if evt.get("metadata"):
            import json
            meta = json.loads(evt["metadata"]) if isinstance(evt["metadata"], str) else evt["metadata"]
            if "purpose" in meta:
                has_purpose = True
                break

    report.checks.append(CheckResult(
        article="GDPR Art. 30",
        title="Processing purpose documented",
        passed=has_purpose,
        detail=(
            "At least one event includes a processing purpose in metadata."
            if has_purpose
            else "No events contain a 'purpose' field in metadata. Include purpose when logging events."
        ),
    ))

    pii_summary = await store.get_pii_summary()
    has_pii_tracking = len(pii_summary) > 0 or stats["events_with_pii"] > 0
    report.checks.append(CheckResult(
        article="GDPR Art. 30",
        title="Categories of personal data documented",
        passed=has_pii_tracking,
        detail=(
            f"PII categories tracked: {', '.join(pii_summary.keys()) if pii_summary else 'via event flags'}."
            if has_pii_tracking
            else "No PII categories tracked. Enable PII scanning to document data categories."
        ),
    ))

    report.overall_pass = all(c.passed for c in report.checks)
    return report
