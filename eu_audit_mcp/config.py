from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class PIIConfig:
    enabled: bool = True
    language: str = "en"
    entities: list[str] = field(
        default_factory=lambda: [
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "IBAN_CODE",
            "LOCATION",
            "DATE_TIME",
        ]
    )


@dataclass
class AuditConfig:
    database_path: str = "./audit.db"
    chain_secret: str | None = None
    retention_months: int = 6
    pii: PIIConfig = field(default_factory=PIIConfig)

    @classmethod
    def load(cls, path: str | Path | None = None) -> AuditConfig:
        path = path or os.environ.get("AUDIT_CONFIG")
        if path is None:
            return cls()

        p = Path(path)
        if not p.exists():
            return cls()

        with open(p) as f:
            raw = yaml.safe_load(f) or {}

        pii_raw = raw.pop("pii", {}) or {}
        pii = PIIConfig(**pii_raw)
        return cls(pii=pii, **raw)
