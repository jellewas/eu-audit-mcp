from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from cryptography.fernet import Fernet

from .config import PIIConfig


@dataclass
class PIIResult:
    redacted_text: str
    mappings: list[dict[str, str]] = field(default_factory=list)
    entity_types: list[str] = field(default_factory=list)


class PIIEngine:
    """Detect and redact PII using Microsoft Presidio, with encrypted vault storage."""

    def __init__(self, config: PIIConfig, fernet_key: bytes | None = None) -> None:
        self._config = config
        self._key = fernet_key or Fernet.generate_key()
        self._fernet = Fernet(self._key)
        self._analyzer = None
        self._anonymizer = None
        self._counters: Counter[str] = Counter()

    def _ensure_loaded(self) -> None:
        if self._analyzer is not None:
            return
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

    def scan_and_redact(self, text: str) -> PIIResult:
        if not self._config.enabled or not text:
            return PIIResult(redacted_text=text)

        self._ensure_loaded()
        assert self._analyzer is not None
        assert self._anonymizer is not None

        results = self._analyzer.analyze(
            text=text,
            entities=self._config.entities,
            language=self._config.language,
        )

        if not results:
            return PIIResult(redacted_text=text)

        # Remove overlapping detections, keeping the higher-score match
        results = sorted(results, key=lambda r: r.start)
        filtered: list = []
        for r in results:
            if filtered and r.start < filtered[-1].end:
                if r.score > filtered[-1].score:
                    filtered[-1] = r
            else:
                filtered.append(r)

        # Process in reverse order so string offsets stay valid
        filtered.sort(key=lambda r: r.start, reverse=True)
        mappings: list[dict[str, str]] = []
        entity_types: list[str] = []
        redacted = text

        for result in filtered:
            self._counters[result.entity_type] += 1
            count = self._counters[result.entity_type]
            placeholder = f"[{result.entity_type}_{count}]"

            original = text[result.start:result.end]
            encrypted = self._fernet.encrypt(original.encode()).decode()

            mappings.append({
                "placeholder": placeholder,
                "entity_type": result.entity_type,
                "encrypted_val": encrypted,
            })
            entity_types.append(result.entity_type)
            redacted = redacted[:result.start] + placeholder + redacted[result.end:]

        mappings.reverse()
        entity_types.reverse()

        return PIIResult(
            redacted_text=redacted,
            mappings=mappings,
            entity_types=entity_types,
        )

    def decrypt_value(self, encrypted_val: str) -> str:
        return self._fernet.decrypt(encrypted_val.encode()).decode()

    @property
    def fernet_key(self) -> bytes:
        """Return the Fernet key for persistence."""
        return self._key
