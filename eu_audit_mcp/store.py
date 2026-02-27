from __future__ import annotations

import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from .chain import GENESIS_HASH, compute_hash, generate_secret, verify_event
from .config import AuditConfig

MAX_CONTENT_SIZE = 65_536  # 64 KB
MAX_METADATA_SIZE = 16_384  # 16 KB
MAX_QUERY_LIMIT = 10_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    content       TEXT,
    metadata      TEXT,
    pii_types     TEXT,
    session_id    TEXT,
    chain_hash    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

CREATE TABLE IF NOT EXISTS pii_vault (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL,
    placeholder   TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    encrypted_val TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_vault_event ON pii_vault(event_id);
CREATE INDEX IF NOT EXISTS idx_vault_type ON pii_vault(entity_type);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class AuditStore:
    def __init__(self, config: AuditConfig) -> None:
        self._config = config
        self._db_path = self._validate_db_path(config.database_path)
        self._db: aiosqlite.Connection | None = None
        self._secret: str | None = None

    @staticmethod
    def _validate_db_path(raw_path: str) -> Path:
        if ".." in Path(raw_path).parts:
            raise ValueError(f"database_path must not contain '..': {raw_path}")
        return Path(raw_path).resolve()

    @staticmethod
    def _restrict_permissions(path: Path) -> None:
        """Set database file to owner-read/write only (0600)."""
        if path.exists():
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass

    async def open(self) -> None:
        is_new_db = not self._db_path.exists()
        self._db = await aiosqlite.connect(str(self._db_path))
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        if is_new_db:
            self._restrict_permissions(self._db_path)
        await self._init_secret()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def secret(self) -> str:
        assert self._secret is not None, "Store not opened"
        return self._secret

    async def _init_secret(self) -> None:
        assert self._db is not None
        row = await self._db.execute_fetchall(
            "SELECT value FROM metadata WHERE key = 'chain_secret'"
        )
        if row:
            self._secret = row[0][0]
        else:
            self._secret = self._config.chain_secret or generate_secret()
            await self._db.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                ("chain_secret", self._secret),
            )
            await self._db.commit()

    async def get_metadata(self, key: str) -> str | None:
        assert self._db is not None
        rows = await self._db.execute_fetchall(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        )
        return rows[0][0] if rows else None

    async def set_metadata(self, key: str, value: str) -> None:
        assert self._db is not None
        await self._db.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value),
        )
        await self._db.commit()

    async def _last_hash(self) -> str:
        assert self._db is not None
        rows = await self._db.execute_fetchall(
            "SELECT chain_hash FROM events ORDER BY rowid DESC LIMIT 1"
        )
        if rows:
            return rows[0][0]
        return GENESIS_HASH

    async def append_event(
        self,
        event_type: str,
        content: str | None = None,
        metadata: dict[str, Any] | None = None,
        pii_types: list[str] | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        assert self._db is not None

        if content and len(content) > MAX_CONTENT_SIZE:
            raise ValueError(
                f"content exceeds maximum size ({MAX_CONTENT_SIZE} bytes)"
            )

        event_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata, default=str) if metadata else None
        if meta_json and len(meta_json) > MAX_METADATA_SIZE:
            raise ValueError(
                f"metadata exceeds maximum size ({MAX_METADATA_SIZE} bytes)"
            )
        pii_json = json.dumps(pii_types) if pii_types else None

        event_data = {
            "id": event_id,
            "timestamp": ts,
            "event_type": event_type,
            "content": content,
            "metadata": meta_json,
            "pii_types": pii_json,
            "session_id": session_id,
        }

        prev_hash = await self._last_hash()
        chain_hash = compute_hash(event_data, prev_hash, self.secret)

        await self._db.execute(
            """INSERT INTO events (id, timestamp, event_type, content, metadata, pii_types, session_id, chain_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, ts, event_type, content, meta_json, pii_json, session_id, chain_hash),
        )
        await self._db.commit()

        return {"event_id": event_id, "timestamp": ts, "chain_hash": chain_hash}

    async def store_pii_mapping(
        self,
        event_id: str,
        placeholder: str,
        entity_type: str,
        encrypted_val: str,
    ) -> None:
        assert self._db is not None
        await self._db.execute(
            "INSERT INTO pii_vault (event_id, placeholder, entity_type, encrypted_val) VALUES (?, ?, ?, ?)",
            (event_id, placeholder, entity_type, encrypted_val),
        )
        await self._db.commit()

    async def query_events(
        self,
        event_type: str | None = None,
        session_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        assert self._db is not None
        limit = min(max(1, limit), MAX_QUERY_LIMIT)
        clauses: list[str] = []
        params: list[Any] = []

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp <= ?")
            params.append(until)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        rows = await self._db.execute_fetchall(
            f"SELECT * FROM events{where} ORDER BY rowid ASC LIMIT ?",
            params,
        )
        return [dict(r) for r in rows]

    async def get_stats(
        self, since: str | None = None, until: str | None = None
    ) -> dict[str, Any]:
        assert self._db is not None
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp <= ?")
            params.append(until)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

        total = await self._db.execute_fetchall(
            f"SELECT COUNT(*) as cnt FROM events{where}", params
        )
        by_type = await self._db.execute_fetchall(
            f"SELECT event_type, COUNT(*) as cnt FROM events{where} GROUP BY event_type",
            params,
        )
        pii_count = await self._db.execute_fetchall(
            f"SELECT COUNT(*) as cnt FROM events{where} AND pii_types IS NOT NULL"
            if where
            else "SELECT COUNT(*) as cnt FROM events WHERE pii_types IS NOT NULL",
            params if where else [],
        )

        cost_query = (
            f"SELECT metadata FROM events{where}"
            + (" AND " if where else " WHERE ")
            + "event_type = 'llm_inference'"
        )
        cost_rows = await self._db.execute_fetchall(cost_query, params)
        total_cost = 0.0
        total_tokens_in = 0
        total_tokens_out = 0
        for row in cost_rows:
            if row[0]:
                meta = json.loads(row[0])
                total_cost += float(meta.get("cost_eur", 0))
                total_tokens_in += int(meta.get("tokens_in", 0))
                total_tokens_out += int(meta.get("tokens_out", 0))

        return {
            "total_events": total[0][0],
            "by_type": {r[0]: r[1] for r in by_type},
            "events_with_pii": pii_count[0][0],
            "total_cost_eur": round(total_cost, 6),
            "total_tokens_in": total_tokens_in,
            "total_tokens_out": total_tokens_out,
        }

    async def verify_chain(self) -> dict[str, Any]:
        assert self._db is not None
        rows = await self._db.execute_fetchall(
            "SELECT id, timestamp, event_type, content, metadata, pii_types, session_id, chain_hash "
            "FROM events ORDER BY rowid ASC"
        )
        prev_hash = GENESIS_HASH
        for row in rows:
            row_dict = dict(row)
            stored_hash = row_dict.pop("chain_hash")
            if not verify_event(row_dict, stored_hash, prev_hash, self.secret):
                return {
                    "intact": False,
                    "broken_at_event": row_dict["id"],
                    "position": rows.index(row),
                    "total_events": len(rows),
                }
            prev_hash = stored_hash
        return {"intact": True, "total_events": len(rows)}

    async def get_pii_summary(self) -> dict[str, int]:
        assert self._db is not None
        rows = await self._db.execute_fetchall(
            "SELECT entity_type, COUNT(*) as cnt FROM pii_vault GROUP BY entity_type"
        )
        return {r[0]: r[1] for r in rows}

    @staticmethod
    def _escape_like(pattern: str) -> str:
        """Escape SQL LIKE special characters to prevent wildcard injection."""
        return pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    async def erase_entity(self, entity_type: str, placeholder_pattern: str) -> dict[str, Any]:
        """Redact events containing a specific PII entity and remove vault entries.

        The event rows are NOT deleted (that would break the hash chain).
        Instead, content is replaced with a redaction notice.
        """
        assert self._db is not None

        safe_pattern = self._escape_like(placeholder_pattern)
        vault_rows = await self._db.execute_fetchall(
            "SELECT DISTINCT event_id FROM pii_vault WHERE entity_type = ? AND placeholder LIKE ? ESCAPE '\\'",
            (entity_type, f"%{safe_pattern}%"),
        )
        event_ids = [r[0] for r in vault_rows]

        if not event_ids:
            return {"events_redacted": 0, "vault_entries_removed": 0}

        placeholders_sql = ",".join("?" for _ in event_ids)

        await self._db.execute(
            f"UPDATE events SET content = '[REDACTED — GDPR Art. 17 erasure]' WHERE id IN ({placeholders_sql})",
            event_ids,
        )

        result = await self._db.execute(
            f"DELETE FROM pii_vault WHERE event_id IN ({placeholders_sql})",
            event_ids,
        )

        erasure_meta = {
            "entity_type": entity_type,
            "pattern": placeholder_pattern,
            "events_affected": len(event_ids),
        }
        await self.append_event(
            event_type="gdpr_erasure",
            content=f"GDPR Art. 17 erasure executed for {entity_type}",
            metadata=erasure_meta,
        )

        await self._db.commit()
        return {
            "events_redacted": len(event_ids),
            "vault_entries_removed": result.rowcount if result else 0,
        }

    async def oldest_event_timestamp(self) -> str | None:
        assert self._db is not None
        rows = await self._db.execute_fetchall(
            "SELECT timestamp FROM events ORDER BY rowid ASC LIMIT 1"
        )
        return rows[0][0] if rows else None

    async def event_type_exists(self, event_type: str) -> bool:
        assert self._db is not None
        rows = await self._db.execute_fetchall(
            "SELECT 1 FROM events WHERE event_type = ? LIMIT 1",
            (event_type,),
        )
        return len(rows) > 0
