# Security Policy

## Threat Model

`eu-audit-mcp` is designed to run as a **local stdio MCP server** inside a desktop application. It assumes:

- **Trusted transport** — The parent process (your desktop app) communicates over stdio. No network listener is exposed.
- **Trusted operator** — The user who launches the server controls the machine and the configuration.
- **Untrusted LLM output** — The content passed into logging tools may come from an LLM and is treated as untrusted input (bounded, parameterized queries, no eval).

## Security Measures

| Measure | Implementation |
|---|---|
| SQL injection prevention | All queries use parameterized placeholders (`?`); no string interpolation of user data into SQL |
| Input size limits | Content capped at 64 KB, metadata at 16 KB to prevent memory exhaustion |
| Query result limits | All queries capped at 10,000 rows maximum |
| Database file permissions | New databases are created with `0600` (owner read/write only) |
| PII encryption | PII vault entries encrypted with Fernet (AES-128-CBC + HMAC-SHA256); key persisted in the database |
| Hash chain integrity | HMAC-SHA256 chain using `hmac.compare_digest` for timing-safe comparison |
| Secret generation | Chain secret uses `secrets.token_hex(32)` (cryptographically secure) |
| YAML parsing | Uses `yaml.safe_load()` (immune to deserialization attacks) |
| Path validation | Database path is resolved and validated against path traversal |
| LIKE wildcard escaping | SQL LIKE patterns are escaped to prevent wildcard injection |

## What This Server Does NOT Do

- **No network authentication.** The server communicates only via stdio. If you expose it over a network transport, you must add authentication yourself.
- **No disk encryption.** The SQLite file is encrypted at the application level (PII vault only). Full-disk encryption is the operator's responsibility.
- **No key management service.** The Fernet key is stored in the SQLite metadata table. For production deployments with higher security requirements, consider integrating with a KMS.

## Configuration Security

- **Never commit `audit_config.yaml`** if it contains a `chain_secret`. The file is in `.gitignore` by default. Use `audit_config.example.yaml` as a template.
- **Environment variables** (`AUDIT_CONFIG`) are the recommended way to point to your config file.

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public issue.**
2. Email the maintainer directly (see the GitHub profile for contact information).
3. Include a description of the vulnerability, steps to reproduce, and any suggested fix.
4. You will receive an acknowledgment within 48 hours and a fix timeline within 7 days.
