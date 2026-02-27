# eu-audit-mcp

<!-- mcp-name: io.github.jellewas/eu-audit-mcp -->

Tamper-evident audit trail MCP server for EU AI Act and GDPR compliance. Designed to be integrated into a local desktop application via stdio transport.

## Features

- **Tamper-evident logging** — HMAC-SHA256 hash chain over all events
- **PII scanning** — Automatic detection and redaction via Microsoft Presidio (EU patterns)
- **GDPR erasure** — Article 17 right-to-erasure support with audit trail
- **Compliance checks** — Technical checklist against EU AI Act Articles 12/19 and GDPR Article 30
- **Local-first** — All data stays on your machine in a single SQLite file

## Regulatory context

This server implements technical measures for the following EU regulations:

| Regulation | Articles | What it requires |
|---|---|---|
| **EU AI Act** (2024/1689) | [Art. 12](https://artificialintelligenceact.eu/article/12/) | Automatic recording of events (logs) for high-risk AI systems |
| | [Art. 19](https://artificialintelligenceact.eu/article/19/) | Retention of automatically generated logs for at least 6 months |
| **GDPR** (2016/679) | [Art. 17](https://gdpr.eu/article-17-right-to-be-forgotten/) | Right to erasure of personal data ("right to be forgotten") |
| | [Art. 30](https://gdpr.eu/article-30-records-of-processing-activities/) | Records of processing activities, including purposes and data categories |

The EU AI Act high-risk obligations enter into force on **2 August 2026**.

See [LEGAL_REFERENCES.md](LEGAL_REFERENCES.md) for the full article texts and a detailed mapping of how each tool addresses each requirement.

> **Disclaimer:** This tool provides a technical checklist, not legal advice. Consult qualified legal counsel for compliance decisions.

## Quick start

```bash
pip install -e ".[dev]"
```

### Run the server (stdio)

```bash
python -m eu_audit_mcp.server
```

### MCP client configuration

```json
{
  "mcpServers": {
    "eu-audit": {
      "command": "python",
      "args": ["-m", "eu_audit_mcp.server"],
      "env": {
        "AUDIT_CONFIG": "./audit_config.yaml"
      }
    }
  }
}
```

### Run tests

```bash
pytest tests/
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `log_event` | Record an audit event with automatic PII scanning |
| `log_inference` | Log an LLM inference call (model, tokens, cost) |
| `log_data_access` | Log a document/data access event |
| `query_log` | Search events by time range, type, session |
| `get_session_trace` | Full ordered trace of a session |
| `get_stats` | Summary statistics over a time period |
| `compliance_check` | Check against EU AI Act Art. 12/19 and GDPR Art. 30 |
| `execute_erasure` | GDPR Article 17 right-to-erasure |
| `get_pii_summary` | Summary of detected PII types (counts only) |
| `verify_chain` | Verify hash chain integrity |

## Configuration

Copy the example config and customize:

```bash
cp audit_config.example.yaml audit_config.yaml
```

Set the `AUDIT_CONFIG` environment variable to point to your config file. **Do not commit `audit_config.yaml`** if it contains a `chain_secret` — it is in `.gitignore` by default.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, security measures, and vulnerability reporting.

## License

Apache-2.0
