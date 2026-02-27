# Contributing to eu-audit-mcp

Thank you for considering a contribution. This guide covers everything you need to get started.

## Development setup

```bash
# Fork and clone
git clone https://github.com/<your-username>/eu-audit-mcp.git
cd eu-audit-mcp

# Create a virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

## Running tests

```bash
pytest tests/ -v
```

All pull requests must pass the full test suite. If you add a new feature, add tests for it.

## Making changes

1. **Create a branch** from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes.** Follow the existing code style.

3. **Run the checks:**

   ```bash
   pre-commit run --all-files   # linting + formatting
   pytest tests/ -v              # tests
   ```

4. **Commit** with a clear message:

   ```
   feat: add support for custom PII entity types
   fix: handle empty metadata in compliance check
   docs: clarify GDPR Art. 17 erasure behavior
   ```

   Prefix with `feat:`, `fix:`, `docs:`, `test:`, `ci:`, or `refactor:`.

5. **Push and open a PR** against `main`.

## What makes a good PR

- Solves one thing (don't mix unrelated changes)
- Includes tests for new functionality
- Does not commit secrets, database files, or `audit_config.yaml`
- Passes CI (pytest across Python 3.10, 3.11, 3.12)
- Has a clear description of what and why

## Security

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
