# Contributing

Contributions that improve the experimental contract, validation, analysis, or
documentation are welcome.

## Development setup

Install Python 3.10 or newer and `uv`, then run:

```bash
uv sync --frozen --extra dev --extra notebook
uv run --frozen --extra dev pytest
uvx ruff check .
```

Changes to scenarios or traces must remain valid under the JSON Schemas in
`schemas/`. Changes to generated artifacts should include the command used to
regenerate them and must keep `mas-safety validate` free of blocking issues.

Before submitting a change, review [SECURITY.md](SECURITY.md). Never commit live
credentials, secret signing keys, unredacted provider responses, or sensitive
data. By contributing, you agree that your contribution is licensed under the
repository's MIT License.
