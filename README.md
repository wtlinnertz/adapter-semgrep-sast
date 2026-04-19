# adapter-semgrep-sast

AIEOS adapter: `security.sast` via semgrep. Normalizes semgrep's SARIF
output to the AIEOS SARIF 2.1.0 subset
(`findings/schemas/sarif-2.1.0.schema.json`).

Prereq: `semgrep` on `$PATH`. Unit tests mock the subprocess and can run
anywhere; conformance runs the real tool.

```bash
pip install -e '.[dev]'
pytest
ruff check .
```

MIT.
