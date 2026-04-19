"""AIEOS adapter: security.sast via semgrep.

Invokes semgrep with `--sarif` output, writes to a tempfile, parses it, and
normalizes to the AIEOS SARIF 2.1.0 subset (findings/schemas/sarif-2.1.0.
schema.json). AIEOS adds driver.version + per-result level as required
fields; the adapter populates these from semgrep's native output with
safe defaults.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

# semgrep severity -> SARIF level
_SEMGREP_TO_SARIF_LEVEL = {
    "INFO": "note",
    "WARNING": "warning",
    "ERROR": "error",
}


@dataclass
class AdapterResult:
    findings: dict[str, Any] | None
    evidence: list[str]
    exit_code: int


class SemgrepSastAdapter:
    """Wraps semgrep for the security.sast contract."""

    def __init__(self, semgrep_binary: str = "semgrep") -> None:
        self._semgrep = semgrep_binary

    def execute(self, inputs: dict[str, Any]) -> AdapterResult:
        source_dir = Path(inputs["source_dir"]).resolve()
        if not source_dir.is_dir():
            return AdapterResult(findings=None, evidence=["exit-code:2"], exit_code=2)

        ruleset = inputs.get("ruleset_ref") or "auto"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif.json", delete=False) as tmp:
            sarif_path = Path(tmp.name)

        try:
            cmd = [
                self._semgrep,
                "scan",
                "--config",
                ruleset,
                "--sarif",
                "--sarif-output",
                str(sarif_path),
                "--quiet",
                str(source_dir),
            ]
            try:
                proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
            except FileNotFoundError:
                return AdapterResult(
                    findings=None,
                    evidence=["exit-code:127", "stderr:semgrep binary not on $PATH"],
                    exit_code=127,
                )

            if not sarif_path.is_file():
                return AdapterResult(
                    findings=None,
                    evidence=[
                        f"exit-code:{proc.returncode}",
                        "stderr:" + (proc.stderr[:500] or ""),
                    ],
                    exit_code=proc.returncode if proc.returncode != 0 else 3,
                )

            raw = json.loads(sarif_path.read_text())
            normalized = normalize_semgrep_sarif(raw)
            return AdapterResult(
                findings=normalized,
                evidence=[
                    f"sarif-report:{sarif_path.name}",
                    f"exit-code:{proc.returncode}",
                ],
                exit_code=0,
            )
        finally:
            if sarif_path.is_file():
                sarif_path.unlink()


def normalize_semgrep_sarif(document: dict[str, Any]) -> dict[str, Any]:
    """Normalize semgrep's SARIF into the AIEOS subset.

    AIEOS requires tool.driver.version and per-result level to be present.
    Semgrep populates driver.name/version natively; level is sometimes
    missing when semgrep's severity is not recognized — this function fills
    in "warning" as a conservative default.
    """
    out = dict(document)
    out.setdefault("version", "2.1.0")
    runs_in = document.get("runs", []) or []
    runs_out: list[dict[str, Any]] = []
    for run in runs_in:
        run = dict(run)
        tool = dict(run.get("tool", {}))
        driver = dict(tool.get("driver", {}))
        driver.setdefault("name", "semgrep")
        driver.setdefault("version", "unknown")
        tool["driver"] = driver
        run["tool"] = tool

        results = []
        for r in run.get("results", []) or []:
            r = dict(r)
            # Semgrep sometimes emits level inline; fall back to mapping
            # from properties.severity.
            if "level" not in r:
                sev = (r.get("properties", {}) or {}).get("severity", "WARNING")
                r["level"] = _SEMGREP_TO_SARIF_LEVEL.get(str(sev).upper(), "warning")
            # message must be an object with .text
            msg = r.get("message")
            if isinstance(msg, str):
                r["message"] = {"text": msg}
            elif not isinstance(msg, dict) or "text" not in msg:
                r["message"] = {"text": "<no message>"}
            results.append(r)
        run["results"] = results
        runs_out.append(run)
    out["runs"] = runs_out
    return out
