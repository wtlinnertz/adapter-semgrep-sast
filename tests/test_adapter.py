"""Unit tests for adapter-semgrep-sast."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from aieos_adapter_semgrep_sast import SemgrepSastAdapter, normalize_semgrep_sarif


class _Proc:
    def __init__(self, rc: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr


SEMGREP_SARIF_SAMPLE = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep", "version": "1.42.0"}},
            "results": [
                {
                    "ruleId": "python.lang.security.some-rule",
                    "level": "error",
                    "message": {"text": "potential injection"},
                }
            ],
        }
    ],
}


def test_normalize_adds_missing_version_and_level():
    """Missing level gets a conservative default; driver fields auto-populate."""
    minimal = {
        "runs": [
            {
                "tool": {"driver": {}},
                "results": [{"ruleId": "X", "message": "no level"}],
            }
        ]
    }
    out = normalize_semgrep_sarif(minimal)
    assert out["version"] == "2.1.0"
    assert out["runs"][0]["tool"]["driver"]["version"] == "unknown"
    assert out["runs"][0]["results"][0]["level"] == "warning"
    assert out["runs"][0]["results"][0]["message"] == {"text": "no level"}


def test_normalize_maps_semgrep_severity_to_sarif_level():
    doc = {
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "version": "1.0.0"}},
                "results": [
                    {"ruleId": "r", "message": {"text": "m"}, "properties": {"severity": "INFO"}},
                    {"ruleId": "r", "message": {"text": "m"}, "properties": {"severity": "ERROR"}},
                ],
            }
        ]
    }
    out = normalize_semgrep_sarif(doc)
    assert out["runs"][0]["results"][0]["level"] == "note"
    assert out["runs"][0]["results"][1]["level"] == "error"


def test_execute_happy_path(tmp_path):
    src = tmp_path / "src"
    src.mkdir()

    def _fake_run(cmd, **kw):
        # write a sample sarif to the --sarif-output path
        for i, arg in enumerate(cmd):
            if arg == "--sarif-output":
                Path(cmd[i + 1]).write_text(json.dumps(SEMGREP_SARIF_SAMPLE))
                break
        return _Proc(0)

    with patch("subprocess.run", side_effect=_fake_run):
        result = SemgrepSastAdapter().execute({"source_dir": str(src)})

    assert result.exit_code == 0
    assert result.findings["version"] == "2.1.0"
    assert any("sarif-report:" in e for e in result.evidence)


def test_execute_missing_source_dir(tmp_path):
    result = SemgrepSastAdapter().execute({"source_dir": str(tmp_path / "no")})
    assert result.exit_code != 0 and result.findings is None


def test_execute_semgrep_not_installed(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = SemgrepSastAdapter().execute({"source_dir": str(src)})
    assert result.exit_code == 127
    assert any("binary not on $PATH" in e for e in result.evidence)


def test_ruleset_forwarded_to_command(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    captured = {}

    def _cap(cmd, **kw):
        captured["cmd"] = cmd
        for i, arg in enumerate(cmd):
            if arg == "--sarif-output":
                Path(cmd[i + 1]).write_text(json.dumps(SEMGREP_SARIF_SAMPLE))
        return _Proc(0)

    with patch("subprocess.run", side_effect=_cap):
        SemgrepSastAdapter().execute({"source_dir": str(src), "ruleset_ref": "p/python"})
    assert "p/python" in captured["cmd"]
