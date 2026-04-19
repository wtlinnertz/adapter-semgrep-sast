# MAPPING — adapter-semgrep-sast

## Tool

`semgrep scan --config <ruleset> --sarif --sarif-output <tmp> --quiet <source_dir>`.
Default ruleset: `auto` (semgrep's curated set). Callers override via
`ruleset_ref` input (registry ref, file path, or URL).

## SARIF normalization

AIEOS requires driver.version and per-result level; semgrep populates
driver.version natively but occasionally omits level on edge-case rules.
The normalizer:

- Fills `tool.driver.name="semgrep"` and `tool.driver.version="unknown"` if
  absent.
- Maps `properties.severity` (semgrep's INFO/WARNING/ERROR) to SARIF's
  `level` (note/warning/error) when the result doesn't carry level inline.
- Defaults missing severity to "warning" (conservative — no silent upgrades
  to "error", no silent downgrades to "note").
- Coerces string `message` fields to `{"text": <string>}`.

## Evidence

`sarif-report:<filename>`, `exit-code:<N>`. SARIF file contents are the
findings; the evidence reference points to the temp-file artifact (consumed
by the harness before cleanup).

## Exit code

0 when semgrep produced a SARIF file (even with findings). 127 when
semgrep isn't on $PATH. 2 on missing source dir. 3 on semgrep zero-exit
without SARIF output.
