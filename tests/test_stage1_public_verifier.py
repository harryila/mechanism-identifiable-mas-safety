from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "verify_stage1_release.py"
)
MODULE_SPEC = importlib.util.spec_from_file_location(
    "verify_stage1_release", MODULE_PATH
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
verify_module = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = verify_module
MODULE_SPEC.loader.exec_module(verify_module)

VerificationError = verify_module.VerificationError
verify_release = verify_module.verify_release


SOURCE_RELEASE = Path("results/stage1-v0.2.1")


def _copy_release(tmp_path: Path) -> Path:
    destination = tmp_path / "stage1-release"
    shutil.copytree(SOURCE_RELEASE, destination)
    return destination


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames is not None
        return reader.fieldnames, list(reader)


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _refresh_checksums(release: Path) -> None:
    checksum_path = release / "SHA256SUMS"
    names = [
        line.partition("  ")[2]
        for line in checksum_path.read_text(encoding="utf-8").splitlines()
    ]
    lines = [
        f"{hashlib.sha256((release / name).read_bytes()).hexdigest()}  {name}"
        for name in names
    ]
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_public_verifier_recomputes_tables_gates_and_decision() -> None:
    report = verify_release(SOURCE_RELEASE)

    assert report["pass"] is True
    assert report["public_data_verification_pass"] is True
    assert report["decision_recomputed"] == "GO"
    assert report["table_derived_gate_count"] == 6
    assert report["full_independent_verification"] is False
    assert report["attestation_only_gates"] == ["hard_qa", "raw_archive_complete"]
    assert report["gate_results"]["valid_structured_decisions"] == {
        "denominator": 762,
        "evidence": "EXACTLY_INFERRED_FROM_ARM_RATES_NOT_RUN_LEVEL_RECOMPUTABLE",
        "limitation": (
            "runs.csv omits per-run structured-decision counts; the numerator is the "
            "unique integer compatible with each arm's six-decimal rate and call count"
        ),
        "numerator": 758,
        "pass": True,
    }


def test_require_full_is_truthfully_unsatisfied() -> None:
    report = verify_release(SOURCE_RELEASE, require_full=True)

    assert report["pass"] is False
    assert report["public_data_verification_pass"] is True
    assert report["require_full_evidence_satisfied"] is False
    assert report["full_independent_verification"] is False


def test_outcome_tamper_is_detected_even_with_refreshed_checksums(
    tmp_path: Path,
) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / "runs.csv")
    row = next(
        item
        for item in rows
        if item["safety_variant"] == "unsafe"
        and item["mechanism_active"] == "True"
        and item["local_allow_global_harm"] == "True"
    )
    row["local_allow_global_harm"] = "False"
    _write_csv(release / "runs.csv", fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="arm_metric_mismatch"):
        verify_release(release)


@pytest.mark.parametrize(
    ("filename", "field", "value", "error"),
    [
        ("arm_metrics.csv", "lgh_rate", "0.125", "arm_metric_mismatch"),
        ("mechanism_effects.csv", "paired_effect", "0.125", "effect_value_mismatch"),
    ],
)
def test_derived_table_tamper_is_detected(
    tmp_path: Path,
    filename: str,
    field: str,
    value: str,
    error: str,
) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / filename)
    rows[0][field] = value
    _write_csv(release / filename, fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match=error):
        verify_release(release)


def test_summary_tamper_is_detected_even_with_refreshed_checksums(
    tmp_path: Path,
) -> None:
    release = _copy_release(tmp_path)
    summary_path = release / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["decision"] = "NO_GO"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="summary_decision_mismatch"):
        verify_release(release)


def test_checksum_tamper_is_detected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    with (release / "runs.csv").open("a", encoding="utf-8") as handle:
        handle.write("\n")

    with pytest.raises(VerificationError, match="checksum_mismatch"):
        verify_release(release)


def test_duplicate_run_is_rejected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / "runs.csv")
    rows.append(dict(rows[0]))
    _write_csv(release / "runs.csv", fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="run_count_mismatch"):
        verify_release(release)


def test_malformed_boolean_is_rejected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / "runs.csv")
    rows[0]["refusal"] = "yes"
    _write_csv(release / "runs.csv", fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="invalid_boolean"):
        verify_release(release)


def test_nonfinite_rate_is_rejected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / "arm_metrics.csv")
    rows[0]["structured_decision_rate"] = "NaN"
    _write_csv(release / "arm_metrics.csv", fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="invalid_decimal"):
        verify_release(release)
