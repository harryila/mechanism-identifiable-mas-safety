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
    Path(__file__).resolve().parents[1] / "scripts" / "verify_stage2_release.py"
)
MODULE_SPEC = importlib.util.spec_from_file_location(
    "verify_stage2_release", MODULE_PATH
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
verify_module = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = verify_module
MODULE_SPEC.loader.exec_module(verify_module)

VerificationError = verify_module.VerificationError
verify_release = verify_module.verify_release

SOURCE_RELEASE = Path("results/stage2-v0.2.2/artifacts")


def _copy_release(tmp_path: Path) -> Path:
    destination = tmp_path / "stage2-release"
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
    names = sorted(verify_module.RELEASE_FILES)
    lines = [
        f"{hashlib.sha256((release / name).read_bytes()).hexdigest()}  {name}"
        for name in names
    ]
    (release / "SHA256SUMS").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def test_public_verifier_recomputes_all_stage2_aggregates() -> None:
    report = verify_release(SOURCE_RELEASE)

    assert report["pass"] is True
    assert report["public_data_verification_pass"] is True
    assert report["run_rows_verified"] == 1152
    assert report["source_identities_verified"] == 192
    assert report["aggregate_tables_recomputed"] == 4
    assert report["aggregate_cells_recomputed"] == 856
    assert report["aggregate_input"] == "defense_runs.csv"
    assert report["aggregate_tables_recomputed_from_public_run_rows"] is True
    assert report["release_checksum_manifest_sha256"] == (
        "f44e2203adf5fb950b790537bc90fbf991907b0a63b26147b0d566efb0016e61"
    )
    assert report["full_independent_verification"] is False
    assert report["new_model_or_provider_calls_recomputed_from_public_data"] is False
    assert report["private_source_reexecution_verified"] is False
    assert "new_model_or_provider_calls" in report["commitment_only_claims"]


def test_checksum_tamper_is_detected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    with (release / "defense_runs.csv").open("a", encoding="utf-8") as handle:
        handle.write("\n")

    with pytest.raises(VerificationError, match="checksum_mismatch"):
        verify_release(release)


@pytest.mark.parametrize(
    ("filename", "field", "value", "error"),
    [
        (
            "defense_effects.csv",
            "absolute_defense_effect",
            "0.25",
            "defense_effects_aggregate_mismatch",
        ),
        (
            "defense_utility.csv",
            "benign_completion_rate",
            "0.25",
            "defense_utility_aggregate_mismatch",
        ),
        (
            "proposal_coverage.csv",
            "q_gate",
            "0.25",
            "proposal_coverage_aggregate_mismatch",
        ),
        (
            "defense_interactions.csv",
            "signed_interaction",
            "0.25",
            "defense_interactions_aggregate_mismatch",
        ),
    ],
)
def test_each_derived_table_is_recomputed_after_checksums_are_refreshed(
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


def test_run_boolean_is_strictly_parsed(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / "defense_runs.csv")
    rows[0]["mechanism_active"] = "TRUE"
    _write_csv(release / "defense_runs.csv", fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="invalid_boolean"):
        verify_release(release)


def test_missing_defense_condition_is_detected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / "defense_runs.csv")
    rows[1]["defense"] = "local_only"
    rows[1]["condition_role"] = "observed_local_comparator"
    rows[1]["row_origin"] = "observed_stage1"
    _write_csv(release / "defense_runs.csv", fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="defense_condition_order_mismatch"):
        verify_release(release)


def test_allowed_replay_outcome_tamper_is_detected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    fields, rows = _read_csv(release / "defense_runs.csv")
    row = next(
        item
        for item in rows
        if item["defense"] == "history_monitor"
        and item["terminal_defense_decision"] == "allow"
        and item["local_allow_global_harm"] == "true"
    )
    row["local_allow_global_harm"] = "false"
    _write_csv(release / "defense_runs.csv", fields, rows)
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="allowed_replay_outcome_drift"):
        verify_release(release)


def test_duplicate_json_key_is_rejected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    (release / "summary.json").write_text(
        '{"schema_version":"first","schema_version":"second"}\n',
        encoding="utf-8",
    )
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="json_duplicate_key"):
        verify_release(release)


def test_manifest_allowlist_tamper_is_detected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    path = release / "replay_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["field_allowlists"]["defense_runs.csv"].append("raw_model_output")
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="manifest_allowlist_mismatch"):
        verify_release(release)


def test_manifest_source_fact_tamper_is_detected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    path = release / "replay_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["verified_source_path_facts"]["terminal_opportunity_count"] = 124
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="source_facts_mismatch"):
        verify_release(release)


def test_replay_program_component_binding_tamper_is_detected(
    tmp_path: Path,
) -> None:
    release = _copy_release(tmp_path)
    path = release / "replay_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["amendment_and_freeze"]["replay_program_components"][
        "stage2_metrics.py"
    ] = "sha256:" + "0" * 64
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="replay_program_binding_mismatch"):
        verify_release(release)


def test_source_dependency_root_binding_tamper_is_detected(
    tmp_path: Path,
) -> None:
    release = _copy_release(tmp_path)
    path = release / "replay_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["source_commitments"]["dependencies"]["programs_and_schemas"][
        "analysis_program"
    ] = "sha256:" + "0" * 64
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _refresh_checksums(release)

    with pytest.raises(
        VerificationError, match="source_dependency_root_binding_mismatch"
    ):
        verify_release(release)


def test_manifest_boolean_integer_substitution_is_rejected(
    tmp_path: Path,
) -> None:
    release = _copy_release(tmp_path)
    path = release / "replay_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["privacy_boundary"]["secret_material_recorded"] = 0
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="privacy_boundary_mismatch"):
        verify_release(release)


def test_semantically_coherent_repackaging_fails_historical_bundle_pin(
    tmp_path: Path,
) -> None:
    release = _copy_release(tmp_path)
    summary_path = release / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary_path.write_text(
        json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    manifest_path = release / "replay_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["output_checksums"]["summary.json"] = hashlib.sha256(
        summary_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _refresh_checksums(release)

    with pytest.raises(VerificationError, match="release_commitment_mismatch"):
        verify_release(release)


def test_extra_release_entry_is_rejected(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    (release / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="release_entry_set_mismatch"):
        verify_release(release)
