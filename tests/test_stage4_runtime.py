from __future__ import annotations

import json
import hashlib
import subprocess
from collections.abc import Iterator, Mapping
from dataclasses import replace
from pathlib import Path

import pytest

import mas_safety.cli as cli_module
import mas_safety.stage4_runtime as runtime_module
from mas_safety.stage4_live import build_stage4_schedule, load_confirmatory_workflows
from mas_safety.stage4_runtime import (
    FROZEN_MODEL_IDS,
    MINIMUM_REQUIRED_NANO_USD,
    Stage4PreflightError,
    _is_safe_public_attestation,
    _is_safe_public_identifier,
    _verify_budget_credential_storage,
    _verify_repository_and_tag,
    build_stage4_run_bindings,
    load_stage4_freeze_manifest,
    load_stage4_schedule_manifest,
    run_stage4_preflight,
    stage4_run_bindings_sha256,
)


REPOSITORY = Path(__file__).resolve().parents[1]
BATCH_ID = "stage4-v0.4-confirmatory"


def test_git_environment_disables_fsmonitor_and_lazy_fetch(monkeypatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "credential.helper")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "malicious-helper")

    environment = runtime_module._git_environment()

    assert environment["GIT_CONFIG_COUNT"] == "1"
    assert environment["GIT_CONFIG_KEY_0"] == "core.fsmonitor"
    assert environment["GIT_CONFIG_VALUE_0"] == "false"
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert "GIT_CONFIG_KEY_1" not in environment
    assert "GIT_CONFIG_VALUE_1" not in environment


def test_finalization_and_runtime_public_value_grammars_are_identical() -> None:
    assert _is_safe_public_identifier("credential:v1")
    assert _is_safe_public_identifier("a" * 128)
    assert not _is_safe_public_identifier("a" * 129)
    assert not _is_safe_public_identifier("credential/path")
    assert not _is_safe_public_identifier("sk-forbidden")
    assert not _is_safe_public_identifier("bearer-forbidden")
    assert not _is_safe_public_identifier("secret-forbidden")

    assert _is_safe_public_attestation("vault/path(stage4)-v1")
    assert _is_safe_public_attestation("a" * 128)
    assert not _is_safe_public_attestation("a" * 129)
    assert not _is_safe_public_attestation("attestation value")
    assert not _is_safe_public_attestation("secret-forbidden")


def _schedule():
    return build_stage4_schedule(
        load_confirmatory_workflows(REPOSITORY / "scenarios" / "confirmatory"),
        FROZEN_MODEL_IDS,
        seed="stable-seed",
    )


def test_schedule_rows_bind_to_exact_paired_runtime_identities() -> None:
    bindings = build_stage4_run_bindings(_schedule(), batch_id=BATCH_ID)

    assert len(bindings) == 768
    assert len({binding.scheduled_run_id for binding in bindings}) == 768
    assert stage4_run_bindings_sha256(bindings) == (
        "cb4d291c623740ef7448db6d44dacb5dd0598a2d0fd8caeb477d3680be3ba7f4"
    )
    for pair_index in range(384):
        first, second = bindings[pair_index * 2 : pair_index * 2 + 2]
        assert first.pair_id == second.pair_id
        assert first.model_id == second.model_id
        assert first.run_spec.seed == second.run_spec.seed
        assert first.run_spec.invocation_id == second.run_spec.invocation_id
        assert {first.run_spec.mechanism_active, second.run_spec.mechanism_active} == {
            False,
            True,
        }
        assert {
            first.run_spec.cohort,
            second.run_spec.cohort,
        } == {"mechanism_off", "mechanism_on"}
        assert first.run_spec.batch_id == second.run_spec.batch_id == BATCH_ID


def test_runtime_mapping_rejects_bool_integer_substitution() -> None:
    schedule = _schedule()
    rows = list(schedule.runs)
    rows[0] = replace(rows[0], mechanism_on=1)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="type-substituted"):
        build_stage4_run_bindings(replace(schedule, runs=tuple(rows)), batch_id=BATCH_ID)


def test_schedule_loader_rebuilds_and_rejects_duplicate_keys(tmp_path: Path) -> None:
    schedule_path = tmp_path / "schedule.json"
    schedule_path.write_text(
        json.dumps(_schedule().to_manifest(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    loaded = load_stage4_schedule_manifest(schedule_path)
    assert loaded == _schedule()

    schedule_path.write_text('{"schema_version":"x","schema_version":"y"}\n')
    with pytest.raises(Stage4PreflightError, match="json_duplicate_key"):
        load_stage4_schedule_manifest(schedule_path)


def test_committed_draft_freeze_loads_crossed_measurement_structure() -> None:
    manifest = load_stage4_freeze_manifest(
        REPOSITORY / "manifests" / "stage4_freeze.json"
    )

    assert manifest["claim_boundary"]["repeated_measurement_structure"] == {
        "model_snapshots": "crossed_with_workflows",
        "repetitions": "nested_within_workflow_model_cells",
    }


def test_missing_freeze_fails_closed_without_creating_runtime_state(
    tmp_path: Path,
) -> None:
    report = run_stage4_preflight(repository_root=tmp_path, environment={})

    assert report == {
        "schema_version": "stage4-confirmatory-preflight-v1",
        "pass": False,
        "preflight_only": True,
        "provider_calls_made": 0,
        "provider_client_constructed": False,
        "authority_consumed": False,
        "ledger_created": False,
        "account_access_verified": False,
        "blockers": ["stage4_freeze_manifest_missing"],
    }
    assert list(tmp_path.iterdir()) == []


def test_cli_requires_preflight_latch_and_exposes_no_execution_overrides() -> None:
    parser = cli_module.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["run-stage4-confirmatory"])
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "run-stage4-confirmatory",
                "--preflight-only",
                "--output",
                "outputs/private/stage1-v0.2.1-20260901",
            ]
        )
    args = parser.parse_args(["run-stage4-confirmatory", "--preflight-only"])
    assert args.preflight_only is True
    assert not hasattr(args, "output")
    assert not hasattr(args, "authority_dir")
    assert not hasattr(args, "budget_ledger")


def test_cli_redacts_structural_preflight_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_args: object) -> dict[str, object]:
        raise Stage4PreflightError("stage4_test_failure")

    monkeypatch.setattr(runtime_module, "execute_stage4_command", fail)
    assert cli_module.main(["run-stage4-confirmatory", "--preflight-only"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "error": "stage4_test_failure",
        "schema_version": "stage4-confirmatory-preflight-error-v1",
    }


def test_provider_free_boundary_never_reads_stage4_secret_values(
    tmp_path: Path,
) -> None:
    class SecretNamesOnly(Mapping[str, str]):
        names = {
            "MAS_SAFETY_STAGE4_API_KEY",
            "MAS_SAFETY_STAGE4_PROVENANCE_KEY_B64",
            "MAS_SAFETY_STAGE4_PROVENANCE_KEY_ID",
        }

        def __getitem__(self, key: str) -> str:
            raise AssertionError(f"preflight read secret value for {key}")

        def __iter__(self) -> Iterator[str]:
            return iter(self.names)

        def __len__(self) -> int:
            return len(self.names)

        def __contains__(self, key: object) -> bool:
            return key in self.names

    manifest = {
        "budget_authority": {
            "authorized_ceiling_nano_usd": MINIMUM_REQUIRED_NANO_USD,
            "authorized_ceiling_usd": "257.023620000",
            "ledger_path": (
                "outputs/private/stage4-v0.4-confirmatory/budget_ledger.jsonl"
            ),
        },
        "credential_boundary": {
            "credential_id": "stage4-fresh-credential-v1",
            "credential_fingerprint_sha256": "a" * 64,
        },
        "provenance_boundary": {
            "key_id": "stage4-fresh-provenance-v1",
            "key_fingerprint_sha256": "b" * 64,
        },
        "storage_authority": {
            "execution_output_path": "outputs/private/stage4-v0.4-confirmatory",
            "encrypted_at_rest_attestation": "operator-attested-test-fixture",
        },
    }
    (tmp_path / "outputs" / "private").mkdir(parents=True)
    blockers: set[str] = set()

    _verify_budget_credential_storage(
        manifest,
        tmp_path,
        SecretNamesOnly(),
        blockers,
    )

    assert not any("credential" in code for code in blockers)
    assert not any("provenance" in code for code in blockers)


def test_provider_free_boundary_rejects_unknown_openai_and_stage1_key_id(
    tmp_path: Path,
) -> None:
    manifest = {
        "budget_authority": {
            "authorized_ceiling_nano_usd": MINIMUM_REQUIRED_NANO_USD,
            "authorized_ceiling_usd": "257.023620000",
            "ledger_path": (
                "outputs/private/stage4-v0.4-confirmatory/budget_ledger.jsonl"
            ),
        },
        "credential_boundary": {
            "credential_id": "stage4-fresh-credential-v1",
            "credential_fingerprint_sha256": "a" * 64,
        },
        "provenance_boundary": {
            "key_id": "stage4-fresh-provenance-v1",
            "key_fingerprint_sha256": "b" * 64,
        },
        "storage_authority": {
            "execution_output_path": "outputs/private/stage4-v0.4-confirmatory",
            "encrypted_at_rest_attestation": "operator-attested-test-fixture",
            "immutable_archive_attestation": "immutable-archive-test-fixture",
        },
    }
    (tmp_path / "outputs" / "private").mkdir(parents=True)
    blockers: set[str] = set()

    _verify_budget_credential_storage(
        manifest,
        tmp_path,
        {
            "OPENAI_LOG": "debug",
            "MAS_SAFETY_PROVENANCE_KEY_ID": "stage1-provenance-key-id",
        },
        blockers,
    )

    assert "ambient_openai_configuration_forbidden" in blockers
    assert "ambient_stage1_provenance_key_id_forbidden" in blockers


def test_old_stage1_budget_and_existing_stage4_state_fail_closed(
    tmp_path: Path,
) -> None:
    manifest = {
        "budget_authority": {
            "authorized_ceiling_nano_usd": 20_000_000_000,
            "authorized_ceiling_usd": "20.000000000",
            "ledger_path": (
                "outputs/private/stage4-v0.4-confirmatory/budget_ledger.jsonl"
            ),
        },
        "credential_boundary": {
            "credential_id": "stage4-fresh-credential-v1",
            "credential_fingerprint_sha256": "a" * 64,
        },
        "provenance_boundary": {
            "key_id": "stage4-fresh-provenance-v1",
            "key_fingerprint_sha256": "b" * 64,
        },
        "storage_authority": {
            "execution_output_path": "outputs/private/stage4-v0.4-confirmatory",
            "encrypted_at_rest_attestation": "test-only-attestation",
        },
    }
    output = tmp_path / "outputs" / "private" / "stage4-v0.4-confirmatory"
    output.mkdir(parents=True)
    (output / "budget_ledger.jsonl").write_text("existing\n", encoding="utf-8")
    authority = (
        tmp_path
        / "outputs"
        / "private"
        / "stage4-authorities"
        / "v0.4-stage4-confirmatory.authority.json"
    )
    authority.parent.mkdir(parents=True)
    authority.write_text("{}\n", encoding="utf-8")
    blockers: set[str] = set()

    _verify_budget_credential_storage(manifest, tmp_path, {}, blockers)

    assert "stage4_authorized_ceiling_insufficient" in blockers
    assert "stage4_output_already_exists" in blockers
    assert "stage4_budget_ledger_already_exists" in blockers
    assert "stage4_one_shot_authority_already_consumed" in blockers


def test_annotated_tag_must_target_clean_head_with_exact_commitments(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Stage4 Test")
    git("config", "user.email", "stage4-test@example.invalid")
    (repository / "implementation.txt").write_text("implementation\n")
    git("add", "implementation.txt")
    git("commit", "-qm", "implementation")

    manifest_path = repository / "manifests" / "stage4_freeze.json"
    schedule_path = repository / "manifests" / "stage4_schedule.json"
    manifest_path.parent.mkdir()
    manifest_path.write_text('{"freeze":"draft"}\n', encoding="utf-8")
    schedule_path.write_text('{"schedule":"fixture"}\n', encoding="utf-8")
    checksum_path = repository / "manifests" / "stage4_freeze.sha256"
    draft_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    checksum_path.write_text(
        f"{draft_sha}  manifests/stage4_freeze.json\n", encoding="utf-8"
    )
    git("add", "manifests")
    git("commit", "-qm", "candidate")
    parent = git("rev-parse", "HEAD")

    manifest_path.write_text("{}\n", encoding="utf-8")
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    schedule_sha = hashlib.sha256(schedule_path.read_bytes()).hexdigest()
    seal_sha = "c" * 64
    checksum_path.write_text(
        f"{manifest_sha}  manifests/stage4_freeze.json\n", encoding="utf-8"
    )
    git("add", "manifests/stage4_freeze.json", "manifests/stage4_freeze.sha256")
    git("commit", "-qm", "freeze")
    tag = "stage4-test-freeze"
    message = "\n".join(
        [
            f"Stage 4 freeze manifest SHA-256: {manifest_sha}",
            f"Stage 4 ordered schedule file SHA-256: {schedule_sha}",
            f"Stage 3 selection seal SHA-256: {seal_sha}",
        ]
    )
    git("tag", "-a", tag, "-m", message)
    manifest = {
        "repository_binding": {
            "planned_annotated_tag": tag,
            "manifest_parent_commit_sha": parent,
            "tag_message_commitments": [
                "stage4_freeze_manifest_sha256",
                "stage4_schedule_file_sha256",
                "stage3_selection_seal_sha256",
            ],
            "detached_manifest_checksum_path": "manifests/stage4_freeze.sha256",
        },
        "stage3_binding": {"selection_seal_sha256": seal_sha},
    }
    blockers: set[str] = set()

    head = _verify_repository_and_tag(
        manifest,
        repository,
        manifest_path,
        schedule_sha,
        blockers,
    )

    assert head == git("rev-parse", "HEAD")
    assert blockers == set()

    (repository / "forbidden.txt").write_text("not manifest-only\n", encoding="utf-8")
    git("add", "forbidden.txt")
    git("commit", "--amend", "-qm", "freeze with forbidden extra file")
    git("tag", "-d", tag)
    git("tag", "-a", tag, "-m", message)
    scope_blockers: set[str] = set()
    _verify_repository_and_tag(
        manifest,
        repository,
        manifest_path,
        schedule_sha,
        scope_blockers,
    )
    assert "freeze_commit_scope_mismatch" in scope_blockers

    (repository / "after.txt").write_text("new head\n", encoding="utf-8")
    git("add", "after.txt")
    git("commit", "-qm", "move head after freeze tag")
    moved_blockers: set[str] = set()
    _verify_repository_and_tag(
        manifest,
        repository,
        manifest_path,
        schedule_sha,
        moved_blockers,
    )
    assert "freeze_tag_target_not_clean_head" in moved_blockers
