from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from mas_safety import cli as root_cli
from mas_safety import stage2_cli
from mas_safety.stage2_replay import Stage2ReplayResult


@dataclass(frozen=True)
class RuntimeFixture:
    repository: Path
    source: Path
    public_stage1: Path
    output: Path
    authority: Path
    freeze_manifest: Path
    archive_commitment: Path
    implementation_commit: str
    freeze_commit: str
    key: bytes
    args: argparse.Namespace


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage2_cli.configure_stage2_parser(subparsers)
    return parser


def _runtime_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    commitment_overrides: dict[str, Any] | None = None,
    tracked_overrides: dict[str, str] | None = None,
    key_id: str = "stage2-production-v1",
) -> RuntimeFixture:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "stage2-test@example.invalid")
    _git(repository, "config", "user.name", "Stage2 Test")

    archive_commitment = (
        repository / "preservation/stage1-v0.2.1/archive-commitment.json"
    )
    archive_payload = {
        "algorithm": stage2_cli.ARCHIVE_COMMITMENT_ALGORITHM,
        "archive_scope": {
            "entries": "all descendant directories and regular files",
            "exclusions": [],
            "metadata_committed": [
                "entry_type",
                "relative_posix_utf8_path",
                "regular_file_size",
                "regular_file_sha256",
            ],
            "metadata_excluded": [
                "mode",
                "uid",
                "gid",
                "mtime",
                "ctime",
                "xattrs",
            ],
            "multiply_linked_regular_files": "rejected",
            "special_files": "rejected",
            "symbolic_links": "rejected",
        },
        "directory_count": stage2_cli.FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT,
        "merkle_root_sha256": stage2_cli.FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256,
        "privacy": {
            "filenames_disclosed": False,
            "per_file_digests_disclosed": False,
            "per_file_sizes_disclosed": False,
        },
        "regular_file_count": stage2_cli.FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT,
        "schema_version": stage2_cli.ARCHIVE_SCHEMA_VERSION,
    }
    _write(archive_commitment, json.dumps(archive_payload, sort_keys=True) + "\n")
    artifact_payloads = {
        "protocols/v0.2.2-stage2-replay-amendment.md": "# frozen amendment\n",
        "results/stage1-v0.2.1/runs.csv": "scheduled_workflow_run_order\n",
        "results/stage1-v0.2.1/summary.json": "{}\n",
        "scripts/archive_commitment.py": "# frozen archive verifier\n",
        "src/mas_safety/stage2_cli.py": "# frozen stage2 cli\n",
        "src/mas_safety/stage2_metrics.py": "# frozen metrics\n",
        "src/mas_safety/stage2_replay.py": "# frozen replay\n",
    }
    for relative, payload in artifact_payloads.items():
        _write(repository / relative, payload)
    _git(repository, "add", ".")
    _git(repository, "commit", "-qm", "Stage2 implementation")
    implementation_commit = _git(repository, "rev-parse", "HEAD")

    tracked = {
        relative: _sha256(repository / relative)
        for relative in sorted(stage2_cli._MANDATORY_TRACKED_ARTIFACTS)
    }
    if tracked_overrides:
        tracked.update(tracked_overrides)
    key = b"stage2-production-test-key-material-32-bytes"
    commitments: dict[str, Any] = {
        "amendment_sha256": _sha256(
            repository / "protocols/v0.2.2-stage2-replay-amendment.md"
        ),
        "private_archive_directory_count": (
            stage2_cli.FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT
        ),
        "private_archive_regular_file_count": (
            stage2_cli.FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT
        ),
        "private_archive_root_sha256": (
            stage2_cli.FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256
        ),
        "provenance_key_id": key_id,
        "provenance_key_sha256": hashlib.sha256(key).hexdigest(),
        "public_stage1_runs_sha256": _sha256(
            repository / "results/stage1-v0.2.1/runs.csv"
        ),
        "public_stage1_summary_sha256": _sha256(
            repository / "results/stage1-v0.2.1/summary.json"
        ),
        "replay_program_sha256": "sha256:" + "7" * 64,
        "source_dependency_root_sha256": "8" * 64,
    }
    if commitment_overrides:
        commitments.update(commitment_overrides)
    freeze_ref = "v0.2.2-stage2-freeze-test"
    freeze_manifest = repository / "manifests/stage2-v0.2.2-freeze.json"
    freeze_payload = {
        "claim_boundary": stage2_cli.FROZEN_CLAIM_BOUNDARY,
        "commitments": commitments,
        "freeze_ref": freeze_ref,
        "implementation_commit_sha": implementation_commit,
        "schema_version": stage2_cli.FREEZE_SCHEMA_VERSION,
        "tracked_artifact_sha256": tracked,
    }
    _write(freeze_manifest, json.dumps(freeze_payload, indent=2, sort_keys=True) + "\n")
    _git(repository, "add", "manifests/stage2-v0.2.2-freeze.json")
    _git(repository, "commit", "-qm", "Freeze Stage2")
    freeze_commit = _git(repository, "rev-parse", "HEAD")
    _git(repository, "tag", freeze_ref)

    source = tmp_path / "verified-readonly-source"
    source.mkdir()
    (source / "private-record.bin").write_bytes(b"private test fixture")
    (source / "private-record.bin").chmod(0o400)
    source.chmod(0o500)
    output = tmp_path / "fresh-output"
    authority = repository / stage2_cli.DEFAULT_AUTHORITY_DIR
    public_stage1 = repository / "results/stage1-v0.2.1"
    args = _parser().parse_args(
        [
            "run-stage2-replay",
            "--source",
            str(source),
            "--public-stage1",
            str(public_stage1),
            "--output",
            str(output),
            "--freeze-manifest",
            str(freeze_manifest),
            "--archive-commitment",
            str(archive_commitment),
        ]
    )
    monkeypatch.setattr(stage2_cli, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(
        stage2_cli,
        "stage2_amendment_sha256",
        lambda: commitments["amendment_sha256"],
    )
    monkeypatch.setattr(
        stage2_cli,
        "replay_program_sha256",
        lambda: "sha256:" + "7" * 64,
    )
    monkeypatch.setenv(stage2_cli.PROVENANCE_KEY_ENV, base64.b64encode(key).decode())
    return RuntimeFixture(
        repository=repository,
        source=source,
        public_stage1=public_stage1,
        output=output,
        authority=authority,
        freeze_manifest=freeze_manifest,
        archive_commitment=archive_commitment,
        implementation_commit=implementation_commit,
        freeze_commit=freeze_commit,
        key=key,
        args=args,
    )


def _verified_archive() -> dict[str, Any]:
    return {
        "directory_count": stage2_cli.FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT,
        "merkle_root_sha256": stage2_cli.FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256,
        "pass": True,
        "regular_file_count": stage2_cli.FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT,
        "schema_version": stage2_cli.ARCHIVE_SCHEMA_VERSION,
    }


def _result(output: Path) -> Stage2ReplayResult:
    return Stage2ReplayResult(
        output_dir=output,
        summary={"schema_version": "stage2-replay-summary-v1", "safe": True},
        checksums={
            name: hashlib.sha256(name.encode()).hexdigest()
            for name in stage2_cli.PUBLIC_OUTPUT_NAMES
        },
        authority_id="a" * 64,
    )


def test_parser_exposes_exact_command_and_defaults() -> None:
    args = _parser().parse_args(["run-stage2-replay"])

    assert args.command == "run-stage2-replay"
    assert args.source_dir == stage2_cli.DEFAULT_SOURCE_DIR
    assert args.public_stage1_dir == stage2_cli.DEFAULT_PUBLIC_STAGE1_DIR
    assert args.output == stage2_cli.DEFAULT_OUTPUT_DIR
    assert args.authority_dir == stage2_cli.DEFAULT_AUTHORITY_DIR
    assert args.freeze_manifest == stage2_cli.DEFAULT_FREEZE_MANIFEST
    assert args.archive_commitment == stage2_cli.DEFAULT_ARCHIVE_COMMITMENT
    assert args.stage2_executor is stage2_cli.execute_stage2_command


def test_parser_does_not_expose_authority_directory_override() -> None:
    with pytest.raises(SystemExit):
        _parser().parse_args(
            [
                "run-stage2-replay",
                "--authority-dir",
                "outputs/private/authorities/bypass",
            ]
        )


def test_crafted_authority_path_switch_fails_before_verification_or_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    args = argparse.Namespace(**vars(runtime.args))
    args.authority_dir = Path("outputs/private/authorities/bypass")
    verifier_called = False
    replay_called = False

    def verifier(*_args: Any) -> dict[str, Any]:
        nonlocal verifier_called
        verifier_called = True
        return _verified_archive()

    def runner(**_kwargs: Any) -> Stage2ReplayResult:
        nonlocal replay_called
        replay_called = True
        return _result(runtime.output)

    monkeypatch.setattr(stage2_cli, "_run_archive_verifier", verifier)

    with pytest.raises(
        stage2_cli.Stage2CLIError,
        match="authority_directory_override_forbidden",
    ):
        stage2_cli.execute_stage2_command(args, replay_runner=runner)

    assert verifier_called is False
    assert replay_called is False


def test_execute_verifies_archive_immediately_before_exact_replay_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    call_order: list[str] = []

    def verifier(source: Path, commitment: Path, repository: Path) -> dict[str, Any]:
        call_order.append("archive_verify")
        assert source == runtime.source
        assert commitment == runtime.archive_commitment
        assert repository == runtime.repository
        return _verified_archive()

    def runner(**kwargs: Any) -> Stage2ReplayResult:
        call_order.append("replay")
        assert kwargs["source_dir"] == runtime.source
        assert kwargs["public_stage1_dir"] == runtime.public_stage1
        assert kwargs["output_dir"] == runtime.output
        assert kwargs["authority_dir"] == runtime.authority
        assert kwargs["provenance_signing_key"] == runtime.key
        assert kwargs["provenance_key_id"] == "stage2-production-v1"
        assert kwargs["commitments"] is stage2_cli.FROZEN_STAGE1_COMMITMENTS
        assert kwargs["stage2_freeze"].freeze_commit_sha == runtime.freeze_commit
        assert kwargs["archive_root_audit"] == stage2_cli.ArchiveRootAudit(
            algorithm=stage2_cli.ARCHIVE_COMMITMENT_ALGORITHM,
            merkle_root_sha256=stage2_cli.FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256,
            regular_file_count=stage2_cli.FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT,
            directory_count=stage2_cli.FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT,
            passed=True,
        )
        return _result(runtime.output)

    monkeypatch.setattr(stage2_cli, "_run_archive_verifier", verifier)
    report = stage2_cli.execute_stage2_command(runtime.args, replay_runner=runner)

    assert call_order == ["archive_verify", "replay"]
    assert report["authority"] == {"consumed": True, "id": "a" * 64}
    assert report["model_or_provider_calls"] == 0
    assert report["archive_root_audit"]["regular_file_count"] == 1537
    serialized = json.dumps(report, sort_keys=True)
    assert base64.b64encode(runtime.key).decode() not in serialized
    assert runtime.key.decode() not in serialized
    assert "source_dir" not in serialized


def test_import_does_not_load_live_or_openai_modules() -> None:
    code = (
        "import sys; import mas_safety.stage2_cli; "
        "assert 'openai' not in sys.modules; "
        "assert 'mas_safety.live' not in sys.modules; "
        "assert 'mas_safety.live_backends' not in sys.modules"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path("src").resolve())
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert completed.returncode == 0, completed.stderr


def test_root_parser_registers_stage2_command() -> None:
    args = root_cli.build_parser().parse_args(["run-stage2-replay"])

    assert args.command == "run-stage2-replay"
    assert args.stage2_executor is stage2_cli.execute_stage2_command
    assert args.source_dir == stage2_cli.DEFAULT_SOURCE_DIR
    assert args.freeze_manifest == stage2_cli.DEFAULT_FREEZE_MANIFEST


def test_root_cli_dispatches_stage2_executor(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    observed: list[argparse.Namespace] = []

    def executor(args: argparse.Namespace) -> dict[str, Any]:
        observed.append(args)
        return {"schema_version": "stage2-cli-result-v1", "ok": True}

    monkeypatch.setattr(stage2_cli, "execute_stage2_command", executor)

    assert root_cli.main(["run-stage2-replay"]) == 0
    assert len(observed) == 1
    assert observed[0].command == "run-stage2-replay"
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "schema_version": "stage2-cli-result-v1",
    }


def test_root_cli_redacts_stage2_error_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    private_detail = "PRIVATE_PATH_AND_KEY_MATERIAL"

    def executor(_args: argparse.Namespace) -> dict[str, Any]:
        try:
            raise RuntimeError(private_detail)
        except RuntimeError as exc:
            raise stage2_cli.Stage2CLIError("stage2_fixture_failure") from exc

    monkeypatch.setattr(stage2_cli, "execute_stage2_command", executor)

    assert root_cli.main(["run-stage2-replay"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {
        "error": "stage2_fixture_failure",
        "schema_version": "stage2-cli-error-v1",
    }
    assert private_detail not in output.err


def test_root_cli_redacts_unexpected_stage2_error_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    private_detail = "/private/archive/unexpected-secret-value"

    def executor(_args: argparse.Namespace) -> dict[str, Any]:
        raise RuntimeError(private_detail)

    monkeypatch.setattr(stage2_cli, "execute_stage2_command", executor)

    assert root_cli.main(["run-stage2-replay"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {
        "error": "stage2_unexpected_failure",
        "schema_version": "stage2-cli-error-v1",
    }
    assert private_detail not in output.err


def test_importing_root_cli_does_not_load_live_or_openai_modules() -> None:
    code = (
        "import sys; import mas_safety.cli; "
        "assert 'openai' not in sys.modules; "
        "assert 'mas_safety.live' not in sys.modules; "
        "assert 'mas_safety.live_backends' not in sys.modules"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path("src").resolve())
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ('{"schema_version":"x","schema_version":"y"}', "json_duplicate_key"),
        ('{"schema_version":NaN}', "json_nonfinite_number"),
    ],
)
def test_freeze_json_is_strict(tmp_path: Path, payload: str, error: str) -> None:
    manifest = tmp_path / "freeze.json"
    manifest.write_text(payload, encoding="utf-8")

    with pytest.raises(stage2_cli.Stage2CLIError, match=error):
        stage2_cli.load_stage2_freeze_manifest(manifest)


def test_secret_shaped_provenance_id_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    manifest = json.loads(runtime.freeze_manifest.read_text(encoding="utf-8"))
    manifest["commitments"]["provenance_key_id"] = "secret-stage2-key"
    candidate = tmp_path / "unsafe-freeze.json"
    candidate.write_text(json.dumps(manifest), encoding="utf-8")
    parsed = stage2_cli.load_stage2_freeze_manifest(candidate)

    with pytest.raises(
        stage2_cli.Stage2CLIError, match="stage2_provenance_identity_invalid"
    ):
        stage2_cli._verify_manifest_commitments(
            parsed,
            repository=runtime.repository,
            public_stage1=runtime.public_stage1,
            archive_commitment=runtime.archive_commitment,
            key=runtime.key,
        )


@pytest.mark.parametrize(
    ("encoded", "error"),
    [
        (None, "stage2_provenance_key_missing"),
        ("not valid base64!", "stage2_provenance_key_invalid_base64"),
        (base64.b64encode(b"short").decode(), "stage2_provenance_key_too_short"),
    ],
)
def test_provenance_environment_is_mandatory_and_strict(
    monkeypatch: pytest.MonkeyPatch, encoded: str | None, error: str
) -> None:
    if encoded is None:
        monkeypatch.delenv(stage2_cli.PROVENANCE_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(stage2_cli.PROVENANCE_KEY_ENV, encoded)

    with pytest.raises(stage2_cli.Stage2CLIError, match=error):
        stage2_cli._decode_stage2_provenance_key()


def test_wrong_key_fingerprint_fails_before_archive_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    monkeypatch.setenv(
        stage2_cli.PROVENANCE_KEY_ENV,
        base64.b64encode(b"different-production-key-material-32-bytes").decode(),
    )
    verifier_called = False

    def verifier(*_args: Any) -> dict[str, Any]:
        nonlocal verifier_called
        verifier_called = True
        return _verified_archive()

    monkeypatch.setattr(stage2_cli, "_run_archive_verifier", verifier)
    with pytest.raises(
        stage2_cli.Stage2CLIError, match="stage2_provenance_fingerprint_mismatch"
    ):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=_result)
    assert verifier_called is False


def test_dirty_git_worktree_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    _write(runtime.repository / "untracked.txt", "dirty\n")

    with pytest.raises(stage2_cli.Stage2CLIError, match="git_worktree_dirty"):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=_result)


def test_wrong_or_missing_freeze_tag_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    _git(runtime.repository, "tag", "-d", "v0.2.2-stage2-freeze-test")

    with pytest.raises(stage2_cli.Stage2CLIError, match="git_verification_failed"):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=_result)


def test_nonancestor_implementation_commit_is_rejected_from_returncode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    tree = _git(runtime.repository, "rev-parse", f"{runtime.implementation_commit}^{{tree}}")
    unrelated = _git(runtime.repository, "commit-tree", tree, "-m", "unrelated")
    manifest = json.loads(runtime.freeze_manifest.read_text(encoding="utf-8"))
    manifest["implementation_commit_sha"] = unrelated
    runtime.freeze_manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _git(runtime.repository, "add", "manifests/stage2-v0.2.2-freeze.json")
    _git(runtime.repository, "commit", "--amend", "-qm", "Freeze Stage2 unrelated")
    _git(
        runtime.repository,
        "tag",
        "-f",
        "v0.2.2-stage2-freeze-test",
    )

    with pytest.raises(
        stage2_cli.Stage2CLIError, match="implementation_not_ancestor"
    ):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=_result)


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"public_stage1_runs_sha256": "0" * 64}, "public_stage1_hash_mismatch"),
        ({"private_archive_root_sha256": "0" * 64}, "freeze_archive_commitment_mismatch"),
    ],
)
def test_wrong_frozen_commitment_hash_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, Any],
    error: str,
) -> None:
    runtime = _runtime_fixture(
        tmp_path, monkeypatch, commitment_overrides=overrides
    )

    with pytest.raises(stage2_cli.Stage2CLIError, match=error):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=_result)


def test_wrong_tracked_artifact_hash_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(
        tmp_path,
        monkeypatch,
        tracked_overrides={"src/mas_safety/stage2_cli.py": "0" * 64},
    )

    with pytest.raises(
        stage2_cli.Stage2CLIError, match="tracked_artifact_hash_mismatch"
    ):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=_result)


def test_source_output_authority_overlap_and_existing_output_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    overlap_args = argparse.Namespace(**vars(runtime.args))
    overlap_args.output = runtime.source / "nested-output"
    with pytest.raises(stage2_cli.Stage2CLIError, match="source_output_path_overlap"):
        stage2_cli.execute_stage2_command(overlap_args, replay_runner=_result)

    runtime.output.mkdir()
    with pytest.raises(stage2_cli.Stage2CLIError, match="stage2_output_already_exists"):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=_result)


def test_symlink_source_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    linked = tmp_path / "linked-source"
    try:
        linked.symlink_to(runtime.source, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links unavailable")
    args = argparse.Namespace(**vars(runtime.args))
    args.source_dir = linked

    with pytest.raises(stage2_cli.Stage2CLIError, match="source_archive_unsafe"):
        stage2_cli.execute_stage2_command(args, replay_runner=_result)


def test_git_environment_drops_ambient_repository_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambient = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/private/alternate-objects",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "/private/injector",
        "GIT_DIR": "/private/spoofed-repository",
        "GIT_EXEC_PATH": "/private/spoofed-exec-path",
        "GIT_INDEX_FILE": "/private/spoofed-index",
        "GIT_WORK_TREE": "/private/spoofed-worktree",
    }
    for name, value in ambient.items():
        monkeypatch.setenv(name, value)

    environment = stage2_cli._git_environment()

    assert all(name not in environment for name in ambient)
    assert {
        name for name in environment if name.startswith("GIT_")
    } == {
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_SYSTEM",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OPTIONAL_LOCKS",
    }
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_CONFIG_SYSTEM"] == os.devnull
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_archive_verifier_uses_isolated_sanitized_python_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    verifier = repository / "scripts/archive_commitment.py"
    _write(verifier, "# synthetic verifier\n")
    sensitive_environment = {
        "DYLD_INSERT_LIBRARIES": "/private/injector.dylib",
        "LD_PRELOAD": "/private/injector.so",
        "MAS_SAFETY_STAGE2_PROVENANCE_KEY_B64": "private-provenance-value",
        "OPENAI_API_KEY": "private-openai-value",
        "OPENAI_BASE_URL": "https://private.invalid",
        "PYTHONHOME": "/private/python-home",
        "PYTHONPATH": "/private/python-path",
        "VIRTUAL_ENV": "/private/virtual-environment",
        "X_CUSTOM_HEADER": "private-header-value",
    }
    for name, value in sensitive_environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("STAGE2_BENIGN_SENTINEL", "preserved")
    observed: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(_verified_archive()),
            stderr="",
        )

    monkeypatch.setattr(stage2_cli.subprocess, "run", fake_run)
    result = stage2_cli._run_archive_verifier(
        tmp_path / "source",
        tmp_path / "commitment.json",
        repository,
    )

    assert result == _verified_archive()
    assert observed["command"][1:4] == ["-I", "-S", "-B"]
    child_environment = observed["environment"]
    assert all(name not in child_environment for name in sensitive_environment)
    assert child_environment["PYTHONHASHSEED"] == "0"
    assert child_environment["PYTHONNOUSERSITE"] == "1"
    assert child_environment["PYTHONSAFEPATH"] == "1"
    assert child_environment["STAGE2_BENIGN_SENTINEL"] == "preserved"


def test_archive_commitment_requires_exact_field_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    manifest = stage2_cli.load_stage2_freeze_manifest(runtime.freeze_manifest)
    payload = json.loads(runtime.archive_commitment.read_text(encoding="utf-8"))
    payload["unexpected_private_metadata"] = "must not be accepted"
    candidate = tmp_path / "commitment-with-extra-field.json"
    candidate.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        stage2_cli.Stage2CLIError,
        match="archive_commitment_field_set_invalid",
    ):
        stage2_cli._validate_archive_commitment_file(
            candidate,
            manifest["commitments"],
        )


def test_symlink_public_input_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    public_stage1 = tmp_path / "unsafe-public-stage1"
    public_stage1.mkdir()
    try:
        (public_stage1 / "runs.csv").symlink_to(
            runtime.public_stage1 / "runs.csv"
        )
    except OSError:
        pytest.skip("symbolic links unavailable")
    _write(public_stage1 / "summary.json", "{}\n")
    args = argparse.Namespace(**vars(runtime.args))
    args.public_stage1_dir = public_stage1

    with pytest.raises(
        stage2_cli.Stage2CLIError,
        match="public_stage1_input_unsafe",
    ):
        stage2_cli.execute_stage2_command(args, replay_runner=_result)


def test_hardlinked_regular_input_is_rejected(tmp_path: Path) -> None:
    original = tmp_path / "original.json"
    linked = tmp_path / "linked.json"
    original.write_text("{}\n", encoding="utf-8")
    try:
        os.link(original, linked)
    except OSError:
        pytest.skip("hard links unavailable")

    with pytest.raises(stage2_cli.Stage2CLIError, match="unsafe_input"):
        stage2_cli._require_regular_input(linked, "unsafe_input")


def test_replay_failure_is_redacted_without_private_exception_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        stage2_cli,
        "_run_archive_verifier",
        lambda *_args: _verified_archive(),
    )
    private_detail = "/private/archive/request-very-secret"

    def runner(**_kwargs: Any) -> Stage2ReplayResult:
        raise stage2_cli.Stage2ReplayError(private_detail)

    with pytest.raises(stage2_cli.Stage2CLIError) as caught:
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=runner)

    assert str(caught.value) == "stage2_replay_failed"
    assert private_detail not in str(caught.value)
    assert caught.value.__suppress_context__ is True


def test_replay_does_not_mask_process_control_exceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        stage2_cli,
        "_run_archive_verifier",
        lambda *_args: _verified_archive(),
    )

    def runner(**_kwargs: Any) -> Stage2ReplayResult:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        stage2_cli.execute_stage2_command(runtime.args, replay_runner=runner)
