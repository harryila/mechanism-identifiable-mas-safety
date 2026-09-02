#!/usr/bin/env python3
"""Finalize the provider-free Stage 4 manifest without reading any secret."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import sysconfig
import tempfile
import zipimport
from contextlib import contextmanager
from pathlib import Path


REQUIRED_MINIMUM_NANO_USD = 257_023_620_000
_FORBIDDEN_PYTHON_ENV = frozenset(
    {
        "PYTHONBREAKPOINT",
        "PYTHONCASEOK",
        "PYTHONEXECUTABLE",
        "PYTHONHASHSEED",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONNOUSERSITE",
        "PYTHONOPTIMIZE",
        "PYTHONPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONSAFEPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "__PYVENV_LAUNCHER__",
    }
)


def _git_environment() -> dict[str, str]:
    safe_ambient_names = ("PATH", "LANG", "LC_ALL", "TMPDIR", "TZ", "SYSTEMROOT")
    environment = {
        key: os.environ[key] for key in safe_ambient_names if key in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        env=_git_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise RuntimeError("Stage 4 finalization could not resolve repository state")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("Stage 4 repository state was not ASCII") from exc


def _git_bytes(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        env=_git_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise RuntimeError("Stage 4 finalization could not resolve repository bytes")
    return completed.stdout


def _standard_path_hooks() -> list[object]:
    loader_details = (
        (
            importlib.machinery.ExtensionFileLoader,
            importlib.machinery.EXTENSION_SUFFIXES,
        ),
        (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES),
        (
            importlib.machinery.SourcelessFileLoader,
            importlib.machinery.BYTECODE_SUFFIXES,
        ),
    )
    return [
        zipimport.zipimporter,
        importlib.machinery.FileFinder.path_hook(*loader_details),
    ]


class _FrozenProjectSourceLoader(importlib.abc.Loader):
    """Execute one verified project module directly from its source bytes."""

    def __init__(
        self,
        *,
        fullname: str,
        source_path: Path,
        source_bytes: bytes,
        is_package: bool,
    ) -> None:
        self.fullname = fullname
        self.source_path = source_path
        self.source_bytes = source_bytes
        self.is_package = is_package

    def create_module(self, spec: object) -> None:
        del spec
        return None

    def exec_module(self, module: object) -> None:
        namespace = module.__dict__
        namespace["__file__"] = str(self.source_path)
        namespace["__cached__"] = None
        if self.is_package:
            namespace["__path__"] = [str(self.source_path.parent)]
        try:
            code = compile(
                self.source_bytes,
                str(self.source_path),
                "exec",
                dont_inherit=True,
            )
        except (SyntaxError, ValueError) as exc:
            raise RuntimeError(
                "Stage 4 finalizer frozen project source could not compile"
            ) from exc
        exec(code, namespace)


class _FrozenProjectSourceFinder(importlib.abc.MetaPathFinder):
    """Resolve every ``mas_safety`` import without consulting bytecode caches."""

    def __init__(self, repository: Path, package_root: Path) -> None:
        self.repository = repository
        self.package_root = package_root

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: object = None,
    ) -> object:
        del path, target
        if fullname != "mas_safety" and not fullname.startswith("mas_safety."):
            return None
        parts = fullname.split(".")[1:]
        candidate = self.package_root.joinpath(*parts) if parts else self.package_root
        package_source = candidate / "__init__.py"
        if package_source.is_file() and not package_source.is_symlink():
            source_path = package_source
            is_package = True
        else:
            source_path = candidate.with_suffix(".py")
            is_package = False
        if not source_path.is_file() or source_path.is_symlink():
            raise ModuleNotFoundError(
                f"Frozen Stage 4 project module is unavailable: {fullname}"
            )
        try:
            relative = source_path.resolve(strict=True).relative_to(
                self.package_root
            )
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                "Stage 4 finalizer project import escaped repository"
            ) from exc
        git_relative = (Path("src") / "mas_safety" / relative).as_posix()
        source_bytes = source_path.read_bytes()
        if source_bytes != _git_bytes(
            self.repository,
            "show",
            f"HEAD:{git_relative}",
        ):
            raise RuntimeError(
                "Stage 4 finalizer imported source differs from clean HEAD"
            )
        loader = _FrozenProjectSourceLoader(
            fullname=fullname,
            source_path=source_path,
            source_bytes=source_bytes,
            is_package=is_package,
        )
        return importlib.util.spec_from_loader(
            fullname,
            loader,
            origin=str(source_path),
            is_package=is_package,
        )


def _assert_finalizer_process_boundary() -> None:
    if sys.flags.isolated != 1:
        raise RuntimeError("Stage 4 finalization requires python -I")
    if any(name in os.environ for name in _FORBIDDEN_PYTHON_ENV) or any(
        name.startswith("PYTHON") or name == "__PYVENV_LAUNCHER__"
        for name in os.environ
    ):
        raise RuntimeError("Stage 4 finalization forbids Python startup overrides")
    if any(
        name == "mas_safety" or name.startswith("mas_safety.")
        for name in sys.modules
    ):
        raise RuntimeError("Stage 4 finalization rejects preloaded project modules")


def _assert_finalizer_script_binding(repository: Path) -> None:
    script_path = Path(__file__).resolve(strict=True)
    expected_script_path = (
        repository / "scripts" / "finalize_stage4_freeze.py"
    ).resolve()
    if (
        script_path != expected_script_path
        or script_path.read_bytes()
        != _git_bytes(repository, "show", "HEAD:scripts/finalize_stage4_freeze.py")
    ):
        raise RuntimeError("Stage 4 finalizer script differs from clean HEAD")


@contextmanager
def _frozen_builder_import(repository: Path):
    """Import the finalizer implementation only from the clean frozen tree."""

    _assert_finalizer_process_boundary()

    source_root = (repository / "src").resolve(strict=True)
    package_root = (source_root / "mas_safety").resolve(strict=True)
    configured = sysconfig.get_paths()
    trusted_entries = [source_root]
    for name in ("stdlib", "platstdlib", "purelib", "platlib"):
        candidate = Path(configured[name]).resolve(strict=True)
        if candidate not in trusted_entries:
            trusted_entries.append(candidate)
    stdlib = Path(configured["stdlib"]).resolve()
    standard_zip = (
        stdlib.parent / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
    ).resolve()
    trusted_entries.insert(1, standard_zip)

    prior_path = list(sys.path)
    prior_meta_path = list(sys.meta_path)
    prior_path_hooks = list(sys.path_hooks)
    sys.path[:] = [str(path) for path in trusted_entries]
    sys.meta_path[:] = [
        _FrozenProjectSourceFinder(repository, package_root),
        importlib.machinery.BuiltinImporter,
        importlib.machinery.FrozenImporter,
        importlib.machinery.PathFinder,
    ]
    sys.path_hooks[:] = _standard_path_hooks()
    sys.path_importer_cache.clear()
    try:
        module = importlib.import_module("mas_safety.stage4_freeze")
        for name, loaded in tuple(sys.modules.items()):
            if name != "mas_safety" and not name.startswith("mas_safety."):
                continue
            origin = getattr(loaded, "__file__", None)
            if not isinstance(origin, str):
                raise RuntimeError("Stage 4 finalizer project import origin is invalid")
            path = Path(origin).resolve(strict=True)
            if path.suffix in {".pyc", ".pyo"}:
                path = Path(importlib.util.source_from_cache(str(path))).resolve(
                    strict=True
                )
            try:
                relative = path.relative_to(package_root)
            except ValueError as exc:
                raise RuntimeError(
                    "Stage 4 finalizer project import escaped repository"
                ) from exc
            git_relative = (Path("src") / "mas_safety" / relative).as_posix()
            if path.read_bytes() != _git_bytes(
                repository, "show", f"HEAD:{git_relative}"
            ):
                raise RuntimeError(
                    "Stage 4 finalizer imported source differs from clean HEAD"
                )
        yield module
    finally:
        sys.path[:] = prior_path
        sys.meta_path[:] = prior_meta_path
        sys.path_hooks[:] = prior_path_hooks
        sys.path_importer_cache.clear()


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Apply only non-secret Stage 4 finalization fields. This command makes "
            "zero provider calls and does not create execution authority."
        )
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--authorized-ceiling-nano-usd",
        type=int,
        required=True,
        help=(
            "Explicit Stage 4-only hard ceiling; minimum "
            f"{REQUIRED_MINIMUM_NANO_USD} nano-USD."
        ),
    )
    parser.add_argument("--credential-id", required=True)
    parser.add_argument("--credential-fingerprint-sha256", required=True)
    parser.add_argument("--provenance-key-id", required=True)
    parser.add_argument("--provenance-key-fingerprint-sha256", required=True)
    parser.add_argument("--encrypted-at-rest-attestation", required=True)
    parser.add_argument("--immutable-archive-attestation", required=True)
    return parser.parse_args()


def main() -> int:
    _assert_finalizer_process_boundary()
    args = _parse_args()
    repository = args.repository_root.resolve()
    if not (repository / ".git").is_dir():
        raise RuntimeError("Stage 4 finalization requires the repository checkout")
    if _git(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("Stage 4 finalization requires a clean implementation HEAD")
    _assert_finalizer_script_binding(repository)

    with _frozen_builder_import(repository) as freeze_builder:
        freeze_manifest_path = freeze_builder.FREEZE_MANIFEST_PATH
        freeze_checksum_path = freeze_builder.FREEZE_CHECKSUM_PATH
        schedule_path = freeze_builder.SCHEDULE_PATH

        # This proves the checked-in draft, schedule, commitments, and every
        # tracked implementation dependency reproduce before the manifest is
        # changed.
        freeze_builder.verify_candidate_artifacts(repository)
        parent_commit = _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
        manifest_path = repository / freeze_manifest_path
        draft = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(draft, dict):
            raise RuntimeError("Stage 4 draft manifest is not a JSON object")
        finalized = freeze_builder.build_finalized_freeze_manifest(
            draft,
            manifest_parent_commit_sha=parent_commit,
            authorized_ceiling_nano_usd=args.authorized_ceiling_nano_usd,
            credential_id=args.credential_id,
            credential_fingerprint_sha256=args.credential_fingerprint_sha256,
            provenance_key_id=args.provenance_key_id,
            provenance_key_fingerprint_sha256=(
                args.provenance_key_fingerprint_sha256
            ),
            encrypted_at_rest_attestation=args.encrypted_at_rest_attestation,
            immutable_archive_attestation=args.immutable_archive_attestation,
        )
        manifest_bytes = (
            json.dumps(finalized, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        checksum_bytes = (
            f"{manifest_sha256}  {freeze_manifest_path.as_posix()}\n"
        ).encode("ascii")
        _atomic_write(manifest_path, manifest_bytes)
        _atomic_write(repository / freeze_checksum_path, checksum_bytes)

        # The overlay verifier proves no claim-bearing field was changed. It
        # does not create the final commit or tag; those remain explicit
        # operator acts.
        freeze_builder.verify_candidate_artifacts(repository)
        schedule_sha256 = hashlib.sha256(
            (repository / schedule_path).read_bytes()
        ).hexdigest()
        stage3_seal_sha256 = finalized["stage3_binding"]["selection_seal_sha256"]
        report = {
            "schema_version": "stage4-provider-free-finalization-v1",
            "pass": True,
            "provider_calls_made": 0,
            "secrets_read": False,
            "authority_created": False,
            "manifest_parent_commit_sha": parent_commit,
            "freeze_manifest_sha256": manifest_sha256,
            "next_required_actions": [
                "commit_only_the_finalized_manifest_and_detached_checksum",
                "create_the_exact_annotated_freeze_tag",
                "run_read_only_preflight",
                "invoke_execute_only_under_separate_explicit_authority",
            ],
            "annotated_tag_message_lines": [
                f"Stage 4 freeze manifest SHA-256: {manifest_sha256}",
                f"Stage 4 ordered schedule file SHA-256: {schedule_sha256}",
                f"Stage 3 selection seal SHA-256: {stage3_seal_sha256}",
            ],
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
