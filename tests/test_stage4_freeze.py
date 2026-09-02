from __future__ import annotations

import json
from pathlib import Path

import pytest

from mas_safety.stage4_freeze import (
    ALL_EXECUTE_MAXIMUM_COST_NANO_USD,
    BATCH_ID,
    EXPECTED_CALLS,
    FREEZE_CHECKSUM_PATH,
    FREEZE_MANIFEST_PATH,
    PROMPT_COMMITMENTS_PATH,
    REQUIRED_MINIMUM_NANO_USD,
    SCHEDULE_PATH,
    SCHEDULE_SEED,
    build_finalized_freeze_manifest,
    verify_finalized_freeze_overlay,
    verify_candidate_artifacts,
)


REPOSITORY = Path(__file__).resolve().parents[1]


def _load(relative: Path) -> dict[str, object]:
    value = json.loads((REPOSITORY / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_committed_stage4_candidate_artifacts_rebuild_exactly_offline() -> None:
    verify_candidate_artifacts(REPOSITORY)


def test_stage4_schedule_and_request_commitments_have_exact_frozen_counts() -> None:
    schedule = _load(SCHEDULE_PATH)
    commitments = _load(PROMPT_COMMITMENTS_PATH)

    assert schedule["seed"] == SCHEDULE_SEED
    assert len(schedule["runs"]) == 768  # type: ignore[arg-type]
    assert commitments["batch_id"] == BATCH_ID
    assert commitments["call_count"] == EXPECTED_CALLS
    assert commitments["required_minimum_nano_usd"] == REQUIRED_MINIMUM_NANO_USD
    assert (
        commitments["all_execute_maximum_cost_nano_usd"]
        == ALL_EXECUTE_MAXIMUM_COST_NANO_USD
    )
    assert [
        item["completion_safe_cost_nano_usd"]  # type: ignore[index]
        for item in commitments["models"]  # type: ignore[union-attr]
    ] == [85_674_540_000, 171_349_080_000]
    assert commitments["minimum_request_utf8_bytes"] == 3_408
    assert commitments["maximum_request_utf8_bytes"] == 4_281
    assert commitments["total_request_utf8_bytes"] == 11_804_904
    assert commitments["contains_prompt_or_request_bodies"] is False
    assert commitments["binds_all_potential_provider_requests"] is True
    assert {item["calls"] for item in commitments["models"]} == {1_536}  # type: ignore[index,union-attr]


def test_candidate_freeze_is_explicitly_unexecutable_and_has_no_reused_authority() -> None:
    manifest = _load(FREEZE_MANIFEST_PATH)

    assert manifest["freeze_status"] == "draft_unexecutable"
    assert manifest["unresolved_blockers"]
    assert manifest["budget_authority"]["prior_authority_reusable"] is False  # type: ignore[index]
    assert manifest["budget_authority"]["authorized_ceiling_nano_usd"] is None  # type: ignore[index]
    assert manifest["credential_boundary"]["forbidden_env"] == "OPENAI_API_KEY"  # type: ignore[index]
    assert manifest["repository_binding"]["freeze_commit_sha"] is None  # type: ignore[index]
    assert manifest["repository_binding"]["manifest_embeds_containing_commit"] is False  # type: ignore[index]
    checksum = (REPOSITORY / FREEZE_CHECKSUM_PATH).read_text(encoding="utf-8")
    assert checksum.endswith("  manifests/stage4_freeze.json\n")


def test_provider_free_finalization_changes_only_explicit_authority_fields() -> None:
    draft = _load(FREEZE_MANIFEST_PATH)
    finalized = build_finalized_freeze_manifest(
        draft,
        manifest_parent_commit_sha="1" * 40,
        authorized_ceiling_nano_usd=REQUIRED_MINIMUM_NANO_USD,
        credential_id="stage4-credential-2026-09-01",
        credential_fingerprint_sha256="2" * 64,
        provenance_key_id="stage4-provenance-2026-09-01",
        provenance_key_fingerprint_sha256="3" * 64,
        encrypted_at_rest_attestation="encrypted-volume:stage4-v0.4",
        immutable_archive_attestation="immutable-archive:stage4-v0.4",
    )

    verify_finalized_freeze_overlay(finalized, draft)
    assert finalized["freeze_status"] == "frozen_executable"
    assert finalized["unresolved_blockers"] == []
    assert finalized["repository_binding"]["freeze_commit_sha"] is None
    assert finalized["provider_contract"]["account_access_verified"] is False
    assert (
        finalized["budget_authority"]["authorized_ceiling_usd"]
        == "257.023620000"
    )

    finalized["decision_rule"]["minimum_qualifying_mechanisms"] = 0
    with pytest.raises(ValueError, match="outside the allowed overlay"):
        verify_finalized_freeze_overlay(finalized, draft)


def test_provider_free_finalization_rejects_insufficient_or_secret_shaped_inputs() -> None:
    draft = _load(FREEZE_MANIFEST_PATH)
    common = {
        "manifest_parent_commit_sha": "1" * 40,
        "credential_id": "stage4-credential",
        "credential_fingerprint_sha256": "2" * 64,
        "provenance_key_id": "stage4-provenance",
        "provenance_key_fingerprint_sha256": "3" * 64,
        "encrypted_at_rest_attestation": "encrypted-volume:stage4",
        "immutable_archive_attestation": "immutable-archive:stage4",
    }
    with pytest.raises(ValueError, match="below"):
        build_finalized_freeze_manifest(
            draft,
            authorized_ceiling_nano_usd=REQUIRED_MINIMUM_NANO_USD - 1,
            **common,
        )
    with pytest.raises(ValueError, match="non-secret identifier"):
        build_finalized_freeze_manifest(
            draft,
            authorized_ceiling_nano_usd=REQUIRED_MINIMUM_NANO_USD,
            credential_id="sk-forbidden",
            **{key: value for key, value in common.items() if key != "credential_id"},
        )
