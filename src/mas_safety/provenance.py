from __future__ import annotations

import hashlib
import hmac
import json

DEVELOPMENT_KEY_ID = "development-hmac-sha256-v1"
DEVELOPMENT_SIGNING_KEY = b"mas-safety-deterministic-development-key-v1"


def sign_claims(
    key: bytes,
    *,
    scenario_id: str,
    artifact_id: str,
    claims: dict[str, object],
) -> str:
    payload = {
        "artifact_id": artifact_id,
        "claims": claims,
        "scenario_id": scenario_id,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"
