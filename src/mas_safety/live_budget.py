from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

NANO_USD_PER_USD = 1_000_000_000
FROZEN_GROSS_CEILING_USD = 20
FROZEN_GROSS_CEILING_NANO_USD = (
    FROZEN_GROSS_CEILING_USD * NANO_USD_PER_USD
)
FROZEN_INPUT_RESERVATION_TOKENS = 65_536
FROZEN_OUTPUT_RESERVATION_TOKENS = 512
MAX_PROVIDER_REQUEST_UTF8_BYTES = 32_768

FROZEN_MODEL_IDS = (
    "gpt-5.5-2026-04-23",
    "gpt-5.4-2026-03-05",
)

_ALLOWED_BUDGET_PHASES = frozenset(
    {
        "pre_stage_1_smoke",
        "stage_1_live_feasibility",
        "stage_4_confirmatory",
    }
)

# Standard-tier list prices frozen on 2026-08-31. One nano-USD is 1e-9 USD.
# $5.00 / 1M tokens = 5,000 nano-USD per token, for example.
MODEL_PRICING_NANO_USD_PER_TOKEN: dict[str, dict[str, int]] = {
    "gpt-5.5-2026-04-23": {"input": 5_000, "output": 30_000},
    "gpt-5.4-2026-03-05": {"input": 2_500, "output": 15_000},
}


class LiveBudgetError(RuntimeError):
    """Base class for a condition that must abort live provider execution."""

    abort_live_batch = True


class BudgetCeilingExceeded(LiveBudgetError):
    """Raised before a call that cannot fit inside the authorized ceiling."""


class BudgetAccountingError(LiveBudgetError):
    """Raised when provider usage cannot be conservatively reconciled."""


@dataclass(frozen=True)
class BudgetReservation:
    reservation_id: str
    phase: str
    model_id: str
    call_stem: str
    request_sha256: str
    request_utf8_bytes: int
    input_token_bound: int
    output_token_bound: int
    reserved_nano_usd: int
    event_sequence: int


class LiveBudgetLedger:
    """Private append-only spending authority shared by smoke, Stage 1, and Stage 4.

    A full conservative call allowance is durably held before network I/O. A
    response with valid usage settles at full, uncached standard-tier rates and
    releases the unused allowance. When usage is unavailable, the entire held
    allowance is treated as spent. A process crash leaves its final reservation
    visibly held, so the ledger never silently restores authority.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        ceiling_nano_usd: int = FROZEN_GROSS_CEILING_NANO_USD,
    ) -> None:
        if type(ceiling_nano_usd) is not int or ceiling_nano_usd <= 0:
            raise ValueError("Budget ceiling must be a positive integer nano-USD value")
        self.path = Path(path)
        if self.path.exists():
            raise FileExistsError("Refusing to reuse an existing live budget ledger")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._ceiling = ceiling_nano_usd
        self._committed = 0
        self._held = 0
        self._sequence = 0
        self._previous_event_sha256: str | None = None
        self._active: dict[str, BudgetReservation] = {}
        self._reservation_count = 0
        self._settled_count = 0
        self._forfeited_count = 0
        self._cancelled_count = 0
        self._denied_count = 0
        self._record_event(
            {
                "event": "ledger_initialized",
                "ceiling_nano_usd": self._ceiling,
                "ceiling_usd": _nano_usd_string(self._ceiling),
                "pricing_basis": "standard_service_tier_full_uncached_list_price",
                "pricing_nano_usd_per_token": MODEL_PRICING_NANO_USD_PER_TOKEN,
                "input_token_reservation_per_call": (
                    FROZEN_INPUT_RESERVATION_TOKENS
                ),
                "output_token_reservation_per_call": (
                    FROZEN_OUTPUT_RESERVATION_TOKENS
                ),
                "maximum_provider_request_utf8_bytes": (
                    MAX_PROVIDER_REQUEST_UTF8_BYTES
                ),
                "stage4_successful_input_token_bound": (
                    "canonical_request_utf8_bytes"
                ),
            },
            create=True,
        )
        _fsync_directory(self.path.parent)

    def reserve(
        self,
        *,
        phase: str,
        model_id: str,
        call_stem: str,
        request_sha256: str,
        request_utf8_bytes: int,
    ) -> BudgetReservation:
        if phase not in _ALLOWED_BUDGET_PHASES:
            raise ValueError("Unknown live-budget phase")
        if model_id not in MODEL_PRICING_NANO_USD_PER_TOKEN:
            raise ValueError("Model has no frozen standard-tier price")
        if not call_stem or not request_sha256:
            raise ValueError("Budget reservation requires call and request identities")
        if type(request_utf8_bytes) is not int or request_utf8_bytes <= 0:
            raise ValueError("Provider request byte count must be a positive integer")

        reservation_id = f"budget-{self._reservation_count + 1:06d}"
        if request_utf8_bytes > MAX_PROVIDER_REQUEST_UTF8_BYTES:
            self._denied_count += 1
            self._record_event(
                {
                    "event": "reservation_denied",
                    "reason": "provider_request_exceeds_frozen_byte_limit",
                    "reservation_id": reservation_id,
                    "phase": phase,
                    "model_id": model_id,
                    "call_stem": call_stem,
                    "request_sha256": request_sha256,
                    "request_utf8_bytes": request_utf8_bytes,
                }
            )
            raise BudgetCeilingExceeded(
                "Provider request exceeds the frozen budget sizing envelope"
            )

        price = MODEL_PRICING_NANO_USD_PER_TOKEN[model_id]
        reserved_nano_usd = (
            FROZEN_INPUT_RESERVATION_TOKENS * price["input"]
            + FROZEN_OUTPUT_RESERVATION_TOKENS * price["output"]
        )
        if self._committed + self._held + reserved_nano_usd > self._ceiling:
            self._denied_count += 1
            self._record_event(
                {
                    "event": "reservation_denied",
                    "reason": "hard_gross_ceiling",
                    "reservation_id": reservation_id,
                    "phase": phase,
                    "model_id": model_id,
                    "call_stem": call_stem,
                    "request_sha256": request_sha256,
                    "request_utf8_bytes": request_utf8_bytes,
                    "requested_reservation_nano_usd": reserved_nano_usd,
                }
            )
            if phase == "stage_4_confirmatory":
                message = (
                    "The next provider call cannot fit inside the hard Stage 4 "
                    "authorized ceiling"
                )
            else:
                # Preserve the historical Stage 1 error contract.
                message = (
                    "The next provider call cannot fit inside the hard USD 20 ceiling"
                )
            raise BudgetCeilingExceeded(message)

        self._reservation_count += 1
        self._held += reserved_nano_usd
        event_sequence = self._sequence + 1
        reservation = BudgetReservation(
            reservation_id=reservation_id,
            phase=phase,
            model_id=model_id,
            call_stem=call_stem,
            request_sha256=request_sha256,
            request_utf8_bytes=request_utf8_bytes,
            input_token_bound=FROZEN_INPUT_RESERVATION_TOKENS,
            output_token_bound=FROZEN_OUTPUT_RESERVATION_TOKENS,
            reserved_nano_usd=reserved_nano_usd,
            event_sequence=event_sequence,
        )
        self._active[reservation_id] = reservation
        self._record_event(
            {
                "event": "reservation_held",
                **asdict(reservation),
            }
        )
        return reservation

    def settle(
        self,
        reservation: BudgetReservation,
        *,
        input_tokens: int,
        output_tokens: int,
    ) -> dict[str, object]:
        active = self._require_active(reservation)
        stage4_input_within_committed_request = (
            active.phase != "stage_4_confirmatory"
            or (
                type(input_tokens) is int
                and input_tokens <= active.request_utf8_bytes
            )
        )
        valid_usage = (
            type(input_tokens) is int
            and 0 <= input_tokens <= active.input_token_bound
            and type(output_tokens) is int
            and 0 <= output_tokens <= active.output_token_bound
            and stage4_input_within_committed_request
        )
        if not valid_usage:
            reason = (
                "provider_usage_above_canonical_request_utf8_byte_bound"
                if not stage4_input_within_committed_request
                else "missing_malformed_or_out_of_bounds_provider_usage"
            )
            self.forfeit(
                reservation,
                reason=reason,
            )
            raise BudgetAccountingError(
                "Provider usage could not be reconciled inside the frozen reservation"
            )

        price = MODEL_PRICING_NANO_USD_PER_TOKEN[active.model_id]
        settled_nano_usd = (
            input_tokens * price["input"] + output_tokens * price["output"]
        )
        if settled_nano_usd > active.reserved_nano_usd:
            self.forfeit(reservation, reason="settlement_exceeded_reservation")
            raise BudgetAccountingError(
                "Provider usage exceeded the conservative call reservation"
            )

        del self._active[active.reservation_id]
        self._held -= active.reserved_nano_usd
        self._committed += settled_nano_usd
        self._settled_count += 1
        event = self._record_event(
            {
                "event": "reservation_settled",
                "reservation_id": active.reservation_id,
                "phase": active.phase,
                "model_id": active.model_id,
                "call_stem": active.call_stem,
                "request_sha256": active.request_sha256,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "settled_nano_usd": settled_nano_usd,
                "released_nano_usd": (
                    active.reserved_nano_usd - settled_nano_usd
                ),
                "disposition": "usage_settled_full_uncached_rates",
            }
        )
        return dict(event)

    def forfeit(
        self,
        reservation: BudgetReservation,
        *,
        reason: str,
    ) -> dict[str, object]:
        active = self._require_active(reservation)
        del self._active[active.reservation_id]
        self._held -= active.reserved_nano_usd
        self._committed += active.reserved_nano_usd
        self._forfeited_count += 1
        event = self._record_event(
            {
                "event": "reservation_forfeited",
                "reservation_id": active.reservation_id,
                "phase": active.phase,
                "model_id": active.model_id,
                "call_stem": active.call_stem,
                "request_sha256": active.request_sha256,
                "settled_nano_usd": active.reserved_nano_usd,
                "released_nano_usd": 0,
                "disposition": reason,
            }
        )
        return dict(event)

    def cancel_before_provider_call(
        self,
        reservation: BudgetReservation,
        *,
        reason: str,
    ) -> dict[str, object]:
        active = self._require_active(reservation)
        del self._active[active.reservation_id]
        self._held -= active.reserved_nano_usd
        self._cancelled_count += 1
        event = self._record_event(
            {
                "event": "reservation_cancelled",
                "reservation_id": active.reservation_id,
                "phase": active.phase,
                "model_id": active.model_id,
                "call_stem": active.call_stem,
                "request_sha256": active.request_sha256,
                "settled_nano_usd": 0,
                "released_nano_usd": active.reserved_nano_usd,
                "disposition": reason,
            }
        )
        return dict(event)

    def snapshot(self) -> dict[str, object]:
        return {
            "schema_version": "0.2.1",
            "hard_gross_ceiling_nano_usd": self._ceiling,
            "hard_gross_ceiling_usd": _nano_usd_string(self._ceiling),
            "committed_nano_usd": self._committed,
            "committed_usd": _nano_usd_string(self._committed),
            "held_nano_usd": self._held,
            "held_usd": _nano_usd_string(self._held),
            "gross_exposure_nano_usd": self._committed + self._held,
            "gross_exposure_usd": _nano_usd_string(
                self._committed + self._held
            ),
            "remaining_authority_nano_usd": (
                self._ceiling - self._committed - self._held
            ),
            "remaining_authority_usd": _nano_usd_string(
                self._ceiling - self._committed - self._held
            ),
            "active_reservations": len(self._active),
            "reservations_held_total": self._reservation_count,
            "reservations_settled": self._settled_count,
            "reservations_forfeited": self._forfeited_count,
            "reservations_cancelled_before_call": self._cancelled_count,
            "reservations_denied": self._denied_count,
            "event_count": self._sequence,
            "last_event_sha256": self._previous_event_sha256,
            "ledger_path": self.path.name,
        }

    def assert_quiescent(self) -> None:
        if self._active:
            raise BudgetAccountingError(
                "Live budget ledger has an unresolved provider-call reservation"
            )

    def _require_active(
        self, reservation: BudgetReservation
    ) -> BudgetReservation:
        active = self._active.get(reservation.reservation_id)
        if active != reservation:
            raise BudgetAccountingError("Unknown or already finalized reservation")
        return active

    def _record_event(
        self, payload: dict[str, object], *, create: bool = False
    ) -> dict[str, object]:
        self._sequence += 1
        event = {
            "schema_version": "0.2.1",
            "sequence": self._sequence,
            "recorded_at_utc": _utc_now(),
            "previous_event_sha256": self._previous_event_sha256,
            **payload,
            "committed_nano_usd": self._committed,
            "held_nano_usd": self._held,
            "gross_exposure_nano_usd": self._committed + self._held,
            "remaining_authority_nano_usd": (
                self._ceiling - self._committed - self._held
            ),
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        event_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        event["event_sha256"] = event_sha256
        serialized = json.dumps(event, sort_keys=True) + "\n"
        flags = os.O_WRONLY | (os.O_CREAT | os.O_EXCL if create else os.O_APPEND)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        self._previous_event_sha256 = event_sha256
        return event


def audit_budget_ledger(path: str | Path) -> dict[str, object]:
    """Verify the ledger hash chain and return its recorded terminal exposure."""

    ledger_path = Path(path)
    checks = {
        "file_present": ledger_path.is_file(),
        "private_file_permissions": True,
        "json_lines_parse": True,
        "sequence_complete": True,
        "hash_chain_valid": True,
        "frozen_pricing_and_reservation_configuration": True,
        "event_state_replays": True,
        "reservations_resolve_at_most_once": True,
        "all_reservations_resolved": True,
        "exposure_never_exceeds_ceiling": True,
        "terminal_state_self_consistent": True,
    }
    events: list[dict[str, object]] = []
    if not ledger_path.is_file():
        return {"pass": False, "checks": checks, "event_count": 0}
    try:
        if ledger_path.stat().st_mode & 0o077:
            checks["private_file_permissions"] = False
        ledger_bytes = ledger_path.read_bytes()
        events = [
            json.loads(line)
            for line in ledger_bytes.decode("utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        checks["json_lines_parse"] = False
        return {"pass": False, "checks": checks, "event_count": 0}

    previous: str | None = None
    ceiling: int | None = None
    replay_committed = 0
    replay_held = 0
    active: dict[str, dict[str, object]] = {}
    resolved: set[str] = set()
    for index, event in enumerate(events, start=1):
        if event.get("sequence") != index:
            checks["sequence_complete"] = False
        supplied_hash = event.get("event_sha256")
        unhashed = {key: value for key, value in event.items() if key != "event_sha256"}
        canonical = json.dumps(unhashed, sort_keys=True, separators=(",", ":"))
        recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if supplied_hash != recomputed or event.get("previous_event_sha256") != previous:
            checks["hash_chain_valid"] = False
        previous = supplied_hash if isinstance(supplied_hash, str) else None
        if index == 1 and event.get("event") == "ledger_initialized":
            value = event.get("ceiling_nano_usd")
            ceiling = value if type(value) is int else None
            if not (
                event.get("pricing_nano_usd_per_token")
                == MODEL_PRICING_NANO_USD_PER_TOKEN
                and event.get("input_token_reservation_per_call")
                == FROZEN_INPUT_RESERVATION_TOKENS
                and event.get("output_token_reservation_per_call")
                == FROZEN_OUTPUT_RESERVATION_TOKENS
                and event.get("maximum_provider_request_utf8_bytes")
                == MAX_PROVIDER_REQUEST_UTF8_BYTES
                and event.get("stage4_successful_input_token_bound")
                == "canonical_request_utf8_bytes"
            ):
                checks["frozen_pricing_and_reservation_configuration"] = False
        elif index == 1:
            checks["event_state_replays"] = False

        event_kind = event.get("event")
        reservation_id = event.get("reservation_id")
        if event_kind == "reservation_held":
            model_id = event.get("model_id")
            reserved = event.get("reserved_nano_usd")
            expected_reserved = (
                estimate_standard_cost_nano_usd(
                    model_id,
                    input_tokens=FROZEN_INPUT_RESERVATION_TOKENS,
                    output_tokens=FROZEN_OUTPUT_RESERVATION_TOKENS,
                )
                if isinstance(model_id, str)
                and model_id in MODEL_PRICING_NANO_USD_PER_TOKEN
                else None
            )
            if not (
                isinstance(reservation_id, str)
                and reservation_id not in active
                and reservation_id not in resolved
                and type(reserved) is int
                and reserved == expected_reserved
                and event.get("input_token_bound")
                == FROZEN_INPUT_RESERVATION_TOKENS
                and event.get("output_token_bound")
                == FROZEN_OUTPUT_RESERVATION_TOKENS
                and type(event.get("request_utf8_bytes")) is int
                and 0 < int(event["request_utf8_bytes"])
                <= MAX_PROVIDER_REQUEST_UTF8_BYTES
            ):
                checks["event_state_replays"] = False
            else:
                active[reservation_id] = event
                replay_held += reserved
        elif event_kind in {
            "reservation_settled",
            "reservation_forfeited",
            "reservation_cancelled",
        }:
            held_event = (
                active.get(reservation_id)
                if isinstance(reservation_id, str)
                else None
            )
            if held_event is None or reservation_id in resolved:
                checks["reservations_resolve_at_most_once"] = False
                checks["event_state_replays"] = False
            else:
                reserved = int(held_event["reserved_nano_usd"])
                settled = event.get("settled_nano_usd")
                if event_kind == "reservation_settled":
                    model_id = str(held_event["model_id"])
                    input_tokens = event.get("input_tokens")
                    output_tokens = event.get("output_tokens")
                    expected_settlement = (
                        estimate_standard_cost_nano_usd(
                            model_id,
                            input_tokens=input_tokens,
                            output_tokens=output_tokens,
                        )
                        if type(input_tokens) is int
                        and input_tokens >= 0
                        and type(output_tokens) is int
                        and output_tokens >= 0
                        else None
                    )
                elif event_kind == "reservation_forfeited":
                    expected_settlement = reserved
                else:
                    expected_settlement = 0
                if not (
                    type(settled) is int
                    and settled == expected_settlement
                    and settled <= reserved
                    and event.get("model_id") == held_event.get("model_id")
                    and event.get("call_stem") == held_event.get("call_stem")
                    and event.get("request_sha256")
                    == held_event.get("request_sha256")
                    and (
                        event_kind != "reservation_settled"
                        or (
                            type(input_tokens) is int
                            and 0
                            <= input_tokens
                            <= FROZEN_INPUT_RESERVATION_TOKENS
                            and type(output_tokens) is int
                            and 0
                            <= output_tokens
                            <= FROZEN_OUTPUT_RESERVATION_TOKENS
                            and (
                                held_event.get("phase")
                                != "stage_4_confirmatory"
                                or (
                                    type(held_event.get("request_utf8_bytes"))
                                    is int
                                    and input_tokens
                                    <= int(held_event["request_utf8_bytes"])
                                )
                            )
                        )
                    )
                ):
                    checks["event_state_replays"] = False
                replay_held -= reserved
                replay_committed += settled if type(settled) is int else 0
                del active[reservation_id]
                resolved.add(reservation_id)
        elif event_kind not in {"ledger_initialized", "reservation_denied"}:
            checks["event_state_replays"] = False

        exposure = event.get("gross_exposure_nano_usd")
        remaining = event.get("remaining_authority_nano_usd")
        committed = event.get("committed_nano_usd")
        held = event.get("held_nano_usd")
        if not (
            type(exposure) is int
            and type(remaining) is int
            and type(committed) is int
            and type(held) is int
            and exposure == committed + held
            and ceiling is not None
            and remaining == ceiling - exposure
        ):
            checks["terminal_state_self_consistent"] = False
        if committed != replay_committed or held != replay_held:
            checks["event_state_replays"] = False
        if ceiling is None or not isinstance(exposure, int) or exposure > ceiling:
            checks["exposure_never_exceeds_ceiling"] = False

    if active:
        checks["all_reservations_resolved"] = False
    terminal = events[-1] if events else {}
    return {
        "pass": bool(events) and all(checks.values()),
        "checks": checks,
        "event_count": len(events),
        "ceiling_nano_usd": ceiling,
        "ledger_file_sha256": hashlib.sha256(ledger_bytes).hexdigest(),
        "last_event_sha256": previous,
        "committed_nano_usd": terminal.get("committed_nano_usd"),
        "committed_usd": (
            _nano_usd_string(terminal["committed_nano_usd"])
            if type(terminal.get("committed_nano_usd")) is int
            else None
        ),
        "held_nano_usd": terminal.get("held_nano_usd"),
        "active_reservations": len(active),
        "remaining_authority_nano_usd": terminal.get(
            "remaining_authority_nano_usd"
        ),
    }


def estimate_standard_cost_nano_usd(
    model_id: str, *, input_tokens: int, output_tokens: int
) -> int:
    if model_id not in MODEL_PRICING_NANO_USD_PER_TOKEN:
        raise ValueError("Model has no frozen standard-tier price")
    if (
        type(input_tokens) is not int
        or input_tokens < 0
        or type(output_tokens) is not int
        or output_tokens < 0
    ):
        raise ValueError("Token estimates must be non-negative integers")
    price = MODEL_PRICING_NANO_USD_PER_TOKEN[model_id]
    return input_tokens * price["input"] + output_tokens * price["output"]


def _nano_usd_string(value: int) -> str:
    sign = "-" if value < 0 else ""
    magnitude = abs(value)
    whole, fractional = divmod(magnitude, NANO_USD_PER_USD)
    return f"{sign}{whole}.{fractional:09d}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)
