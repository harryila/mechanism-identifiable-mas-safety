from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from mas_safety.runner import ExperimentRunner, pilot_specs
from mas_safety.scenarios import load_scenarios


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def test_formal_schemas_are_valid_draft_2020_12() -> None:
    schema_paths = (
        Path("schemas/scenario.schema.json"),
        Path("schemas/trace.schema.json"),
    )
    for path in schema_paths:
        Draft202012Validator.check_schema(_load_json(path))


def test_checked_in_scenarios_conform_to_formal_schema() -> None:
    validator = Draft202012Validator(_load_json(Path("schemas/scenario.schema.json")))
    for path in sorted(Path("scenarios").glob("*.json")):
        validator.validate(_load_json(path))


def test_emitted_traces_conform_to_formal_schema() -> None:
    validator = Draft202012Validator(_load_json(Path("schemas/trace.schema.json")))
    scenarios = load_scenarios()
    traces = ExperimentRunner(scenarios).run_many(pilot_specs(scenarios))
    for trace in traces:
        validator.validate(trace.to_dict())
