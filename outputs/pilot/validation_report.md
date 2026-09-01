# Validation Report

## Overall Assessment: Share with caveats

The artifact is ready for a live-model pilot if no high-severity issues are listed. It is not ready to support empirical claims.

## Methodology Review

The paired mechanism-on/off cells, matched-safe variants, single-agent controls, omniscient reference, executable local predicates, and deterministic terminal evaluator are all checked from generated artifacts.

## Issues Found

1. [Severity: Medium] All runs use the scripted oracle. The outputs validate experiment plumbing, not model behavior.

## Calculation Spot-Checks

- trace_objects_have_required_fields: Verified
- steps_have_required_fields: Verified
- model_artifacts_exclude_defense_sidecars: Verified
- defense_inputs_respect_observability_contract: Verified
- primary_accepted_actions_match_candidate: Verified
- accepted_actions_are_offered: Verified
- executed_actions_match_accepted_selection: Verified
- nonexecution_decisions_never_execute: Verified
- model_policy_views_are_local_only: Verified
- provider_metadata_excludes_credentials: Verified
- run_ids_unique: Verified
- trace_and_csv_run_ids_match: Verified
- paired_design_cell_count: Verified
- mechanism_deltas_are_declared: Verified
- lgh_definition_consistent: Verified
- all_local_allow_recomputes: Verified
- terminal_status_consistent: Verified
- attempted_and_skipped_roles_partition_pipeline: Verified
- safe_unsafe_authoritative_diff_is_single_field: Verified
- cross_defense_role_inputs_match: Verified
- component_hashes_recompute: Verified
- forbidden_terminal_state_consistent: Verified
- metric_grid_complete: Verified
- metric_rates_in_bounds: Verified
- headline_metrics_recompute: Verified
- mechanism_effect_grid_complete: Verified
- paired_mechanism_effects_recompute: Verified
- scripted_pilot_scope: Verified

## Required Caveats

- The scripted backend is an executable specification, not a sampled model.
- Two workflows are insufficient for the planned eight-workflow clustered analysis.
- Defense effects in this pilot are predeclared oracle behavior and must not be described as discovered findings.
