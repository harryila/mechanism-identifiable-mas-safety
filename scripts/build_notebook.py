from __future__ import annotations

import argparse
from pathlib import Path

import nbformat
from nbclient import NotebookClient

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK_PATH = ROOT / "notebooks" / "pilot_analysis.ipynb"


def build_notebook() -> nbformat.NotebookNode:
    new_markdown = nbformat.v4.new_markdown_cell
    new_code = nbformat.v4.new_code_cell
    cells = [
        new_markdown(
            "# v0.2 scripted preflight analysis\n\n"
            "This notebook is the reproducible analysis companion for the current "
            "two-workflow v0.2 scripted compatibility/preflight run. The exact v0.1 "
            "archive is tag-bound; this scripted backend remains an executable "
            "specification, not empirical model evidence."
        ),
        new_markdown(
            "## tl;dr\n\n"
            "The generated v0.2 preflight contains 192 deterministic traces: 160 paired "
            "mechanism-on/off core cells plus 32 architecture/reference cells. The "
            "harness checks pass and the scripted oracle exhibits the preregistered "
            "mechanism-specific profiles. The empirical decision remains "
            "`not_evaluable_scripted_backend`; a live-model pilot is required."
        ),
        new_markdown(
            "## Context & Methods\n\n"
            "The unit is the base workflow. LGH is the joint indicator of a deterministic "
            "global violation and allow decisions from every invoked local policy. "
            "Matched-safe completion and defense overblocking are separate outcomes.\n\n"
            "### Key Assumptions\n\n"
            "- These two workflows are development fixtures, not held-out evidence.\n"
            "- Cluster intervals group complete cells by workflow.\n"
            "- Scripted defense outcomes are unit-oracle predictions and cannot be "
            "described as discovered effectiveness."
        ),
        new_code(
            "import csv\n"
            "import json\n"
            "from pathlib import Path\n\n"
            "candidate_roots = [Path.cwd(), Path.cwd().parent]\n"
            "ROOT = next(path for path in candidate_roots if (path / 'outputs' / 'pilot').exists())\n"
            "OUTPUT = ROOT / 'outputs' / 'pilot'\n"
            "print('Reading generated artifacts from outputs/pilot')"
        ),
        new_markdown("## Data"),
        new_code(
            "with (OUTPUT / 'runs.csv').open(newline='') as handle:\n"
            "    runs = list(csv.DictReader(handle))\n"
            "with (OUTPUT / 'mechanism_defense.csv').open(newline='') as handle:\n"
            "    metrics = list(csv.DictReader(handle))\n"
            "with (OUTPUT / 'mechanism_effects.csv').open(newline='') as handle:\n"
            "    mechanism_effects = list(csv.DictReader(handle))\n"
            "summary = json.loads((OUTPUT / 'summary.json').read_text())\n"
            "validation = json.loads((OUTPUT / 'validation_report.json').read_text())\n\n"
            "assert len(runs) == summary['trace_count'] == 192\n"
            "assert len(metrics) == 20\n"
            "assert len(mechanism_effects) == 8\n"
            "assert validation['blocking_issue_count'] == 0\n"
            "print('Cohorts:', summary['cohort_counts'])\n"
            "print('Scenarios:', summary['scenario_count'])\n"
            "print('Validation:', validation['overall_assessment'])"
        ),
        new_markdown("## Results"),
        new_code(
            "mechanisms = summary['mechanisms']\n"
            "defenses = summary['primary_defenses']\n"
            "model_id = summary['model_ids'][0]\n"
            "lookup = {(row['model_id'], row['mechanism'], row['defense']): row for row in metrics}\n\n"
            "header = ['defense', *mechanisms, 'safe utility']\n"
            "print(' | '.join(header))\n"
            "print(' | '.join(['---'] * len(header)))\n"
            "for defense in defenses:\n"
            "    lgh = [float(lookup[(model_id, mechanism, defense)]['lgh_rate']) for mechanism in mechanisms]\n"
            "    utility = sum(float(lookup[(model_id, mechanism, defense)]['benign_utility']) for mechanism in mechanisms) / len(mechanisms)\n"
            "    print(' | '.join([defense, *[f'{value:.2f}' for value in lgh], f'{utility:.2f}']))"
        ),
        new_code(
            "go_no_go = summary['go_no_go']\n"
            "assert go_no_go['development_gates_passed'] is True\n"
            "assert go_no_go['held_out_execution_decision'] == 'not_evaluable_scripted_backend'\n"
            "model_gate = go_no_go['per_model'][model_id]\n"
            "print('Mechanisms passing the scripted feasibility gate:', ', '.join(model_gate['mechanisms_lgh_in_both_workflows_with_positive_paired_effects']))\n"
            "print('Raw rank flips in unit oracle:', len(summary['raw_rank_flip_pairs']))\n"
            "print('Qualifying held-out reversals:', summary['qualifying_held_out_reversal_count'])\n"
            "print('Held-out decision:', go_no_go['held_out_execution_decision'])\n"
            "print('Claim boundary:', go_no_go['claim_boundary'])"
        ),
        new_code(
            "from IPython.display import SVG, display\n\n"
            "display(SVG(filename=str(OUTPUT / 'mechanism_interventions.svg')))\n"
            "display(SVG(filename=str(OUTPUT / 'defense_heatmap.svg')))"
        ),
        new_markdown(
            "## Takeaways\n\n"
            "1. The paired mechanism-on/off matrix, safe controls, and architecture "
            "references are internally consistent in the deterministic harness.\n"
            "2. The unit oracle creates multiple mechanism-specific defense profiles, "
            "so the ranking and heatmap code exercise the intended analysis path.\n"
            "3. No model was sampled. The next evidentiary step is a sealed live-model "
            "run on the two development workflows, followed by eight held-out workflows "
            "only if the preregistered gates pass."
        ),
    ]
    for index, cell in enumerate(cells):
        cell["id"] = f"mas-pilot-{index:02d}"
    notebook = nbformat.v4.new_notebook(cells=cells)
    notebook.metadata.update(
        {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python", "version": "3.10+"},
        }
    )
    return notebook


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    notebook = build_notebook()
    if args.execute:
        client = NotebookClient(
            notebook,
            timeout=120,
            kernel_name="python3",
            allow_errors=False,
            record_timing=False,
        )
        client.execute(cwd=str(ROOT))
    NOTEBOOK_PATH.parent.mkdir(parents=True, exist_ok=True)
    nbformat.write(notebook, NOTEBOOK_PATH)
    print(f"Wrote {NOTEBOOK_PATH}")


if __name__ == "__main__":
    main()
