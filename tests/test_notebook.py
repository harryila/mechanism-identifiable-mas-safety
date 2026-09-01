from __future__ import annotations

import json
from pathlib import Path


def test_pilot_notebook_is_executed_without_errors() -> None:
    path = Path("notebooks/pilot_analysis.ipynb")
    notebook = json.loads(path.read_text(encoding="utf-8"))
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert code_cells
    assert all(cell["execution_count"] is not None for cell in code_cells)
    assert not [
        output
        for cell in code_cells
        for output in cell.get("outputs", [])
        if output.get("output_type") == "error"
    ]
    assert [cell for cell in notebook["cells"] if "## tl;dr" in "".join(cell["source"])]
    assert [
        cell
        for cell in notebook["cells"]
        if "## Context & Methods" in "".join(cell["source"])
    ]
    assert [cell for cell in notebook["cells"] if "## Data" in "".join(cell["source"])]
    assert [cell for cell in notebook["cells"] if "## Results" in "".join(cell["source"])]
    assert [cell for cell in notebook["cells"] if "## Takeaways" in "".join(cell["source"])]
