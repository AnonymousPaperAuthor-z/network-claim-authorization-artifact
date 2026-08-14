#!/usr/bin/env python3
"""Exercise complete-first evidence compilation on synthetic observations."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from probeagent.evidence.budget_compiler import compile_for_budget


def _unit(
    context: str,
    unit_id: str,
    source_type: str,
    text: str,
    scores: dict[str, float],
    *,
    mandatory: bool = False,
) -> dict[str, Any]:
    start = context.index(text)
    return {
        "unit_id": unit_id,
        "source_type": source_type,
        "text": text,
        "start_char": start,
        "end_char": start + len(text),
        "raw_span_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "mandatory": mandatory,
        "scores": scores,
    }


def main() -> int:
    metadata = "[OBSERVATION_METADATA]\nservice=http"
    firmware = "[DEVICE_BANNER]\nModel=VX-200 Firmware=6.2.5"
    component = "[STATIC_RESOURCE]\n" + "library-cache-token=7.4.1 " * 24
    complete = "\n\n".join((metadata, firmware, component))
    units = [
        _unit(
            complete,
            "u-meta",
            "target_metadata",
            metadata,
            {"support_brand": 0.0, "support_model": 0.0,
             "support_firmware": 0.0, "risk": 0.0},
            mandatory=True,
        ),
        _unit(
            complete,
            "u-device",
            "device_banner",
            firmware,
            {"support_brand": 0.4, "support_model": 0.9,
             "support_firmware": 0.95, "risk": 0.02},
        ),
        _unit(
            complete,
            "u-cache",
            "cache_artifact",
            component,
            {"support_brand": 0.01, "support_model": 0.01,
             "support_firmware": 0.05, "risk": 0.98},
        ),
    ]

    def unexpected_pase_call() -> list[dict[str, Any]]:
        raise AssertionError("PASE provider ran on a within-budget packet")

    within = compile_for_budget(
        complete,
        unexpected_pase_call,
        max_context_units=len(complete) + 1,
    )
    over = compile_for_budget(
        complete,
        units,
        max_context_units=420,
    )
    if within.mode != "complete" or within.context != complete:
        raise AssertionError("within-budget evidence did not preserve Complete")
    if over.mode != "pase":
        raise AssertionError("over-budget evidence did not invoke PASE")
    if over.compiled_context_units > over.max_context_units:
        raise AssertionError("compiled PASE packet exceeded its budget")
    if set(over.selected_unit_ids) != {"u-meta", "u-device"}:
        raise AssertionError(
            f"unexpected PASE selection: {over.selected_unit_ids}"
        )

    output = ROOT / "outputs/evidence_budget_demo.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": "PASS",
        "within_budget": within.to_dict(),
        "over_budget": over.to_dict(),
    }
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "within_budget_mode": within.mode,
                "over_budget_mode": over.mode,
                "over_budget_selected": list(over.selected_unit_ids),
                "output": str(output.relative_to(ROOT)),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
