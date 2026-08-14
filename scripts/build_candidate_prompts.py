#!/usr/bin/env python3
"""Build candidate-extraction prompts from released benchmark records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEM = (
    "Extract network-asset identity from observed evidence. Use only the exact "
    "evidence. Component, server, library, cache, and generic protocol values "
    "are not device identity unless the evidence explicitly binds them to the "
    "target device and requested attribute. Return the required JSON object."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--records",
        type=Path,
        nargs="+",
        default=sorted((ROOT / "benchmark/vericlaim_sec/records").glob("*.jsonl")),
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "outputs/candidate_prompts.jsonl"
    )
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.output.open("w", encoding="utf-8") as output:
        for path in args.records:
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    item = {
                        "custom_id": row["record_id"],
                        "record_id": row["record_id"],
                        "messages": [
                            {"role": "system", "content": SYSTEM},
                            {
                                "role": "user",
                                "content": (
                                    "Identify the vendor, product, and firmware version. "
                                    "Use an empty string when the observation does not support "
                                    "an attribute. Preserve exact supporting spans.\n\n"
                                    f"Observation evidence:\n{row['evidence']}"
                                ),
                            },
                        ],
                    }
                    output.write(json.dumps(item, ensure_ascii=False) + "\n")
                    count += 1
    print(json.dumps({"records": count, "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
