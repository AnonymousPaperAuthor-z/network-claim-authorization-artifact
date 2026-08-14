#!/usr/bin/env python3
"""Score provenance-bound evidence units with a trained PASE checkpoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--units",
        type=Path,
        nargs="+",
        default=sorted((ROOT / "training/vericlaim_sec/pase").glob("*.jsonl")),
    )
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/pase_scores.jsonl")
    parser.add_argument("--split", choices=("train", "validation", "test"))
    parser.add_argument("--max-length", type=int, default=384)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    args = parser.parse_args()

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        from train_pase import LABEL_NAMES, model_text, read_jsonl
    except ImportError as exc:
        raise SystemExit(
            "PASE inference requires the optional 'models' dependencies"
        ) from exc

    device = args.device
    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cuda" and not torch.cuda.is_available():
        raise SystemExit("CUDA was requested but is unavailable")

    rows = read_jsonl(args.units)
    if args.split:
        rows = [row for row in rows if row.get("split") == args.split]
    checkpoint = Path(args.checkpoint)
    tokenizer = AutoTokenizer.from_pretrained(
        checkpoint, local_files_only=True, use_fast=True
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        checkpoint, local_files_only=True
    ).to(device)
    label_path = checkpoint / "label_names.json"
    label_names = (
        json.loads(label_path.read_text(encoding="utf-8"))
        if label_path.is_file()
        else LABEL_NAMES
    )
    if list(label_names) != LABEL_NAMES or int(model.config.num_labels) != len(LABEL_NAMES):
        raise SystemExit("PASE checkpoint label contract does not match this release")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    model.eval()
    with args.output.open("w", encoding="utf-8") as output, torch.inference_mode():
        for start in range(0, len(rows), args.batch_size):
            batch = rows[start : start + args.batch_size]
            encoded = tokenizer(
                [model_text(row) for row in batch],
                padding=True,
                truncation=True,
                max_length=args.max_length,
                return_tensors="pt",
            )
            inputs = {key: value.to(device) for key, value in encoded.items()}
            probabilities = torch.sigmoid(model(**inputs).logits).cpu().tolist()
            for row, scores in zip(batch, probabilities):
                item = {
                    "unit_id": row["unit_id"],
                    "record_id": row["record_id"],
                    "split": row.get("split"),
                    "scores": dict(zip(label_names, scores)),
                }
                output.write(json.dumps(item, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
