#!/usr/bin/env python3
"""Run the six-head EEV checkpoint on released target-conditioned examples."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--examples",
        type=Path,
        nargs="+",
        default=sorted((ROOT / "training/vericlaim_sec/eev").glob("transfer-*.jsonl")),
    )
    parser.add_argument("--encoder-model-path", required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--tokenizer-path", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/eev_scores.jsonl")
    parser.add_argument("--split", choices=("train", "calibration", "test", "transfer"))
    parser.add_argument("--max-length", type=int, default=384)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    args = parser.parse_args()

    try:
        import torch
        from transformers import AutoTokenizer

        from train_eev import EEV, HEAD_CLASSES, model_text, read_jsonl
    except ImportError as exc:
        raise SystemExit(
            "EEV inference requires the optional 'models' dependencies"
        ) from exc

    device = args.device
    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cuda" and not torch.cuda.is_available():
        raise SystemExit("CUDA was requested but is unavailable")

    rows = read_jsonl(args.examples)
    if args.split:
        rows = [row for row in rows if row.get("split") == args.split]
    tokenizer_path = args.tokenizer_path or args.checkpoint.parent / "tokenizer"
    tokenizer = AutoTokenizer.from_pretrained(
        tokenizer_path, local_files_only=True, use_fast=True
    )
    payload = torch.load(args.checkpoint, map_location="cpu", weights_only=False)
    checkpoint_heads = {
        head: tuple(values) for head, values in payload.get("head_classes", {}).items()
    }
    if checkpoint_heads != HEAD_CLASSES:
        raise SystemExit("EEV checkpoint head contract does not match this release")
    model = EEV(args.encoder_model_path, unfreeze_last_layers=0, dropout=0.0)
    model.load_state_dict(payload["model_state_dict"], strict=True)
    model.to(device).eval()

    args.output.parent.mkdir(parents=True, exist_ok=True)
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
            _, logits = model(**inputs)
            probabilities = {
                head: torch.softmax(values, dim=-1).cpu().tolist()
                for head, values in logits.items()
            }
            for index, row in enumerate(batch):
                predictions = {}
                for head, classes in HEAD_CLASSES.items():
                    scores = probabilities[head][index]
                    best = max(range(len(scores)), key=scores.__getitem__)
                    predictions[head] = {
                        "label": classes[best],
                        "probabilities": {
                            str(label): score for label, score in zip(classes, scores)
                        },
                    }
                item = {
                    "example_id": row["example_id"],
                    "record_id": row["record_id"],
                    "attribute": row["attribute"],
                    "candidate_value": row["candidate_value"],
                    "predictions": predictions,
                }
                output.write(json.dumps(item, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
