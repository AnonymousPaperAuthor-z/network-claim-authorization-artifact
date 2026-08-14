#!/usr/bin/env python3
"""Train the four-head PASE evidence-unit scorer."""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup,
)


ROOT = Path(__file__).resolve().parents[1]
LABEL_NAMES = ["support_brand", "support_model", "support_firmware", "risk"]


def read_jsonl(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            rows.extend(json.loads(line) for line in handle if line.strip())
    return rows


def model_text(row: dict[str, Any]) -> str:
    return (
        f"[SOURCE={row.get('source_type', 'unknown')}] "
        f"[SECTION={row.get('parent_section', '')}] "
        f"[MARKER={row.get('marker', '')}]\n{row.get('text', '')}"
    )


class UnitDataset(Dataset):
    def __init__(self, rows: list[dict[str, Any]], tokenizer: Any, max_length: int):
        self.rows = rows
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> dict[str, Any]:
        row = self.rows[index]
        encoded = self.tokenizer(
            model_text(row), truncation=True, max_length=self.max_length
        )
        return {
            "input_ids": encoded["input_ids"],
            "attention_mask": encoded["attention_mask"],
            "labels": row["labels"],
            "label_mask": row["label_mask"],
        }


class Collator:
    def __init__(self, tokenizer: Any):
        self.tokenizer = tokenizer

    def __call__(self, batch: list[dict[str, Any]]) -> dict[str, torch.Tensor]:
        encoded = self.tokenizer.pad(
            [
                {"input_ids": row["input_ids"], "attention_mask": row["attention_mask"]}
                for row in batch
            ],
            return_tensors="pt",
        )
        encoded["labels"] = torch.tensor(
            [row["labels"] for row in batch], dtype=torch.float32
        )
        encoded["label_mask"] = torch.tensor(
            [row["label_mask"] for row in batch], dtype=torch.float32
        )
        return encoded


def seed_all(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--units",
        type=Path,
        nargs="+",
        default=sorted((ROOT / "training/vericlaim_sec/pase").glob("*.jsonl")),
    )
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/pase_model")
    parser.add_argument("--max-length", type=int, default=384)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--gradient-accumulation", type=int, default=4)
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.06)
    parser.add_argument("--seed", type=int, default=73)
    parser.add_argument("--bf16", action="store_true")
    args = parser.parse_args()

    if not torch.cuda.is_available():
        raise SystemExit("CUDA is required to train PASE")
    seed_all(args.seed)
    rows = read_jsonl(args.units)
    train = [row for row in rows if row.get("split") == "train"]
    tokenizer = AutoTokenizer.from_pretrained(
        args.model_path, local_files_only=True, use_fast=True
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_path,
        local_files_only=True,
        num_labels=len(LABEL_NAMES),
        problem_type="multi_label_classification",
        ignore_mismatched_sizes=True,
    ).cuda()
    loader = DataLoader(
        UnitDataset(train, tokenizer, args.max_length),
        batch_size=args.batch_size,
        shuffle=True,
        collate_fn=Collator(tokenizer),
        num_workers=2,
        pin_memory=True,
    )
    labels = np.asarray([row["labels"] for row in train], dtype=np.float32)
    masks = np.asarray([row["label_mask"] for row in train], dtype=np.float32)
    positive = (labels * masks).sum(axis=0)
    negative = ((1.0 - labels) * masks).sum(axis=0)
    pos_weight = torch.tensor(
        np.divide(negative, np.maximum(positive, 1.0)),
        dtype=torch.float32,
        device="cuda",
    ).clamp(max=30.0)
    criterion = torch.nn.BCEWithLogitsLoss(reduction="none", pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=args.learning_rate, weight_decay=args.weight_decay
    )
    steps = math.ceil(len(loader) / args.gradient_accumulation) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer, int(steps * args.warmup_ratio), steps
    )

    model.train()
    optimizer.zero_grad(set_to_none=True)
    for epoch in range(args.epochs):
        running = 0.0
        for step, batch in enumerate(loader, 1):
            targets = batch.pop("labels").cuda(non_blocking=True)
            mask = batch.pop("label_mask").cuda(non_blocking=True)
            inputs = {key: value.cuda(non_blocking=True) for key, value in batch.items()}
            with torch.autocast(
                device_type="cuda",
                dtype=torch.bfloat16,
                enabled=args.bf16 and torch.cuda.is_bf16_supported(),
            ):
                logits = model(**inputs).logits
                loss = (criterion(logits, targets) * mask).sum() / mask.sum().clamp_min(1)
                loss = loss / args.gradient_accumulation
            loss.backward()
            running += float(loss.detach()) * args.gradient_accumulation
            if step % args.gradient_accumulation == 0 or step == len(loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
        print(json.dumps({"epoch": epoch + 1, "mean_loss": running / len(loader)}))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    (args.output_dir / "label_names.json").write_text(
        json.dumps(LABEL_NAMES, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
