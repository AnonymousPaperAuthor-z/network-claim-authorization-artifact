#!/usr/bin/env python3
"""Train the six-head target-conditioned Evidence-Entitlement Verifier."""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler
from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup


ROOT = Path(__file__).resolve().parents[1]
HEAD_CLASSES: dict[str, tuple[Any, ...]] = {
    "source_role": ("cache_artifact", "component", "device_banner", "library", "protocol_self_report", "screenshot_title", "server_software", "static_resource"),
    "subject_role": ("component", "library", "peer_device", "protocol_generic", "same_vendor_product", "server", "target_device", "unknown"),
    "support_type": ("coarse_grained", "conflicting", "direct", "none"),
    "confusion_risk": ("cache_stale", "cross_source_conflict", "generic_protocol", "none", "other", "same_vendor_peer", "server_component"),
    "authorized_for_attribute": (0, 1),
    "terminal_eligibility": ("defer", "direct_accept", "reduced_resolution"),
}
LOSS_WEIGHTS = {
    "source_role": 0.25,
    "subject_role": 1.0,
    "support_type": 0.75,
    "confusion_risk": 0.75,
    "authorized_for_attribute": 2.0,
    "terminal_eligibility": 1.5,
}
LABEL_TO_ID = {
    head: {value: index for index, value in enumerate(values)}
    for head, values in HEAD_CLASSES.items()
}


def read_jsonl(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            rows.extend(json.loads(line) for line in handle if line.strip())
    return rows


def model_text(row: dict[str, Any]) -> str:
    return (
        f"[ATTRIBUTE={row.get('attribute', '')}]\n"
        f"[CANDIDATE={row.get('candidate_value', '')}]\n"
        f"[SOURCE={row.get('source_type_observed', '')}]\n"
        f"[FIELD={row.get('field_path', '')}]\n"
        f"[SECTION={row.get('section', '')}]\n"
        f"[SPAN]\n{row.get('exact_span', '')}\n"
        f"[CONTEXT]\n{row.get('local_context', '')}"
    )


class ExampleDataset(Dataset):
    def __init__(self, rows: list[dict[str, Any]]):
        self.rows = rows

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.rows[index]


class Collator:
    def __init__(self, tokenizer: Any, max_length: int):
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __call__(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        encoded = self.tokenizer(
            [model_text(row) for row in rows],
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        encoded["labels"] = {
            head: torch.tensor(
                [LABEL_TO_ID[head][row[head]] for row in rows], dtype=torch.long
            )
            for head in HEAD_CLASSES
        }
        encoded["masks"] = {
            head: torch.tensor(
                [bool((row.get("label_masks") or {}).get(head)) for row in rows],
                dtype=torch.bool,
            )
            for head in HEAD_CLASSES
        }
        encoded["example_ids"] = [row["example_id"] for row in rows]
        return encoded


class EEV(nn.Module):
    def __init__(self, model_path: str, unfreeze_last_layers: int, dropout: float):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_path, local_files_only=True)
        hidden = int(self.encoder.config.hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.heads = nn.ModuleDict(
            {head: nn.Linear(hidden, len(values)) for head, values in HEAD_CLASSES.items()}
        )
        for parameter in self.encoder.parameters():
            parameter.requires_grad = False
        layers = self.encoder.encoder.layer
        if unfreeze_last_layers > 0:
            for layer in layers[-unfreeze_last_layers:]:
                for parameter in layer.parameters():
                    parameter.requires_grad = True

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor):
        encoded = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        representation = self.dropout(encoded.last_hidden_state[:, 0])
        return representation, {
            head: classifier(representation) for head, classifier in self.heads.items()
        }


def class_weights(rows: list[dict[str, Any]]) -> dict[str, torch.Tensor]:
    result = {}
    for head, classes in HEAD_CLASSES.items():
        counts = Counter(
            row[head] for row in rows if bool((row.get("label_masks") or {}).get(head))
        )
        total = sum(counts.values())
        result[head] = torch.tensor(
            [
                min(8.0, math.sqrt(total / (len(classes) * counts[value])))
                if counts[value]
                else 0.0
                for value in classes
            ],
            dtype=torch.float32,
            device="cuda",
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--examples",
        type=Path,
        nargs="+",
        default=sorted((ROOT / "training/vericlaim_sec/eev").glob("train-*.jsonl")),
    )
    parser.add_argument(
        "--pairs",
        type=Path,
        default=ROOT / "training/vericlaim_sec/eev/contrastive_pairs-000.jsonl",
    )
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/eev_model")
    parser.add_argument("--max-length", type=int, default=384)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--gradient-accumulation", type=int, default=4)
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--encoder-lr", type=float, default=2e-5)
    parser.add_argument("--head-lr", type=float, default=2e-4)
    parser.add_argument("--warmup-ratio", type=float, default=0.06)
    parser.add_argument("--unfreeze-last-layers", type=int, default=6)
    parser.add_argument("--contrastive-margin", type=float, default=0.35)
    parser.add_argument("--contrastive-weight", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=83)
    args = parser.parse_args()

    if not torch.cuda.is_available():
        raise SystemExit("CUDA is required to train EEV")
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.cuda.manual_seed_all(args.seed)
    rows = [row for row in read_jsonl(args.examples) if row.get("split") == "train"]
    pairs = read_jsonl([args.pairs])
    by_id = {row["example_id"]: row for row in rows}
    tokenizer = AutoTokenizer.from_pretrained(
        args.model_path, local_files_only=True, use_fast=True
    )
    collator = Collator(tokenizer, args.max_length)
    model = EEV(args.model_path, args.unfreeze_last_layers, 0.15).cuda()
    weights = class_weights(rows)
    sampler = WeightedRandomSampler(
        [4.0 if row.get("partition") == "broad_record_complete" else 1.0 for row in rows],
        num_samples=len(rows),
        replacement=True,
        generator=torch.Generator().manual_seed(args.seed),
    )
    loader = DataLoader(
        ExampleDataset(rows),
        batch_size=args.batch_size,
        sampler=sampler,
        collate_fn=collator,
        num_workers=2,
        pin_memory=True,
    )
    optimizer = torch.optim.AdamW(
        [
            {"params": [p for p in model.encoder.parameters() if p.requires_grad], "lr": args.encoder_lr},
            {"params": model.heads.parameters(), "lr": args.head_lr},
        ]
    )
    steps = math.ceil(len(loader) / args.gradient_accumulation) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer, int(steps * args.warmup_ratio), steps
    )

    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad(set_to_none=True)
        running = 0.0
        for step, batch in enumerate(loader, 1):
            labels = {key: value.cuda() for key, value in batch.pop("labels").items()}
            masks = {key: value.cuda() for key, value in batch.pop("masks").items()}
            batch.pop("example_ids")
            inputs = {key: value.cuda() for key, value in batch.items()}
            with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                _, logits = model(**inputs)
                loss = torch.zeros((), device="cuda")
                for head in HEAD_CLASSES:
                    if masks[head].any():
                        value = nn.functional.cross_entropy(
                            logits[head][masks[head]],
                            labels[head][masks[head]],
                            weight=weights[head],
                        )
                        loss += LOSS_WEIGHTS[head] * value
                loss /= args.gradient_accumulation
            loss.backward()
            running += float(loss.detach()) * args.gradient_accumulation
            if step % args.gradient_accumulation == 0 or step == len(loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)

        # Same-literal pairs use the released relation ordering: left is the
        # authorized context and right is the ineligible context.
        usable = [p for p in pairs if p["left_example_id"] in by_id and p["right_example_id"] in by_id]
        if usable:
            model.train()
            pair_rows = [by_id[p["left_example_id"]] for p in usable] + [by_id[p["right_example_id"]] for p in usable]
            batch = collator(pair_rows)
            inputs = {key: value.cuda() for key, value in batch.items() if key in {"input_ids", "attention_mask"}}
            _, logits = model(**inputs)
            probability = torch.softmax(logits["authorized_for_attribute"], -1)[:, 1]
            size = len(usable)
            contrastive = args.contrastive_weight * torch.relu(
                args.contrastive_margin - (probability[:size] - probability[size:])
            ).mean()
            optimizer.zero_grad(set_to_none=True)
            contrastive.backward()
            optimizer.step()
        print(json.dumps({"epoch": epoch + 1, "mean_loss": running / len(loader)}))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    torch.save(
        {"model_state_dict": model.state_dict(), "head_classes": HEAD_CLASSES},
        args.output_dir / "eev.pt",
    )
    tokenizer.save_pretrained(args.output_dir / "tokenizer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
