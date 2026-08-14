#!/usr/bin/env python3
"""Compute counterfactual source-dependency deltas for candidate claims."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from probeagent.evidence.source_type_classifier import SpanLabel, classify_spans


PROMPT = """Use only the observation evidence to answer the requested network-asset attribute.
Attribute: {attribute}
Observation evidence:
{evidence}
Answer with the supported value or Unsupported:
"""


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def mask_type(text: str, labels: list[SpanLabel], source_type: str) -> str:
    intervals = sorted(
        (label.start, label.end)
        for label in labels
        if label.source_type == source_type
    )
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        parts.extend((text[cursor:start], f"[MASKED_SOURCE:{source_type}]"))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


class TeacherForcedScorer:
    def __init__(self, model_path: str, tensor_parallel_size: int, max_model_len: int):
        from transformers import AutoTokenizer
        from vllm import LLM, SamplingParams

        self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        self.model = LLM(
            model=model_path,
            tensor_parallel_size=tensor_parallel_size,
            max_model_len=max_model_len,
            trust_remote_code=True,
        )
        self.sampling = SamplingParams(max_tokens=1, temperature=0.0, prompt_logprobs=1)

    def score(self, evidence: str, attribute: str, value: str) -> float:
        prompt = PROMPT.format(attribute=attribute, evidence=evidence)
        prompt_ids = self.tokenizer.encode(prompt, add_special_tokens=False)
        target_ids = self.tokenizer.encode(value, add_special_tokens=False)
        output = self.model.generate(
            [{"prompt_token_ids": prompt_ids + target_ids}], self.sampling, use_tqdm=False
        )[0]
        logprobs = output.prompt_logprobs
        total = 0.0
        offset = len(prompt_ids)
        for index, token_id in enumerate(target_ids):
            entry = logprobs[offset + index]
            item = entry.get(token_id) if entry else None
            if item is None:
                return float("-inf")
            total += float(item.logprob)
        return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claims", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/csda.jsonl")
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--tensor-parallel-size", type=int, default=1)
    parser.add_argument("--max-model-len", type=int, default=32768)
    args = parser.parse_args()
    rows = read_jsonl(args.claims)
    scorer = TeacherForcedScorer(
        args.model_path, args.tensor_parallel_size, args.max_model_len
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as output:
        for row in rows:
            evidence = str(row["evidence"])
            labels = classify_spans(evidence, service=row.get("service"))
            source_types = sorted({label.source_type for label in labels})
            full = scorer.score(evidence, row["attribute"], row["candidate_value"])
            deltas = {}
            for source_type in source_types:
                masked = mask_type(evidence, labels, source_type)
                deltas[source_type] = full - scorer.score(
                    masked, row["attribute"], row["candidate_value"]
                )
            finite = {key: value for key, value in deltas.items() if math.isfinite(value)}
            dominant = max(finite, key=finite.get) if finite else "unknown"
            item = {
                "record_id": row["record_id"],
                "attribute": row["attribute"],
                "candidate_value": row["candidate_value"],
                "full_logprob": full,
                "source_deltas": deltas,
                "dominant_source": dominant,
            }
            output.write(json.dumps(item, ensure_ascii=False) + "\n")
            output.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
