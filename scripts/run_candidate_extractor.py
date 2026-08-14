#!/usr/bin/env python3
"""Run deterministic structured candidate extraction with vLLM."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "outputs/candidate_prompts.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/candidate_outputs.jsonl")
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--tensor-parallel-size", type=int, default=1)
    parser.add_argument("--max-model-len", type=int, default=32768)
    parser.add_argument("--gpu-memory-utilization", type=float, default=0.80)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args()

    from transformers import AutoTokenizer
    from vllm import LLM, SamplingParams
    from vllm.sampling_params import GuidedDecodingParams

    rows = read_jsonl(args.input)
    tokenizer = AutoTokenizer.from_pretrained(args.model_path, trust_remote_code=True)
    prompts = [
        tokenizer.apply_chat_template(
            row["messages"], tokenize=False, add_generation_prompt=True, enable_thinking=False
        )
        for row in rows
    ]
    schema = json.loads(
        (ROOT / "config/candidate_extraction.schema.json").read_text(encoding="utf-8")
    )
    sampling = SamplingParams(
        temperature=0.0,
        top_p=1.0,
        max_tokens=args.max_tokens,
        guided_decoding=GuidedDecodingParams(json=schema),
    )
    model = LLM(
        model=args.model_path,
        tensor_parallel_size=args.tensor_parallel_size,
        max_model_len=args.max_model_len,
        gpu_memory_utilization=args.gpu_memory_utilization,
        trust_remote_code=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as output:
        for start in range(0, len(rows), args.batch_size):
            generated = model.generate(
                prompts[start : start + args.batch_size], sampling, use_tqdm=False
            )
            for row, result in zip(rows[start : start + args.batch_size], generated):
                response = result.outputs[0]
                item = {
                    "record_id": row["record_id"],
                    "raw_response": response.text,
                    "finish_reason": str(response.finish_reason),
                }
                output.write(json.dumps(item, ensure_ascii=False) + "\n")
            output.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
