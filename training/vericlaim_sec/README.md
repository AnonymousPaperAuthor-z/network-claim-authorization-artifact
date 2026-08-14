# VeriClaim Training Views

This directory contains privacy-filtered public supervision subsets for the
Provenance-Aware Selective Evidence compiler (PASE) and Evidence-Entitlement
Verifier (EEV). The release excludes rows derived from internal product-label
summaries as well as endpoint IP addresses, network ports, private record IDs,
hostnames, account and contact values, session credentials, annotation
workbooks, and reviewer notes. Consequently, the public subset is
smaller than the full training corpus reported in the paper; it preserves the
same schemas, targets, and record-grouped split semantics for executable
artifact inspection.

## PASE Units

`pase/units-*.jsonl` contains 27,292 provenance-bound evidence units. Each row
provides the exact unit text, source type, split, four masked targets
(`support_brand`, `support_model`, `support_firmware`, and `risk`), and a
content digest. The labels are weak or heuristic supervision and are explicitly
marked `weak_or_heuristic_not_adjudicated_gold`.

## EEV Examples

`eev/train-*.jsonl` contains 45,114 target-conditioned span/claim examples,
and `eev/transfer-*.jsonl` contains 1,067 record-disjoint transfer examples.
Each row preserves the target attribute, candidate, exact evidence span, field
path, local context, source type, six semantic targets, task masks, split, and
supervision source. Seventeen same-literal contrastive pairs link examples in
which identical strings have different evidence roles.

The six EEV targets are:

- `source_role`: the evidence-source category;
- `subject_role`: the entity described by the span;
- `support_type`: direct, coarse, conflicting, or absent support;
- `confusion_risk`: the source-confusion family, when present;
- `authorized_for_attribute`: whether the span may establish the target
  attribute; and
- `terminal_eligibility`: direct acceptance, reduced resolution, or deferral.

`label_masks` states which targets are supervised for each row. A training
label is never silently promoted to benchmark Gold.

## Gold Boundary

Only `benchmark/vericlaim_sec/cells/*.jsonl` contains final benchmark Gold.
The training views retain their supervision provenance and must not replace
`gold_values` during evaluation.

Run the integrity, privacy, schema, and provenance gate with:

```bash
python scripts/verify_training_data.py
```

`release_manifest.json` records exact shard counts and SHA-256 digests.
