# VeriClaim Artifact

This anonymous artifact accompanies the paper **VeriClaim: Mitigating Source
Confusion in LLM-Derived Network-Asset Identity**. VeriClaim preserves the
provenance of heterogeneous network observations, proposes replaceable
vendor, product, and firmware-version candidates, and authorizes each value
before it reaches an inventory or vulnerability-analysis workflow.

The release contains the offline evidence-planning, candidate-extraction,
source-aware verification, and action-routing components evaluated in the
paper, the three-track VeriClaim-Sec benchmark, privacy-filtered public PASE
and EEV training subsets, aggregate paper-result counts, and deterministic integrity and
privacy checks. It intentionally excludes live probing, measurement endpoints, annotation
workbooks, private ID mappings, model weights, raw model generations, and
intermediate experiment files.

## Quick Start

Python 3.10 or newer is sufficient for the default checks. They require no
network access, model download, or GPU.

```bash
python scripts/run_all.py
```

The final line should be:

```text
ARTIFACT_CHECKS_COMPLETE
```

The command verifies the benchmark and training schemas, Gold cardinalities,
privacy transformations, aggregate metrics, runtime contracts, repository
scope, release manifest, and anonymous Git metadata.

## Repository Layout

```text
benchmark/vericlaim_sec/  sanitized observations and final attribute Gold
training/vericlaim_sec/   privacy-filtered PASE and EEV supervision subsets
probeagent/evidence/      evidence planning, source typing, and contracts
probeagent/policy/        deterministic terminal action routing
probeagent/knowledge/     conservative coarse-identity completion
scripts/                  training, inference, metrics, and release gates
tests/                    deterministic unit tests
data/                     synthetic runtime cases and aggregate paper counts
```

## VeriClaim-Sec

VeriClaim-Sec contains 8,600 pairwise-disjoint records and 25,800 attribute
cells for `brand`, `model`, and `firmware_version`. Its three tracks are:

- Candidate Verification: 2,000 records for matched verifier comparison;
- Broad Record-Complete: 6,000 records for record-complete evaluation; and
- Evidence-rich: 600 records for deep-evidence transfer and composition.

Each record contains sanitized observed evidence. Each attribute cell contains
the final Gold value set; an empty set is an explicit negative label rather
than a missing annotation. Endpoint IP addresses, network ports, hostnames,
URL authorities and queries, MAC addresses, serial identifiers, credentials,
collection timestamps, and private measurement IDs are removed or replaced by
typed placeholders. See `benchmark/vericlaim_sec/README.md` for the exact
schema and label semantics.

## Model-dependent Reproduction

The release does not redistribute third-party model weights. After installing
the optional model dependencies and supplying local model paths, the following
entry points reproduce the corresponding stages:

```bash
python scripts/train_pase.py --model-path /path/to/roberta-large
python scripts/run_pase.py --checkpoint outputs/pase_model --split test
python scripts/train_eev.py --model-path /path/to/roberta-large
python scripts/run_eev.py --encoder-model-path /path/to/roberta-large \
  --checkpoint outputs/eev_model/eev.pt --split transfer
python scripts/run_candidate_extractor.py --model-path /path/to/qwen3-14b
python scripts/run_csda.py --model-path /path/to/qwen3-14b \
  --claims /path/to/candidate_claims.jsonl
```

All model scripts read only public schemas, preserve the supplied record-grouped
splits, and write outputs under `outputs/`, which is ignored by Git.

## Release Boundary

This repository is the anonymous submission artifact. It contains no author
names, personal links, acknowledgements, private paths, credentials, endpoint
coordinates, discussion notes, post-submission extensions, or non-anonymous
repository history. Run `python scripts/verify_release.py` immediately before
any public update.

## License

The code is released under the Apache License 2.0. The benchmark and training
views are provided for research evaluation under the same repository license.
