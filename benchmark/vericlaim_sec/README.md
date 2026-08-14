# VeriClaim-Sec Benchmark

VeriClaim-Sec is the expert-annotated benchmark suite used in the paper. It
contains **8,600 pairwise-disjoint network-observation records** and **25,800
attribute cells** for vendor (`brand`), product (`model`), and firmware version
(`firmware_version`).

| Track | Records | Attribute cells | Evaluation role |
|---|---:|---:|---|
| `candidate_verification` | 2,000 | 6,000 | Matched verifier comparison |
| `broad_record_complete` | 6,000 | 18,000 | Broad record-complete evaluation |
| `evidence_rich` | 600 | 1,800 | Deep-evidence transfer and composition |

The tracks are record-disjoint. The release preserves the complete
vendor/product/firmware-version grid for every record, including explicit
negative cells.

## Files and Join Key

`records/*.jsonl` contains the sanitized observed evidence. One record has:

| Field | Meaning |
|---|---|
| `schema_version` | Public schema identifier |
| `record_id` | Release-only pseudonymous record key |
| `track` | One of the three evaluation tracks above |
| `service` | Normalized application service, without a port number |
| `transport` | `tcp`, `udp`, or an empty value when unavailable |
| `evidence` | Provenance-preserving sanitized observation text |
| `evidence_sha256` | SHA-256 of the exact released evidence string |

`cells/*.jsonl` contains one Gold decision for each record and attribute:

| Field | Meaning |
|---|---|
| `cell_id` | Release-only pseudonymous attribute-cell key |
| `record_id` | Foreign key into `records/*.jsonl` |
| `track` | Evaluation track, equal to the parent record's track |
| `attribute` | `brand`, `model`, or `firmware_version` |
| `gold_values` | Final supported value set for this attribute |
| `gold_supported` | `true` exactly when `gold_values` is nonempty |

An empty `gold_values` list is an explicit Gold negative: the released
observation does not support a value for that attribute. It is not a missing
annotation. Gold values describe only what the preserved evidence supports;
they do not expose an endpoint coordinate or private measurement identifier.

## Collection and Annotation

The records were sampled from the real network-measurement corpus described in
the paper. Two domain experts labeled vendor, product, and firmware-version
support from the preserved evidence, and a third expert adjudicated
disagreements. The public release contains the final attribute Gold used for
evaluation. Detailed annotation rules and agreement analysis are outside this
submission snapshot.

## Privacy Transformation

The public evidence removes endpoint IP addresses and network ports, internal
record IDs, hostnames, URL authorities and queries, MAC and email addresses,
serial/UUID values, credentials and session tokens, certificate identifiers,
collection timestamps, and raw page titles. Typed placeholders such as
`<IP>`, `<HOST>`, `<PORT>`, `<TIME>`, and `<REDACTED>` preserve evidence
structure without disclosing endpoint coordinates. Release-only record and
cell IDs cannot be reversed without a private mapping, which is not included.

When a repeated static-resource query value itself carries a firmware release,
the release preserves only `observed_query_version=<value>` beside the
sanitized resource path. The original query key, the rest of the query string,
and all endpoint coordinates remain removed.

The verifier checks schemas, hashes, cardinalities, track disjointness, Gold
consistency, and the privacy contract:

```bash
python scripts/verify_benchmark.py
```

`release_manifest.json` records the expected counts and SHA-256 digest of each
shard.
