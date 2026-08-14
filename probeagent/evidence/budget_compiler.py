"""Budget-aware routing between complete serialization and PASE.

The compiler is label blind. It first validates that every PASE unit is an
exact span of the complete serialization. The complete packet is returned
unchanged when it fits. Otherwise, PASE support/risk scores select an exact
span packet under the same caller-provided budget measure.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable, Mapping


BudgetMeasure = Callable[[str], int]


class EvidenceBudgetError(ValueError):
    """Raised when no provenance-preserving packet can satisfy the budget."""


@dataclass(frozen=True)
class EvidenceUnit:
    unit_id: str
    source_type: str
    text: str
    start_char: int
    end_char: int
    raw_span_sha256: str
    mandatory: bool = False
    support_brand: float = 0.0
    support_model: float = 0.0
    support_firmware: float = 0.0
    risk: float = 0.0

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> "EvidenceUnit":
        scores = row.get("scores") or row.get("model_scores") or {}
        if not isinstance(scores, Mapping):
            raise TypeError("scores/model_scores must be a mapping")
        text = str(row.get("text") or "")
        start = int(row.get("start_char", 0))
        return cls(
            unit_id=str(row.get("unit_id") or ""),
            source_type=str(row.get("source_type") or "unknown"),
            text=text,
            start_char=start,
            end_char=int(row.get("end_char", start + len(text))),
            raw_span_sha256=str(row.get("raw_span_sha256") or ""),
            mandatory=bool(row.get("mandatory")),
            support_brand=float(scores.get("support_brand", 0.0)),
            support_model=float(scores.get("support_model", 0.0)),
            support_firmware=float(scores.get("support_firmware", 0.0)),
            risk=float(scores.get("risk", 0.0)),
        )

    def utility(self, risk_weight: float) -> float:
        support = max(
            self.support_brand,
            self.support_model,
            self.support_firmware,
        )
        return 10.0 if self.mandatory else support - risk_weight * self.risk


PaseUnitSource = Iterable[EvidenceUnit | Mapping[str, Any]] | Callable[
    [], Iterable[EvidenceUnit | Mapping[str, Any]]
]


@dataclass(frozen=True)
class CompiledEvidence:
    context: str
    mode: str
    budget_unit: str
    max_context_units: int
    complete_context_units: int
    compiled_context_units: int
    selected_unit_ids: tuple[str, ...]
    dropped_unit_ids: tuple[str, ...]
    source_context_sha256: str
    compiled_context_sha256: str
    provenance_exact: bool
    selection_used_labels: bool = False
    selection_policy: str = "complete-first-pase"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _coerce_units(
    rows: Iterable[EvidenceUnit | Mapping[str, Any]],
) -> list[EvidenceUnit]:
    units = [
        row if isinstance(row, EvidenceUnit) else EvidenceUnit.from_mapping(row)
        for row in rows
    ]
    ids = [unit.unit_id for unit in units]
    if not units:
        raise EvidenceBudgetError("PASE fallback requires at least one evidence unit")
    if any(not unit_id for unit_id in ids):
        raise EvidenceBudgetError("every evidence unit requires a nonempty unit_id")
    if len(set(ids)) != len(ids):
        raise EvidenceBudgetError("evidence unit IDs must be unique")
    return units


def _resolve_units(source: PaseUnitSource) -> list[EvidenceUnit]:
    rows = source() if callable(source) else source
    return _coerce_units(rows)


def _validate_exact_spans(
    complete_context: str,
    units: Iterable[EvidenceUnit],
) -> None:
    for unit in units:
        if not 0 <= unit.start_char <= unit.end_char <= len(complete_context):
            raise EvidenceBudgetError(
                f"invalid span for {unit.unit_id}: "
                f"{unit.start_char}:{unit.end_char}"
            )
        if complete_context[unit.start_char : unit.end_char] != unit.text:
            raise EvidenceBudgetError(
                f"provenance mismatch for evidence unit {unit.unit_id}"
            )
        if unit.raw_span_sha256 and _sha256(unit.text) != unit.raw_span_sha256:
            raise EvidenceBudgetError(
                f"digest mismatch for evidence unit {unit.unit_id}"
            )


def _render_pase(units: Iterable[EvidenceUnit]) -> str:
    lines = [
        "[PASE_SELECTED_EVIDENCE]",
        "Exact observed spans follow. PASE does not generate or paraphrase evidence.",
        "",
    ]
    for unit in sorted(units, key=lambda item: (item.start_char, item.unit_id)):
        digest = unit.raw_span_sha256 or _sha256(unit.text)
        lines.append(
            f"[PASE_UNIT id={unit.unit_id} source={unit.source_type} "
            f"sha256={digest[:16]}]"
        )
        lines.append(unit.text.rstrip())
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def compile_for_budget(
    complete_context: str,
    pase_units: PaseUnitSource,
    max_context_units: int,
    *,
    measure: BudgetMeasure = len,
    budget_unit: str = "characters",
    risk_weight: float = 0.35,
) -> CompiledEvidence:
    """Compile one evidence packet under a context budget.

    ``measure`` defaults to character count to reproduce the frozen 20K PASE
    contract. A production caller can pass a tokenizer counter and set
    ``budget_unit="tokens"`` without changing the routing logic.
    """

    if max_context_units <= 0:
        raise ValueError("max_context_units must be positive")
    if risk_weight < 0:
        raise ValueError("risk_weight must be nonnegative")
    if not callable(measure):
        raise TypeError("measure must be callable")

    complete_size = int(measure(complete_context))
    if complete_size < 0:
        raise ValueError("measure returned a negative size")

    source_digest = _sha256(complete_context)
    if complete_size <= max_context_units:
        return CompiledEvidence(
            context=complete_context,
            mode="complete",
            budget_unit=budget_unit,
            max_context_units=max_context_units,
            complete_context_units=complete_size,
            compiled_context_units=complete_size,
            selected_unit_ids=(),
            dropped_unit_ids=(),
            source_context_sha256=source_digest,
            compiled_context_sha256=source_digest,
            provenance_exact=True,
        )

    # Unit segmentation and PASE scoring can be supplied lazily. They
    # are resolved only after the complete packet fails the budget gate.
    units = _resolve_units(pase_units)
    _validate_exact_spans(complete_context, units)
    mandatory = [unit for unit in units if unit.mandatory]
    selected = sorted(mandatory, key=lambda item: (item.start_char, item.unit_id))
    mandatory_packet = _render_pase(selected)
    if int(measure(mandatory_packet)) > max_context_units:
        raise EvidenceBudgetError(
            "mandatory evidence exceeds the context budget; refusing to "
            "truncate provenance metadata"
        )

    ranked = sorted(
        (unit for unit in units if not unit.mandatory),
        key=lambda item: (
            -item.utility(risk_weight),
            item.start_char,
            item.unit_id,
        ),
    )
    for unit in ranked:
        candidate = selected + [unit]
        if int(measure(_render_pase(candidate))) <= max_context_units:
            selected.append(unit)

    packet = _render_pase(selected)
    packet_size = int(measure(packet))
    if packet_size > max_context_units:
        raise EvidenceBudgetError("compiled PASE packet exceeds the budget")

    selected_ids = tuple(unit.unit_id for unit in selected)
    selected_set = set(selected_ids)
    dropped_ids = tuple(
        unit.unit_id for unit in units if unit.unit_id not in selected_set
    )
    return CompiledEvidence(
        context=packet,
        mode="pase",
        budget_unit=budget_unit,
        max_context_units=max_context_units,
        complete_context_units=complete_size,
        compiled_context_units=packet_size,
        selected_unit_ids=selected_ids,
        dropped_unit_ids=dropped_ids,
        source_context_sha256=source_digest,
        compiled_context_sha256=_sha256(packet),
        provenance_exact=True,
    )
