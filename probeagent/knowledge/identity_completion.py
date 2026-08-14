"""Conservative hierarchical identity completion from an audited model KB."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from probeagent.evidence.identity_alias import brand_key


def clean(value: Any) -> str:
    return " ".join(str(value or "").replace("\x00", " ").split()).strip()


def canonical(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", clean(value).casefold())


def literal_present(value: Any, evidence: Any) -> bool:
    needle = canonical(value)
    return bool(len(needle) >= 3 and needle in canonical(evidence))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class IdentityCompletion:
    status: str
    target_attribute: str
    derived_value: str = ""
    provenance: str = ""
    rule_id: str = ""
    anchor_attributes: tuple[str, ...] = ()
    anchor_values: tuple[str, ...] = ()
    reason: str = ""
    kb_sha256: str = ""

    @property
    def accepted(self) -> bool:
        return self.status == "ACCEPT"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IdentityKnowledgeBase:
    """Versioned exact-match KB; never infers installed firmware."""

    def __init__(
        self,
        database: dict[str, Any],
        *,
        source_id: str,
        sha256: str = "",
        audited_mappings: list[dict[str, Any]] | None = None,
        blocked_mappings: list[dict[str, Any]] | None = None,
    ) -> None:
        self.source_id = source_id
        self.sha256 = sha256
        self.model_to_brands: dict[str, dict[str, str]] = {}
        self.brand_version_to_models: dict[tuple[str, str], dict[str, str]] = {}
        self.audited_anchor_to_brands: dict[str, dict[str, dict[str, str]]] = {}
        self.blocked_anchors: dict[tuple[str, str], str] = {}
        self.brand_names: set[str] = set()
        for model_name, brand_map in database.items():
            model = clean(model_name)
            model_key = canonical(model)
            if not model_key or not isinstance(brand_map, dict):
                continue
            brands = self.model_to_brands.setdefault(model_key, {})
            for brand_name, versions in brand_map.items():
                brand = clean(brand_name)
                brand_norm = brand_key(brand)
                if not brand_norm:
                    continue
                brands[brand_norm] = brand
                self.brand_names.add(brand)
                if not isinstance(versions, list):
                    continue
                for version in versions:
                    version_text = clean(version)
                    if not version_text:
                        continue
                    self.brand_version_to_models.setdefault(
                        (brand_norm, canonical(version_text)), {}
                    )[model_key] = model

        for mapping in audited_mappings or []:
            if clean(mapping.get("target_attribute")).lower() != "brand":
                continue
            anchor_attribute = clean(mapping.get("anchor_attribute")).lower()
            anchor_value = clean(mapping.get("anchor_value"))
            derived_value = clean(mapping.get("derived_value"))
            if anchor_attribute not in {"model", "identity_anchor"} or not anchor_value or not derived_value:
                continue
            anchor_key = canonical(anchor_value)
            brand_norm = brand_key(derived_value)
            self.audited_anchor_to_brands.setdefault(anchor_key, {})[brand_norm] = {
                "derived_value": derived_value,
                "mapping_role": clean(mapping.get("mapping_role")),
                "rule_id": clean(mapping.get("rule_id")) or "AUDITED_IDENTITY_ANCHOR_TO_BRAND_V1",
                "anchor_value": anchor_value,
            }
            self.brand_names.add(derived_value)

        for mapping in blocked_mappings or []:
            target = clean(mapping.get("target_attribute")).lower()
            anchor_value = clean(mapping.get("anchor_value"))
            if target and anchor_value:
                self.blocked_anchors[(target, canonical(anchor_value))] = (
                    clean(mapping.get("reason")) or "AUDITED_AMBIGUOUS_IDENTITY_ANCHOR"
                )

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        audited_mappings_path: Path | None = None,
    ) -> "IdentityKnowledgeBase":
        with path.open(encoding="utf-8") as handle:
            database = json.load(handle)
        if not isinstance(database, dict):
            raise ValueError(f"identity KB must be a JSON object: {path}")
        mappings: list[dict[str, Any]] = []
        blocked_mappings: list[dict[str, Any]] = []
        source_id = str(path)
        digest_parts = [_sha256(path)]
        if audited_mappings_path is not None:
            with audited_mappings_path.open(encoding="utf-8") as handle:
                mapping_payload = json.load(handle)
            mappings = mapping_payload.get("mappings") or []
            if not isinstance(mappings, list):
                raise ValueError(f"audited KB mappings must be a list: {audited_mappings_path}")
            blocked_mappings = mapping_payload.get("blocked_mappings") or []
            if not isinstance(blocked_mappings, list):
                raise ValueError(f"blocked KB mappings must be a list: {audited_mappings_path}")
            source_id = f"{path};{audited_mappings_path}"
            digest_parts.append(_sha256(audited_mappings_path))
        return cls(
            database,
            source_id=source_id,
            sha256=hashlib.sha256(";".join(digest_parts).encode()).hexdigest(),
            audited_mappings=mappings,
            blocked_mappings=blocked_mappings,
        )

    def complete(
        self,
        *,
        target_attribute: str,
        observed: dict[str, str],
        evidence_context: str,
        role_valid: bool,
        has_identity_conflict: bool,
    ) -> IdentityCompletion:
        target = clean(target_attribute).lower()
        if target == "firmware_version":
            return IdentityCompletion(
                "ABSTAIN", target, reason="KB_FIRMWARE_COMPLETION_FORBIDDEN", kb_sha256=self.sha256
            )
        if has_identity_conflict:
            return IdentityCompletion(
                "ESCALATE", target, reason="IDENTITY_CONFLICT_BLOCKS_KB_COMPLETION", kb_sha256=self.sha256
            )
        if not role_valid:
            return IdentityCompletion(
                "ABSTAIN", target, reason="ANCHOR_ROLE_NOT_DEVICE_IDENTITY", kb_sha256=self.sha256
            )

        model = clean(observed.get("model"))
        identity_anchor = clean(observed.get("identity_anchor"))
        brand = clean(observed.get("brand"))
        firmware = clean(observed.get("firmware_version"))

        if target == "brand" and model and literal_present(model, evidence_context):
            blocked_reason = self.blocked_anchors.get((target, canonical(model)))
            if blocked_reason:
                return IdentityCompletion("ABSTAIN", target, reason=blocked_reason, kb_sha256=self.sha256)
            brands = self.model_to_brands.get(canonical(model), {})
            if len(brands) == 1:
                derived = next(iter(brands.values()))
                return IdentityCompletion(
                    "ACCEPT",
                    target,
                    derived_value=derived,
                    provenance="KB_DERIVED_IDENTITY_COMPLETION",
                    rule_id="MODEL_EXACT_UNIQUE_BRAND_V1",
                    anchor_attributes=("model",),
                    anchor_values=(model,),
                    reason="DIRECT_MODEL_ANCHOR_HAS_UNIQUE_BRAND",
                    kb_sha256=self.sha256,
                )
            reason = "MODEL_NOT_IN_KB" if not brands else "MODEL_MAPS_TO_MULTIPLE_BRANDS"
            audited = self.audited_anchor_to_brands.get(canonical(model), {})
            if len(audited) == 1:
                mapping = next(iter(audited.values()))
                return IdentityCompletion(
                    "ACCEPT",
                    target,
                    derived_value=mapping["derived_value"],
                    provenance="KB_DERIVED_IDENTITY_COMPLETION",
                    rule_id=mapping["rule_id"],
                    anchor_attributes=("model",),
                    anchor_values=(model,),
                    reason=mapping["mapping_role"] or "AUDITED_IDENTITY_ANCHOR_HAS_UNIQUE_BRAND",
                    kb_sha256=self.sha256,
                )
            return IdentityCompletion("ABSTAIN", target, reason=reason, kb_sha256=self.sha256)

        if target == "brand" and identity_anchor and literal_present(identity_anchor, evidence_context):
            blocked_reason = self.blocked_anchors.get((target, canonical(identity_anchor)))
            if blocked_reason:
                return IdentityCompletion("ABSTAIN", target, reason=blocked_reason, kb_sha256=self.sha256)
            audited = self.audited_anchor_to_brands.get(canonical(identity_anchor), {})
            if len(audited) == 1:
                mapping = next(iter(audited.values()))
                return IdentityCompletion(
                    "ACCEPT",
                    target,
                    derived_value=mapping["derived_value"],
                    provenance="KB_DERIVED_IDENTITY_COMPLETION",
                    rule_id=mapping["rule_id"],
                    anchor_attributes=("identity_anchor",),
                    anchor_values=(identity_anchor,),
                    reason=mapping["mapping_role"] or "AUDITED_IDENTITY_ANCHOR_HAS_UNIQUE_BRAND",
                    kb_sha256=self.sha256,
                )

        if (
            target == "model"
            and brand
            and firmware
            and literal_present(brand, evidence_context)
            and literal_present(firmware, evidence_context)
        ):
            models = self.brand_version_to_models.get((brand_key(brand), canonical(firmware)), {})
            if len(models) == 1:
                derived = next(iter(models.values()))
                return IdentityCompletion(
                    "ACCEPT",
                    target,
                    derived_value=derived,
                    provenance="KB_DERIVED_IDENTITY_COMPLETION",
                    rule_id="BRAND_AND_OBSERVED_FIRMWARE_UNIQUE_MODEL_V1",
                    anchor_attributes=("brand", "firmware_version"),
                    anchor_values=(brand, firmware),
                    reason="DIRECT_BRAND_FIRMWARE_ANCHORS_HAVE_UNIQUE_MODEL",
                    kb_sha256=self.sha256,
                )
            reason = "BRAND_FIRMWARE_NOT_IN_KB" if not models else "BRAND_FIRMWARE_MAPS_TO_MULTIPLE_MODELS"
            return IdentityCompletion("ABSTAIN", target, reason=reason, kb_sha256=self.sha256)

        return IdentityCompletion(
            "ABSTAIN",
            target,
            reason="NO_DIRECT_FINE_GRAINED_ANCHOR",
            kb_sha256=self.sha256,
        )
