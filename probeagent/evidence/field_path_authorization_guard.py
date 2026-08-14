"""Hard field-path authorization boundaries for device attributes."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class FieldPathAuthorization:
    blocked: bool
    reason: str = ""


_SCANNER_METADATA = re.compile(
    r"(?:^|[._ ])(?:req_name|service_name|target_metadata)(?:$|[._ ])",
    re.IGNORECASE,
)
_APP_METADATA = re.compile(
    r"(?:^|[._ ])app_detection_summary_observed(?:$|[._ ])",
    re.IGNORECASE,
)
_INSTANCE_IDENTITY = re.compile(
    r"(?:^|[._ ])(?:hostname|serialnumber|serial_number|udn|uuid)(?:$|[._ ])",
    re.IGNORECASE,
)
_NON_FIRMWARE_VERSION_FIELD = re.compile(
    r"(?:^|[._ ])(?:modelnumber|model_number|hardwareid|hardware_id|"
    r"hardwareversion|hardware_version|serialnumber|serial_number|"
    r"last_modified|last-modified)(?:$|[._ ])",
    re.IGNORECASE,
)


def evaluate_field_path_authorization(
    attribute: str,
    field_path: str,
    *,
    source_type: str = "",
) -> FieldPathAuthorization:
    """Return a deterministic veto for semantically impossible field roles.

    The guard is deliberately narrow. It rejects scanner-generated metadata
    and fields whose schema role conflicts with the requested device
    attribute. It does not decide whether an otherwise eligible span is true.
    """

    normalized_attribute = str(attribute or "").strip().lower()
    normalized_path = str(field_path or "").strip().lower()
    normalized_source = str(source_type or "").strip().lower()

    if _SCANNER_METADATA.search(normalized_path):
        return FieldPathAuthorization(
            True,
            "SCANNER_METADATA_NOT_DEVICE_ATTESTATION",
        )
    if _APP_METADATA.search(normalized_path):
        return FieldPathAuthorization(
            True,
            "APP_METADATA_NOT_DEVICE_ATTESTATION",
        )
    if (
        normalized_attribute == "model"
        and _INSTANCE_IDENTITY.search(normalized_path)
    ):
        return FieldPathAuthorization(
            True,
            "INSTANCE_IDENTITY_NOT_PRODUCT_MODEL",
        )
    if (
        normalized_attribute == "firmware_version"
        and _NON_FIRMWARE_VERSION_FIELD.search(normalized_path)
    ):
        return FieldPathAuthorization(
            True,
            "FIELD_ROLE_NOT_FIRMWARE",
        )
    if (
        normalized_attribute == "brand"
        and normalized_source in {"component_version", "library_version"}
    ):
        return FieldPathAuthorization(
            True,
            "COMPONENT_SOURCE_NOT_DEVICE_VENDOR",
        )
    return FieldPathAuthorization(False)
