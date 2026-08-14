from __future__ import annotations

import unittest

from probeagent.evidence.source_type_classifier import classify_spans


class SourceClassifierTest(unittest.TestCase):
    def test_pase_device_banner_block(self) -> None:
        context = (
            "[PASE_UNIT id=demo source=device_banner sha256="
            "0123456789abcdef]\nFirmwareVersion: 1.2.3"
        )
        labels = classify_spans(context)
        self.assertIn("device_banner", {label.source_type for label in labels})

    def test_static_resource_is_not_device_banner(self) -> None:
        labels = classify_spans("[STATIC_FULL 1]\n/assets/app-1.2.3.js")
        sources = {label.source_type for label in labels}
        self.assertIn("static_resource", sources)


if __name__ == "__main__":
    unittest.main()
