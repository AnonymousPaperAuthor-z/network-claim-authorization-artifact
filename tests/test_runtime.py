from __future__ import annotations

import unittest
from pathlib import Path

from probeagent.evidence.candidate_shape_guard import evaluate_candidate_shape
from probeagent.knowledge.identity_completion import IdentityKnowledgeBase
from probeagent.policy.runtime import AcquisitionRequest, run_claim


ROOT = Path(__file__).resolve().parents[1]


class RuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.kb = IdentityKnowledgeBase.from_path(
            ROOT / "data/synthetic_identity_kb.json"
        )

    def test_candidate_shape_guard(self) -> None:
        self.assertTrue(
            evaluate_candidate_shape("firmware_version", "21").blocked
        )
        self.assertTrue(
            evaluate_candidate_shape("brand", "ONVIF").blocked
        )
        self.assertFalse(
            evaluate_candidate_shape("firmware_version", "6.2.5-1052741330").blocked
        )

    def test_kb_never_completes_firmware(self) -> None:
        completion = self.kb.complete(
            target_attribute="firmware_version",
            observed={"brand": "Example Networks", "model": "VX-200"},
            evidence_context="Manufacturer: Example Networks\nModel: VX-200",
            role_valid=True,
            has_identity_conflict=False,
        )
        self.assertEqual(completion.status, "ABSTAIN")
        self.assertEqual(completion.reason, "KB_FIRMWARE_COMPLETION_FORBIDDEN")

    def test_pending_acquisition_is_not_accept(self) -> None:
        trace = run_claim(
            record_id="unit-acquire",
            attribute="firmware_version",
            candidate_value="",
            evidence_context="Model: VX-200",
            verifier_accept=False,
            verifier_reason="missing",
            acquisition_request=AcquisitionRequest(
                action="ACQUIRE_STATIC_INFO",
                target="same endpoint",
                executor="authorized collector",
            ),
        )
        self.assertEqual(trace.terminal_action, "ACQUIRE_STATIC_INFO")
        self.assertFalse(trace.terminal_value)


if __name__ == "__main__":
    unittest.main()
