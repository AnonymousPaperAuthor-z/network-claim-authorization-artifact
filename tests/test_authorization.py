import unittest

from probeagent.evidence.authorization import authorize_claim


class AuthorizationTest(unittest.TestCase):
    def test_component_version_cannot_attest_firmware(self) -> None:
        decision = authorize_claim(
            attribute="firmware_version",
            candidate_value="1.7.2",
            source_type="library_version",
            field_path="static_resource.script_path",
        )
        self.assertFalse(decision.authorized)

    def test_protocol_field_requires_target_semantics(self) -> None:
        decision = authorize_claim(
            attribute="model",
            candidate_value="Example Device",
            source_type="protocol_self_report",
            field_path="protocol.model_name",
            risk_flags={"generic_protocol_value": True},
        )
        self.assertFalse(decision.authorized)

    def test_repeated_firmware_static_path_can_be_authorized(self) -> None:
        decision = authorize_claim(
            attribute="firmware_version",
            candidate_value="6.2.5",
            source_type="static_resource",
            field_path="static_resource.path",
            evidence_row={
                "static_resource_prompt_context": (
                    "[STATIC_RESOURCE]\n"
                    "url=/firmware/6.2.5/update.bin\n"
                    "url=/firmware/6.2.5/manifest.json"
                )
            },
        )
        self.assertTrue(decision.authorized)


if __name__ == "__main__":
    unittest.main()
