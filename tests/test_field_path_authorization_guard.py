import unittest

from probeagent.evidence.field_path_authorization_guard import evaluate_field_path_authorization


class FieldPathAuthorizationGuardTest(unittest.TestCase):
    def test_scanner_metadata_cannot_attest_brand(self):
        decision = evaluate_field_path_authorization("brand", "banner_full 1.req_name", source_type="device_banner")
        self.assertTrue(decision.blocked)
        self.assertEqual(decision.reason, "SCANNER_METADATA_NOT_DEVICE_ATTESTATION")

    def test_hostname_cannot_attest_model(self):
        self.assertTrue(evaluate_field_path_authorization("model", "banner_full 1.hostname", source_type="device_banner").blocked)

    def test_model_number_cannot_attest_firmware(self):
        decision = evaluate_field_path_authorization("firmware_version", "banner_full 1.modelnumber", source_type="protocol_self_report")
        self.assertEqual(decision.reason, "FIELD_ROLE_NOT_FIRMWARE")

    def test_explicit_firmware_field_remains_eligible(self):
        self.assertFalse(evaluate_field_path_authorization("firmware_version", "banner_full 1.tds:firmwareversion", source_type="protocol_self_report").blocked)


if __name__ == "__main__":
    unittest.main()
