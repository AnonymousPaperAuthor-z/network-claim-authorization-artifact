import unittest

from probeagent.evidence.candidate_shape_guard import evaluate_candidate_shape


class CandidateShapeGuardTest(unittest.TestCase):
    def test_rejects_nonidentity_shapes(self) -> None:
        for value in ("21", "2030-01-23", "20300123", "1609459228"):
            self.assertTrue(evaluate_candidate_shape("firmware_version", value).blocked)
        for value in ("Generic", "Private", "ONVIF_IPNC", "SIP", "UPnP"):
            self.assertTrue(evaluate_candidate_shape("brand", value).blocked)
        self.assertTrue(evaluate_candidate_shape("brand", "25").blocked)
        self.assertTrue(evaluate_candidate_shape("model", "123").blocked)
        self.assertTrue(evaluate_candidate_shape("model", "3E").blocked)

    def test_preserves_plausible_identity_values(self) -> None:
        self.assertFalse(evaluate_candidate_shape("brand", "Example Networks").blocked)
        self.assertFalse(evaluate_candidate_shape("model", "M50").blocked)
        self.assertFalse(evaluate_candidate_shape("model", "1234").blocked)
        self.assertFalse(
            evaluate_candidate_shape("firmware_version", "6.2.5-1052741330").blocked
        )


if __name__ == "__main__":
    unittest.main()
