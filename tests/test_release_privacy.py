from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from verify_benchmark import check_evidence_privacy  # noqa: E402


def privacy_errors(text: str) -> list[str]:
    errors: list[str] = []
    check_evidence_privacy(
        text,
        allowed_version_values=set(),
        allowed_identity_values=set(),
        errors=errors,
        label="test",
    )
    return errors


class ReleasePrivacyTest(unittest.TestCase):
    def test_prefixed_api_key_is_rejected(self) -> None:
        errors = privacy_errors(
            '"SYNTHETIC_SERVICE_API_KEY": "0123456789abcdef0123456789abcdef"'
        )
        self.assertTrue(any("credential" in error for error in errors))

    def test_prefixed_private_key_is_rejected(self) -> None:
        errors = privacy_errors(
            '"SYNTHETIC_RSA_PRIVATE_KEY": "SYNTHETIC_PRIVATE_MATERIAL_123456"'
        )
        self.assertTrue(any("credential" in error for error in errors))

    def test_password_policy_name_is_not_a_credential(self) -> None:
        self.assertEqual(privacy_errors('"password_policy": "/apps/password_policy"'), [])

    def test_javascript_password_variable_is_not_a_literal_credential(self) -> None:
        text = (
            'post_data += "&auth_passwd=" + auth_passwd; '
            "new HTTP(url, 'POST', post_data)"
        )
        self.assertEqual(privacy_errors(text), [])

    def test_numeric_host_port_fragment_is_rejected(self) -> None:
        errors = privacy_errors('203.0.113:54321/v1')
        self.assertTrue(any("host-port" in error for error in errors))

    def test_concatenated_host_port_is_rejected(self) -> None:
        errors = privacy_errors('"https://" + <HOST> + ":9002/dify"')
        self.assertTrue(any("host-port" in error for error in errors))

    def test_redacted_values_are_accepted(self) -> None:
        text = (
            '"VITE_GLOB_VOICE_API_KEY": "<REDACTED_TOKEN>", '
            '"VITE_GLOB_VOICE_APPID": "<REDACTED_ID>", '
            '"url": "https://<HOST>:<PORT>/v1"'
        )
        self.assertEqual(privacy_errors(text), [])


if __name__ == "__main__":
    unittest.main()
