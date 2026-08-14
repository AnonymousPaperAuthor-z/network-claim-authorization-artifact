from __future__ import annotations

import hashlib
import unittest

from probeagent.evidence.budget_compiler import (
    EvidenceBudgetError,
    compile_for_budget,
)


def unit(
    context: str,
    unit_id: str,
    text: str,
    *,
    mandatory: bool = False,
    support: float = 0.0,
    risk: float = 0.0,
) -> dict[str, object]:
    start = context.index(text)
    return {
        "unit_id": unit_id,
        "source_type": "device_banner",
        "text": text,
        "start_char": start,
        "end_char": start + len(text),
        "raw_span_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "mandatory": mandatory,
        "scores": {
            "support_brand": 0.0,
            "support_model": support,
            "support_firmware": support,
            "risk": risk,
        },
    }


class BudgetCompilerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = "[TARGET_METADATA]\nservice=http"
        self.device = "[DEVICE_BANNER]\nModel=VX-200 Firmware=6.2.5"
        self.noise = "[STATIC_RESOURCE]\n" + "cache=7.4.1 " * 30
        self.complete = "\n\n".join(
            (self.metadata, self.device, self.noise)
        )
        self.units = [
            unit(
                self.complete,
                "meta",
                self.metadata,
                mandatory=True,
            ),
            unit(
                self.complete,
                "device",
                self.device,
                support=0.95,
                risk=0.01,
            ),
            unit(
                self.complete,
                "noise",
                self.noise,
                support=0.05,
                risk=0.99,
            ),
        ]

    def test_complete_is_used_when_it_fits(self) -> None:
        provider_calls = 0

        def provider() -> list[dict[str, object]]:
            nonlocal provider_calls
            provider_calls += 1
            return self.units

        result = compile_for_budget(
            self.complete,
            provider,
            len(self.complete),
        )
        self.assertEqual(result.mode, "complete")
        self.assertEqual(result.context, self.complete)
        self.assertEqual(result.selected_unit_ids, ())
        self.assertEqual(result.dropped_unit_ids, ())
        self.assertEqual(provider_calls, 0)

    def test_over_budget_uses_pase(self) -> None:
        result = compile_for_budget(
            self.complete,
            self.units,
            420,
        )
        self.assertEqual(result.mode, "pase")
        self.assertLessEqual(
            result.compiled_context_units,
            result.max_context_units,
        )
        self.assertEqual(set(result.selected_unit_ids), {"meta", "device"})
        self.assertEqual(result.dropped_unit_ids, ("noise",))
        self.assertIn(self.device, result.context)
        self.assertNotIn(self.noise, result.context)
        self.assertFalse(result.selection_used_labels)

    def test_caller_can_supply_token_measure(self) -> None:
        result = compile_for_budget(
            self.complete,
            self.units,
            80,
            measure=lambda value: len(value.split()),
            budget_unit="tokens",
        )
        self.assertEqual(result.budget_unit, "tokens")
        self.assertLessEqual(result.compiled_context_units, 80)

    def test_span_tampering_fails_closed(self) -> None:
        tampered = dict(self.units[1])
        tampered["text"] = "Model=not-observed"
        with self.assertRaisesRegex(EvidenceBudgetError, "provenance mismatch"):
            compile_for_budget(
                self.complete,
                [self.units[0], tampered],
                420,
            )

    def test_mandatory_overflow_fails_closed(self) -> None:
        with self.assertRaisesRegex(EvidenceBudgetError, "mandatory evidence"):
            compile_for_budget(
                self.complete,
                self.units,
                40,
            )


if __name__ == "__main__":
    unittest.main()
