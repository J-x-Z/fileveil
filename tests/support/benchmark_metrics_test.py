#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Focused correctness checks for the developer benchmark measurement harness."""

import importlib.util
from pathlib import Path
import unittest

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "benchmark_watermarks", ROOT / "tools/benchmark-watermarks.py"
)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class BenchmarkMetrics(unittest.TestCase):
    def test_equal_pixels_have_zero_mse_infinite_psnr_and_unit_ssim(self):
        image = Image.fromarray(np.full((64, 96, 3), 127, dtype=np.uint8))
        result = benchmark.metrics(image, image.copy())
        self.assertEqual(result["mse"], 0)
        self.assertTrue(result["psnr_infinite"])
        self.assertIsNone(result["psnr_db"])
        self.assertAlmostEqual(result["ssim"], 1, places=6)

    def test_known_constant_error_matches_psnr_definition(self):
        source = Image.fromarray(np.full((64, 64, 3), 100, dtype=np.uint8))
        modified = Image.fromarray(np.full((64, 64, 3), 110, dtype=np.uint8))
        result = benchmark.metrics(source, modified)
        self.assertEqual(result["mse"], 100)
        self.assertAlmostEqual(result["psnr_db"], 28.1308036086791)
        self.assertLess(result["ssim"], 1)

    def test_quality_rejects_unaligned_geometry(self):
        image = Image.new("RGB", (64, 64))
        self.assertIsNone(benchmark.metrics(image, image.resize((32, 32)))["ssim"])

    def test_summary_keeps_failures_in_end_to_end_denominator(self):
        rows = [
            dict(
                source_id=1,
                attack="jpeg_10",
                ok=True,
                detector={"status": "detected"},
                payload_matches=True,
            ),
            dict(source_id=2, attack="jpeg_10", ok=False, error="embedding_failed"),
        ]
        group = benchmark.summarize(rows, {})["attacks"]["jpeg_10"]
        self.assertEqual(group["assessed"], 1)
        self.assertEqual(group["errors"], 1)
        self.assertEqual(group["correct_payload_rate"], 1)
        self.assertEqual(group["end_to_end_correct_payload_rate"], 0.5)

    def test_unkeyed_baseline_is_not_assessed_as_a_wrong_key_success(self):
        rows = [dict(attack="wrong_key", ok=False, capability_status="not_applicable")]
        group = benchmark.summarize(rows, {})["attacks"]["wrong_key"]
        self.assertEqual(group["not_applicable"], 1)
        self.assertEqual(group["errors"], 0)
        self.assertIsNone(group["false_positive_rate"])

    def test_independent_v1_coefficient_observation_recovers_known_frame(self):
        spec = importlib.util.spec_from_file_location(
            "oracle", ROOT / "tests/support/heritage_robust_oracle.py"
        )
        oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oracle)
        marked = oracle.embed(
            np.full((512, 512, 3), 128, dtype=np.uint8), "benchmark-unit-work", 32
        )
        result = benchmark.baseline_ber(
            Image.fromarray(marked), "benchmark-unit-work", {}
        )
        self.assertEqual(result["bits"], 256)
        self.assertEqual(result["bit_errors"], 0)

    def test_geometric_attack_records_share_the_known_reference_transform(self):
        source = Image.fromarray(
            np.arange(64 * 64 * 3, dtype=np.uint8).reshape(64, 64, 3)
        )
        for name in ("scale_75", "crop_offset_75", "rotate_90", "screen_resample"):
            output, reference = benchmark.transform(source, name, 1)
            self.assertEqual(output.size, reference.size)
            self.assertTrue(np.array_equal(np.asarray(output), np.asarray(reference)))


if __name__ == "__main__":
    unittest.main()
