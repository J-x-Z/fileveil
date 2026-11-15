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

    def test_cleanup_metrics_keep_indeterminate_separate_from_strict_negative(self):
        spec = importlib.util.spec_from_file_location(
            "compare", ROOT / "tools/benchmark-compare.py"
        )
        compare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(compare)
        rows = [
            dict(
                attack="clean",
                ok=True,
                detector=dict(status="not_detected", frame_valid=False),
            ),
            dict(
                attack="clean",
                ok=True,
                detector=dict(status="indeterminate", frame_valid=False),
            ),
        ]
        values = compare.aggregate(rows)
        self.assertEqual(values["clean_valid_frame_disruption_rate"], 1)
        self.assertEqual(values["clean_strict_negative_rate"], 0.5)
        self.assertEqual(values["clean_indeterminate"], 1)

    def test_uncertain_control_is_preserved_separately_from_detected_frames(self):
        spec = importlib.util.spec_from_file_location(
            "compare", ROOT / "tools/benchmark-compare.py"
        )
        compare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(compare)
        rows = [
            dict(
                attack=attack,
                ok=True,
                detector=dict(status="indeterminate", frame_valid=False),
            )
            for attack in ("negative", "wrong_key")
        ]
        values = compare.aggregate(rows)
        self.assertEqual(values["negative_indeterminate"], 1)
        self.assertEqual(values["wrong_key_indeterminate"], 1)
        self.assertEqual(values["false_positives"], 0)

    def test_comparison_rejects_different_source_bytes(self):
        import json
        import tempfile

        spec = importlib.util.spec_from_file_location(
            "compare", ROOT / "tools/benchmark-compare.py"
        )
        compare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(compare)
        with tempfile.TemporaryDirectory() as folder:
            paths = []
            for index, checksum in enumerate(["first", "different"]):
                path = Path(folder) / f"{index}-summary.json"
                path.write_text(json.dumps({}))
                row = dict(
                    source_id=1,
                    source_sha256=checksum,
                    work_sha256="same",
                    prepared_dimensions=[512, 512],
                    attack="embedding",
                )
                path.with_name(f"{index}.jsonl").write_text(json.dumps(row) + "\n")
                paths.append(path)
            with self.assertRaisesRegex(ValueError, "Source hashes"):
                compare.compare(paths)

    def test_resume_rejects_changed_compiled_runner(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "run.json"
            benchmark.bind_run(path, dict(runner_sha256="original"), False)
            benchmark.bind_run(path, dict(runner_sha256="original"), True)
            with self.assertRaisesRegex(ValueError, "Run identity changed"):
                benchmark.bind_run(path, dict(runner_sha256="changed"), True)

    def test_resume_rejects_unbound_old_measurements(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "lack their run identity"):
                benchmark.bind_run(Path(folder) / "run.json", {}, True)

    def test_unavailable_platform_resources_are_not_reported_as_zero(self):
        spec = importlib.util.spec_from_file_location(
            "compare", ROOT / "tools/benchmark-compare.py"
        )
        compare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(compare)
        result = compare.aggregate(
            [
                dict(
                    attack="original",
                    algorithm_cpu_seconds=None,
                    process_peak_rss_bytes=None,
                )
            ]
        )
        self.assertIsNone(result["recorded_operations_cpu_seconds"])
        self.assertIsNone(result["worker_process_peak_rss_bytes"])
        summary = benchmark.summarize(
            [dict(attack="original", ok=True, detector=dict(status="not_detected"))],
            {},
        )["attacks"]["original"]
        self.assertIsNone(summary["cpu_seconds"])
        self.assertIsNone(summary["peak_rss_bytes"])


if __name__ == "__main__":
    unittest.main()

# FVPROV1 8291 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlODEzZjlkZjI2YmMyMzdlODE2NDc2OTgzZDdkMmZjMDhhYTZlZGU1NGJlMzkwNzNmNmE4N2IxZDUyNDM5NTM1IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3N1cHBvcnQvYmVuY2htYXJrX21ldHJpY3NfdGVzdC5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImEyZmVmNWExMWZiNTAzM2ZhNTNkYTI3NzVhMWYxZTNhMTA2OGQ0MTIzMjg0MTIxODI3YmJmYjIyNjJlMTU5MWZjMzQ3ZmQ4MWMxZTIwZmFkNzkxYjJmMzBiZWQ1NDAwNTEzOGU1OWVhMmVmY2FlOTA4MDI0ZDFiM2ZmYWRjODAyIn1dfV0= FVPROV1-END
