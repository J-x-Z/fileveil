#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Compare frozen watermark measurements on exactly matching source images."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics

EXCLUDED = {"embedding", "negative", "wrong_key", "clean"}


def load(summary_path):
    summary = json.loads(summary_path.read_text())
    journal = summary_path.with_name(
        summary_path.name.replace("-summary.json", ".jsonl")
    )
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    samples = {
        row["source_id"]: (
            row["source_sha256"],
            row["work_sha256"],
            row.get("copy_sha256"),
            tuple(row["prepared_dimensions"]),
        )
        for row in records
        if row["attack"] == "embedding"
    }
    return summary, records, samples, journal


def aggregate(records):
    positives = [r for r in records if r["attack"] not in EXCLUDED]
    embeddings = [r for r in records if r["attack"] == "embedding"]
    negative = [r for r in records if r["attack"] == "negative"]
    wrong_key = [r for r in records if r["attack"] == "wrong_key"]
    clean = [r for r in records if r["attack"] == "clean"]

    def detected(rows):
        return sum(
            r.get("ok") is True and r.get("detector", {}).get("status") == "detected"
            for r in rows
        )

    def mean_quality(rows, field):
        values = [
            r["quality"][field]
            for r in rows
            if r.get("quality", {}).get(field) is not None
        ]
        return statistics.fmean(values) if values else None

    def indeterminate(rows):
        return sum(
            r.get("ok") is True
            and r.get("detector", {}).get("status") == "indeterminate"
            for r in rows
        )

    def ratio(n, d):
        return n / d if d else None

    negative_assessed = sum(r.get("ok") is True for r in negative)
    wrong_assessed = sum(r.get("ok") is True for r in wrong_key)
    strict_clean = sum(
        r.get("ok") is True and r.get("detector", {}).get("status") == "not_detected"
        for r in clean
    )
    clean_indeterminate = sum(
        r.get("ok") is True and r.get("detector", {}).get("status") == "indeterminate"
        for r in clean
    )
    valid_frame_absent = sum(
        r.get("ok") is True and r.get("detector", {}).get("frame_valid") is False
        for r in clean
    )
    cpu = [
        r["algorithm_cpu_seconds"]
        for r in positives
        if r.get("algorithm_cpu_seconds") is not None
    ]
    recorded_cpu = [
        r["algorithm_cpu_seconds"]
        for r in records
        if r.get("algorithm_cpu_seconds") is not None
    ]
    rss = [
        r["process_peak_rss_bytes"]
        for r in records
        if r.get("process_peak_rss_bytes") is not None
    ]
    ber = {}
    for row in positives:
        measurement = row.get("raw_ber")
        if measurement and measurement.get("ber") is not None:
            ber.setdefault(measurement["scope"], []).append(measurement["ber"])
    return dict(
        positive_cases=len(positives),
        positive_correct=sum(bool(r.get("payload_matches")) for r in positives),
        positive_correct_rate=ratio(
            sum(bool(r.get("payload_matches")) for r in positives), len(positives)
        ),
        negative_cases=len(negative),
        negative_assessed=negative_assessed,
        negative_indeterminate=indeterminate(negative),
        false_positives=detected(negative),
        false_positive_rate=ratio(detected(negative), negative_assessed),
        wrong_key_cases=len(wrong_key),
        wrong_key_assessed=wrong_assessed,
        wrong_key_indeterminate=indeterminate(wrong_key),
        wrong_key_valid_frames=detected(wrong_key),
        wrong_key_false_positive_rate=ratio(detected(wrong_key), wrong_assessed),
        wrong_work_reference_matches=sum(
            bool(r.get("different_work_reference_matches")) for r in positives
        ),
        wrong_copy_reference_matches=sum(
            bool(r.get("different_copy_reference_matches")) for r in positives
        ),
        embed_cases=len(embeddings),
        embed_success=sum(r.get("ok") is True for r in embeddings),
        embedding_psnr_db=mean_quality(embeddings, "psnr_db"),
        embedding_ssim=mean_quality(embeddings, "ssim"),
        clean_cases=len(clean),
        clean_valid_frame_absent=valid_frame_absent,
        clean_valid_frame_disruption_rate=ratio(valid_frame_absent, len(clean)),
        clean_strict_negative=strict_clean,
        clean_strict_negative_rate=ratio(strict_clean, len(clean)),
        clean_indeterminate=clean_indeterminate,
        clean_psnr_db=mean_quality(clean, "psnr_db"),
        clean_ssim=mean_quality(clean, "ssim"),
        positive_cpu_seconds_total=sum(cpu) if cpu else None,
        positive_cpu_seconds_mean=statistics.fmean(cpu) if cpu else None,
        positive_cpu_seconds_p95=sorted(cpu)[min(len(cpu) - 1, int(len(cpu) * 0.95))]
        if cpu
        else None,
        recorded_operations_cpu_seconds=sum(recorded_cpu) if recorded_cpu else None,
        worker_process_peak_rss_bytes=max(rss) if rss else None,
        ber_by_measurement_scope={
            name: dict(observations=len(values), mean=statistics.fmean(values))
            for name, values in ber.items()
        },
    )


def compare(paths):
    loaded = [(path, *load(path)) for path in paths]
    expected = loaded[0][3]
    expected_cases = {(r["source_id"], r["attack"]) for r in loaded[0][2]}
    for path, summary, records, samples, journal in loaded:
        if samples != expected:
            raise ValueError(
                f"Source hashes, identifiers or prepared dimensions differ in {path}"
            )
        cases = {(r["source_id"], r["attack"]) for r in records}
        if len(cases) != len(records):
            raise ValueError(f"Duplicate measurement keys in {journal}")
        if cases != expected_cases:
            raise ValueError(f"Measured source and attack pairs differ in {journal}")
    results = {}
    for path, summary, records, samples, journal in loaded:
        label = f"{summary['protocol']}-s{summary['strength']}"
        if label in results:
            raise ValueError(
                "Comparison labels must identify distinct protocols or recipes"
            )
        strata = sorted({r["stratum"] for r in records})
        results[label] = dict(
            summary_path=str(path),
            summary_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            raw_records_path=str(journal),
            raw_records_sha256=hashlib.sha256(journal.read_bytes()).hexdigest(),
            runner_sha256=summary["runner_sha256"],
            algorithm_source_sha256=summary.get(
                "algorithm_source_sha256", summary["baseline_source_sha256"]
            ),
            images=len(samples),
            aggregate=aggregate(records),
            strata={
                s: aggregate([r for r in records if r["stratum"] == s]) for s in strata
            },
            prepared_max_edge_bands={
                name: aggregate(
                    [
                        row
                        for row in records
                        if lower <= max(row["prepared_dimensions"]) <= upper
                    ]
                )
                for name, lower, upper in (
                    ("512_to_1023", 512, 1023),
                    ("1024", 1024, 1024),
                )
            },
            attacks={
                name: aggregate([r for r in records if r["attack"] == name])
                for name in sorted({r["attack"] for r in records})
            },
        )
    return dict(
        schema="fileveil.watermark.benchmark.comparison.v1",
        paired_source_images=len(expected),
        cohort_scope="Fixed source hashes, expected work identifiers and prepared dimensions are identical. Related-source clusters remain present. Recompression uses real Pillow codecs; screenshot-style resampling is simulated.",
        performance_scope="CPU records measure stored Rust calls. Supplementary clean-output detect calls are absent from the stored CPU total. Positive-attack latency includes the complete recorded analyze/detect call. RSS is the process-lifetime high-water mark. One-pass same-host measurements include concurrent load affecting wall time.",
        ber_scope="Measurement scopes remain distinct. Nominal unsynchronized v1 BER and best-pilot coded v2 BER have separate denominators and synchronization definitions.",
        results=results,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summaries", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.summaries)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    csv_path = args.output.with_suffix(".csv")
    labels = list(result["results"])
    with csv_path.open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            ["attack"]
            + [f"{label}_correct" for label in labels]
            + [f"{label}_cases" for label in labels]
        )
        names = sorted(
            set().union(*(set(r["attacks"]) for r in result["results"].values()))
            - EXCLUDED
        )
        for name in names:
            writer.writerow(
                [name]
                + [
                    result["results"][label]["attacks"]
                    .get(name, {})
                    .get("positive_correct", 0)
                    for label in labels
                ]
                + [
                    result["results"][label]["attacks"]
                    .get(name, {})
                    .get("positive_cases", 0)
                    for label in labels
                ]
            )
    print(
        json.dumps(
            {
                "images": result["paired_source_images"],
                "recipes": labels,
                "comparison": str(args.output),
            }
        )
    )


if __name__ == "__main__":
    main()

# FVPROV1 10324 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI0MWQ5ZTIzMDVmYzVkMTJkNWI5OTdkZDQ1YTg2YmNiOTQzZDVlYThmZDgzOThjMDU1MmI2NWYzNmQ3YTE0YTUwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL2JlbmNobWFyay1jb21wYXJlLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMTVhZjMxZjM5ZTUwNmYzMGU0OTg5NzNkMDY4NDYyNDFlMWE4MzQzNzE3ZmE1ODBmMjFhNjJlYzMyNzFjNWJjZmUxZmQ4OTIxYjI1ODI0OWQ5NzE2MGIxMWY0NjljZDgzNjMzZGU4NDg4YWY4NjQ0MDgyNTM5MjY5ZTE0MWRkMDUifV19XQ== FVPROV1-END
