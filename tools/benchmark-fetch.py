#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Fetch or replay a small, attributed public-image watermark benchmark corpus."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import html
import json
from pathlib import Path
import re
import ssl
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
AGENT = "FileVeilBenchmark/0.5 (image robustness research; https://github.com/J-x-Z/fileveil)"
API = "https://commons.wikimedia.org/w/api.php"
QUERIES = {
    "photograph": [
        f"intitle:{term} filetype:bitmap -painting -drawing -map -screenshot"
        for term in (
            "forest",
            "flower",
            "street",
            "bird",
            "food",
            "night",
            "building",
            "beach",
            "mountain",
            "animal",
            "car",
            "waterfall",
        )
    ],
    "screenshot": [
        f"intitle:{term} filetype:bitmap screenshot"
        for term in (
            "GNOME",
            "KDE",
            "Firefox",
            "LibreOffice",
            "Blender",
            "GIMP",
            "Inkscape",
            "Debian",
            "Ubuntu",
            "Xfce",
        )
    ],
    "illustration": [
        f"intitle:{term} filetype:bitmap -screenshot"
        for term in (
            "illustration",
            "woodcut",
            "watercolor",
            "lithograph",
            "engraving",
            "painting",
            "drawing",
        )
    ],
    "text": [
        f"intitle:{term} filetype:bitmap {extra}"
        for term, extra in (
            ("page", "book"),
            ("manuscript", ""),
            ("newspaper", ""),
            ("letter", "manuscript"),
            ("poster", "text"),
            ("receipt", ""),
            ("book", "text"),
        )
    ],
}
COUNTS = {"photograph": 80, "screenshot": 40, "illustration": 40, "text": 40}


def context():
    system = Path("/etc/ssl/cert.pem")
    return ssl.create_default_context(cafile=str(system) if system.exists() else None)


def fetch(url, maximum=4 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(
                request, timeout=45, context=context()
            ) as response:
                data = response.read(maximum + 1)
            if len(data) > maximum:
                raise ValueError("Image exceeds bounded download size")
            return data
        except (OSError, TimeoutError):
            if attempt == 3:
                raise
            time.sleep(2**attempt)


def query(search, offset):
    params = dict(
        action="query",
        format="json",
        generator="search",
        gsrsearch=search,
        gsrnamespace=6,
        gsrlimit=10,
        gsroffset=offset,
        prop="imageinfo",
        iiprop="url|size|mime|extmetadata",
        iiurlwidth=1024,
        iiurlheight=1024,
        iiextmetadatafilter="LicenseShortName|LicenseUrl|Artist|AttributionRequired",
    )
    result = json.loads(fetch(API + "?" + urllib.parse.urlencode(params)))
    return sorted(
        result.get("query", {}).get("pages", {}).values(),
        key=lambda page: page.get("index", 0),
    )


def plain(value):
    return html.unescape(re.sub("<[^>]+>", "", value)).strip()


def candidate(page, group, search):
    infos = page.get("imageinfo", [])
    if not infos:
        return None
    info = infos[0]
    metadata = info.get("extmetadata", {})
    license_name = metadata.get("LicenseShortName", {}).get("value", "")
    if license_name not in (
        "Public domain",
        "CC0",
        "CC0 1.0",
        "CC BY 2.0",
        "CC BY 2.5",
        "CC BY 3.0",
        "CC BY 4.0",
        "CC BY-SA 2.0",
        "CC BY-SA 2.5",
        "CC BY-SA 3.0",
        "CC BY-SA 4.0",
    ):
        return None
    width, height = info.get("width", 0), info.get("height", 0)
    if min(width, height) < 512 or max(width, height) / min(width, height) > 2:
        return None
    if info.get("mime") not in ("image/jpeg", "image/png", "image/webp"):
        return None
    original = info["size"] <= 1_200_000 and max(width, height) <= 2048
    url = info["url"] if original else info.get("thumburl")
    if not url:
        return None
    return dict(
        page_id=page["pageid"],
        title=page["title"],
        stratum=group,
        selection_query=search,
        description_url=info["descriptionurl"],
        original_url=info["url"],
        original_dimensions=[width, height],
        original_bytes=info["size"],
        download_url=url,
        source_variant="original" if original else "upstream_bounded_thumbnail",
        license=plain(license_name),
        license_url=metadata.get("LicenseUrl", {}).get(
            "value", "https://commons.wikimedia.org/wiki/Help:Public_domain"
        ),
        attribution=plain(metadata.get("Artist", {}).get("value", "")),
    )


def acquire(item, folder):
    from PIL import Image
    import io

    data = fetch(item["download_url"])
    image = Image.open(io.BytesIO(data))
    if max(image.size) > 4096 or image.width * image.height > 12_000_000:
        raise ValueError("Decoded source exceeds bounded dimensions")
    image.load()
    if min(image.size) < 512 or max(image.size) / min(image.size) > 2:
        raise ValueError(
            "Delivered thumbnail dimensions do not meet the declared comparison scope"
        )
    rgb = image.convert("RGB")
    small = rgb.resize((32, 32), Image.Resampling.LANCZOS).convert("L")
    values = list(small.resize((9, 8), Image.Resampling.LANCZOS).getdata())
    perceptual = sum(
        (values[y * 9 + x] > values[y * 9 + x + 1]) << (y * 8 + x)
        for y in range(8)
        for x in range(8)
    )
    sha = hashlib.sha256(data).hexdigest()
    suffix = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}.get(
        image.format, ".image"
    )
    path = folder / (str(item["page_id"]) + suffix)
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != sha:
        raise RuntimeError("Existing source conflicts with fetched bytes")
    if not path.exists():
        with path.open("xb") as stream:
            stream.write(data)
    return {
        **item,
        "path": str(path.relative_to(folder.parent)),
        "sha256": sha,
        "bytes": len(data),
        "downloaded_dimensions": list(image.size),
        "dhash64": f"{perceptual:016x}",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "work/v05-benchmark")
    parser.add_argument(
        "--replay",
        type=Path,
        help="Replay an immutable source manifest, validating each SHA-256",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    images = args.output / "sources"
    images.mkdir(exist_ok=True)
    manifest_path = args.output / "manifest.json"
    if args.replay:
        manifest = json.loads(args.replay.read_text())
        for item in manifest["images"]:
            path = args.output / item["path"]
            if (
                path.is_file()
                and hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
            ):
                continue
            fetched = acquire(item, images)
            if fetched["sha256"] != item["sha256"]:
                raise RuntimeError("Remote bytes changed since pinned corpus creation")
        content = args.replay.read_bytes()
        if manifest_path.exists() and manifest_path.read_bytes() != content:
            raise RuntimeError(
                "Output contains a different corpus manifest; choose a fresh output directory"
            )
        manifest_path.write_bytes(content)
        print(
            json.dumps(
                {
                    "verified_images": len(manifest["images"]),
                    "manifest_sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        )
        return
    selected = (
        json.loads(manifest_path.read_text()).get("images", [])
        if manifest_path.exists()
        else []
    )
    seen = {item["page_id"] for item in selected}
    hashes = {item["sha256"] for item in selected}
    rejected = []
    for group, expected in COUNTS.items():
        current = sum(
            item.get("selection_stratum", item["stratum"]) == group for item in selected
        )
        for offset in (0, 10, 20):
            if current >= expected:
                break
            for search in QUERIES[group]:
                if current >= expected:
                    break
                candidates = [
                    candidate(page, group, search) for page in query(search, offset)
                ]
                candidates = [
                    item
                    for item in candidates
                    if item is not None and item["page_id"] not in seen
                ]
                with ThreadPoolExecutor(max_workers=3) as pool:
                    futures = {
                        pool.submit(acquire, item, images): item
                        for item in candidates[: expected - current]
                    }
                    for future in as_completed(futures):
                        item = futures[future]
                        seen.add(item["page_id"])
                        try:
                            record = future.result()
                            phash = int(record["dhash64"], 16)
                            duplicate = any(
                                (phash ^ int(old["dhash64"], 16)).bit_count() <= 3
                                for old in selected
                            )
                            if record["sha256"] in hashes or duplicate:
                                rejected.append(
                                    {
                                        "page_id": item["page_id"],
                                        "reason": "duplicate_content",
                                    }
                                )
                                continue
                            selected.append(record)
                            hashes.add(record["sha256"])
                            current += 1
                        except Exception as error:
                            rejected.append(
                                {
                                    "page_id": item["page_id"],
                                    "reason": type(error).__name__,
                                }
                            )
                manifest = dict(
                    schema="fileveil.watermark.benchmark.corpus.v1",
                    source="Wikimedia Commons",
                    image_count=len(selected),
                    images=selected,
                    rejected=rejected,
                    scope="200 distinct public images with source/license/byte hashes. Upstream bounded thumbnails are explicitly distinguished from originals. No synthetic variants count toward corpus size.",
                )
                manifest_path.write_text(
                    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
                )
                print(
                    json.dumps(
                        {
                            "stratum": group,
                            "selected": current,
                            "expected": expected,
                            "total": len(selected),
                        }
                    ),
                    flush=True,
                )
                if sum(item["bytes"] for item in selected) > 300 * 1024 * 1024:
                    raise RuntimeError("Declared source download budget exceeded")
                time.sleep(0.5)
        if current < expected:
            raise RuntimeError(
                f"Insufficient distinct licensed images in {group}: {current}/{expected}"
            )
    print(
        json.dumps(
            {
                "images": len(selected),
                "bytes": sum(item["bytes"] for item in selected),
                "manifest": str(manifest_path),
            }
        )
    )


if __name__ == "__main__":
    main()

# FVPROV1 12451 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJmZDIxMTZkMzIzYTZiZTYzMWQ4MmE3OTU1NmE3NTY5ZTY4NWIzODlhYTFiNWIwMzM5MTUzMDViOTVlM2Q1ZmYzIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL2JlbmNobWFyay1mZXRjaC5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjUxZDgzNDZjNzYyOTI4NWVlN2JhZGVhZWI3NjI1ZGQ2NWRhZTI1NDJmYWMzNDFhYzlkZjg5MmYwY2U4NThlYjUxN2ZkYmM4ZTk4NWU1NzQyZTAzOTExMmQ2NzVhZmRmNGQ4NWViYzc2MWVkZWI3ZTZiZDY5MTY5YjMyZTY0ZjBmIn1dfV0= FVPROV1-END
