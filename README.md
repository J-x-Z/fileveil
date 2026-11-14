<!-- SPDX-License-Identifier: MPL-2.0 -->
# FileVeil

[English](README.md) | [简体中文](README.zh-CN.md)

**Clean metadata. Mark ownership. Verify provenance. Test watermarks.**

[![CI](https://github.com/J-x-Z/fileveil/actions/workflows/ci.yml/badge.svg)](https://github.com/J-x-Z/fileveil/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)
![Status: Public Alpha](https://img.shields.io/badge/status-public%20alpha-orange)

FileVeil is an **offline-first, cross-platform file privacy and watermark toolkit** written in Rust. It helps you inspect hidden metadata, create verified sanitized copies, embed your own signed provenance records, and study how image watermarks survive editing or removal.

**Windows · macOS · Linux | Native desktop GUI · CLI · local MCP**

**English · 简体中文 · 日本語 · 한국어 · Español · Français · Deutsch · Português · Русский**

Select the interface language in Settings. Technical report values and unrecognized backend messages may be shown in English.

> **Alpha notice:** FileVeil is experimental. Its verification results apply to explicitly reported checks, not to every possible hidden watermark or identifying feature. Keep your originals and review outputs before sharing important files.

## What you can do

| Workflow | Capabilities |
| --- | --- |
| **Clean** | Inspect and remove supported EXIF/XMP, document properties, selected editing history, file-system metadata, and known watermark carriers. Generate new copies and verify the changes. |
| **Mark** | Add versioned, optionally invisible image watermarks, signed file records, and work/copy identifiers. |
| **Verify** | Check supported watermark signals, Ed25519 signatures, content binding, C2PA credentials, and independently verifiable evidence. |
| **Trace** | Build signed version and custody records, including key rotation, countersigned transfers, and external checkpoints. |
| **Lab** | Compare images, visualize signal differences, and benchmark watermark resilience against JPEG/AVIF/WebP recompression, cropping, rotation, resizing, noise, and other transforms. |

File processing runs locally by default, without an account or telemetry. FileVeil preserves the original input and writes sanitized or marked copies to new paths. The GUI, CLI, and MCP interfaces share the Rust processing core.

### File support at a glance

- **Images:** JPEG, PNG; HEIC/HEIF and AVIF metadata rewriting, with optional compatible local pixel codecs.
- **Documents:** PDF (qpdf backend), DOCX, XLSX, PPTX; selected TXT, Markdown, and HTML cleanup.
- **Media:** MP4/MOV container metadata; WAV/FLAC metadata; limited read-only MP3 auditing.
- **Provenance:** Offline C2PA verification on supported formats, and C2PA creation for JPEG, PNG, and PDF with user-provided signing credentials.
- **Watermarks:** FileVeil v1/v2, supported public Stable Diffusion 1/SDXL signatures, and selected legacy file markers.

Some formats support inspection but not every kind of cleanup. See the [format-by-format support matrix](docs/FORMAT_SUPPORT.md).

## Download and run

Download the [v0.5.0-alpha.3 Alpha packages](https://github.com/J-x-Z/fileveil/releases/tag/v0.5.0-alpha.3) for Windows, macOS, and Linux.

- **macOS Apple Silicon** — `.dmg` with drag-to-Applications installation, or `.zip`.
- **Windows x64** — `.exe` installer or portable `.zip`.
- **Linux x64** — `.deb` package or `.tar.gz`.

The macOS build uses an ad-hoc signature and is rejected by Gatekeeper. Windows packages are unsigned and may show an unknown-publisher warning. Public-distribution signing certificates are currently unavailable. Building from source is also supported.

**Build requirements:** Rust **1.96+** and Cargo. PDF rewriting uses **qpdf**; independent PDF visual/text checks use optional Poppler tools. Some HEIC/AVIF and media features depend on locally installed codecs or FFmpeg. FileVeil reports unavailable optional backends instead of silently claiming support.

```bash
git clone https://github.com/J-x-Z/fileveil.git
cd fileveil
cargo build --locked --release -p fileveil-gui -p fileveil-cli

# Desktop application
./target/release/fileveil-gui

# Inspect supported features on your system
./target/release/fileveil capabilities --json
```

On Windows, launch the corresponding `.exe` files from `target\release\`. See the [GUI guide](docs/GUI.md) for packaging and desktop workflows.

## Quick start

**Scan and clean a file:**

```bash
./target/release/fileveil scan photo.jpg --json
./target/release/fileveil sanitize photo.jpg --profile safe --output photo.clean.jpg --json
./target/release/fileveil verify photo.jpg photo.clean.jpg --json
```

**Sign and watermark an image:**

```bash
./target/release/fileveil heritage-keygen --output owner.key --json
./target/release/fileveil mark photo.png --output photo.marked.png \
  --key owner.key --work-id demo-work --copy-id demo-copy \
  --created-at 2026-11-13T00:00:00Z --pixel --json
./target/release/fileveil verify photo.marked.png --watermark-key owner.key --json
./target/release/fileveil clean photo.marked.png --output photo.clean.png \
  --pixel --watermark-key owner.key --json
```

The CLI also offers `trace`, `lab`, `provenance`, and evidence export/verification. Signing and watermark verification are separate: a recovered work identifier does not, by itself, establish legal copyright ownership.

## Watermark Engine 2.0: measured results

We compared v0.4 and v0.5 on **200 real images** from four content categories, using **40 fixed operations per image** (8,000 recovery trials per configuration):

| Configuration | Correct work/copy recovery | Mean embedded-image SSIM |
| --- | ---: | ---: |
| v0.4 | **77.74%** | 0.9290 |
| v0.5 · Quality 12 (default) | **89.09%** | 0.9704 |
| v0.5 · Robust 20 | **95.90%** | 0.9512 |

The benchmark includes lossless controls as well as difficult transformations; performance differs substantially by operation. Higher resilience may cost more visual quality and compute time. These are **results from a fixed test corpus**, not a universal detection or removal guarantee. Read the [full methodology and per-operation data](docs/WATERMARK_BENCHMARK.md).

## Privacy, limitations, and security

- **Offline by default:** no required cloud account, telemetry, or upload of selected files.
- **Originals are kept:** transformations create new files and perform format-appropriate verification.
- **Scope-aware reporting:** `verified_within_scope`, `partially_verified`, and `not_assessed` distinguish what was actually checked.
- **Not a universal watermark detector:** proprietary OEM/AI keyed watermarks, complete video watermark removal, some protected document structures, and rare media variants remain outside current coverage.
- **Signature and provenance boundaries:** cryptographic validity, asset binding, issuer trust, and copyright ownership are different questions.

Read the [security model](docs/SECURITY.md), [threat model](docs/THREAT_MODEL.md), and [validation log](docs/VALIDATION.md) for details. Please report security-sensitive findings privately rather than attaching confidential documents to public issues.

## Research and compatibility

FileVeil combines original watermark research with compatibility work on publicly documented formats, including historic file-tracking mechanisms studied in Red Star OS and related devices. The legacy readers are independently implemented in Rust; historical binary samples are **not** distributed as part of the application. See [research notes](docs/LEGACY_RESEARCH.md) and [protocol details](docs/HERITAGE_RESEARCH.md).

## Contributing

FileVeil welcomes reproducible bug reports, compatibility findings, benchmark datasets, translations, and focused pull requests. Open an [issue](https://github.com/J-x-Z/fileveil/issues) with your OS, FileVeil version, file format, expected behavior, and a minimal non-sensitive sample or redacted report. Confirm the relevant behavior before opening a PR; more community guidance will follow as the alpha develops.

## License

FileVeil's own source code is licensed under the **[Mozilla Public License 2.0](LICENSE)**. Dependencies, fonts, tools, and research samples retain their respective licenses; see [third-party notices](THIRD_PARTY_NOTICES.txt).
