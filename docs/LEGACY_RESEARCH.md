<!-- SPDX-License-Identifier: MPL-2.0 -->
# Legacy format research

## Evidence and provenance

The Rust implementation was written independently from observed wire structures
and public research facts. Upstream scripts, binaries, modules and samples are
research inputs and retain their original licensing. They are outside the product
source tree. No downloaded program or kernel module was executed.

The pinned Red Star research commit is
`760ce17a45b7ddf84049e6c477c682cedc995b78`. Its image reader documents 24-byte
DES-ECB records, the public key `0706050403020100`, a little-endian u32 record-byte
count and an `EOF` suffix. The public first-user and second-user JPEGs contain one
and two records. Removing precisely those trailers restores the original JPEG
byte for byte. Its SHA-256 is
`5fa55db03f0cee1209939ace1576a8b42da3855af567fed222e479d5ed50a451`.
[Research repository](https://github.com/takeshixx/redstar-tools/tree/760ce17a45b7ddf84049e6c477c682cedc995b78)

The original `opprc` and `scnprc` ELF `szKey` objects instead contain
`1352070d133a0810`, matching the researchers' 2015 slides. Decoding tries both
published profiles and requires a printable, zero-padded serial before reporting
an identifier. Reports distinguish the sample-tested profile from the statically
extracted binary profile. A separately generated OpenSSL vector tests the latter,
for which an original program-generated output specimen remains unavailable.

The upstream `love.docx` and the pre-existing local specimen are identical. Their
SHA-256 is `ad90dd10a4520ad042878ea72f030795b8e51911ce913e4338b2115b1cd31976`.
Its packet occupies offsets 80 through 110 inclusive, inside the first local ZIP
header's observed `0xa220` / `0xa028` padding wrapper. The central directory has
no corresponding extra field. Cleaning zeroes only the packet, keeps archive
length and member offsets, and preserves all 12 uncompressed members exactly.
The plaintext hash matches an independent OpenSSL DES-ECB decode.
[DOCX specimen](https://github.com/takeshixx/redstar-tools/blob/760ce17a45b7ddf84049e6c477c682cedc995b78/watermarked/love.docx)

## Woolim scope

The published SELFSIGN layout comprises a 256-byte RSA block, a 520-byte encrypted
identity block, a u32 total length of 792, four zero bytes and an eight-byte
suffix. The implementation checks that geometry and the independently parsed
base container boundary. RSA authenticity and encrypted identity decoding remain
`not_assessed`. An original device-generated specimen was unavailable. The
encrypted identity is represented by its hash.
[Authors' article](https://insinuator.net/2016/12/woolim-lifting-the-fog-on-dprks-latest-tablet-pc/),
[Authors' Android appendix, pages 7–8](https://www.nktechlab.org/wp-content/uploads/2025/05/2022-Reveal-Android-Code-Section-ENG.pdf)

Pyongyang 2407 uses a distinct NATISIGN ABI. Restoring the researchers' three
documented patched instructions yields SHA-256
`5ce3bbd3c0c16b7e3c1b70f7dd5d0e278a3cabe4f5c248ec7f61be893306894a`,
matching the original-library hash in Project Reveal's Android appendix. Static
Thumb analysis establishes a total-length u32 at EOF minus 12, an eight-byte
suffix, a variable packet length capped at 320, a 48-byte scrambled metadata
prefix, a four-byte selector and RSA input beginning at packet offset 52.
The reader independently implements the public bit obfuscation transform and
checks its zero schema marker, declared base length and encoded-format extension.
An independently written inverse encoder and Python vector validate that transform.
[Researchers' published library and original instruction listing](https://github.com/hackerhouse-opensource/pyongyang_2407/tree/3ec5b7a2f252b83fae459cafc2555cc4e3139c3e),
[Published original-library hashes, page 13](https://www.nktechlab.org/wp-content/uploads/2025/05/2022-Reveal-Android-Code-Section-ENG.pdf)

Explicit cleaning supports the 320-byte form only when every known metadata check
passes and its start equals the independently parsed encoded-content end. The
result is `partially_verified`, with exact retained-byte verification. RSA/NV-key
validation, pattern policy, original signed specimens and Woolim ABI equivalence
remain unassessed. Other lengths are decoded structurally and protected. The
earlier 272-byte plus reserved-padding hypothesis is now explicitly deprecated,
reported as `deprecated_candidate_unverified` and protected from cleaning.
Synthetic nested trailers test bounds without asserting historical deployment.

## Validation and boundaries

The focused Rust suite has 18 passing tests when pinned samples are available.
Default CI runs 17 synthetic/control tests and leaves the external specimen test
explicitly ignored. OpenSSL, Python `zipfile`, `python-docx` and Pillow independently
check decode hashes, archive content, visible text/styles and image pixels.

Supported cleaning scope is JPEG/PNG trailers and the observed DOCX local padding.
Unrecognized prefixes, malformed lengths and invalid padding fail closed. An
unknown-key packet retains structural detection and an unresolved identity.
Cleaning can remove its bounded structure while preserving the validated base.
Limits bound file bytes, metadata, records and 32 layers.
Reports withhold serial values unless disclosure is explicitly selected. Legacy
serials and public markers are forgeable and do not authenticate identity.

The pinned upstream repository also supplies `opprc`, `scnprc` and `rtscan.ko`.
All three were obtained for static inspection. They are ELF32/i386 objects.
`llvm-readelf` exposes DES ECB routines and watermark-related symbols in the two
programs, and extension-control symbols in the kernel module. These observations
establish that original artifacts were inspected. They provide no runtime
acceptance, hardware observation or additional crypto-authenticity claim. Exact
hashes and tool outputs are retained in the local static-analysis receipt.

Local reproducibility evidence is under `work/v04-research`. The source manifest
records URLs, pinned commits, byte counts and SHA-256 hashes. The interoperability
receipt records original and output hashes. Research material is excluded from
release source archives by the existing ignored-work-directory boundary.
