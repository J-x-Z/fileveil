<!-- SPDX-License-Identifier: MPL-2.0 -->
# Source provenance

The Alpha source distribution carries FileVeil Ed25519 signatures. Project-owned Rust, Python, Swift, TOML and workflow sources contain a terminal ASCII comment with a signed content hash, file work identifier and release copy identifier. The source catalog covers the distributed files, including dependencies' license texts and fixtures under their existing licenses.

## Verify a distribution

Python 3.11 or newer and OpenSSL 3 are required for the independent verifier.

```sh
python3 tools/verify-source-tree.py . \
  --key-id 99ea63efccfd0fdbd68e16ed8f03d337f15ec2e4a6a3d64e11d714ea1e542533
```

The public key is in `provenance/release-key.json`. Compare the fingerprint with the publisher's release record before using it as a trust anchor. The verifier checks the signed TOML catalog, its evidence package, listed file bytes, additional files and per-source signatures. A changed file fails verification.

The Alpha uses the asserted date `2026-11-14`. The signatures carry that declaration. Trusted external timestamp evidence can be supplied through FileVeil's RFC 3161 workflow.

## Verify or clean one source file

```sh
fileveil verify crates/fileveil-core/src/lib.rs --json
fileveil trace crates/fileveil-core/src/lib.rs --json
fileveil clean crates/fileveil-core/src/lib.rs -o lib.clean.rs --json
```

Clean writes a new copy and restores the exact source bytes that preceded the provenance comment. Ordinary source comments, strings, SPDX identifiers and executable text are preserved. The marked files remain valid source input. The signed catalog binds the bytes distributed in the release.

## Prepare a source release

The publisher keeps the signing key in a local owner-only file outside the tracked source tree. `release-key.json` contains its public key and identifier. FileVeil also supports explicit system key references.

```sh
python3 tools/mark-source-tree.py \
  --executable target/release/fileveil \
  --key /path/to/private/release-signing.key \
  --release v0.5.0-alpha.1 --created-at 2026-11-14
```

Add `--apply` to stage signatures, verify them, test byte-exact Clean roundtrips and update the project files. The tool also writes `provenance/source-catalog.toml` and `provenance/source-catalog.evidence.json`. Commit the verified tree before tagging a release. Editing published source requires a new signed distribution.

The project uses MPL-2.0. Third-party code, license assets, fonts and test fixtures retain their own applicable license and attribution records. Their hashes in the catalog provide distribution integrity.

## Public history

Public commits use the publisher's GitHub noreply identity. `provenance/history-map.json` maps development revision identifiers to the public revisions with the same trees, commit messages and dates. Historical benchmark receipts keep their original identifiers and byte hashes. The Alpha tag and its workflow identify the published distribution.
