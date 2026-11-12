<!-- SPDX-License-Identifier: MPL-2.0 -->
# Provenance 2.0

## Signed events

`fileveil.heritage.signature.v1` retains its original canonical bytes and domain. New v2 statements use `fileveil.provenance.signature.v2`, a signed `copy_id`, and separate signature and finalized-record domains. Optional v2 fields are absent from serialized v1 records.

The signature message is the UTF-8 domain, including its final NUL byte, followed by canonical typed JSON. Properties use sorted ASCII names, strings preserve UTF-8 without normalization, arrays retain order, and integers are exact nonnegative I-JSON values. Unknown or duplicate properties are rejected. A finalized record hash sorts its signatures by key ID before canonicalization. Each predecessor digest binds all finalized predecessor signatures.

| Object | Domain |
| --- | --- |
| v1 statement | `FileVeil Heritage signature v1\0` |
| v1 finalized record | `FileVeil Heritage finalized record v1\0` |
| v2 statement | `FileVeil provenance signature v2\0` |
| v2 finalized record | `FileVeil provenance finalized record v2\0` |
| External checkpoint | `FileVeil external chain checkpoint v1\0` |
| Copyright evidence | `FileVeil copyright evidence package v1\0` |
| Transfer proposal | `FileVeil transfer proposal v1\0` |

Ed25519 key IDs are lowercase SHA-256 of the 32-byte public key. V2 transfer events require valid signatures from the current custodian and designated recipient. Key rotation similarly requires current and successor key signatures. Later events must use the successor custodian. Local issuer trust remains an explicit verifier policy. Historical signatures and rotated keys remain visible in the supplied signed sequence.

A `modify` event changes the version and binds its parent version. An optional transformation records the preceding content hash, source format, target format and operation label. V2 copy IDs remain stable across modifications and transfers. An `issue` event can identify a separately issued copy.

## Two-device handoff

The sender prepares `fileveil.provenance.transfer_proposal.v1` using their own private key. It contains the existing signed history, a sender-signed pending transfer and the current asset declaration. A second sender signature covers this complete proposal.

The recipient imports that JSON on their device, selects their own key and can supply the received asset for independent hash and size verification. Acceptance checks the proposal signature, complete prior history, designated recipient, predecessor hash, work and copy IDs, version and content binding. The recipient co-signs the pending event, then signs the resulting portable evidence package as the new current custodian. A mismatched recipient or supplied asset fails safely. Asset receipt without an explicit local reference retains an unassessed byte-verification scope.

The resulting evidence package can supply the previous history for a later modified or converted asset. Previously signed events keep their original signatures.

## Independent checkpoints and evidence

A checkpoint binds a specific record sequence, finalized record hash, content hash, work/copy identifiers and an asserted time. An independently retained trusted checkpoint detects a supplied history that omits or replaces that sequence. Verification reports signature, locally configured witness trust and history binding separately. Global history completeness requires independently obtained checkpoints and prior assets.

`fileveil.provenance.evidence.v1` contains signed events, asset hash/size/type declarations, optional checkpoints, optional RFC 3161 responses and a current-custodian envelope signature. Authors and work identifiers are intentionally present in an explicitly exported evidence file. Ordinary reports retain hashes and verification summaries.

The standalone verifier uses Python and OpenSSL, without the Rust parser or private keys. It can independently unwrap JPEG, PNG, PDF, Office and terminal ISO-media FileVeil carriers before checking an explicitly provided asset.

```sh
python3 tools/verify-evidence.py evidence.json --asset received.png \
  --checkpoint-key LOWERCASE_ED25519_PUBLIC_KEY_HEX --tsa-roots tsa-roots.pem
```

The verifier checks public signatures, predecessor/custody rules, signed asset declarations, explicitly provided asset bytes and trusted checkpoint keys. TSA verification applies when explicit roots are supplied. Identity claims, unprovided historical assets and broader issuer trust retain their separately reported scopes.

## System key storage

File-backed owner-only keys remain supported. Explicit system storage uses macOS Security.framework generic-password records, Windows current-user Credential Manager generic credentials, or Linux Secret Service through `secret-tool`. Secret bytes pass through native calls or bounded standard input. Private bytes are excluded from command arguments, reports and diagnostics. References contain public key IDs.

The platform service controls storage encryption, access prompts and login-session availability. A missing or locked service reports its actual failure. Operations address a single explicitly selected FileVeil key ID. Importing a file key creates a separate system-managed credential, while the original file remains user-owned private-key material.

The watermark key is HKDF-SHA-256 of the signing seed with fixed, versioned FileVeil salt and info strings. Its extraction and expansion use HMAC-SHA-256. The derived watermark key has its own purpose and remains in zeroizing buffers.

## RFC 3161

Timestamp requests carry a SHA-256 imprint of a finalized signed record and an OpenSSL-generated nonce. The exported request contains the digest and protocol fields. Network submission requires a separate, explicitly authorized workflow.

Response verification uses a bounded local OpenSSL backend, explicit PEM trust roots, the expected SHA-256 imprint and the original query nonce when supplied. Certificate validity is evaluated at generation time extracted from the CMS-signed TSTInfo. Unsigned status text does not determine that time. The report marks the generation time as asserted until cryptographic verification succeeds. Default system trust stores and online revocation queries are outside this operation.

With no original query, a generated nonce-free SHA-256 reference query enforces the declared digest algorithm and imprint. A timestamp without explicit trust roots remains unassessed. The local interoperability test creates a temporary ES256 TSA and rejects wrong roots, wrong imprints, wrong nonces and changed responses.

[Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161), [OpenSSL timestamp command](https://docs.openssl.org/3.0/man1/openssl-ts/), [OpenSSL explicit timestamp certificate-store construction](https://github.com/openssl/openssl/blob/openssl-3.6.0/apps/ts.c), [Windows current-user credential semantics](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew)
