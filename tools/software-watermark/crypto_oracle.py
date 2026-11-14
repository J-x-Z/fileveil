#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Independent Ed25519/ChaCha20-Poly1305 software-packet verifier.

Requires the Python cryptography package. Container extraction uses oracle.py,
which shares no parsing or cryptographic code with the Rust implementation.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import oracle


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def derive(seed, label):
    intermediate = hmac.digest(b"FileVeil software HKDF salt v1", seed, "sha256")
    return hmac.digest(intermediate, label + b"\x01", "sha256")


def inspect_packet(packet, key_path=None):
    if not 0 < len(packet) <= 32768:
        raise ValueError("packet budget exceeded")
    envelope = json.loads(packet, object_pairs_hook=strict_object)
    if set(envelope) != {"body", "signature"}:
        raise ValueError("invalid packet envelope")
    body, signature = envelope["body"], envelope["signature"]
    if body["schema"] != "fileveil.software.packet.v1" or body["encryption"] != "ChaCha20Poly1305-RFC8439":
        raise ValueError("unsupported packet identity")
    public = bytes.fromhex(signature["public_key_hex"])
    if hashlib.sha256(public).hexdigest() != signature["key_id"]:
        raise ValueError("public key identity mismatch")
    Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(signature["signature_hex"]),
        b"FileVeil software packet signature v1\0" + canonical(body))
    result = {"signature": "valid", "trust": "not_assessed", "decoded": False,
              "packet_sha256": hashlib.sha256(packet).hexdigest(), "key_id": signature["key_id"],
              "input_sha256": body["input_sha256"], "ir_sha256": body["canonical_ir_sha256"]}
    if key_path is None:
        return result
    if not key_path.is_file() or key_path.stat().st_size > 16384:
        raise ValueError("private key exceeds its input budget")
    key_bytes = key_path.read_bytes()
    magic = b"FILEVEIL-ED25519-KEY-V1\n"
    if not key_bytes.startswith(magic) or len(key_bytes) != len(magic) + 32:
        raise ValueError("unsupported private key")
    seed = key_bytes[len(magic):]
    supplied = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if supplied != public:
        result["decryption"] = "key_mismatch"
        return result
    nonce = bytes.fromhex(body["nonce_hex"])
    material = derive(seed, b"software ChaCha20Poly1305 v1\0")
    plaintext = ChaCha20Poly1305(material).decrypt(nonce, bytes.fromhex(body["ciphertext_hex"]),
        b"FileVeil software encrypted claims v1\0")
    claims = json.loads(plaintext, object_pairs_hook=strict_object)
    witness = int.from_bytes(hmac.digest(derive(seed, b"software witness v1\0"), canonical(claims), "sha256")[:8], "little")
    if f"{witness:016x}" != body["witness_hex"]:
        raise ValueError("authenticated witness mismatch")
    challenge = int.from_bytes(hmac.digest(derive(seed, b"software challenge v1\0"), nonce, "sha256")[:8], "little")
    result.update(decoded=True, decryption="valid", witness_hex=f"{witness:016x}",
                  challenge_hex=f"{challenge:016x}", work_id_digest=hashlib.sha256(claims["work_id"].encode()).hexdigest(),
                  copy_id_digest=hashlib.sha256(claims["copy_id"].encode()).hexdigest())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--packet", action="store_true", help="Input is an extracted packet JSON")
    args = parser.parse_args()
    if args.packet:
        if args.artifact.stat().st_size > 32768:
            raise ValueError("packet exceeds its input budget")
        packet = args.artifact.read_bytes()
    else:
        result = oracle.inspect(args.artifact)
        if not result["carrier_present"]:
            raise ValueError("no carrier found")
        packet = bytes.fromhex(result["packet_hex"])
    print(json.dumps(inspect_packet(packet, args.key), sort_keys=True))


if __name__ == "__main__":
    main()
