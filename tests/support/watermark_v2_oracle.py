#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Independent OpenCV V2 protocol oracle for explicit developer tests.

The error decoder uses a complete weight<=3 syndrome table, independently of
Rust's Berlekamp-Massey/Chien implementation. It verifies the 96-bit HMAC with
Python's standard hmac module. CLI uses a fixed PUBLIC test key, never real keys.
Only native-size, quarter-turn and pixel/tile phase searches are included.
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import itertools
import json
from pathlib import Path
import struct
import cv2
import numpy as np
from PIL import Image
TEST_KEY = bytes(range(32))
DOMAIN = b'FileVeil watermark frame v2\x00'
MAGIC = b'FVW2'
CODE_BITS = 441

def layout(key):

    def words():
        for counter in itertools.count():
            yield from struct.unpack('>8I', hashlib.sha256(b'FileVeil keyed carrier layout v2\x00' + key + struct.pack('>Q', counter)).digest())
    random = words()
    permutation = list(range(512))
    for i in range(511, 0, -1):
        j = next(random) % (i + 1)
        permutation[i], permutation[j] = (permutation[j], permutation[i])
    signs = np.array([next(random) & 1 for _ in range(512)], np.uint8)
    pilots = np.array([next(random) & 1 for _ in range(512)], np.uint8)
    return (np.array(permutation), signs, pilots)

class BCH:

    def __init__(self):
        self.exp = []
        self.log = [0] * 64
        x = 1
        for i in range(63):
            self.exp.append(x)
            self.log[x] = i
            x <<= 1
            if x & 64:
                x ^= 67
        self.exp *= 2
        roots = set()
        for start in range(1, 7):
            x = start
            while x not in roots:
                roots.add(x)
                x = x * 2 % 63
        polynomial = [1]
        for root in sorted(roots):
            result = [0] * (len(polynomial) + 1)
            for i, c in enumerate(polynomial):
                result[i] ^= self.mul(c, self.exp[root])
                result[i + 1] ^= c
            polynomial = result
        assert len(polynomial) == 19 and set(polynomial) <= {0, 1}
        self.generator = sum((c << i for i, c in enumerate(polynomial)))
        self.single = [self.syndrome(1 << i) for i in range(63)]
        self.errors = {0: 0}
        for n in (1, 2, 3):
            for bits in itertools.combinations(range(63), n):
                syndrome = 0
                mask = 0
                for bit in bits:
                    syndrome ^= self.single[bit]
                    mask ^= 1 << bit
                assert syndrome not in self.errors
                self.errors[syndrome] = mask

    def mul(self, a, b):
        return self.exp[self.log[a] + self.log[b]] if a and b else 0

    def syndrome(self, word):
        result = 0
        for s in range(1, 7):
            value = 0
            for bit in range(63):
                if word >> bit & 1:
                    value ^= self.exp[s * bit % 63]
            result |= value << (s - 1) * 6
        return result

    def encode(self, message):
        word = message << 18
        remainder = word
        for bit in range(62, 17, -1):
            if remainder >> bit & 1:
                remainder ^= self.generator << bit - 18
        return word | remainder

    def decode(self, word):
        error = self.errors.get(self.syndrome(word))
        return None if error is None else ((word ^ error) >> 18, error.bit_count())

def frame(work, copy, key):
    prefix = MAGIC + hashlib.sha256(work.encode()).digest()[:12] + hashlib.sha256(copy.encode()).digest()[:8]
    return prefix + hmac.new(key, DOMAIN + prefix, hashlib.sha256).digest()[:12]

def encode_bits(work, copy, key, bch):
    payload = np.unpackbits(np.frombuffer(frame(work, copy, key), np.uint8))
    padded = np.pad(payload, (0, 315 - len(payload)))
    output = []
    for chunk in padded.reshape(7, 45):
        message = int(''.join(map(str, chunk.tolist())), 2)
        output.extend((int(x) for x in f'{bch.encode(message):063b}'))
    return np.array(output, np.uint8)

def decode_bits(bits, key, bch):
    messages = []
    corrections = 0
    for wordbits in bits.reshape(7, 63):
        word = int(''.join(map(str, wordbits.tolist())), 2)
        decoded = bch.decode(word)
        if decoded is None:
            return None
        message, n = decoded
        corrections += n
        messages.extend((int(x) for x in f'{message:045b}'))
    if any(messages[288:]):
        return None
    raw = np.packbits(messages[:288]).tobytes()
    if raw[:4] != MAGIC or not hmac.compare_digest(raw[24:], hmac.new(key, DOMAIN + raw[:24], hashlib.sha256).digest()[:12]):
        return None
    return {'work_id_digest': raw[4:16].hex(), 'copy_id_digest': raw[16:24].hex(), 'corrected_bits': corrections}

def detect(image, key=TEST_KEY, bch=None):
    bch = bch or BCH()
    permutation, signs, pilots = layout(key)
    rgb = np.asarray(image.convert('RGB'), np.float32)
    for rotation in range(4):
        oriented = np.rot90(rgb, -rotation)
        gray = oriented @ np.array([0.299, 0.587, 0.114], np.float32)
        for py in range(8):
            for px in range(8):
                h = (gray.shape[0] - py) // 8
                w = (gray.shape[1] - px) // 8
                if min(h, w) < 16:
                    continue
                votes = np.zeros((2, 16, 16), np.float64)
                for by in range(h):
                    for bx in range(w):
                        dct = cv2.dct(gray[py + by * 8:py + by * 8 + 8, px + bx * 8:px + bx * 8 + 8])
                        votes[0, by % 16, bx % 16] += np.clip(dct[2, 1] - dct[1, 2], -64, 64)
                        votes[1, by % 16, bx % 16] += np.clip(dct[3, 1] - dct[1, 3], -64, 64)
                candidates = []
                for ty in range(16):
                    for tx in range(16):
                        shifted = np.roll(votes, (-ty, -tx), axis=(1, 2)).reshape(-1)[permutation]
                        pilot = shifted[CODE_BITS:] * (1 - 2 * (pilots[CODE_BITS:] ^ signs[CODE_BITS:]).astype(np.int16))
                        score = -pilot.sum() / np.maximum(np.abs(pilot).sum(), 1e-10)
                        candidates.append((score, tx, ty, shifted))
                for score, tx, ty, shifted in sorted(candidates, key=lambda x: x[0], reverse=True)[:16]:
                    if score < 0.25:
                        continue
                    bits = (shifted[:CODE_BITS] >= 0).astype(np.uint8) ^ signs[:CODE_BITS]
                    decoded = decode_bits(bits, key, bch)
                    if decoded:
                        return {'status': 'detected', **decoded, 'rotation': rotation * 90, 'pixel_phase': [px, py], 'tile_phase': [tx, ty], 'pilot_correlation': float(score)}
    return {'status': 'not_detected'}

def encode(image, work, copy, key=TEST_KEY, strength=24, bch=None):
    bch = bch or BCH()
    permutation, signs, pilots = layout(key)
    encoded = encode_bits(work, copy, key, bch)
    payload = np.concatenate([encoded, pilots[CODE_BITS:]]) ^ signs
    bits = np.empty(512, np.uint8)
    bits[permutation] = payload
    bits = bits.reshape(2, 16, 16)
    rgb = np.asarray(image.convert('RGB'), np.float32)
    assert rgb.shape[:2] == (512, 512)
    for _ in range(2):
        gray = rgb @ np.array([0.299, 0.587, 0.114], np.float32)
        delta = np.zeros((512, 512), np.float32)
        for by in range(64):
            for bx in range(64):
                block = gray[by * 8:by * 8 + 8, bx * 8:bx * 8 + 8]
                dct = cv2.dct(block)
                level = strength * np.clip(0.65 + float(block.std()) / 48, 0.65, 1.35)
                correction = np.zeros((8, 8), np.float32)
                for channel, (a, b) in enumerate(((1, 2), (1, 3))):
                    difference = dct[b, a] - dct[a, b]
                    bit = bool(bits[channel, by % 16, bx % 16])
                    change = (max(level - difference, 0) if bit else min(-level - difference, 0)) * 0.5
                    correction[b, a] += change
                    correction[a, b] -= change
                delta[by * 8:by * 8 + 8, bx * 8:bx * 8 + 8] = cv2.idct(correction)
        rgb = np.floor(np.clip(rgb + delta[:, :, None], 0, 255) + 0.5)
    return Image.fromarray(rgb.astype(np.uint8))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--encode', type=Path)
    parser.add_argument('--work-id', default='v2-work')
    parser.add_argument('--copy-id', default='copy-A')
    parser.add_argument('--output-json', type=Path)
    parser.add_argument('--rotation-fixtures', type=Path)
    args = parser.parse_args()
    image = Image.open(args.input).convert('RGB')
    bch = BCH()
    if args.encode:
        image = encode(image, args.work_id, args.copy_id, bch=bch)
        image.save(args.encode)
    if args.rotation_fixtures:
        args.rotation_fixtures.mkdir(parents=True, exist_ok=True)
        for angle in (3, 5, 15, 27, 43):
            image.rotate(angle, resample=Image.Resampling.BICUBIC, fillcolor=(127, 127, 127)).save(args.rotation_fixtures / f'angle-{angle}.png')
    result = {'scope': 'independent OpenCV full DCT plus complete t<=3 syndrome lookup and standard hmac; fixed public developer key', 'bch_generator_hex': hex(bch.generator), 'bch_error_table_entries': len(bch.errors), 'report': detect(image, bch=bch)}
    text = json.dumps(result, indent=2)
    if args.output_json:
        args.output_json.write_text(text + '\n')
    print(text)
if __name__ == '__main__':
    main()

# FVPROV1 9626 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4Yzg4Y2YyZWI3MDk3NTI3MjAxMTUzODNhYTNmNWFhOWFiZGJmM2U4Yjg0OGVlMjBjMDBlMDQ1M2EwNjlhNDkxIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3N1cHBvcnQvd2F0ZXJtYXJrX3YyX29yYWNsZS5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjhkMjA1NzYzOWY2NzcxOWFjMGVmOWEyZWNlM2RiNjFmMDMzMWY1NjNmMWQ0Mjk1Njk3MGZjNGY3NGVjYjY2OTJmNTJiNTM5YTA2Y2QwODMxZDQwZjYxN2ZlYWE5ODY4ZDVmNDQ4NmI4ZTczN2U1ZmM5YjBlYjU2ZjYyMzgzNDBkIn1dfV0= FVPROV1-END
