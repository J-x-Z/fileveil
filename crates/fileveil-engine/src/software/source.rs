// SPDX-License-Identifier: MPL-2.0
//! Reproducible source-level CRT witness with an authenticated original prefix.
use super::packet::{MAX_PACKET_BYTES, PreparedPacket, hex, unhex};
use fileveil_core::{Error, Result, digest};
use std::fmt::Write;

const BEGIN: &[u8] = b"\n/* FILEVEIL_SOFTWARE_SOURCE_V1 ";
const END: &[u8] = b"\n/* FILEVEIL_SOFTWARE_SOURCE_END_V1 */\n";
const PRIMES: [u32; 9] = [251, 241, 239, 233, 229, 227, 223, 211, 199];

pub(super) struct SourceMark {
    pub prefix: Vec<u8>,
    pub packet: Vec<u8>,
    pub witness: u64,
}

pub(super) fn decode(bytes: &[u8]) -> Result<SourceMark> {
    if !bytes.ends_with(END) {
        return Err(Error::Unsupported(
            "No complete FileVeil source witness footer is present".into(),
        ));
    }
    let start = bytes
        .windows(BEGIN.len())
        .rposition(|window| window == BEGIN)
        .ok_or_else(|| Error::Input("Source witness header is missing".into()))?;
    let fields_start = start + BEGIN.len();
    let line_end = bytes[fields_start..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|offset| fields_start + offset)
        .ok_or_else(|| Error::Input("Source witness header is truncated".into()))?;
    if line_end - fields_start > MAX_PACKET_BYTES * 2 + 128 {
        return Err(Error::Blocked(
            "Source witness header exceeds its budget".into(),
        ));
    }
    let header = std::str::from_utf8(&bytes[fields_start..line_end])
        .map_err(|_| Error::Input("Invalid source witness header encoding".into()))?;
    let fields: Vec<_> = header.split_whitespace().collect();
    if fields.len() != 4 || fields[3] != "*/" {
        return Err(Error::Input("Invalid source witness header".into()));
    }
    let length: usize = fields[0]
        .parse()
        .map_err(|_| Error::Input("Invalid source original length".into()))?;
    let packet = unhex(fields[1])?;
    let witness = u64::from_str_radix(fields[2], 16)
        .map_err(|_| Error::Input("Invalid source witness token".into()))?;
    if length != start
        || packet.is_empty()
        || packet.len() > MAX_PACKET_BYTES
        || fields[2].len() != 16
    {
        return Err(Error::Input(
            "Source witness prefix or packet bounds are invalid".into(),
        ));
    }
    Ok(SourceMark {
        prefix: bytes[..length].to_vec(),
        packet,
        witness,
    })
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

pub(super) fn carrier_bytes(packet: &PreparedPacket) -> Vec<u8> {
    let mut bytes = b"FVSWM01\0".to_vec();
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((packet.bytes.len() as u32).to_le_bytes());
    bytes.extend(packet.witness.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(9u32.to_le_bytes());
    // digest is the shared SHA-256 primitive. Its fixed lowercase hex encoding
    // is converted locally to avoid exposing any key material to the compiler.
    bytes.extend(unhex(&digest(&packet.bytes)).expect("fixed SHA-256 hexadecimal"));
    let mut state = packet.witness ^ 0x465653574d303031;
    for byte in &packet.bytes {
        let share = splitmix(&mut state) as u8;
        bytes.extend([share, byte ^ share]);
    }
    bytes
}

fn array(text: &mut String, name: &str, bytes: &[u8], section: &str) {
    writeln!(text, "__fileveil_swm_used __attribute__((section({section}))) static const unsigned char {name}[] = {{").unwrap();
    for chunk in bytes.chunks(16) {
        text.push_str("  ");
        for byte in chunk {
            write!(text, "0x{byte:02x},").unwrap();
        }
        text.push('\n');
    }
    text.push_str("};\n");
}

pub(super) fn encode(original: &[u8], packet: &PreparedPacket) -> Result<Vec<u8>> {
    if packet.bytes.is_empty() || packet.bytes.len() > MAX_PACKET_BYTES {
        return Err(Error::Input(
            "Source watermark packet exceeds its bounded format".into(),
        ));
    }
    if original
        .windows(b"__fileveil_swm_".len())
        .any(|bytes| bytes == b"__fileveil_swm_")
        || original
            .windows(b"fileveil_swm_probe_v1".len())
            .any(|bytes| bytes == b"fileveil_swm_probe_v1")
        || original.windows(BEGIN.len()).any(|bytes| bytes == BEGIN)
    {
        return Err(Error::Blocked(
            "Source uses a reserved FileVeil witness name or already contains a source witness"
                .into(),
        ));
    }
    let mut state = packet.witness ^ 0x43525453454d3031;
    let seed = splitmix(&mut state);
    let mut descriptor = b"FVSWD01\0".to_vec();
    descriptor.extend(1u32.to_le_bytes());
    descriptor.extend(9u32.to_le_bytes());
    descriptor.extend(seed.to_le_bytes());
    let mut factors = [0u32; 9];
    let mut offsets = [0u32; 9];
    for (index, prime) in PRIMES.into_iter().enumerate() {
        factors[index] = (splitmix(&mut state) % (prime - 1) as u64 + 1) as u32;
        let product =
            ((seed ^ packet.challenge) % prime as u64) * factors[index] as u64 % prime as u64;
        offsets[index] = (packet.witness % prime as u64 + prime as u64 - product) as u32 % prime;
        descriptor.extend(prime.to_le_bytes());
        descriptor.extend(factors[index].to_le_bytes());
        descriptor.extend(offsets[index].to_le_bytes());
    }
    let mut text = String::new();
    writeln!(
        text,
        "\n/* FILEVEIL_SOFTWARE_SOURCE_V1 {} {} {:016x} */",
        original.len(),
        hex(&packet.bytes),
        packet.witness
    )
    .unwrap();
    text.push_str(
        r#"#include <stdint.h>
#if !defined(__clang__) && !defined(__GNUC__)
#error FileVeil source witnesses require a compatible Clang/GNU C compiler
#endif
#if defined(__APPLE__)
#define __fileveil_swm_carrier_section "__DATA_CONST,__fvwm"
#define __fileveil_swm_descriptor_section "__DATA_CONST,__fvcalc"
#define __fileveil_swm_seed_section "__DATA,__fvseed"
#define __fileveil_swm_values_section "__DATA,__fvdata"
#define __fileveil_swm_scratch_section "__DATA,__fvscratch"
#define __fileveil_swm_code_section "__TEXT,__fvcode"
#else
#define __fileveil_swm_carrier_section ".fvwm"
#define __fileveil_swm_descriptor_section ".fvcalc"
#define __fileveil_swm_seed_section ".fvseed"
#define __fileveil_swm_values_section ".fvdata"
#define __fileveil_swm_scratch_section ".fvscr"
#define __fileveil_swm_code_section ".fvcode"
#endif
#if __has_attribute(retain)
#define __fileveil_swm_used __attribute__((used,retain))
#else
#define __fileveil_swm_used __attribute__((used))
#endif
#if defined(_WIN32)
#define __fileveil_swm_export __declspec(dllexport)
#else
#define __fileveil_swm_export __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
"#,
    );
    array(
        &mut text,
        "__fileveil_swm_carrier_v1",
        &carrier_bytes(packet),
        "__fileveil_swm_carrier_section",
    );
    array(
        &mut text,
        "__fileveil_swm_descriptor_v1",
        &descriptor,
        "__fileveil_swm_descriptor_section",
    );
    writeln!(text, "__fileveil_swm_used __attribute__((section(__fileveil_swm_seed_section))) static volatile uint64_t __fileveil_swm_seed_v1 = UINT64_C({seed});").unwrap();
    text.push_str(r#"__fileveil_swm_used __attribute__((section(__fileveil_swm_values_section))) static uint32_t __fileveil_swm_values_v1[9];
__fileveil_swm_used __attribute__((section(__fileveil_swm_scratch_section))) static uint64_t __fileveil_swm_scratch_v1;
__fileveil_swm_export __attribute__((noinline,section(__fileveil_swm_code_section))) uint32_t fileveil_swm_probe_v1(uint32_t index, uint64_t challenge) {
  uint64_t mixed;
  uint32_t residue;
  switch (index) {
"#);
    for index in 0..9 {
        writeln!(text, "  case {index}:\n    mixed = (__fileveil_swm_seed_v1 ^ challenge) % UINT64_C({});\n    residue = (uint32_t)((mixed * UINT64_C({}) + UINT64_C({})) % UINT64_C({}));\n    break;", PRIMES[index], factors[index], offsets[index], PRIMES[index]).unwrap();
    }
    text.push_str(r#"  default:
    return UINT32_MAX;
  }
  __atomic_store_n(&__fileveil_swm_values_v1[index], residue, __ATOMIC_RELAXED);
  if ((residue & 1u) == 0)
    __atomic_store_n(&__fileveil_swm_scratch_v1, (uint64_t)residue, __ATOMIC_RELAXED);
  else
    __atomic_store_n(&__fileveil_swm_scratch_v1, (uint64_t)residue ^ UINT64_C(0x9e3779b97f4a7c15), __ATOMIC_RELAXED);
  return residue;
}
__attribute__((constructor,used)) static void __fileveil_swm_init_v1(void) {
  for (uint32_t index = 0; index < 9; ++index) (void)fileveil_swm_probe_v1(index, 0);
}
#ifdef __cplusplus
}
#endif
#undef __fileveil_swm_carrier_section
#undef __fileveil_swm_descriptor_section
#undef __fileveil_swm_seed_section
#undef __fileveil_swm_values_section
#undef __fileveil_swm_scratch_section
#undef __fileveil_swm_code_section
#undef __fileveil_swm_used
#undef __fileveil_swm_export
"#);
    let mut bytes = original.to_vec();
    bytes.extend(text.as_bytes());
    bytes.extend(END);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_payload_is_reproducible_and_original_prefix_exact() {
        let source = b"int main(void) { return 0; }\n";
        let packet = PreparedPacket {
            bytes: b"bounded opaque fixture".to_vec(),
            witness: 0x123456789abcdef,
            challenge: 9,
        };
        let marked = encode(source, &packet).unwrap();
        let found = decode(&marked).unwrap();
        assert_eq!(found.prefix, source);
        assert_eq!(found.packet, packet.bytes);
        assert_eq!(found.witness, packet.witness);
        assert_eq!(encode(&found.prefix, &packet).unwrap(), marked);
        assert!(encode(&marked, &packet).is_err());
    }
    #[test]
    fn appended_user_code_is_protected_from_source_cleanup() {
        let packet = PreparedPacket {
            bytes: vec![1, 2, 3],
            witness: 7,
            challenge: 9,
        };
        let mut marked = encode(b"int original;", &packet).unwrap();
        marked.extend(b"int later_user_code;\n");
        assert!(decode(&marked).is_err());
    }
}

// FVPROV1 10277 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxYjg3YWI4NWQ1MGViMzI2MTk3ODkwYWQyYzU3NTFiMmM5MDg3YzdlMjg4ZDEyMmYxMzU0NDU3NDEwYzBiNGY2IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3NvZnR3YXJlL3NvdXJjZS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjY0OTY3OWRhNTI4NzQ5NWFkOGQxOWI4YmUzYmJiZWI1YTgwZTYwZjhmMzhmYTI3ZWVhZGI3YTI4Zjc3NTk3Y2RlNzJiY2QzMDhhODdiMjA4Yjk4NTA1YjY5MmU0YWNjNGNhMjNjYWFlMWUzZDk2YjAyZGUxNjJmNzlhODY3YTA5In1dfV0= FVPROV1-END
