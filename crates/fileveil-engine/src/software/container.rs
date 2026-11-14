// SPDX-License-Identifier: MPL-2.0
//! Bounded executable structure parsing. No instructions are executed here.
use super::{
    SoftwareRequest,
    packet::{self, MAX_PACKET_BYTES, PreparedPacket},
};
use crate::heritage::signing::SigningKey;
use fileveil_core::{Error, Limits, Result, digest};
use serde::Serialize;
use serde_json::{Value, json};

const CARRIER_MAGIC: &[u8] = b"FVSWM01\0";
const DESCRIPTOR_MAGIC: &[u8] = b"FVSWD01\0";
const FOOTER_MAGIC: &[u8] = b"FVSWTAIL01\0\0";
const PRIMES: [u32; 9] = [251, 241, 239, 233, 229, 227, 223, 211, 199];
const MAX_SECTIONS: usize = 4096;

#[derive(Serialize)]
pub(super) struct Section {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub address: u64,
    pub executable: bool,
    pub writable: bool,
    pub sha256: String,
}

pub(super) struct Carrier {
    pub offset: u64,
    pub length: u64,
    pub packet: Vec<u8>,
    pub witness: u64,
}

pub(super) struct Descriptor {
    pub offset: u64,
    pub length: u64,
    pub seed: u64,
    pub triples: Vec<[u32; 3]>,
}

pub(super) struct Binary {
    pub format: String,
    pub architecture: String,
    pub entrypoint: u64,
    pub sections: Vec<Section>,
    pub carriers: Vec<Carrier>,
    pub descriptors: Vec<Descriptor>,
    pub signed: bool,
    pub details: Value,
}

fn malformed() -> Error {
    Error::Input("Executable structure contains an invalid or out-of-bounds field".into())
}

fn span(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset.checked_add(size).ok_or_else(malformed)?;
    if end > bytes.len() as u64 {
        return Err(malformed());
    }
    Ok(&bytes[offset as usize..end as usize])
}

fn u32_at(bytes: &[u8], offset: usize, little: bool) -> Result<u32> {
    let data: [u8; 4] = span(bytes, offset as u64, 4)?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(if little {
        u32::from_le_bytes(data)
    } else {
        u32::from_be_bytes(data)
    })
}

fn u64_at(bytes: &[u8], offset: usize, little: bool) -> Result<u64> {
    let data: [u8; 8] = span(bytes, offset as u64, 8)?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(if little {
        u64::from_le_bytes(data)
    } else {
        u64::from_be_bytes(data)
    })
}

fn table(bytes: &[u8], offset: u64, count: usize, stride: usize) -> Result<()> {
    if count > MAX_SECTIONS {
        return Err(Error::Blocked(
            "Executable table exceeds its entry budget".into(),
        ));
    }
    span(
        bytes,
        offset,
        count.checked_mul(stride).ok_or_else(malformed)? as u64,
    )?;
    Ok(())
}

fn text_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&v| v == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end.min(128)]).into_owned()
}

fn add_section(binary: &mut Binary, bytes: &[u8], mut section: Section) -> Result<()> {
    if binary.sections.len() >= MAX_SECTIONS {
        return Err(Error::Blocked("Executable section budget exceeded".into()));
    }
    let data = span(bytes, section.offset, section.size)?;
    let total = binary
        .sections
        .iter()
        .try_fold(section.size, |sum, value| sum.checked_add(value.size))
        .ok_or_else(malformed)?;
    if total > (bytes.len() as u64).saturating_mul(4) {
        return Err(Error::Blocked(
            "Overlapping executable sections exceed the analysis budget".into(),
        ));
    }
    section.sha256 = digest(data);
    binary.sections.push(section);
    Ok(())
}

fn empty(format: &str, architecture: String, entrypoint: u64) -> Binary {
    Binary {
        format: format.into(),
        architecture,
        entrypoint,
        sections: Vec::new(),
        carriers: Vec::new(),
        descriptors: Vec::new(),
        signed: false,
        details: json!({}),
    }
}

fn elf(bytes: &[u8]) -> Result<Binary> {
    use goblin::elf::{Elf, ProgramHeader, SectionHeader, section_header};
    let header = Elf::parse_header(bytes).map_err(|_| malformed())?;
    let ctx = goblin::container::Ctx::new(
        header.container().map_err(|_| malformed())?,
        header.endianness().map_err(|_| malformed())?,
    );
    let expected_sh = SectionHeader::size(ctx);
    let expected_ph = if header.e_ident[4] == 2 { 56 } else { 32 };
    if (header.e_shoff != 0 && (header.e_shnum == 0 || header.e_shentsize as usize != expected_sh))
        || (header.e_phnum != 0 && header.e_phentsize as usize != expected_ph)
    {
        return Err(Error::Unsupported(
            "Extended or nonstandard ELF header tables require separate analysis".into(),
        ));
    }
    table(bytes, header.e_shoff, header.e_shnum as usize, expected_sh)?;
    table(bytes, header.e_phoff, header.e_phnum as usize, expected_ph)?;
    let sections = if header.e_shnum == 0 {
        Vec::new()
    } else {
        SectionHeader::parse(bytes, header.e_shoff as usize, header.e_shnum as usize, ctx)
            .map_err(|_| malformed())?
    };
    let programs =
        ProgramHeader::parse(bytes, header.e_phoff as usize, header.e_phnum as usize, ctx)
            .map_err(|_| malformed())?;
    for program in &programs {
        span(bytes, program.p_offset, program.p_filesz)?;
    }
    let names = match sections.get(header.e_shstrndx as usize) {
        Some(section) if section.sh_type == section_header::SHT_STRTAB => {
            span(bytes, section.sh_offset, section.sh_size)?
        }
        _ if header.e_shstrndx == 0 => &[],
        _ => return Err(malformed()),
    };
    let architecture = match header.e_machine {
        62 => "x86_64".into(),
        183 => "arm64".into(),
        3 => "x86".into(),
        n => format!("elf_machine_{n}"),
    };
    let mut binary = empty("elf", architecture, header.e_entry);
    let mut fingerprints = Vec::new();
    for section in sections {
        let name = if section.sh_name == 0 {
            String::new()
        } else {
            text_name(names.get(section.sh_name..).ok_or_else(malformed)?)
        };
        let size = if section.sh_type == section_header::SHT_NOBITS {
            0
        } else {
            section.sh_size
        };
        if name == ".comment" && size <= 65536 {
            let data = span(bytes, section.sh_offset, size)?;
            fingerprints
                .push(json!({"kind":"elf_compiler_comment", "sha256":digest(data), "bytes":size}));
        }
        add_section(
            &mut binary,
            bytes,
            Section {
                name,
                offset: if size == 0 { 0 } else { section.sh_offset },
                size,
                address: section.sh_addr,
                executable: section.sh_flags & 4 != 0,
                writable: section.sh_flags & 1 != 0,
                sha256: String::new(),
            },
        )?;
    }
    binary.details = json!({"program_headers":programs.len(),"file_type":header.e_type,
        "compiler_fingerprints":fingerprints,"signature_scope":"platform_signature_not_assessed"});
    Ok(binary)
}

fn coff(bytes: &[u8], pe: bool) -> Result<Binary> {
    use goblin::pe::header::{CoffHeader, Header};
    let (header, mut offset, optional) = if pe {
        let pointer = u32_at(bytes, 0x3c, true)? as usize;
        if pointer > 1024 * 1024 {
            return Err(Error::Blocked(
                "PE DOS stub exceeds its header budget".into(),
            ));
        }
        let header = Header::parse(bytes).map_err(|_| malformed())?;
        let offset = pointer
            .checked_add(24)
            .and_then(|n| n.checked_add(header.coff_header.size_of_optional_header as usize))
            .ok_or_else(malformed)?;
        (header.coff_header, offset, header.optional_header)
    } else {
        let mut offset = 0;
        let header = CoffHeader::parse(bytes, &mut offset).map_err(|_| malformed())?;
        offset += header.size_of_optional_header as usize;
        (header, offset, None)
    };
    table(bytes, offset as u64, header.number_of_sections as usize, 40)?;
    if header.number_of_symbol_table > 1_000_000 {
        return Err(Error::Blocked(
            "COFF symbol table exceeds its budget".into(),
        ));
    }
    if header.number_of_symbol_table != 0 {
        span(
            bytes,
            header.pointer_to_symbol_table as u64,
            header.number_of_symbol_table as u64 * 18,
        )?;
    }
    let sections = header
        .sections(bytes, &mut offset)
        .map_err(|_| malformed())?;
    let architecture = match header.machine {
        0x8664 => "x86_64".into(),
        0xaa64 => "arm64".into(),
        0x14c => "x86".into(),
        n => format!("coff_machine_{n}"),
    };
    let entrypoint = optional
        .as_ref()
        .map(|v| {
            v.windows_fields
                .image_base
                .checked_add(v.standard_fields.address_of_entry_point as u64)
                .ok_or_else(malformed)
        })
        .transpose()?
        .unwrap_or(0);
    let mut binary = empty(if pe { "pe" } else { "coff" }, architecture, entrypoint);
    if let Some(cert) = optional
        .as_ref()
        .and_then(|v| v.data_directories.get_certificate_table())
        && (cert.size != 0 || cert.virtual_address != 0)
    {
        span(bytes, cert.virtual_address as u64, cert.size as u64)?;
        binary.signed = true;
    }
    for section in sections {
        let name = section
            .real_name
            .clone()
            .unwrap_or_else(|| text_name(&section.name));
        add_section(
            &mut binary,
            bytes,
            Section {
                name,
                offset: if section.size_of_raw_data == 0 {
                    0
                } else {
                    section.pointer_to_raw_data as u64
                },
                size: section.size_of_raw_data as u64,
                address: section.virtual_address as u64,
                executable: section.characteristics & 0x20000000 != 0,
                writable: section.characteristics & 0x80000000 != 0,
                sha256: String::new(),
            },
        )?;
    }
    binary.details = json!({"coff_timestamp":header.time_date_stamp,"file_characteristics":header.characteristics,
        "compiler_fingerprints_scope":"header_fields_are_build_clues", "platform_signature":"presence_only_not_cryptographically_verified"});
    Ok(binary)
}

fn macho(bytes: &[u8]) -> Result<Binary> {
    let magic = bytes.get(..4).ok_or_else(malformed)?;
    let little = magic == [0xcf, 0xfa, 0xed, 0xfe] || magic == [0xce, 0xfa, 0xed, 0xfe];
    let wide = magic == [0xcf, 0xfa, 0xed, 0xfe] || magic == [0xfe, 0xed, 0xfa, 0xcf];
    let start = if wide { 32 } else { 28 };
    let count = u32_at(bytes, 16, little)? as usize;
    let commands_size = u32_at(bytes, 20, little)? as usize;
    if count > 1024 || commands_size > 1024 * 1024 {
        return Err(Error::Blocked(
            "Mach-O load commands exceed their budget".into(),
        ));
    }
    span(bytes, start, commands_size as u64)?;
    let mut offset = start as usize;
    let mut signed = false;
    let mut section_count = 0usize;
    for _ in 0..count {
        let command = u32_at(bytes, offset, little)?;
        let size = u32_at(bytes, offset + 4, little)? as usize;
        if size < 8
            || offset
                .checked_add(size)
                .filter(|&v| v <= start as usize + commands_size)
                .is_none()
        {
            return Err(malformed());
        }
        if command == 0x1 || command == 0x19 {
            let segment64 = command == 0x19;
            let (base, stride, nsects_at) = if segment64 {
                (72, 80, 64)
            } else {
                (56, 68, 48)
            };
            let nsects = u32_at(bytes, offset + nsects_at, little)? as usize;
            if size < base || nsects > (size - base) / stride {
                return Err(malformed());
            }
            section_count = section_count.checked_add(nsects).ok_or_else(malformed)?;
            if section_count > MAX_SECTIONS {
                return Err(Error::Blocked("Mach-O section budget exceeded".into()));
            }
        }
        if command == 0x1d {
            if size < 16 {
                return Err(malformed());
            }
            span(
                bytes,
                u32_at(bytes, offset + 8, little)? as u64,
                u32_at(bytes, offset + 12, little)? as u64,
            )?;
            signed = true;
        }
        if command == 0x2 && (size < 24 || u32_at(bytes, offset + 12, little)? > 1_000_000) {
            return Err(Error::Blocked("Mach-O symbol budget exceeded".into()));
        }
        offset += size;
    }
    if offset != start as usize + commands_size {
        return Err(malformed());
    }
    let parsed = goblin::mach::MachO::parse(bytes, 0).map_err(|_| malformed())?;
    let architecture = match parsed.header.cputype {
        0x0100000c => "arm64".into(),
        0x01000007 => "x86_64".into(),
        n => format!("macho_cpu_{n}"),
    };
    let mut binary = empty("mach_o", architecture, parsed.entry);
    binary.signed = signed;
    for segment in &parsed.segments {
        span(bytes, segment.fileoff, segment.filesize)?;
        for section in segment.sections().map_err(|_| malformed())? {
            let (section, _) = section;
            let kind = section.flags & 0xff;
            let size = if matches!(kind, 1 | 0xc | 0x12) {
                0
            } else {
                section.size
            };
            add_section(
                &mut binary,
                bytes,
                Section {
                    name: text_name(&section.sectname),
                    offset: if size == 0 { 0 } else { section.offset as u64 },
                    size,
                    address: section.addr,
                    executable: (!parsed.is_object_file() && segment.initprot & 4 != 0)
                        || section.flags & 0x80000400 != 0,
                    writable: segment.initprot & 2 != 0,
                    sha256: String::new(),
                },
            )?;
        }
    }
    binary.details = json!({"load_commands":count,"file_type":parsed.header.filetype,
        "platform_signature":"presence_only_not_cryptographically_verified"});
    Ok(binary)
}

fn structure(bytes: &[u8]) -> Result<Binary> {
    let magic = bytes.get(..4).ok_or_else(malformed)?;
    if magic == b"\x7fELF" {
        return elf(bytes);
    }
    if bytes.starts_with(b"MZ") {
        return coff(bytes, true);
    }
    if matches!(
        magic,
        [0xcf, 0xfa, 0xed, 0xfe]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xfe, 0xed, 0xfa, 0xce]
    ) {
        return macho(bytes);
    }
    if matches!(
        magic,
        [0xca, 0xfe, 0xba, 0xbe]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xbf, 0xba, 0xfe, 0xca]
    ) {
        let little = magic[0] != 0xca;
        let wide = magic == [0xca, 0xfe, 0xba, 0xbf] || magic == [0xbf, 0xba, 0xfe, 0xca];
        let count = u32_at(bytes, 4, little)? as usize;
        if count == 0 || count > 16 {
            return Err(Error::Blocked(
                "Universal Mach-O architecture budget exceeded".into(),
            ));
        }
        let stride = if wide { 32 } else { 20 };
        table(bytes, 8, count, stride)?;
        let mut binary = empty("mach_o_universal", "multiple".into(), 0);
        let mut slices = Vec::new();
        let mut ranges = Vec::new();
        for index in 0..count {
            let row = 8 + index * stride;
            let (offset, size) = if wide {
                (
                    u64_at(bytes, row + 8, little)?,
                    u64_at(bytes, row + 16, little)?,
                )
            } else {
                (
                    u32_at(bytes, row + 8, little)? as u64,
                    u32_at(bytes, row + 12, little)? as u64,
                )
            };
            let end = offset.checked_add(size).ok_or_else(malformed)?;
            if offset < (8 + count * stride) as u64
                || ranges.iter().any(|&(a, b)| offset < b && a < end)
            {
                return Err(malformed());
            }
            ranges.push((offset, end));
            let mut slice = macho(span(bytes, offset, size)?)?;
            binary.signed |= slice.signed;
            slices.push(json!({"architecture":slice.architecture,"offset":offset,"size":size,"entrypoint":slice.entrypoint}));
            for mut section in slice.sections.drain(..) {
                section.offset = section.offset.checked_add(offset).ok_or_else(malformed)?;
                add_section(&mut binary, bytes, section)?;
            }
        }
        binary.details = json!({"slices":slices});
        return Ok(binary);
    }
    let machine = u16::from_le_bytes(bytes[..2].try_into().map_err(|_| malformed())?);
    if matches!(machine, 0x14c | 0x8664 | 0xaa64) {
        return coff(bytes, false);
    }
    Err(Error::Unsupported(
        "Software forensics supports ELF, PE/COFF and Mach-O containers".into(),
    ))
}

fn decode_carrier(bytes: &[u8], offset: u64) -> Result<Carrier> {
    if !bytes.starts_with(CARRIER_MAGIC)
        || u32_at(bytes, 8, true)? != 1
        || u32_at(bytes, 24, true)? != 1
        || u32_at(bytes, 28, true)? != 9
    {
        return Err(malformed());
    }
    let count = u32_at(bytes, 12, true)? as usize;
    if count == 0 || count > MAX_PACKET_BYTES {
        return Err(Error::Blocked(
            "Software carrier payload exceeds its budget".into(),
        ));
    }
    let length = 64 + count * 2;
    let shares = span(bytes, 64, (count * 2) as u64)?;
    let packet: Vec<_> = shares
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| pair[0] ^ pair[1])
        .collect();
    if packet::hex(span(bytes, 32, 32)?) != digest(&packet) {
        return Err(Error::Verification(
            "Software carrier checksum is invalid".into(),
        ));
    }
    Ok(Carrier {
        offset,
        length: length as u64,
        packet,
        witness: u64_at(bytes, 16, true)?,
    })
}

fn decode_descriptor(bytes: &[u8], offset: u64) -> Result<Descriptor> {
    if !bytes.starts_with(DESCRIPTOR_MAGIC)
        || u32_at(bytes, 8, true)? != 1
        || u32_at(bytes, 12, true)? != 9
    {
        return Err(malformed());
    }
    let mut triples = Vec::new();
    for (index, prime) in PRIMES.into_iter().enumerate() {
        let row = 24 + index * 12;
        let factor = u32_at(bytes, row + 4, true)?;
        let adjustment = u32_at(bytes, row + 8, true)?;
        if u32_at(bytes, row, true)? != prime
            || factor == 0
            || factor >= prime
            || adjustment >= prime
        {
            return Err(malformed());
        }
        triples.push([prime, factor, adjustment]);
    }
    Ok(Descriptor {
        offset,
        length: 132,
        seed: u64_at(bytes, 16, true)?,
        triples,
    })
}

fn footer(bytes: &[u8]) -> Result<Option<(usize, Carrier)>> {
    if bytes.len() < 24 || !bytes[bytes.len() - 24..].starts_with(FOOTER_MAGIC) {
        return Ok(None);
    }
    let end = bytes.len() - 24;
    let length = u32_at(bytes, end + 12, true)? as usize;
    let prefix = u64_at(bytes, end + 16, true)?;
    if prefix
        .checked_add(length as u64)
        .filter(|&n| n == end as u64)
        .is_none()
    {
        return Err(malformed());
    }
    let carrier = decode_carrier(span(bytes, prefix, length as u64)?, prefix)?;
    if carrier.length != length as u64 {
        return Err(malformed());
    }
    Ok(Some((prefix as usize, carrier)))
}

pub(super) fn inspect(bytes: &[u8], limits: &Limits) -> Result<Binary> {
    if bytes.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked("Executable exceeds its file budget".into()));
    }
    let mut binary = structure(bytes)?;
    binary.details["compiler_build_clues"] = super::forensics::compiler_clues(bytes);
    for section in &binary.sections {
        if section.executable {
            continue;
        }
        let (carrier, descriptor) = (
            matches!(section.name.as_str(), ".fvwm" | "__fvwm"),
            matches!(section.name.as_str(), ".fvcalc" | "__fvcalc"),
        );
        if !carrier && !descriptor {
            continue;
        }
        let data = span(bytes, section.offset, section.size)?;
        // Multiple translation units can contribute aligned records to one section.
        let mut cursor = 0usize;
        while cursor < data.len() {
            if data[cursor] == 0 {
                cursor += 1;
                continue;
            }
            if carrier {
                let value = decode_carrier(&data[cursor..], section.offset + cursor as u64)?;
                cursor += value.length as usize;
                binary.carriers.push(value);
            } else {
                let value = decode_descriptor(&data[cursor..], section.offset + cursor as u64)?;
                cursor += value.length as usize;
                binary.descriptors.push(value);
            }
            if binary.carriers.len() + binary.descriptors.len() > 128 {
                return Err(Error::Blocked(
                    "Software watermark record budget exceeded".into(),
                ));
            }
        }
    }
    if let Some((prefix, carrier)) = footer(bytes)? {
        let _ = structure(&bytes[..prefix])?;
        binary.carriers.push(carrier);
        binary.details["footer_prefix_bytes"] = prefix.into();
    }
    Ok(binary)
}

impl Binary {
    pub fn report(&self, request: &SoftwareRequest, key: Option<&SigningKey>) -> Result<Value> {
        let packets: Vec<_> = self.carriers.iter().map(|carrier| {
            let validation = packet::inspect(&carrier.packet,key,&request.trusted_keys,request.disclose_private);
            match validation {
                Ok(mut report) => {
                    report["offset"] = carrier.offset.into();
                    report["bytes"] = carrier.length.into();
                    report["carrier_witness_matches"] = (report["witness_hex"].as_str() == Some(format!("{:016x}",carrier.witness).as_str())).into();
                    report
                }
                Err(error) => {
                    let message = error.to_string();
                    json!({"offset":carrier.offset,"verification":"failed",
                        "signature":if message == "Invalid detached Ed25519 signature" {"invalid"} else {"unable_to_verify"},
                        "error":message})
                },
            }
        }).collect();
        let descriptors: Vec<_> = self.descriptors.iter().map(|value| json!({"offset":value.offset,"bytes":value.length,
            "method":"affine_crt_residue_witness_v1","seed_hex":format!("{:016x}",value.seed),"residue_count":value.triples.len(),
            "runtime_validation":"not_assessed"})).collect();
        let runtime_candidates: Vec<_> = self
            .sections
            .iter()
            .filter(|section| {
                matches!(
                    section.name.as_str(),
                    ".fvseed" | "__fvseed" | ".fvdata" | "__fvdata" | ".fvcode" | "__fvcode"
                ) && section.size != 0
            })
            .map(|section| {
                json!({"name":section.name,"offset":section.offset,"bytes":section.size,
            "sha256":section.sha256,"evidence":"known_protocol_runtime_section_candidate"})
            })
            .collect();
        Ok(
            json!({"format":self.format,"architecture":self.architecture,"entrypoint":self.entrypoint,
            "sections":self.sections,"platform_signature_present":self.signed,"structure":self.details,
            "known_watermark":if !self.carriers.is_empty() {"detected"} else if !runtime_candidates.is_empty() {"candidate_semantic_residue"} else {"not_detected"},"packets":packets,
            "runtime_witness_candidates":runtime_candidates,
            "semantic_descriptors":descriptors,"unknown_watermarks":"not_assessed", "compiler_fingerprint_is_watermark_evidence":false,
            "scope":"bounded_container_and_known_protocol_records"}),
        )
    }
}

pub(super) fn encode_carrier(packet: &PreparedPacket) -> Vec<u8> {
    super::source::carrier_bytes(packet)
}

pub(super) fn append_footer(
    prefix: &[u8],
    packet: &PreparedPacket,
    limits: &Limits,
) -> Result<Vec<u8>> {
    let before = inspect(prefix, limits)?;
    if before.signed || !before.carriers.is_empty() || !before.descriptors.is_empty() {
        return Err(Error::Blocked(
            "Structure marking requires an unsigned binary without an existing FileVeil carrier"
                .into(),
        ));
    }
    let verified = packet::inspect(&packet.bytes, None, &[], false)?;
    if verified["input_sha256"].as_str() != Some(digest(prefix).as_str()) {
        return Err(Error::Verification(
            "Structure declaration does not bind this original binary".into(),
        ));
    }
    let carrier = encode_carrier(packet);
    if (prefix.len() as u64)
        .checked_add(carrier.len() as u64 + 24)
        .filter(|&n| n <= limits.max_file_bytes)
        .is_none()
    {
        return Err(Error::Blocked(
            "Marked binary would exceed its file budget".into(),
        ));
    }
    let mut bytes = prefix.to_vec();
    bytes.extend(&carrier);
    bytes.extend(FOOTER_MAGIC);
    bytes.extend((carrier.len() as u32).to_le_bytes());
    bytes.extend((prefix.len() as u64).to_le_bytes());
    Ok(bytes)
}

pub(super) fn clean_bytes(input: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    let binary = inspect(input, limits)?;
    if let Some((prefix, carrier)) = footer(input)? {
        let report = packet::inspect(&carrier.packet, None, &[], false)?;
        if report["input_sha256"].as_str() != Some(digest(&input[..prefix]).as_str()) {
            return Err(Error::Verification(
                "Software footer no longer matches its original binary".into(),
            ));
        }
        let _ = inspect(&input[..prefix], limits)?;
        return Ok(input[..prefix].to_vec());
    }
    if binary.signed {
        return Err(Error::Blocked(
            "Binary section cleanup would invalidate a platform code signature".into(),
        ));
    }
    if binary.carriers.is_empty() {
        return Err(Error::Unsupported(
            "No authenticated software carrier is available for structural cleanup".into(),
        ));
    }
    for carrier in &binary.carriers {
        packet::inspect(&carrier.packet, None, &[], false)?;
    }
    let mut output = input.to_vec();
    for (offset, length) in binary
        .carriers
        .iter()
        .map(|v| (v.offset, v.length))
        .chain(binary.descriptors.iter().map(|v| (v.offset, v.length)))
    {
        let end = offset.checked_add(length).ok_or_else(malformed)?;
        if binary.sections.iter().any(|section| {
            section.executable && offset < section.offset + section.size && section.offset < end
        }) {
            return Err(Error::Blocked(
                "Software carrier overlaps executable code".into(),
            ));
        }
        output[offset as usize..end as usize].fill(0);
    }
    let _ = inspect(&output, limits)?;
    Ok(output)
}

/// Bounded instruction, CFG and block-local def/use candidates.
pub(super) fn disassembly(text: &str) -> Value {
    let mut report = super::forensics::analyze(text);
    // Preserve the initial software report field consumed by existing GUI readers.
    report["cfg_candidates"] = report["cfg_edges"].clone();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn control() -> Vec<u8> {
        let mut bytes = vec![0u8; 120];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes
    }
    #[test]
    fn signed_footer_restores_exact_original_and_detects_tampering() {
        let original = control();
        let key = SigningKey::generate().unwrap();
        let request = SoftwareRequest {
            work_id: "work".into(),
            copy_id: "copy".into(),
            ..Default::default()
        };
        let packet = packet::prepare(&request, &key, &digest(&original), None).unwrap();
        let limits = Limits::default();
        let marked = append_footer(&original, &packet, &limits).unwrap();
        let report = inspect(&marked, &limits)
            .unwrap()
            .report(&request, Some(&key))
            .unwrap();
        assert_eq!(report["packets"][0]["decoded"], true);
        assert_eq!(clean_bytes(&marked, &limits).unwrap(), original);
        assert!(append_footer(&marked, &packet, &limits).is_err());
        let mut modified = marked.clone();
        modified[100] ^= 1;
        assert!(clean_bytes(&modified, &limits).is_err());
        let mut bad_length = marked.clone();
        let last = bad_length.len() - 8;
        bad_length[last..].fill(0xff);
        assert!(inspect(&bad_length, &limits).is_err());
    }
    #[test]
    fn malformed_headers_and_table_budgets_fail_without_panics() {
        let limits = Limits::default();
        for size in 0..120 {
            assert!(inspect(&control()[..size], &limits).is_err() || size >= 64);
        }
        let mut elf = control();
        elf[40..48].copy_from_slice(&64u64.to_le_bytes());
        elf[60..62].copy_from_slice(&5000u16.to_le_bytes());
        assert!(inspect(&elf, &limits).is_err());
        let mut mach = vec![0u8; 32];
        mach[..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        mach[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(inspect(&mach, &limits).is_err());
        let mut pe = vec![0u8; 64];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(inspect(&pe, &limits).is_err());
    }
    #[test]
    fn normalized_instruction_and_cfg_evidence_is_scoped() {
        let report = disassembly(
            "0000000000001000 <main>:\n1000: mov x0, #42\n1004: cbz x0, 0x1010\n1008: ret\n",
        );
        assert_eq!(report["instruction_count"], 3);
        assert_eq!(report["cfg_candidates"][0]["to"], 0x1010);
        assert_eq!(report["unknown_watermark_detection"], "not_assessed");
    }

    #[test]
    fn runtime_residue_is_visible_after_static_carriers_are_gone() {
        let bytes = control();
        let mut binary = inspect(&bytes, &Limits::default()).unwrap();
        binary.sections.push(Section {
            name: ".fvseed".into(),
            offset: 64,
            size: 8,
            address: 0,
            executable: false,
            writable: true,
            sha256: digest(&bytes[64..72]),
        });
        let report = binary.report(&SoftwareRequest::default(), None).unwrap();
        assert_eq!(report["known_watermark"], "candidate_semantic_residue");
        assert_eq!(
            report["runtime_witness_candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(report["packets"].as_array().unwrap().is_empty());
    }

    #[test]
    fn verify_rejects_a_tampered_signed_packet_through_the_public_pipeline() {
        let original = control();
        let owner = SigningKey::generate().unwrap();
        let marking = SoftwareRequest {
            work_id: "work".into(),
            copy_id: "copy".into(),
            ..Default::default()
        };
        let mut prepared = packet::prepare(&marking, &owner, &digest(&original), None).unwrap();
        let mut envelope: Value = serde_json::from_slice(&prepared.bytes).unwrap();
        envelope["body"]["input_sha256"] = "a".repeat(64).into();
        prepared.bytes = serde_json::to_vec(&envelope).unwrap();
        let carrier = encode_carrier(&prepared);
        let mut bytes = original.clone();
        bytes.extend(&carrier);
        bytes.extend(FOOTER_MAGIC);
        bytes.extend((carrier.len() as u32).to_le_bytes());
        bytes.extend((original.len() as u64).to_le_bytes());
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("tampered.elf");
        std::fs::write(&path, &bytes).unwrap();
        let request = SoftwareRequest {
            action: super::super::SoftwareAction::Verify,
            mode: super::super::SoftwareMode::Structure,
            input_path: path.clone(),
            ..Default::default()
        };
        let report = super::super::run(
            &request,
            &Limits::default(),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.result, fileveil_core::Outcome::Failed);
        assert_eq!(
            report.advanced.unwrap()["software"]["binary"]["packets"][0]["signature"],
            "invalid"
        );
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

// FVPROV1 33366 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIzYTM2ZThiOWU3NGU2ZjkwODM3YmExOWI1YzMxYTMwZjBlZGU2YjFiMzRiM2MzYzgzNGEwZWNkY2JjYjJjNDkwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3NvZnR3YXJlL2NvbnRhaW5lci5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjBkMDM4N2VjYjExY2QzMDQyZGQyYTExM2IxODA4YzJhNzQ1ZmU5MWQ5OTZhZWIyODI3OTBmYTE2ZmEyYTE3ZmQ0ZTNlODQwZmRmNzA1ZjI1NTg1MTMxOTAyNWM1NDBiN2Q4MzQzZWZjNDQxZjQ0YWM4YjM4ODljYmRlODY4YjAyIn1dfV0= FVPROV1-END
