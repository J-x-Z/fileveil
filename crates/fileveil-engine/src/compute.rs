// SPDX-License-Identifier: MPL-2.0
//! Opt-in, bounded CPU replay of Philox CUDA initialization layout candidates.
//! This identifies compatible layouts, never a physical GPU or training location.
use fileveil_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const HEADER_LIMIT: u64 = 1024 * 1024;
const SAMPLE_LIMIT: usize = 65536;
const DRAW_LIMIT: u64 = 32_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeRequest {
    pub path: PathBuf,
    pub tensor: String,
    pub rows: Vec<u64>,
    pub seeds: Vec<u64>,
    #[serde(default = "default_layouts")]
    pub sm_counts: Vec<u32>,
    #[serde(default)]
    pub philox_offset: u64,
    /// Optional tensor-parallel shard size in rows. Each rank advances the seed.
    #[serde(default)]
    pub rows_per_shard: Option<u64>,
    #[serde(default)]
    pub seed_per_rank: u64,
}
fn default_layouts() -> Vec<u32> {
    (16..=256).collect()
}

fn blocked(message: &str) -> Error {
    Error::Blocked(message.into())
}
fn invalid(message: &str) -> Error {
    Error::Input(message.into())
}

fn open_regular(path: &Path) -> Result<File> {
    if let Some(file) = crate::access_guard::open_bound(path)? {
        return Ok(file);
    }
    if !fs::symlink_metadata(path)
        .map_err(|_| invalid("Cannot inspect weight input"))?
        .is_file()
    {
        return Err(invalid(
            "Weights must be a regular file; links are not followed",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
        .open(path)
        .map_err(|_| invalid("Cannot open weight input"))
}

// Reject duplicate keys at every depth, including tensor names and offsets.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("unique-key JSON")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, Unique>()? {
                    if out.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("Duplicate JSON key"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<Unique>()? {
                    out.push(v.0);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}
fn unique_json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|u| u.0)
        .map_err(|_| invalid("Invalid or duplicate-key weight metadata JSON"))
}

pub fn report(request: &ComputeRequest, cancelled: &AtomicBool) -> Result<fileveil_core::Report> {
    let details = analyze(request, cancelled)?;
    let mut report =
        fileveil_core::Report::new("compute_fingerprint", fileveil_core::Format::Unknown);
    report.input_format = "application/x-safetensors".into();
    report.integrity.parseable = true;
    report.result = fileveil_core::Outcome::PartiallyVerified;
    // Whole-file integrity is deliberately unassessed for streaming model inputs.
    report.advanced = Some(json!({"compute_fingerprint":details}));
    report.warnings.push("Experimental initialization-layout evidence only. Seeds and sample rows are supplied; hardware identity, training location and calibrated confidence are not assessed.".into());
    Ok(report)
}

fn resolve(request: &ComputeRequest) -> Result<PathBuf> {
    if request.path.extension().and_then(|x| x.to_str()) == Some("safetensors") {
        return Ok(request.path.clone());
    }
    if !request
        .path
        .file_name()
        .is_some_and(|x| x.to_string_lossy().ends_with(".safetensors.index.json"))
    {
        return Err(invalid(
            "Only safetensors or its shard index is accepted; pickle/model code is never loaded",
        ));
    }
    let mut file = open_regular(&request.path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(HEADER_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("Cannot read shard index"))?;
    if bytes.len() as u64 > HEADER_LIMIT {
        return Err(blocked("Shard index exceeds 1 MiB"));
    }
    let index = unique_json(&bytes)?;
    let name = index["weight_map"][&request.tensor]
        .as_str()
        .ok_or_else(|| invalid("Tensor is not present in shard index"))?;
    if Path::new(name).components().count() != 1
        || name.contains(['/', '\\', ':'])
        || !name.ends_with(".safetensors")
    {
        return Err(blocked("Shard name must be a local safetensors basename"));
    }
    Ok(request.path.parent().unwrap_or(Path::new(".")).join(name))
}

pub fn analyze(request: &ComputeRequest, cancelled: &AtomicBool) -> Result<Value> {
    let start = Instant::now();
    if request.tensor.len() > 1024
        || request.tensor.is_empty()
        || request.rows.is_empty()
        || request.rows.len() > 64
        || request.seeds.is_empty()
        || request.seeds.len() > 16
        || request.sm_counts.len() < 2
        || request.sm_counts.len() > 256
        || !request.philox_offset.is_multiple_of(4)
        || request.sm_counts.iter().any(|n| !(16..=512).contains(n))
        || request.rows_per_shard == Some(0)
    {
        return Err(invalid(
            "Invalid tensor, rows, seeds, layout candidates or aligned Philox offset",
        ));
    }
    for count in [&request.rows, &request.seeds] {
        let mut v = count.clone();
        v.sort_unstable();
        v.dedup();
        if v.len() != count.len() {
            return Err(invalid("Duplicate rows or seeds"));
        }
    }
    if let Some(shard) = request.rows_per_shard
        && request.seed_per_rank == 0
    {
        let mut local_rows: Vec<_> = request.rows.iter().map(|r| r % shard).collect();
        local_rows.sort_unstable();
        local_rows.dedup();
        if local_rows.len() != request.rows.len() {
            return Err(invalid(
                "Repeated effective initialization rows across shards are not independent evidence",
            ));
        }
    }
    let mut layouts = request.sm_counts.clone();
    layouts.sort_unstable();
    layouts.dedup();
    if layouts.len() != request.sm_counts.len() {
        return Err(invalid("Duplicate layout candidates"));
    }
    let path = resolve(request)?;
    let mut file = open_regular(&path)?;
    let before = file
        .metadata()
        .map_err(|_| invalid("Cannot stat weight file"))?;
    if !before.is_file() {
        return Err(invalid("Weights must be a regular file"));
    }
    let mut raw = [0u8; 8];
    file.read_exact(&mut raw)
        .map_err(|_| invalid("Truncated safetensors prefix"))?;
    let header_len = u64::from_le_bytes(raw);
    if header_len == 0 || header_len > HEADER_LIMIT || header_len.saturating_add(8) > before.len() {
        return Err(blocked("Invalid or oversized safetensors header"));
    }
    let mut bytes = vec![0; header_len as usize];
    file.read_exact(&mut bytes)
        .map_err(|_| invalid("Truncated weight header"))?;
    let header = unique_json(&bytes)?;
    let entries = header
        .as_object()
        .ok_or_else(|| invalid("Weight header is not an object"))?;
    if entries.len() > 10000 {
        return Err(blocked("Too many tensors"));
    }
    let mut ranges = Vec::new();
    let data_len = before.len() - 8 - header_len;
    for (name, info) in entries {
        if name == "__metadata__" {
            if !info
                .as_object()
                .is_some_and(|m| m.values().all(Value::is_string))
            {
                return Err(invalid("Invalid safetensors metadata"));
            }
            continue;
        }
        let offsets = info["data_offsets"]
            .as_array()
            .filter(|a| a.len() == 2)
            .ok_or_else(|| invalid("Invalid tensor offsets"))?;
        let a = offsets[0]
            .as_u64()
            .ok_or_else(|| invalid("Invalid tensor offset"))?;
        let b = offsets[1]
            .as_u64()
            .ok_or_else(|| invalid("Invalid tensor offset"))?;
        let width = match info["dtype"].as_str() {
            Some("BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2") => 1,
            Some("BF16" | "F16" | "I16" | "U16") => 2,
            Some("F32" | "I32" | "U32") => 4,
            Some("F64" | "I64" | "U64") => 8,
            _ => return Err(invalid("Unsupported tensor dtype in container")),
        };
        let shape = info["shape"]
            .as_array()
            .filter(|s| s.len() <= 32)
            .ok_or_else(|| invalid("Invalid tensor shape"))?;
        let size = shape
            .iter()
            .try_fold(width, |n: u64, d| n.checked_mul(d.as_u64()?))
            .ok_or_else(|| invalid("Overflowing tensor shape"))?;
        if b < a || b > data_len || b - a != size {
            return Err(invalid("Tensor size or offset exceeds container"));
        }
        ranges.push((a, b));
    }
    ranges.sort_unstable();
    let mut end = 0;
    for (a, b) in ranges {
        if a != end {
            return Err(invalid("Tensor data overlaps or contains holes"));
        }
        end = b;
    }
    if end != data_len {
        return Err(invalid("Unaccounted trailing weight bytes"));
    }
    let info = entries
        .get(&request.tensor)
        .ok_or_else(|| invalid("Requested tensor is absent"))?;
    let shape = info["shape"]
        .as_array()
        .filter(|s| s.len() == 2)
        .ok_or_else(|| invalid("Select a 2D embedding tensor"))?;
    let height = shape[0]
        .as_u64()
        .ok_or_else(|| invalid("Invalid tensor height"))?;
    let width = shape[1]
        .as_u64()
        .ok_or_else(|| invalid("Invalid tensor width"))? as usize;
    if !(64..=16384).contains(&width)
        || request.rows.iter().any(|r| *r >= height)
        || request.rows.len() * width > SAMPLE_LIMIT
    {
        return Err(blocked(
            "Selected rows exceed sample bounds or tensor dimensions",
        ));
    }
    let samples = (request.rows.len() * width) as u64;
    let draws = samples * (request.seeds.len() as u64) * (layouts.len() as u64 + 1);
    if draws > DRAW_LIMIT {
        return Err(blocked(
            "Candidate replay exceeds 32 million draws; reduce rows, seeds or layouts",
        ));
    }
    let dtype = info["dtype"].as_str().unwrap_or("");
    let stride = match dtype {
        "BF16" | "F16" => 2,
        "F32" => 4,
        _ => return Err(invalid("Selected tensor requires BF16, F16 or F32")),
    };
    let at = info["data_offsets"][0]
        .as_u64()
        .ok_or_else(|| invalid("Missing selected offsets"))?
        + 8
        + header_len;
    let mut observed = Vec::new();
    let mut sample_hash = Sha256::new();
    sample_hash.update(b"FileVeil compute sampled rows v1\0");
    for &row in &request.rows {
        let mut buffer = vec![0; width * stride];
        file.seek(SeekFrom::Start(at + row * width as u64 * stride as u64))
            .map_err(|_| invalid("Cannot seek sampled row"))?;
        file.read_exact(&mut buffer)
            .map_err(|_| invalid("Truncated sampled row"))?;
        sample_hash.update(row.to_le_bytes());
        sample_hash.update(&buffer);
        let values: Vec<f64> = buffer
            .chunks_exact(stride)
            .map(|c| match dtype {
                "F32" => f32::from_le_bytes(c.try_into().unwrap()) as f64,
                "BF16" => {
                    f32::from_bits((u16::from_le_bytes(c.try_into().unwrap()) as u32) << 16) as f64
                }
                _ => half(u16::from_le_bytes(c.try_into().unwrap())),
            })
            .collect();
        if values.iter().any(|n| !n.is_finite()) {
            return Err(invalid("Nonfinite sampled weight"));
        }
        observed.push(values);
    }
    let mut candidates = Vec::new();
    for &seed in &request.seeds {
        for &sms in &layouts {
            if cancelled.load(Ordering::Relaxed) || start.elapsed().as_secs() > 60 {
                return Err(blocked("Compute replay cancelled or exceeded 60 seconds"));
            }
            let scores = scores(request, &observed, width, seed, sms)?;
            let median = median(&scores);
            let hits = scores.iter().filter(|r| **r >= 0.98).count();
            candidates.push(json!({"seed":seed,"sm_count":sms,"threads_per_sm_assumption":2048,"median_correlation":median,"rows_above_0_98":hits,"row_correlations":scores}));
        }
    }
    candidates.sort_by(|a, b| {
        b["median_correlation"]
            .as_f64()
            .unwrap()
            .total_cmp(&a["median_correlation"].as_f64().unwrap())
    });
    let best = &candidates[0];
    let best_seed = best["seed"].as_u64().unwrap();
    let best_sms = best["sm_count"].as_u64().unwrap() as u32;
    let wrong_seed = best_seed.wrapping_add(1);
    let controls = scores(request, &observed, width, wrong_seed, best_sms)?;
    let best_r = best["median_correlation"].as_f64().unwrap();
    let next = candidates[1]["median_correlation"].as_f64().unwrap();
    let row_scores = best["row_correlations"].as_array().unwrap();
    let row_min = row_scores
        .iter()
        .filter_map(Value::as_f64)
        .fold(1.0, f64::min);
    let row_max = row_scores
        .iter()
        .filter_map(Value::as_f64)
        .fold(-1.0, f64::max);
    let informative = request
        .rows
        .iter()
        .filter(|r| {
            let row = request.rows_per_shard.map_or(**r, |s| **r % s);
            row * width as u64 >= layouts.iter().max().copied().unwrap() as u64 * 2048
        })
        .count();
    let matched = request.rows.len() >= 3
        && informative >= 3
        && best_r >= 0.98
        && best_r - next >= 0.1
        && median(&controls) < 0.2
        && best["rows_above_0_98"].as_u64().unwrap() >= 3;
    // Re-read the bounded header and samples from the same descriptor; never
    // promote this into a digest claim covering unsampled model bytes.
    file.seek(SeekFrom::Start(0))
        .map_err(|_| invalid("Cannot recheck header"))?;
    let mut prefix_again = [0u8; 8];
    file.read_exact(&mut prefix_again)
        .map_err(|_| invalid("Cannot recheck header prefix"))?;
    if prefix_again != raw {
        return Err(blocked("Weight header prefix changed during analysis"));
    }
    let mut header_again = vec![0; header_len as usize];
    file.read_exact(&mut header_again)
        .map_err(|_| invalid("Cannot recheck header"))?;
    if header_again != bytes {
        return Err(blocked("Weight header changed during analysis"));
    }
    let mut recheck = Sha256::new();
    recheck.update(b"FileVeil compute sampled rows v1\0");
    for &row in &request.rows {
        let mut buffer = vec![0; width * stride];
        file.seek(SeekFrom::Start(at + row * width as u64 * stride as u64))
            .map_err(|_| invalid("Cannot recheck sampled row"))?;
        file.read_exact(&mut buffer)
            .map_err(|_| invalid("Cannot recheck sampled row"))?;
        recheck.update(row.to_le_bytes());
        recheck.update(buffer);
    }
    if recheck.finalize() != sample_hash.clone().finalize() {
        return Err(blocked("Sampled weights changed during analysis"));
    }
    let after = file
        .metadata()
        .map_err(|_| invalid("Cannot recheck weight file"))?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(blocked("Weight input changed during analysis"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
            return Err(blocked("Weight input changed during analysis"));
        }
    }
    let classes = match best_sms {
        108 => vec!["108-SM CUDA layout; includes A100/A800 configurations"],
        132 => vec!["132-SM CUDA layout; includes H100/H800/H200 configurations"],
        148 => vec!["148-SM CUDA layout; includes B200/B300 configurations"],
        152 => vec![
            "152-SM CUDA layout; includes GB200/GB300 configurations; equivalent partitions not excluded",
        ],
        _ => vec!["Unmapped parallel layout"],
    };
    Ok(
        json!({"schema":"fileveil.compute-fingerprint.v1","status":if matched{"candidate_layout_match"}else{"unable_to_determine"},"capability":"experimental","method":"philox4x32_10_cuda_normal_layout_v1","tensor":request.tensor,"shape":[height,width],"dtype":dtype,"sampled_rows":request.rows,"sampled_bytes":samples*stride as u64,"sample_sha256":format!("{:x}",sample_hash.finalize()),"file_sha256":"not_assessed_streaming_sample_only","candidate_hardware_classes":if matched{classes}else{vec![]},"candidates":candidates.into_iter().take(8).collect::<Vec<_>>(),"wrong_seed_control":{"seed":wrong_seed,"median_correlation":median(&controls)},"confidence":{"calibrated_probability":null,"row_correlation_range":[row_min,row_max],"runner_up_median_correlation":next,"runner_up_margin":best_r-next,"scope":"Descriptive evidence under supplied seeds, tensor selection and CUDA normal_ assumptions; not a hardware identity probability"},"resource_usage":{"draws":draws,"sample_values":samples,"elapsed_ms":start.elapsed().as_millis()},"limitations":["No physical GPU identity, training location or complete training hardware attribution","Candidate seeds are supplied, not brute-forced","CPU, framework, algorithm version and partition configurations may differ or share layouts","Truncated normal, trained tensors and quantized integer formats are not supported by this adapter","No model code, pickle payload, network request or whole-model allocation is executed"],"input_opened_read_only":true,"sample_snapshot_unchanged":true}),
    )
}

fn half(bits: u16) -> f64 {
    let sign = if bits >> 15 == 0 { 1.0 } else { -1.0 };
    let e = (bits >> 10) & 31;
    let m = bits & 1023;
    match e {
        0 => sign * (m as f64) * 2f64.powi(-24),
        31 => {
            if m == 0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => sign * (1.0 + m as f64 / 1024.0) * 2f64.powi(e as i32 - 15),
    }
}
fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}
fn scores(
    request: &ComputeRequest,
    observed: &[Vec<f64>],
    width: usize,
    seed: u64,
    sms: u32,
) -> Result<Vec<f64>> {
    observed
        .iter()
        .zip(&request.rows)
        .map(|(values, &row)| {
            let rank = request.rows_per_shard.map_or(0, |s| row / s);
            let row = request.rows_per_shard.map_or(row, |s| row % s);
            let seed = rank
                .checked_mul(request.seed_per_rank)
                .and_then(|n| seed.checked_add(n))
                .ok_or_else(|| invalid("Shard seed overflows"))?;
            let predicted: Vec<f64> = (0..width)
                .map(|i| {
                    normal(
                        row * width as u64 + i as u64,
                        sms as u64 * 2048,
                        seed,
                        request.philox_offset,
                    )
                })
                .collect();
            Ok(correlation(values, &predicted))
        })
        .collect()
}
fn correlation(a: &[f64], b: &[f64]) -> f64 {
    let ma = a.iter().sum::<f64>() / a.len() as f64;
    let mb = b.iter().sum::<f64>() / b.len() as f64;
    let (mut xy, mut xx, mut yy) = (0.0, 0.0, 0.0);
    for (x, y) in a.iter().zip(b) {
        let x = x - ma;
        let y = y - mb;
        xy += x * y;
        xx += x * x;
        yy += y * y;
    }
    if xx <= 0.0 || yy <= 0.0 {
        0.0
    } else {
        (xy / (xx * yy).sqrt()).clamp(-1.0, 1.0)
    }
}
pub fn philox(mut c: [u32; 4], mut k: [u32; 2]) -> [u32; 4] {
    for _ in 0..10 {
        let p0 = 0xD2511F53u64 * c[0] as u64;
        let p1 = 0xCD9E8D57u64 * c[2] as u64;
        c = [
            (p1 >> 32) as u32 ^ c[1] ^ k[0],
            p1 as u32,
            (p0 >> 32) as u32 ^ c[3] ^ k[1],
            p0 as u32,
        ];
        k[0] = k[0].wrapping_add(0x9E3779B9);
        k[1] = k[1].wrapping_add(0xBB67AE85);
    }
    c
}
fn normal(position: u64, g: u64, seed: u64, offset: u64) -> f64 {
    let t = position % g;
    let lane = (position / g) % 4;
    let call = offset / 4 + position / (4 * g);
    let words = philox(
        [call as u32, (call >> 32) as u32, t as u32, (t >> 32) as u32],
        [seed as u32, (seed >> 32) as u32],
    );
    let n = if lane < 2 { 0 } else { 2 };
    let inv = 2f32.powi(-32);
    let u = words[n] as f32 * inv + inv / 2.0;
    let tp = inv * 6.2831855f32;
    let v = words[n + 1] as f32 * tp + tp / 2.0;
    let s = (-2.0 * u.ln()).sqrt();
    (if lane.is_multiple_of(2) {
        v.sin() * s
    } else {
        v.cos() * s
    }) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn random123_known_answers() {
        assert_eq!(
            philox([0; 4], [0; 2]),
            [0x6627e8d5, 0xe169c58d, 0xbc57ac4c, 0x9b00dbd8]
        );
        assert_eq!(
            philox([u32::MAX; 4], [u32::MAX; 2]),
            [0x408f276d, 0x41c83b0e, 0xa20bc7c6, 0x6d5451fd]
        );
        assert_eq!(
            philox(
                [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344],
                [0xa4093822, 0x299f31d0]
            ),
            [0xd16cfe09, 0x94fdcceb, 0x5001e420, 0x24126ea1]
        );
    }
    #[test]
    fn duplicate_metadata_is_rejected() {
        assert!(unique_json(br#"{"x":1,"x":2}"#).is_err());
        assert!(unique_json(br#"{"x":{"shape":[],"shape":[]}}"#).is_err());
    }
    #[test]
    fn flat_or_wrong_seed_is_not_evidence() {
        let a: Vec<_> = (400000..404096)
            .map(|i| normal(i, 148 * 2048, 7, 0))
            .collect();
        let b: Vec<_> = (400000..404096)
            .map(|i| normal(i, 148 * 2048, 8, 0))
            .collect();
        assert!(correlation(&a, &b).abs() < 0.1);
        assert_eq!(correlation(&a, &vec![0.0; 4096]), 0.0);
    }
    fn fixture(seed: u64) -> (tempfile::TempDir, ComputeRequest) {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("weights.safetensors");
        let header = serde_json::to_vec(
            &json!({"embedding":{"dtype":"F32","shape":[4000,256],"data_offsets":[0,4000*256*4]}}),
        )
        .unwrap();
        let mut file = File::create(&path).unwrap();
        file.write_all(&(header.len() as u64).to_le_bytes())
            .unwrap();
        file.write_all(&header).unwrap();
        file.set_len((8 + header.len() + 4000 * 256 * 4) as u64)
            .unwrap();
        for row in [2000, 2500, 3000] {
            file.seek(SeekFrom::Start((8 + header.len() + row * 256 * 4) as u64))
                .unwrap();
            for i in 0..256 {
                file.write_all(
                    &(normal((row * 256 + i) as u64, 148 * 2048, seed, 0) as f32).to_le_bytes(),
                )
                .unwrap();
            }
        }
        (
            dir,
            ComputeRequest {
                path,
                tensor: "embedding".into(),
                rows: vec![2000, 2500, 3000],
                seeds: vec![7],
                sm_counts: vec![108, 132, 148, 152],
                philox_offset: 0,
                rows_per_shard: None,
                seed_per_rank: 0,
            },
        )
    }
    #[test]
    fn sparse_streaming_positive_and_wrong_seed_control() {
        let (_dir, request) = fixture(7);
        let result = analyze(&request, &AtomicBool::new(false)).unwrap();
        assert_eq!(result["status"], "candidate_layout_match");
        assert_eq!(result["candidates"][0]["sm_count"], 148);
        assert_eq!(result["sampled_bytes"], 3072);
        let mut wrong = request;
        wrong.seeds = vec![8];
        assert_eq!(
            analyze(&wrong, &AtomicBool::new(false)).unwrap()["status"],
            "unable_to_determine"
        );
    }
    #[test]
    fn cancellation_and_budget_are_enforced() {
        let (_dir, mut request) = fixture(7);
        assert!(analyze(&request, &AtomicBool::new(true)).is_err());
        request.seeds = (1..=16).collect();
        request.sm_counts = default_layouts();
        request.rows = (2000..2064).collect();
        assert!(matches!(
            analyze(&request, &AtomicBool::new(false)),
            Err(Error::Blocked(_))
        ));
    }
    #[test]
    fn shard_index_rejects_traversal() {
        let (dir, mut request) = fixture(7);
        request.path = dir.path().join("model.safetensors.index.json");
        fs::write(
            &request.path,
            br#"{"weight_map":{"embedding":"../weights.safetensors"}}"#,
        )
        .unwrap();
        assert!(matches!(
            analyze(&request, &AtomicBool::new(false)),
            Err(Error::Blocked(_))
        ));
    }
    #[test]
    fn corrupt_header_and_overlapping_ranges_fail() {
        let (dir, mut request) = fixture(7);
        request.path = dir.path().join("bad.safetensors");
        fs::write(&request.path, u64::MAX.to_le_bytes()).unwrap();
        assert!(analyze(&request, &AtomicBool::new(false)).is_err());
        let header=br#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"embedding":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let mut data = (header.len() as u64).to_le_bytes().to_vec();
        data.extend(header);
        data.extend([0; 4]);
        fs::write(&request.path, data).unwrap();
        assert!(analyze(&request, &AtomicBool::new(false)).is_err());
    }
    #[test]
    fn identical_shard_rows_cannot_multiply_evidence() {
        let (_dir, mut request) = fixture(7);
        request.rows = vec![2000, 6000, 10000];
        request.rows_per_shard = Some(4000);
        assert!(
            analyze(&request, &AtomicBool::new(false))
                .unwrap_err()
                .to_string()
                .contains("independent evidence")
        );
    }
}

// FVPROV1 28571 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJkMTdhYjgyYTliYjY3MmY5MzgxYTE2MDJmNDM3NzBiYmFiYzFkNDgyNjBjZjU0OTY4ZWJlMTUwZTVkZDNhYjExIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2NvbXB1dGUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI0OWE4MTI0NDI5NjVlZjA5Y2ExNjMyZTMwZmRkZDdjNGYxNjc3ZWE4NGJjMGI1MzExNWNlZDgyZWE2NGU1MWRkNTNkNjE3OGY0ZTA0ZDBlN2FhZDI0NWU5MjBkMjEzMGEwYmY0MGJlMGE1MzBjNmFhYTc0Y2M3M2Q1ZmM0MGYwZiJ9XX1d FVPROV1-END
