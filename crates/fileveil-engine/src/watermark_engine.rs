// SPDX-License-Identifier: MPL-2.0
//! Shared versioned signal operations and compiled-in forensic detector registry.
use crate::{
    heritage::{legacy, robust, robust_v2},
    media_pixels, watermark,
};
use fileveil_core::{Error, Format, Limits, Result};
use image::DynamicImage;
use serde_json::{Value, json};

pub fn descriptors() -> Value {
    let mut values: Vec<Value> = watermark::detectors()
        .into_iter()
        .map(|value| json!(value))
        .collect();
    values.extend([
        json!({"method_id":"legacy-redstar-woolim-v1","version":"1.0.0","formats":["jpeg","png","docx"],"requires_key":false,"requires_network":false,"evidence_types":["bounded_structure","decoded_public_des_records"],"supports_postprocess_retest":true}),
        json!({"method_id":robust::METHOD_ID,"version":robust::VERSION,"formats":["jpeg","png","heic","avif"],"requires_key":false,"requires_network":false,"evidence_types":["public_frame_crc","geometry"],"supports_postprocess_retest":true}),
        json!({"method_id":robust_v2::METHOD_ID,"version":robust_v2::VERSION,"formats":["jpeg","png","heic","avif"],"requires_key":true,"requires_network":false,"evidence_types":["keyed_payload_mac","bch_corrections","geometry"],"supports_postprocess_retest":true}),
    ]);
    json!(values)
}

pub fn inspect(
    data: &[u8],
    format: Format,
    key: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<Value> {
    let mut detections = Vec::new();
    if matches!(format, Format::Jpeg | Format::Png | Format::Docx) {
        detections.push(json!(legacy::decode(data, limits, false)?));
    }
    if matches!(
        format,
        Format::Jpeg | Format::Png | Format::Heic | Format::Avif
    ) {
        let image = match media_pixels::decode(data, format, limits) {
            Ok(image) => image,
            Err(Error::Unsupported(reason)) => {
                return Ok(
                    json!({"detections":detections,"primary":{"status":"not_assessed","frame_valid":false,"scope":reason},"offline":true}),
                );
            }
            Err(error) => return Err(error),
        };
        let pixel = inspect_pixels(&image, key, limits)?;
        detections.extend(pixel["detections"].as_array().cloned().unwrap_or_default());
        Ok(
            json!({"detections":detections,"primary":pixel["primary"],"offline":true,"scope":"compiled_in_methods_with_separate_key_and_identity_scopes"}),
        )
    } else {
        Ok(
            json!({"detections":detections,"primary":{"status":"not_assessed","frame_valid":false},"offline":true}),
        )
    }
}

pub fn inspect_pixels(
    image: &DynamicImage,
    key: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<Value> {
    let v1 = match robust::detect(image, limits) {
        Ok(value) => json!(value),
        Err(Error::Unsupported(reason)) => {
            json!({"method_id":robust::METHOD_ID,"status":"not_assessed","frame_valid":false,"scope":reason})
        }
        Err(error) => return Err(error),
    };
    let v2 = if let Some(key) = key {
        match robust_v2::detect(image, key, limits) {
            Ok(value) => json!(value),
            Err(Error::Unsupported(reason)) => {
                json!({"method_id":robust_v2::METHOD_ID,"status":"not_assessed","frame_valid":false,"scope":reason})
            }
            Err(error) => return Err(error),
        }
    } else {
        json!({"method_id":robust_v2::METHOD_ID,"status":"not_assessed","frame_valid":false,"scope":"explicit_watermark_key_required"})
    };
    let primary = if v2["frame_valid"] == true
        || (v1["frame_valid"] != true && v2["status"] == "indeterminate")
    {
        v2.clone()
    } else {
        v1.clone()
    };
    let public = watermark::detect_decoded(Some(image), Format::Png, limits)?;
    let mut detections = vec![v1, v2];
    detections.extend(public.into_iter().map(|report| json!(report)));
    let primary = if primary["frame_valid"] != true {
        detections
            .iter()
            .find(|report| report["status"] == "detected")
            .cloned()
            .unwrap_or(primary)
    } else {
        primary
    };
    Ok(json!({"primary":primary,"detections":detections}))
}

pub fn embed(
    image: &DynamicImage,
    work: &str,
    copy: &str,
    key: Option<&[u8; 32]>,
    version: u8,
    strength: u8,
    limits: &Limits,
) -> Result<(DynamicImage, Value)> {
    match version {
        1 => robust::embed(image, work, strength, limits)
            .map(|(image, report)| (image, json!(report))),
        2 => robust_v2::embed(
            image,
            work,
            copy,
            key.ok_or_else(|| {
                Error::Input("Watermark Engine 2 requires an explicit local key".into())
            })?,
            strength,
            limits,
        )
        .map(|(image, report)| (image, json!(report))),
        _ => Err(Error::Unsupported(
            "Unknown watermark protocol version".into(),
        )),
    }
}

pub fn clean(
    image: &DynamicImage,
    key: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<(DynamicImage, Value)> {
    let before = inspect_pixels(image, key, limits)?;
    let v2 = before["detections"]
        .as_array()
        .and_then(|v| v.get(1))
        .is_some_and(|v| v["frame_valid"] == true);
    let mut output = image.clone();
    let mut methods = Vec::new();
    if v2 {
        let key = key.ok_or_else(|| {
            Error::Input("The detected keyed watermark requires its explicit key".into())
        })?;
        output = robust_v2::clean(&output, key, limits)?.0;
        methods.push(robust_v2::METHOD_ID.to_string());
    }
    let v1_detected = match robust::detect(&output, limits) {
        Ok(report) => report.frame_valid,
        Err(Error::Unsupported(_)) => false,
        Err(error) => return Err(error),
    };
    if v1_detected {
        output = robust::clean(&output, limits)?.0;
        methods.push(robust::METHOD_ID.to_string());
    }
    let (public_cleaned, public) = watermark::clean_known_public(&output, limits)?;
    output = public_cleaned;
    methods.extend(public.processed_methods.iter().cloned());
    if methods.is_empty() {
        return Err(Error::Unsupported(
            "No supported removable watermark was detected under the selected key and search scope"
                .into(),
        ));
    }
    let after = inspect_pixels(&output, key, limits)?;
    if after["detections"].as_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| value["frame_valid"] == true || value["status"] == "detected")
    }) {
        return Err(Error::Verification(
            "A selected watermark protocol remains after processing".into(),
        ));
    }
    Ok((
        output,
        json!({"method_id":methods[0],"processed_methods":methods,"public_processing":public,"before":before,"after":after,"status":after["primary"]["status"],"frame_valid":false,"scope":"selected_protocol_clean_and_blind_recheck"}),
    ))
}

// FVPROV1 7023 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiNjgyZDhlNjUxOGJlY2YzYzA3OWFjNWQxZWRjYzBlNWM2ZjMyYWI1ZWFjYmRiN2JiYmE2NDgyOGJjODRiNTJhIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3dhdGVybWFya19lbmdpbmUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJhZDZjNTgyZmVlNDNmNDNlMTFiMTQyNDNkZDkzMzkzZDA1OTk3NGFiZDk3NjQwZWMxOWExOTM2NWJmOGJiYzI3YTNlNGQwNzA3ZmVlYzM1YTBjNjFhNjYxZjEwZmM4Njk5ZmQ2YWJlMzU0NGY5MjFlY2I3MWFlOTY3OTYzNTQwNiJ9XX1d FVPROV1-END
