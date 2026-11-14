// SPDX-License-Identifier: MPL-2.0
//! Typed C2PA identifier association rejects mismatched public payloads.
use fileveil_core::{Format, Limits};
use fileveil_engine::heritage::{
    c2pa_mark::{self, C2paMarkClaims, C2paMarkContext, C2paWatermarkAssociation},
    robust_v2,
};
use std::{fs, path::Path};

fn claims() -> C2paMarkClaims {
    // Keep this literal at the original six fields to pin the public API.
    C2paMarkClaims {
        title: "Copyright test".into(),
        author: "Private test author".into(),
        work_id: "work-05".into(),
        edition: "edition-1".into(),
        version: "1".into(),
        asserted_time: "2026-11-13T00:00:00Z".into(),
    }
}
fn context() -> C2paMarkContext {
    C2paMarkContext {
        copy_id: "copy-03".into(),
        watermark: Some(C2paWatermarkAssociation {
            method_id: robust_v2::METHOD_ID.into(),
            work_id_digest: robust_v2::work_id_digest("work-05").unwrap(),
            copy_id_digest: robust_v2::copy_id_digest("copy-03").unwrap(),
            key_id: "a".repeat(64),
        }),
    }
}

#[test]
fn mismatched_work_copy_protocol_and_key_identifiers_fail_before_signing() {
    let mut invalid = Vec::new();
    let mut value = context();
    value.watermark.as_mut().unwrap().work_id_digest = "0".repeat(24);
    invalid.push(value);
    let mut value = context();
    value.copy_id = "a different copy".into();
    invalid.push(value);
    let mut value = context();
    value.watermark.as_mut().unwrap().method_id = "unregistered-detector".into();
    invalid.push(value);
    let mut value = context();
    value.watermark.as_mut().unwrap().key_id = "A".repeat(64);
    invalid.push(value);
    for context in invalid {
        let error = c2pa_mark::sign_bytes_v2(
            b"image",
            Format::Png,
            b"certificate",
            b"private key",
            &claims(),
            &context,
            &Limits::default(),
        )
        .err()
        .expect("Mismatched association must be rejected");
        assert!(
            error.to_string().contains("association must match"),
            "{error}"
        );
    }
}

#[test]
fn absent_fileveil_assertions_have_no_signed_identifier_association() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let clean = fs::read(root.join("../../tests/fixtures/png_clean.png")).unwrap();
    assert!(
        c2pa_mark::extract_association(&clean, Format::Png, &Limits::default())
            .unwrap()
            .is_none()
    );
    // The committed SDK fixture has no FileVeil work or copy declaration.
    let foreign = fs::read(root.join("tests/fixtures/provenance/signed.png")).unwrap();
    assert!(
        c2pa_mark::extract_association(&foreign, Format::Png, &Limits::default())
            .unwrap()
            .is_none()
    );
}

// FVPROV1 2832 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlZDhkM2ZjMTFlNjkzNjEzNmM1MjI1MTlmOWQ4ZmNkNzUwZjQ3Yzc1YjRjZDIwYzBhYjQ3MTg1YWEyYTEyYmE0IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvYzJwYV9hc3NvY2lhdGlvbi5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImNhY2VhOTU2Y2M5NDVhNzE1ODE1NDAyMWYxMmNmYmUwOWNhNWI3MzU4NDYyMDkzNjAxNTdlZDI1Njk3NThhYmZiYTA5YzIyNmQ3NzViNDQ3NDAzNzExNmQ4MWZlOWU2ZjRlOWI5YzNiNGRiY2U2MWM1NGE5NTQzZDY1YWNkZDBiIn1dfV0= FVPROV1-END
