// SPDX-License-Identifier: MPL-2.0
//! Explicit local compiler targets become verified, isolated release artifacts.
use super::{files, pipeline, registry::*, *};
use crate::software::{SoftwareAction, SoftwareMode, SoftwareRequest};
use fileveil_core::{Error, Outcome};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct CompiledRelease {
    pub artifacts: Vec<ProjectDerivedArtifact>,
    pub reports: Vec<Value>,
    pub partially_verified: bool,
    _stage: tempfile::TempDir,
}

pub(super) fn compile(
    config: &ProjectConfig,
    project_root: &Path,
    compiler: &RegistryCompilerConfig,
    request: &ProjectRequest,
    limits: &Limits,
    flag: &AtomicBool,
) -> Result<CompiledRelease> {
    if request.scope.is_some() {
        return Err(files::blocked(
            "MCP registry synchronization cannot execute compiler targets",
        ));
    }
    if compiler.targets.is_empty() || compiler.targets.len() > 16 {
        return Err(Error::Input(
            "Compiler policy requires one to sixteen explicit source or LLVM targets".into(),
        ));
    }
    let access = files::Access::new(None)?;
    let root = access.directory(&config.output_directory, true, true)?;
    let stage = tempfile::Builder::new()
        .prefix(".compiler-stage-")
        .tempdir_in(root.bound_path()?)
        .map_err(|_| Error::Io("Could not stage compiler-derived release files".into()))?;
    let logical_stage = config
        .output_directory
        .join(stage.path().file_name().unwrap());
    let key = request
        .options
        .rotate_to
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pipeline::signing_identity(request, limits))?;
    let mut paths = BTreeSet::new();
    let mut artifacts = Vec::new();
    let mut reports = Vec::new();
    let mut partially_verified = false;
    for target in &compiler.targets {
        files::cancelled(flag)?;
        let relative = files::relative_name(&target.output)?;
        if !paths.insert(relative.to_ascii_lowercase()) {
            return Err(Error::Input("Compiler release target names collide".into()));
        }
        let input = files::absolute(&target.input, project_root)?;
        let extension = input
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let valid = match target.backend {
            CompilerBackend::ClangSource => {
                matches!(extension.as_str(), "c" | "cc" | "cpp" | "cxx" | "c++")
            }
            CompilerBackend::LlvmIr => extension == "ll",
        };
        if !valid {
            return Err(Error::Unsupported(
                "Compiler target backend does not match a supported C/C++ or textual LLVM input"
                    .into(),
            ));
        }
        let source = access.hash(&input, limits.max_file_bytes, flag)?;
        let output = logical_stage.join(&relative);
        access.directory(output.parent().unwrap(), true, true)?;
        let operation = SoftwareRequest {
            action: SoftwareAction::Mark,
            mode: SoftwareMode::Compiler,
            input_path: input.clone(),
            output_path: Some(output.clone()),
            key: Some(key.clone()),
            work_id: config.work_id.clone(),
            copy_id: request
                .options
                .copy_id
                .clone()
                .unwrap_or_else(|| config.copy_id.clone()),
            author: config.author.clone(),
            version: request.options.version.clone(),
            created_at: request.options.created_at.clone(),
            llvm_directory: compiler.llvm_directory.clone(),
            plugin_path: compiler.plugin_path.clone(),
            optimization: if compiler.optimization.is_empty() {
                "O2".into()
            } else {
                compiler.optimization.clone()
            },
            target_triple: compiler.target_triple.clone(),
            compiler_arguments: compiler.compiler_arguments.clone(),
            allow_execution: compiler.allow_execution,
            test_arguments: compiler.test_arguments.clone(),
            trusted_keys: request.options.trusted_keys.clone(),
            ..Default::default()
        };
        let marked = crate::software::run(&operation, limits, flag)?;
        if !matches!(
            marked.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        ) {
            return Err(Error::Verification(
                "Compiler watermark creation did not verify".into(),
            ));
        }
        partially_verified |= marked.result == Outcome::PartiallyVerified;
        let packet = &marked.advanced.as_ref().ok_or_else(|| {
            Error::Verification("Compiler mark omitted its packet evidence".into())
        })?["software"]["packet"];
        let expected_copy = request
            .options
            .copy_id
            .as_deref()
            .unwrap_or(&config.copy_id);
        if packet["signature"] != "valid"
            || packet["decoded"] != true
            || packet["input_sha256"] != source.sha256
            || packet["work_id_digest"] != fileveil_core::digest(config.work_id.as_bytes())
            || packet["copy_id_digest"] != fileveil_core::digest(expected_copy.as_bytes())
        {
            return Err(Error::Verification(
                "Compiler packet does not bind the requested source, work and copy".into(),
            ));
        }
        let verify = SoftwareRequest {
            action: SoftwareAction::Verify,
            input_path: output.clone(),
            output_path: None,
            key: Some(key.clone()),
            ..operation
        };
        let checked = crate::software::run(&verify, limits, flag)?;
        if !matches!(
            checked.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        ) {
            return Err(Error::Verification(
                "Compiler-derived release failed independent read-back verification".into(),
            ));
        }
        let verified_packet=checked.advanced.as_ref().and_then(|value|value["software"]["binary"]["packets"].as_array())
            .and_then(|packets|packets.iter().find(|candidate|
                candidate["packet_sha256"]==packet["packet_sha256"]
                && candidate["signature"]=="valid" && candidate["decoded"]==true
                && candidate["key_id"]==packet["key_id"]
                && candidate["carrier_witness_matches"]==true
                && candidate["input_sha256"]==source.sha256
                && candidate["work_id_digest"]==fileveil_core::digest(config.work_id.as_bytes())
                && candidate["copy_id_digest"]==fileveil_core::digest(expected_copy.as_bytes())))
            .ok_or_else(||Error::Verification("Compiled output does not contain its independently decoded authenticated witness".into()))?;
        let sample = access.hash(&output, config.max_file_bytes, flag)?;
        if marked.output_sha256.as_ref() != Some(&sample.sha256)
            || access.hash(&input, limits.max_file_bytes, flag)?.sha256 != source.sha256
        {
            return Err(Error::Verification(
                "Compiler input or output changed during release verification".into(),
            ));
        }
        reports.push(json!({"path":relative,"input_sha256":source.sha256,"output_sha256":sample.sha256,"packet_sha256":verified_packet["packet_sha256"],"signature":"valid","carrier_witness_matches":true,"mark":marked.result,"verify":checked.result,"mode":"compiler","dependency_closure":"not_assessed"}));
        artifacts.push(ProjectDerivedArtifact {
            path: output,
            relative_name: relative,
            expected_sha256: sample.sha256,
            source_sha256: Some(source.sha256),
            method: "fileveil.compiler.v1".into(),
        });
    }
    Ok(CompiledRelease {
        artifacts,
        reports,
        partially_verified,
        _stage: stage,
    })
}

pub(super) fn asserted_time() -> Result<String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Input("System clock precedes the Unix epoch".into()))?
        .as_secs();
    Ok(format!("unix:{seconds}"))
}

// FVPROV1 8376 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJmZjcyMWYzYTk2ODJlZTUyYjQzOTgwZTBjZDBkMWNjY2Q4YmI3OTkyNmUxZWEwNjJjZTNkYzM4OWU4N2UwOTgyIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3Byb2plY3QvY29tcGlsZXIucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJlOTcyYzE0N2Q0NDYxZjYxNDdiMDlkMWZjMjZkOWQ4MDUzMDhlZWYwNWJhNTU4ZWE5NDZiMTYwYmYxZTg1MDZhNDE1OTcxMjkxOTRkOWU1MzA1NzAzNGIxOGYxMjhmMjI2NjQwMzExYzMwYTVhZDgwNDFlNjA5ODc4Y2QwNzYwNCJ9XX1d FVPROV1-END
