// SPDX-License-Identifier: MPL-2.0
//! Explicit compiler experiments and verified, no-clobber software copies.
use super::{SoftwareAction, SoftwareMode, SoftwareRequest, container, packet, source, tools};
use crate::{Snapshot, ensure_new_artifact, os, output_directory, publish};
use fileveil_core::{Error, Format, Limits, Outcome, Policy, Report, Result, digest};
use serde_json::{Value, json};
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

fn timeout(request: &SoftwareRequest) -> Result<Duration> {
    if !(1..=3600).contains(&request.timeout_seconds) {
        return Err(Error::Input(
            "Software timeout must be between 1 and 3600 seconds".into(),
        ));
    }
    Ok(Duration::from_secs(request.timeout_seconds))
}

fn scratch(input: &Path, output: Option<&Path>) -> Result<tempfile::TempDir> {
    // The existing desktop supervisor owns this private backend directory and
    // removes it even when a worker is force-killed. Direct library calls keep
    // the ordinary output-filesystem fallback and its RAII cleanup.
    let directory = if let Some(path) = std::env::var_os("FILEVEIL_SOFTWARE_STAGING")
        .or_else(|| std::env::var_os("FILEVEIL_PDF_STAGING"))
    {
        let path = PathBuf::from(path);
        if !path.is_absolute() || !path.is_dir() {
            return Err(Error::Blocked(
                "Software staging must be an absolute supervisor-owned directory".into(),
            ));
        }
        path
    } else {
        output_directory(input, output)
    };
    tempfile::Builder::new()
        .prefix(".fileveil-software-")
        .tempdir_in(directory)
        .map_err(|_| Error::Io("Could not create private software workspace".into()))
}

fn checked_bytes(path: &Path, limits: &Limits) -> Result<Vec<u8>> {
    let mut file = Snapshot::open_file(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limits.max_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io("Could not read generated software artifact".into()))?;
    if bytes.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Generated software artifact exceeds the file byte limit".into(),
        ));
    }
    Ok(bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| Error::Io("Could not create private software input".into()))?;
    file.write_all(bytes)
        .map_err(|_| Error::Io("Could not write private software input".into()))
}

fn recipe(request: &SoftwareRequest) -> Result<String> {
    let mut value = serde_json::to_value(request)
        .map_err(|_| Error::Input("Invalid software request".into()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::Input("Invalid software request".into()))?;
    object.remove("input_path");
    object.remove("output_path");
    object.remove("key");
    object.insert(
        "signing_identity".into(),
        packet::load_key(request)?
            .map(|key| key.public_key().key_id)
            .into(),
    );
    // Only StructureClean is supervisor-published. Compiler experiments publish
    // inside their already confined local worker after their own verification.
    Ok(digest(&serde_json::to_vec(&value).map_err(|_| {
        Error::Input("Invalid software recipe".into())
    })?))
}

fn base_report(request: &SoftwareRequest, snapshot: &Snapshot) -> Report {
    let mut report = Report::new("software", Format::Unknown);
    report.policy = Policy::Research;
    report.input_sha256 = Some(digest(&snapshot.bytes));
    report.integrity.parseable = true;
    report.advanced = Some(json!({"software": {
        "schema":"fileveil.software.report.v1", "action":request.action,
        "mode":request.mode,"execution_authorized":request.allow_execution,
        "experimental":true,"network_used":false,
    }}));
    report
}

fn details_mut(report: &mut Report) -> &mut Value {
    &mut report
        .advanced
        .as_mut()
        .expect("software report initialized")["software"]
}

fn publish_bytes(
    input: &Path,
    output: &Path,
    original: &Snapshot,
    bytes: &[u8],
    report: &mut Report,
    limits: &Limits,
    executable: bool,
) -> Result<()> {
    if !original.unchanged(input, limits)? {
        return Err(Error::Verification(
            "Original software input changed during processing".into(),
        ));
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".fileveil-software-output-")
        .tempfile_in(parent)
        .map_err(|_| Error::Io("Could not create private software output".into()))?;
    temporary
        .write_all(bytes)
        .map_err(|_| Error::Io("Could not write software output".into()))?;
    temporary
        .flush()
        .map_err(|_| Error::Io("Could not flush software output".into()))?;
    ensure_new_artifact(&original.file, temporary.as_file())?;
    os::write(temporary.as_file(), temporary.path(), &original.attributes)?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::Io("Could not set generated executable permissions".into()))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    let staged = Snapshot::open(temporary.path(), limits)?;
    if staged.bytes != bytes || staged.attributes != original.attributes {
        return Err(Error::Verification(
            "Generated software publication changed bytes or security attributes".into(),
        ));
    }
    if !original.unchanged(input, limits)? {
        return Err(Error::Verification(
            "Original software input changed before publication".into(),
        ));
    }
    let target = publish(temporary.into_temp_path(), input, Some(output))?;
    report.output_name = target
        .file_name()
        .map(|value| value.to_string_lossy().into_owned());
    report.output_sha256 = Some(digest(bytes));
    report.integrity.original_unchanged = Some(true);
    report.integrity.security_markers_preserved = Some(true);
    Ok(())
}

pub(super) fn run(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
) -> Result<Report> {
    let duration = timeout(request)?;
    tools::check_cancel(cancelled)?;
    validate_arguments(request)?;
    if request.action == SoftwareAction::BuildPlugin {
        return build_plugin(request, duration, cancelled);
    }
    let original = Snapshot::open(&request.input_path, limits)?;
    let mut report = base_report(request, &original);
    let work = scratch(&request.input_path, request.output_path.as_deref())?;
    match request.action {
        SoftwareAction::Inspect | SoftwareAction::Detect | SoftwareAction::Verify => {
            if request.mode == SoftwareMode::Source {
                inspect_source(request, &original, &mut report)?;
            } else if request.mode == SoftwareMode::Ir {
                inspect_ir(
                    request,
                    limits,
                    cancelled,
                    &original,
                    work.path(),
                    &mut report,
                )?;
            } else {
                inspect_binary(
                    request,
                    limits,
                    cancelled,
                    &original,
                    work.path(),
                    &mut report,
                )?;
            }
        }
        SoftwareAction::Compare => compare(
            request,
            limits,
            cancelled,
            &original,
            work.path(),
            &mut report,
        )?,
        SoftwareAction::Mark => {
            if request.mode == SoftwareMode::Structure {
                mark_structure(request, limits, &original, &mut report)?;
            } else if request.mode == SoftwareMode::Source {
                mark_source(
                    request,
                    limits,
                    cancelled,
                    &original,
                    work.path(),
                    &mut report,
                )?;
            } else {
                mark(
                    request,
                    limits,
                    cancelled,
                    &original,
                    work.path(),
                    &mut report,
                )?;
            }
        }
        SoftwareAction::Clean => {
            if request.mode == SoftwareMode::Structure {
                clean_structure(request, limits, &original, &mut report)?;
            } else if request.mode == SoftwareMode::Source {
                clean_source(request, limits, &original, &mut report)?;
            } else {
                clean_compiler(
                    request,
                    limits,
                    cancelled,
                    &original,
                    work.path(),
                    &mut report,
                )?;
            }
        }
        SoftwareAction::Lab => lab(
            request,
            limits,
            cancelled,
            &original,
            work.path(),
            &mut report,
        )?,
        SoftwareAction::BuildPlugin => unreachable!(),
    }
    if !original.unchanged(&request.input_path, limits)? {
        return Err(Error::Verification(
            "Original software input changed during the operation".into(),
        ));
    }
    report.integrity.original_unchanged = Some(true);
    details_mut(&mut report)["recipe_sha256"] = recipe(request)?.into();
    Ok(report)
}

fn validate_arguments(request: &SoftwareRequest) -> Result<()> {
    if request.compiler_arguments.len() > 128
        || request.test_arguments.len() > 32
        || request
            .compiler_arguments
            .iter()
            .chain(request.test_arguments.iter().flatten())
            .any(|value| value.contains('\0') || value.len() > 16 * 1024)
        || request
            .test_arguments
            .iter()
            .any(|arguments| arguments.len() > 128)
    {
        return Err(Error::Input(
            "Software arguments exceed their bounded contract".into(),
        ));
    }
    let protected = [
        "-o",
        "--output",
        "-MF",
        "-MJ",
        "-serialize-diagnostics",
        "--serialize-diagnostics",
        "-Xlinker",
        "-Xclang",
        "-load",
        "-plugin",
        "-S",
        "-c",
        "-E",
        "-emit-llvm",
    ];
    for value in &request.compiler_arguments {
        if protected.contains(&value.as_str())
            || value.starts_with('@')
            || value.starts_with("--output=")
            || value.starts_with("-fpass-plugin")
            || value.starts_with("-fplugin")
            || value.starts_with("-Wl,")
            || value.starts_with("-Wa,")
            || value.starts_with("-Wp,")
            || (value.starts_with("-o") && value.len() > 2)
            || value.starts_with("-fmodule-output")
            || value.starts_with("-fprofile-")
        {
            return Err(Error::Input("Compiler arguments cannot redirect managed outputs or load additional compiler plugins".into()));
        }
    }
    tools::optimization(&request.optimization)?;
    tools::target_flags(request.target_triple.as_deref())?;
    Ok(())
}

fn toolchain(
    request: &SoftwareRequest,
    work: &Path,
    cancelled: &AtomicBool,
) -> Result<tools::Toolchain> {
    tools::discover(
        request.llvm_directory.as_deref(),
        work,
        timeout(request)?,
        cancelled,
    )
}

fn inspect_ir(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    work: &Path,
    report: &mut Report,
) -> Result<()> {
    let chain = toolchain(request, work, cancelled)?;
    let plugin = tools::plugin(request.plugin_path.as_deref(), &chain)?;
    details_mut(report)["pass_execution_kind"] = json!(plugin.execution_kind);
    let path = work.join("input.ll");
    write_private(&path, &original.bytes)?;
    let inspection = ir_operation(
        &chain, &plugin, "inspect", &path, None, None, work, request, cancelled,
    )?;
    let marked = inspection["marked"].as_bool().unwrap_or(false);
    details_mut(report)["ir"] = inspection.clone();
    details_mut(report)["llvm_version"] = chain.version.into();
    if marked {
        let bytes = decode_hex(inspection["packet_hex"].as_str().ok_or_else(|| {
            Error::Verification("LLVM inspect omitted the authenticated packet".into())
        })?)?;
        let key = packet::load_key(request)?;
        details_mut(report)["packet"] = packet::inspect(
            &bytes,
            key.as_ref(),
            &request.trusted_keys,
            request.disclose_private,
        )?;
    }
    let _ = limits;
    report.result = Outcome::PartiallyVerified;
    report.warnings.push("IR structure was inspected. Static marker presence alone does not establish runtime execution or complete absence of other software watermarks".into());
    Ok(())
}

fn inspect_binary(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    work: &Path,
    report: &mut Report,
) -> Result<()> {
    let binary = container::inspect(&original.bytes, limits)?;
    let key = packet::load_key(request)?;
    details_mut(report)["binary"] = binary.report(request, key.as_ref())?;
    let input = work.join("inspect.bin");
    write_private(&input, &original.bytes)?;
    match toolchain(request, work, cancelled).and_then(|chain| disassemble(&chain, &input, work, request, cancelled)) {
        Ok(disassembly) => { details_mut(report)["disassembly"] = disassembly; }
        Err(Error::Interrupted(message)) => return Err(Error::Interrupted(message)),
        Err(_) => report.warnings.push("LLVM instruction/CFG analysis was unavailable. Container and signed-packet inspection remain available".into()),
    }
    report.result = Outcome::PartiallyVerified;
    if request.action == SoftwareAction::Verify
        && report.advanced.as_ref().is_some_and(|advanced| {
            advanced["software"]["binary"]["packets"]
                .as_array()
                .is_some_and(|packets| {
                    packets.iter().any(|packet| {
                        packet["verification"] == "failed"
                            || packet["carrier_witness_matches"] == false
                    })
                })
        })
    {
        report.result = Outcome::Failed;
        report.warnings.push("A recognized software packet failed its signature, format or carrier-binding verification".into());
    }
    report.warnings.push("Container, normalized instructions and CFG candidates are scoped forensic evidence. Unknown software watermarks and runtime behavior remain unassessed".into());
    Ok(())
}

fn disassemble(
    chain: &tools::Toolchain,
    path: &Path,
    work: &Path,
    request: &SoftwareRequest,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let output = tools::run(
        &chain.objdump,
        &[
            "--disassemble".into(),
            "--no-show-raw-insn".into(),
            path.as_os_str().into(),
        ],
        work,
        &[],
        timeout(request)?,
        cancelled,
    )?;
    let mut value = container::disassembly(&String::from_utf8_lossy(&output.stdout));
    value["metrics"] = serde_json::to_value(output.metrics)
        .map_err(|_| Error::Io("Could not serialize disassembly metrics".into()))?;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
fn ir_operation(
    chain: &tools::Toolchain,
    plugin: &tools::Plugin,
    action: &str,
    input: &Path,
    output: Option<&Path>,
    pass_packet: Option<&Path>,
    work: &Path,
    request: &SoftwareRequest,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let (program, arguments) = pass_command(chain, plugin, action, input, output)?;
    let environment = pass_packet
        .map(|path| vec![("FILEVEIL_SOFTWARE_PACKET", path.as_os_str())])
        .unwrap_or_default();
    let output = tools::run(
        &program,
        &arguments,
        work,
        &environment,
        timeout(request)?,
        cancelled,
    )?;
    if action == "mark" {
        return Ok(json!({"llvm_ir_verified":true,"metrics":output.metrics,
            "pass_execution_kind":plugin.execution_kind}));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| Error::Verification("LLVM pass returned invalid structured evidence".into()))
}

fn pass_command(
    chain: &tools::Toolchain,
    plugin: &tools::Plugin,
    action: &str,
    input: &Path,
    output: Option<&Path>,
) -> Result<(PathBuf, Vec<OsString>)> {
    if !matches!(action, "inspect" | "mark" | "clean") || (action == "inspect") != output.is_none()
    {
        return Err(Error::Input("Invalid managed LLVM pass operation".into()));
    }
    match plugin.execution_kind {
        tools::PassExecutionKind::Plugin => {
            let mut arguments = vec![
                OsString::from(format!("-load-pass-plugin={}", plugin.path.display())),
                format!("-passes=fileveil-{action}").into(),
            ];
            if let Some(output) = output {
                arguments.extend([
                    "-S".into(),
                    input.as_os_str().into(),
                    "-o".into(),
                    output.as_os_str().into(),
                ]);
            } else {
                arguments.extend(["-disable-output".into(), input.as_os_str().into()]);
            }
            Ok((chain.opt.clone(), arguments))
        }
        tools::PassExecutionKind::StandaloneDriver => {
            let mut arguments = vec![
                "--operation".into(),
                action.into(),
                "--input".into(),
                input.as_os_str().into(),
            ];
            if let Some(output) = output {
                arguments.extend(["--output".into(), output.as_os_str().into()]);
            }
            Ok((plugin.path.clone(), arguments))
        }
    }
}

fn is_ir(path: &Path) -> bool {
    path.extension()
        .is_some_and(|value| value == "ll" || value == "bc")
}

fn compiler(chain: &tools::Toolchain, input: &Path) -> Result<PathBuf> {
    let cxx = input
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|value| matches!(value, "cpp" | "cc" | "cxx" | "C" | "c++"));
    if cxx {
        let path = chain
            .directory
            .join("bin")
            .join(format!("clang++{}", std::env::consts::EXE_SUFFIX));
        if !path.is_file() {
            return Err(Error::Unsupported(
                "The matching clang++ driver is unavailable".into(),
            ));
        }
        Ok(path)
    } else {
        Ok(chain.clang.clone())
    }
}

fn flags(request: &SoftwareRequest, work: &Path, cancelled: &AtomicBool) -> Result<Vec<OsString>> {
    let mut flags = if request.target_triple.is_none() {
        tools::native_flags(work, timeout(request)?, cancelled)?
    } else {
        tools::target_flags(request.target_triple.as_deref())?
    };
    flags.extend(request.compiler_arguments.iter().map(OsString::from));
    Ok(flags)
}

fn base_ir(
    request: &SoftwareRequest,
    limits: &Limits,
    source_path: &Path,
    source: &Snapshot,
    chain: &tools::Toolchain,
    work: &Path,
    cancelled: &AtomicBool,
) -> Result<PathBuf> {
    let output = work.join("base.ll");
    if is_ir(source_path) {
        write_private(&output, &source.bytes)?;
        return Ok(output);
    }
    let basename = source_path
        .file_name()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Input("Source input has no filename".into()))?;
    let local = work.join(basename);
    write_private(&local, &source.bytes)?;
    let mut arguments = flags(request, work, cancelled)?;
    arguments.extend([
        "-O1".into(),
        "-Xclang".into(),
        "-disable-llvm-passes".into(),
        "-S".into(),
        "-emit-llvm".into(),
    ]);
    if let Some(parent) = source_path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
    {
        arguments.extend([
            "-iquote".into(),
            fs::canonicalize(parent)
                .map_err(|_| Error::Input("Source include directory is unavailable".into()))?
                .into_os_string(),
        ]);
    }
    arguments.extend([basename.into(), "-o".into(), output.as_os_str().into()]);
    tools::run_producing(
        &compiler(chain, source_path)?,
        &arguments,
        work,
        &[],
        timeout(request)?,
        cancelled,
        &output,
        limits.max_file_bytes,
    )?;
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn compile(
    request: &SoftwareRequest,
    limits: &Limits,
    source_path: &Path,
    chain: &tools::Toolchain,
    ir: &Path,
    output: &Path,
    work: &Path,
    shared: bool,
    cancelled: &AtomicBool,
) -> Result<tools::Metrics> {
    let mut arguments = flags(request, work, cancelled)?;
    arguments.push(tools::optimization(&request.optimization)?);
    if request.optimization == "LTO" {
        arguments.push("-flto".into());
        #[cfg(target_os = "macos")]
        if request.target_triple.is_none() {
            arguments.push(
                format!(
                    "-Wl,-lto_library,{}",
                    chain.directory.join("lib/libLTO.dylib").display()
                )
                .into(),
            );
        }
    }
    if shared {
        if cfg!(target_os = "macos") {
            arguments.push("-dynamiclib".into());
        } else {
            arguments.extend(["-shared".into(), "-fPIC".into()]);
        }
    }
    arguments.extend([
        ir.as_os_str().into(),
        "-o".into(),
        output.as_os_str().into(),
    ]);
    Ok(tools::run_producing(
        &compiler(chain, source_path)?,
        &arguments,
        work,
        &[],
        timeout(request)?,
        cancelled,
        output,
        limits.max_file_bytes,
    )?
    .metrics)
}

fn functional_compare(
    request: &SoftwareRequest,
    before: &Path,
    after: &Path,
    work: &Path,
    cancelled: &AtomicBool,
) -> Result<Value> {
    if !request.allow_execution {
        return Ok(json!({"assessed":false,"scope":"execution_not_authorized"}));
    }
    if request.target_triple.is_some() {
        return Err(Error::Input(
            "Native functional execution requires the native target; omit the cross target triple"
                .into(),
        ));
    }
    let empty = vec![Vec::new()];
    let cases = if request.test_arguments.is_empty() {
        &empty
    } else {
        &request.test_arguments
    };
    let mut rows = Vec::new();
    for arguments in cases {
        let argv: Vec<OsString> = arguments.iter().map(OsString::from).collect();
        let baseline = tools::run_test(before, &argv, work, timeout(request)?, cancelled)?;
        let changed = tools::run_test(after, &argv, work, timeout(request)?, cancelled)?;
        let equal = baseline.exit_code == changed.exit_code
            && baseline.stdout == changed.stdout
            && baseline.stderr == changed.stderr;
        rows.push(json!({"argument_count":arguments.len(),"equal":equal,
            "baseline":{"exit_code":baseline.exit_code,"stdout_sha256":digest(&baseline.stdout),"stderr_sha256":digest(&baseline.stderr),"metrics":baseline.metrics},
            "output":{"exit_code":changed.exit_code,"stdout_sha256":digest(&changed.stdout),"stderr_sha256":digest(&changed.stderr),"metrics":changed.metrics}}));
        if !equal {
            return Err(Error::Verification(
                "Generated software differs on a supplied functional test vector".into(),
            ));
        }
    }
    Ok(
        json!({"assessed":true,"scope":"provided_native_test_vectors","all_equal":true,"tests":rows}),
    )
}

fn mark(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    work: &Path,
    report: &mut Report,
) -> Result<()> {
    let output = request
        .output_path
        .as_deref()
        .ok_or_else(|| Error::Input("Software Mark requires a new output path".into()))?;
    let chain = toolchain(request, work, cancelled)?;
    let plugin = tools::plugin(request.plugin_path.as_deref(), &chain)?;
    details_mut(report)["pass_execution_kind"] = json!(plugin.execution_kind);
    let base = base_ir(
        request,
        limits,
        &request.input_path,
        original,
        &chain,
        work,
        cancelled,
    )?;
    let inspection = ir_operation(
        &chain, &plugin, "inspect", &base, None, None, work, request, cancelled,
    )?;
    if inspection["marked"] == true {
        return Err(Error::Blocked(
            "Software Mark requires an unmarked source/IR version; reuse the unmarked original"
                .into(),
        ));
    }
    let canonical = inspection["canonical_ir_sha256"]
        .as_str()
        .ok_or_else(|| Error::Verification("Canonical input IR digest is unavailable".into()))?;
    let key = packet::load_key(request)?
        .ok_or_else(|| Error::Input("Software Mark requires a signing identity".into()))?;
    let prepared = packet::prepare(request, &key, &digest(&original.bytes), Some(canonical))?;
    let pass_packet = work.join("pass-packet.json");
    write_private(
        &pass_packet,
        &serde_json::to_vec(&prepared.pass_json())
            .map_err(|_| Error::Input("Invalid public compiler packet".into()))?,
    )?;
    let marked = work.join("marked.ll");
    ir_operation(
        &chain,
        &plugin,
        "mark",
        &base,
        Some(&marked),
        Some(&pass_packet),
        work,
        request,
        cancelled,
    )?;
    let after = ir_operation(
        &chain, &plugin, "inspect", &marked, None, None, work, request, cancelled,
    )?;
    if after["marked"] != true
        || after["base_ir_sha256"] != canonical
        || decode_hex(after["packet_hex"].as_str().unwrap_or_default())? != prepared.bytes
    {
        return Err(Error::Verification(
            "Marked LLVM IR did not preserve its authenticated packet and base digest".into(),
        ));
    }
    details_mut(report)["llvm_version"] = chain.version.clone().into();
    details_mut(report)["packet"] = packet::inspect(
        &prepared.bytes,
        Some(&key),
        &request.trusted_keys,
        request.disclose_private,
    )?;
    details_mut(report)["canonical_input_ir_sha256"] = canonical.into();
    let (bytes, executable) = if request.mode == SoftwareMode::Ir {
        report.result = Outcome::VerifiedWithinScope;
        details_mut(report)["verification_scope"] =
            "authenticated_packet_and_verified_llvm_ir".into();
        (checked_bytes(&marked, limits)?, false)
    } else {
        let marked_binary = work.join(format!("marked{}", std::env::consts::EXE_SUFFIX));
        let metrics = compile(
            request,
            limits,
            &request.input_path,
            &chain,
            &marked,
            &marked_binary,
            work,
            false,
            cancelled,
        )?;
        let bytes = checked_bytes(&marked_binary, limits)?;
        let parsed = container::inspect(&bytes, limits)?;
        if !parsed
            .carriers
            .iter()
            .any(|carrier| carrier.packet == prepared.bytes && carrier.witness == prepared.witness)
        {
            return Err(Error::Verification(
                "The compiler/linker removed or changed the authenticated software carrier".into(),
            ));
        }
        details_mut(report)["binary"] = parsed.report(request, Some(&key))?;
        details_mut(report)["build_metrics"] = serde_json::to_value(metrics)
            .map_err(|_| Error::Io("Invalid compiler metrics".into()))?;
        if request.allow_execution {
            let baseline = work.join(format!("baseline{}", std::env::consts::EXE_SUFFIX));
            let metrics = compile(
                request,
                limits,
                &request.input_path,
                &chain,
                &base,
                &baseline,
                work,
                false,
                cancelled,
            )?;
            details_mut(report)["baseline_build_metrics"] = serde_json::to_value(metrics)
                .map_err(|_| Error::Io("Invalid compiler metrics".into()))?;
            details_mut(report)["functional"] =
                functional_compare(request, &baseline, &marked_binary, work, cancelled)?;
            report.integrity.content_equal = Some(true);
            report.result = Outcome::VerifiedWithinScope;
        } else {
            details_mut(report)["functional"] =
                json!({"assessed":false,"scope":"execution_not_authorized"});
            report.result = Outcome::PartiallyVerified;
        }
        details_mut(report)["verification_scope"] =
            "authenticated_compiler_carrier_with_optional_supplied_native_test_vectors".into();
        (bytes, true)
    };
    report.warnings.push("The experimental witness is independently removable from controlled IR. Resistance to a determined program rewrite and general behavioral equivalence remain unproven".into());
    publish_bytes(
        &request.input_path,
        output,
        original,
        &bytes,
        report,
        limits,
        executable,
    )?;
    Ok(())
}

fn inspect_source(
    request: &SoftwareRequest,
    original: &Snapshot,
    report: &mut Report,
) -> Result<()> {
    let found = match source::decode(&original.bytes) {
        Ok(found) => found,
        Err(Error::Unsupported(_)) => {
            report.result = Outcome::NotAssessed;
            details_mut(report)["source"] =
                json!({"detected":false,"scope":"known_source_witness_protocol_only"});
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let key = packet::load_key(request)?;
    let authenticated = packet::inspect(
        &found.packet,
        key.as_ref(),
        &request.trusted_keys,
        request.disclose_private,
    )?;
    let prefix_matches =
        authenticated["input_sha256"].as_str() == Some(digest(&found.prefix).as_str());
    details_mut(report)["source"] = json!({"detected":true,"original_prefix_sha256":digest(&found.prefix),"prefix_matches_signed_original":prefix_matches,"runtime_assessed":false});
    details_mut(report)["packet"] = authenticated;
    report.result = if prefix_matches {
        Outcome::PartiallyVerified
    } else {
        Outcome::Failed
    };
    Ok(())
}

fn mark_source(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    work: &Path,
    report: &mut Report,
) -> Result<()> {
    if is_ir(&request.input_path) {
        return Err(Error::Input(
            "Source mode requires C/C++ source input; select IR for LLVM modules".into(),
        ));
    }
    let output = request
        .output_path
        .as_deref()
        .ok_or_else(|| Error::Input("Source Mark requires a new C/C++ output path".into()))?;
    let chain = toolchain(request, work, cancelled)?;
    let plugin = tools::plugin(request.plugin_path.as_deref(), &chain)?;
    details_mut(report)["pass_execution_kind"] = json!(plugin.execution_kind);
    let base = base_ir(
        request,
        limits,
        &request.input_path,
        original,
        &chain,
        work,
        cancelled,
    )?;
    let inspection = ir_operation(
        &chain, &plugin, "inspect", &base, None, None, work, request, cancelled,
    )?;
    if inspection["marked"] == true {
        return Err(Error::Blocked(
            "Source Mark requires an unmarked original".into(),
        ));
    }
    let canonical = inspection["canonical_ir_sha256"]
        .as_str()
        .ok_or_else(|| Error::Verification("Canonical source IR digest is unavailable".into()))?;
    let key = packet::load_key(request)?
        .ok_or_else(|| Error::Input("Source Mark requires a signing identity".into()))?;
    let prepared = packet::prepare(request, &key, &digest(&original.bytes), Some(canonical))?;
    let bytes = source::encode(&original.bytes, &prepared)?;
    let source_work = work.join("source-compile");
    fs::create_dir(&source_work)
        .map_err(|_| Error::Io("Could not create source validation workspace".into()))?;
    let mut compile_request = request.clone();
    if let Some(parent) = request
        .input_path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
    {
        compile_request.compiler_arguments.extend([
            "-iquote".into(),
            fs::canonicalize(parent)
                .map_err(|_| {
                    Error::Input("Original source include directory is unavailable".into())
                })?
                .to_string_lossy()
                .into_owned(),
        ]);
    }
    let marked_path = work.join("source-marked").join(
        request
            .input_path
            .file_name()
            .ok_or_else(|| Error::Input("Source input has no filename".into()))?,
    );
    fs::create_dir(marked_path.parent().unwrap())
        .map_err(|_| Error::Io("Could not create source staging folder".into()))?;
    write_private(&marked_path, &bytes)?;
    let marked_snapshot = Snapshot::open(&marked_path, limits)?;
    let marked_ir = base_ir(
        &compile_request,
        limits,
        &marked_path,
        &marked_snapshot,
        &chain,
        &source_work,
        cancelled,
    )?;
    let object = work.join("source-check.o");
    let mut arguments = flags(&compile_request, work, cancelled)?;
    arguments.extend([
        tools::optimization(&request.optimization)?,
        "-c".into(),
        marked_ir.as_os_str().into(),
        "-o".into(),
        object.as_os_str().into(),
    ]);
    let build = tools::run_producing(
        &compiler(&chain, &request.input_path)?,
        &arguments,
        work,
        &[],
        timeout(request)?,
        cancelled,
        &object,
        limits.max_file_bytes,
    )?;
    let parsed = container::inspect(&checked_bytes(&object, limits)?, limits)?;
    if !parsed
        .carriers
        .iter()
        .any(|carrier| carrier.packet == prepared.bytes && carrier.witness == prepared.witness)
    {
        return Err(Error::Verification(
            "Compiled source witness did not retain its authenticated native carrier".into(),
        ));
    }
    details_mut(report)["packet"] = packet::inspect(
        &prepared.bytes,
        Some(&key),
        &request.trusted_keys,
        request.disclose_private,
    )?;
    details_mut(report)["source"] = json!({"generated":true,"original_prefix_preserved":true,"syntax_and_native_object_checked":true,
        "canonical_original_ir_sha256":canonical,"build_metrics":build.metrics,
        "file_macro_scope":"same_basename_controlled_compilation; external_renames_need_equivalent_fmacro_prefix_map"});
    details_mut(report)["verification_scope"] =
        "authenticated_source_prefix_and_compiled_native_witness_structure".into();
    if request.allow_execution {
        let before = work.join(format!("baseline{}", std::env::consts::EXE_SUFFIX));
        let after = work.join(format!("marked{}", std::env::consts::EXE_SUFFIX));
        compile(
            request,
            limits,
            &request.input_path,
            &chain,
            &base,
            &before,
            work,
            false,
            cancelled,
        )?;
        compile(
            &compile_request,
            limits,
            &request.input_path,
            &chain,
            &marked_ir,
            &after,
            work,
            false,
            cancelled,
        )?;
        details_mut(report)["functional"] =
            functional_compare(request, &before, &after, work, cancelled)?;
        let library = work.join(if cfg!(target_os = "macos") {
            "source-witness.dylib"
        } else if cfg!(windows) {
            "source-witness.dll"
        } else {
            "source-witness.so"
        });
        compile(
            &compile_request,
            limits,
            &request.input_path,
            &chain,
            &marked_ir,
            &library,
            work,
            true,
            cancelled,
        )?;
        details_mut(report)["runtime"] = runtime_probe(
            request,
            &chain,
            &library,
            prepared.challenge,
            prepared.witness,
            work,
            cancelled,
        )?;
        report.integrity.content_equal = Some(true);
        report.result = Outcome::VerifiedWithinScope;
    } else {
        report.result = Outcome::PartiallyVerified;
    }
    report.warnings.push("Source validation uses a controlled filename and compiler recipe. Later macro changes, file renames and unsupplied build settings require renewed verification".into());
    publish_bytes(
        &request.input_path,
        output,
        original,
        &bytes,
        report,
        limits,
        false,
    )
}

fn clean_source(
    request: &SoftwareRequest,
    limits: &Limits,
    original: &Snapshot,
    report: &mut Report,
) -> Result<()> {
    let output = request
        .output_path
        .as_deref()
        .ok_or_else(|| Error::Input("Source Clean requires a new output path".into()))?;
    let found = source::decode(&original.bytes)?;
    let key = packet::load_key(request)?.ok_or_else(|| Error::Blocked("Source cleanup requires the correct extraction identity to reproduce the complete witness".into()))?;
    let authenticated = packet::inspect(
        &found.packet,
        Some(&key),
        &request.trusted_keys,
        request.disclose_private,
    )?;
    if authenticated["decoded"] != true
        || authenticated["input_sha256"].as_str() != Some(digest(&found.prefix).as_str())
    {
        return Err(Error::Verification(
            "Source prefix or extraction identity does not match the signed original".into(),
        ));
    }
    let challenge = authenticated["challenge_hex"]
        .as_str()
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .ok_or_else(|| Error::Verification("Source extraction challenge is unavailable".into()))?;
    let prepared = packet::PreparedPacket {
        bytes: found.packet,
        witness: found.witness,
        challenge,
    };
    if source::encode(&found.prefix, &prepared)? != original.bytes {
        return Err(Error::Blocked(
            "Source witness or later user code changed. Byte-exact controlled cleanup is protected"
                .into(),
        ));
    }
    details_mut(report)["packet"] = authenticated;
    details_mut(report)["verification_scope"] =
        "byte_exact_authenticated_original_source_restoration".into();
    report.integrity.content_equal = Some(true);
    report.result = Outcome::VerifiedWithinScope;
    publish_bytes(
        &request.input_path,
        output,
        original,
        &found.prefix,
        report,
        limits,
        false,
    )
}

fn mark_structure(
    request: &SoftwareRequest,
    limits: &Limits,
    original: &Snapshot,
    report: &mut Report,
) -> Result<()> {
    let output = request
        .output_path
        .as_deref()
        .ok_or_else(|| Error::Input("Structure Mark requires a new output path".into()))?;
    let key = packet::load_key(request)?
        .ok_or_else(|| Error::Input("Structure Mark requires a signing identity".into()))?;
    let prepared = packet::prepare(request, &key, &digest(&original.bytes), None)?;
    let bytes = container::append_footer(&original.bytes, &prepared, limits)?;
    let parsed = container::inspect(&bytes, limits)?;
    if !parsed
        .carriers
        .iter()
        .any(|value| value.packet == prepared.bytes)
    {
        return Err(Error::Verification(
            "Native footer did not retain its authenticated packet".into(),
        ));
    }
    details_mut(report)["binary"] = parsed.report(request, Some(&key))?;
    details_mut(report)["verification_scope"] =
        "authenticated_container_footer_with_original_prefix_binding".into();
    details_mut(report)["runtime_witness"] = "not_embedded".into();
    report.result = Outcome::VerifiedWithinScope;
    publish_bytes(
        &request.input_path,
        output,
        original,
        &bytes,
        report,
        limits,
        true,
    )
}

fn clean_structure(
    request: &SoftwareRequest,
    limits: &Limits,
    original: &Snapshot,
    report: &mut Report,
) -> Result<()> {
    let output = request
        .output_path
        .as_deref()
        .ok_or_else(|| Error::Input("Software Clean requires a new output path".into()))?;
    let before = container::inspect(&original.bytes, limits)?;
    let bytes = container::clean_bytes(&original.bytes, limits)?;
    let after = container::inspect(&bytes, limits)?;
    if !after.carriers.is_empty() || !after.descriptors.is_empty() {
        return Err(Error::Verification(
            "Known non-executing software carriers remain after cleanup".into(),
        ));
    }
    for section in before.sections.iter().filter(|section| section.executable) {
        if !after.sections.iter().any(|value| {
            value.offset == section.offset
                && value.size == section.size
                && value.sha256 == section.sha256
        }) {
            return Err(Error::Verification(
                "Software cleanup changed an executable section".into(),
            ));
        }
    }
    let key = packet::load_key(request)?;
    details_mut(report)["before"] = before.report(request, key.as_ref())?;
    details_mut(report)["after"] = after.report(request, key.as_ref())?;
    details_mut(report)["removed_carriers"] = before.carriers.len().into();
    details_mut(report)["removed_descriptors"] = before.descriptors.len().into();
    details_mut(report)["verification_scope"] = "known_non_executing_carrier_spans_only".into();
    details_mut(report)["runtime_witness_removal"] = "not_assessed_semantic_code_preserved".into();
    report.result = Outcome::PartiallyVerified;
    report.warnings.push("Known non-executing carrier records were cleared. Runtime dataflow witnesses and unknown software watermarks can remain".into());
    publish_bytes(
        &request.input_path,
        output,
        original,
        &bytes,
        report,
        limits,
        true,
    )
}

fn clean_compiler(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    work: &Path,
    report: &mut Report,
) -> Result<()> {
    let output = request
        .output_path
        .as_deref()
        .ok_or_else(|| Error::Input("Software Clean requires a new output path".into()))?;
    let chain = toolchain(request, work, cancelled)?;
    let plugin = tools::plugin(request.plugin_path.as_deref(), &chain)?;
    details_mut(report)["pass_execution_kind"] = json!(plugin.execution_kind);
    let key = packet::load_key(request)?;
    if request.mode == SoftwareMode::Ir {
        let marked = work.join("marked.ll");
        write_private(&marked, &original.bytes)?;
        let inspection = ir_operation(
            &chain, &plugin, "inspect", &marked, None, None, work, request, cancelled,
        )?;
        let packet = decode_hex(inspection["packet_hex"].as_str().unwrap_or_default())?;
        let authenticated = packet::inspect(
            &packet,
            key.as_ref(),
            &request.trusted_keys,
            request.disclose_private,
        )?;
        let clean = work.join("clean.ll");
        let result = ir_operation(
            &chain,
            &plugin,
            "clean",
            &marked,
            Some(&clean),
            None,
            work,
            request,
            cancelled,
        )?;
        if result["canonical_base_restored"] != true {
            return Err(Error::Blocked("IR cleanup changed the canonical base. A separately controlled rebuild and functional comparison is required".into()));
        }
        if authenticated["signature"] != "valid"
            || authenticated["ir_sha256"] != result["clean_ir_sha256"]
        {
            return Err(Error::Verification(
                "Canonical IR restoration does not match the signed original digest".into(),
            ));
        }
        details_mut(report)["packet"] = authenticated;
        details_mut(report)["ir_clean"] = result;
        details_mut(report)["verification_scope"] =
            "exact_canonical_ir_restoration_and_llvm_verification".into();
        report.result = Outcome::VerifiedWithinScope;
        let bytes = checked_bytes(&clean, limits)?;
        return publish_bytes(
            &request.input_path,
            output,
            original,
            &bytes,
            report,
            limits,
            false,
        );
    }
    let reference_path = request.reference_path.as_deref().ok_or_else(|| {
        Error::Input(
            "Compiler Clean requires the corresponding unmarked source or IR reference".into(),
        )
    })?;
    let reference = Snapshot::open(reference_path, limits)?;
    let binary = container::inspect(&original.bytes, limits)?;
    let carrier = binary.carriers.first().ok_or_else(|| {
        Error::Blocked(
            "No authenticated carrier is available to bind the rebuild to an original version"
                .into(),
        )
    })?;
    let authenticated = packet::inspect(
        &carrier.packet,
        key.as_ref(),
        &request.trusted_keys,
        request.disclose_private,
    )?;
    let original_ir = base_ir(
        request,
        limits,
        reference_path,
        &reference,
        &chain,
        work,
        cancelled,
    )?;
    let inspection = ir_operation(
        &chain,
        &plugin,
        "inspect",
        &original_ir,
        None,
        None,
        work,
        request,
        cancelled,
    )?;
    if inspection["marked"] != false {
        return Err(Error::Blocked(
            "Rebuild reference must be an unmarked original".into(),
        ));
    }
    let canonical = inspection["canonical_ir_sha256"]
        .as_str()
        .unwrap_or_default();
    let bound = authenticated["input_sha256"].as_str() == Some(digest(&reference.bytes).as_str())
        && authenticated["ir_sha256"].as_str() == Some(canonical);
    if !bound {
        return Err(Error::Blocked("Reference source/IR does not match the authenticated original and canonical IR digests".into()));
    }
    let rebuilt = work.join(format!("clean{}", std::env::consts::EXE_SUFFIX));
    let metrics = compile(
        request,
        limits,
        reference_path,
        &chain,
        &original_ir,
        &rebuilt,
        work,
        false,
        cancelled,
    )?;
    let bytes = checked_bytes(&rebuilt, limits)?;
    let after = container::inspect(&bytes, limits)?;
    if !after.carriers.is_empty() || !after.descriptors.is_empty() {
        return Err(Error::Verification(
            "Rebuilt original still contains recognized software carriers".into(),
        ));
    }
    if request.allow_execution {
        let before = work.join(format!("before{}", std::env::consts::EXE_SUFFIX));
        write_private(&before, &original.bytes)?;
        executable_permissions(&before)?;
        details_mut(report)["functional"] =
            functional_compare(request, &before, &rebuilt, work, cancelled)?;
        report.integrity.content_equal = Some(true);
    }
    if !reference.unchanged(reference_path, limits)? {
        return Err(Error::Verification(
            "Rebuild reference changed during compilation".into(),
        ));
    }
    details_mut(report)["packet"] = authenticated;
    details_mut(report)["canonical_input_ir_sha256"] = canonical.into();
    details_mut(report)["build_metrics"] =
        serde_json::to_value(metrics).map_err(|_| Error::Io("Invalid compiler metrics".into()))?;
    details_mut(report)["after"] = after.report(request, key.as_ref())?;
    details_mut(report)["verification_scope"] =
        "authenticated_original_ir_recompiled_with_optional_supplied_test_vectors".into();
    report.result = Outcome::VerifiedWithinScope;
    report.warnings.push("The rebuilt compilation unit matches its authenticated unmarked IR. External libraries, unsupplied runtime inputs and unrelated software watermark schemes remain outside verification scope".into());
    publish_bytes(
        &request.input_path,
        output,
        original,
        &bytes,
        report,
        limits,
        true,
    )
}

fn executable_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::Io("Could not prepare controlled test executable".into()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn compare(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    work: &Path,
    report: &mut Report,
) -> Result<()> {
    let reference_path = request
        .reference_path
        .as_deref()
        .ok_or_else(|| Error::Input("Software Compare requires a second artifact".into()))?;
    let reference = Snapshot::open(reference_path, limits)?;
    let before = container::inspect(&original.bytes, limits)?;
    let after = container::inspect(&reference.bytes, limits)?;
    let key = packet::load_key(request)?;
    details_mut(report)["before"] = before.report(request, key.as_ref())?;
    details_mut(report)["after"] = after.report(request, key.as_ref())?;
    let unchanged_sections = before
        .sections
        .iter()
        .filter(|first| {
            after
                .sections
                .iter()
                .any(|second| second.name == first.name && second.sha256 == first.sha256)
        })
        .count();
    details_mut(report)["comparison"] = json!({"byte_equal":original.bytes == reference.bytes,"same_section_hashes":unchanged_sections,
        "before_sections":before.sections.len(),"after_sections":after.sections.len(),"reference_sha256":digest(&reference.bytes)});
    let left = work.join("before.bin");
    let right = work.join("after.bin");
    write_private(&left, &original.bytes)?;
    write_private(&right, &reference.bytes)?;
    let instruction_analysis = toolchain(request, work, cancelled).and_then(|chain| {
        Ok((
            disassemble(&chain, &left, work, request, cancelled)?,
            disassemble(&chain, &right, work, request, cancelled)?,
        ))
    });
    match instruction_analysis {
        Ok((before_instructions, after_instructions)) => {
            details_mut(report)["instruction_comparison"] = super::forensics::compare(&before_instructions, &after_instructions);
            details_mut(report)["before_disassembly"] = before_instructions;
            details_mut(report)["after_disassembly"] = after_instructions;
        }
        Err(Error::Interrupted(message)) => return Err(Error::Interrupted(message)),
        Err(_) => report.warnings.push("LLVM disassembly was unavailable. Comparison covers the parsed containers and independently hashed sections".into()),
    }
    if request.allow_execution {
        executable_permissions(&left)?;
        executable_permissions(&right)?;
        details_mut(report)["functional"] =
            functional_compare(request, &left, &right, work, cancelled)?;
        report.integrity.content_equal = Some(true);
    }
    if !reference.unchanged(reference_path, limits)? {
        return Err(Error::Verification(
            "Comparison reference changed during analysis".into(),
        ));
    }
    report.result = Outcome::PartiallyVerified;
    report.warnings.push("Matching normalized instructions, sections or supplied functional tests cannot establish general semantic equivalence or authorship".into());
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() > 65536 {
        return Err(Error::Input(
            "Invalid bounded software packet encoding".into(),
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            digit(pair[0])
                .zip(digit(pair[1]))
                .map(|(high, low)| high * 16 + low)
                .ok_or_else(|| Error::Input("Invalid software packet hexadecimal character".into()))
        })
        .collect()
}

fn pass_source_directory(
    input: &Path,
    configured: Option<std::ffi::OsString>,
    executable: Option<PathBuf>,
    development: PathBuf,
) -> Result<PathBuf> {
    let candidates = if !input.as_os_str().is_empty() {
        vec![input.to_path_buf()]
    } else if let Some(configured) = configured {
        vec![PathBuf::from(configured)]
    } else {
        let mut candidates = Vec::new();
        if let Some(executable) = executable
            && let Some(parent) = executable.parent()
        {
            candidates.push(parent.join("resources/software-watermark"));
            candidates.push(parent.join("../Resources/software-watermark"));
        }
        candidates.push(development);
        candidates
    };
    candidates
        .into_iter()
        .filter_map(|candidate| candidate.canonicalize().ok())
        .find(|candidate| candidate.join("CMakeLists.txt").is_file())
        .ok_or_else(|| {
            Error::Input("Software pass sources with CMakeLists.txt are unavailable".into())
        })
}

fn build_plugin(
    request: &SoftwareRequest,
    duration: Duration,
    cancelled: &AtomicBool,
) -> Result<Report> {
    let source = pass_source_directory(
        &request.input_path,
        std::env::var_os("FILEVEIL_SOFTWARE_TOOLS"),
        std::env::current_exe().ok(),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/software-watermark"),
    )?;
    let output = request.output_path.as_deref().ok_or_else(|| {
        Error::Input("BuildPlugin requires an explicit local build directory".into())
    })?;
    fs::create_dir_all(output)
        .map_err(|_| Error::Io("Could not create software plugin build directory".into()))?;
    let output = fs::canonicalize(output)
        .map_err(|_| Error::Io("Could not resolve software plugin build directory".into()))?;
    if source == output {
        return Err(Error::Input(
            "Plugin build directory must differ from its source directory".into(),
        ));
    }
    let chain = toolchain(request, &output, cancelled)?;
    let cmake = tools::cmake(&source, &output)?;
    let arguments = vec![
        "-S".into(),
        source.as_os_str().into(),
        "-B".into(),
        output.as_os_str().into(),
        format!(
            "-DLLVM_DIR={}",
            chain.directory.join("lib/cmake/llvm").display()
        )
        .into(),
        format!("-DCMAKE_C_COMPILER={}", chain.clang.display()).into(),
        format!(
            "-DCMAKE_CXX_COMPILER={}",
            chain
                .directory
                .join("bin")
                .join(format!("clang++{}", std::env::consts::EXE_SUFFIX))
                .display()
        )
        .into(),
    ];
    let configure = tools::run(&cmake, &arguments, &output, &[], duration, cancelled)?;
    let build = tools::run(
        &cmake,
        &[
            "--build".into(),
            output.as_os_str().into(),
            "--config".into(),
            "Release".into(),
            "-j2".into(),
        ],
        &output,
        &[],
        duration,
        cancelled,
    )?;
    let (plugin, metadata) = built_plugin(&output, &chain)?;
    let mut report = Report::new("software", Format::Unknown);
    report.policy = Policy::Research;
    report.result = Outcome::VerifiedWithinScope;
    report.advanced = Some(
        json!({"software":{"schema":"fileveil.software.report.v1","action":"build_plugin",
        "pass_execution_kind":plugin.execution_kind,
        "abi":metadata,"configure_metrics":configure.metrics,"build_metrics":build.metrics,
        "plugin_sha256":digest(&fs::read(&plugin.path).map_err(|_| Error::Io("Could not read built plugin".into()))?),
        "scope":"local_plugin_build_and_abi_metadata","network_used":false}}),
    );
    Ok(report)
}

fn built_plugin(output: &Path, chain: &tools::Toolchain) -> Result<(tools::Plugin, Value)> {
    let mut built = Vec::new();
    // CMake single-config targets live at the root. Multi-config builds above
    // explicitly select Release, while Debug metadata can exist without a file.
    for directory in [output.to_path_buf(), output.join("Release")] {
        let metadata_path = directory.join("fileveil-plugin.json");
        if !metadata_path.is_file() {
            continue;
        }
        let mut bytes = Vec::new();
        fs::File::open(&metadata_path)
            .and_then(|file| file.take(16 * 1024 + 1).read_to_end(&mut bytes))
            .map_err(|_| Error::Verification("Plugin build omitted ABI metadata".into()))?;
        if bytes.len() > 16 * 1024 {
            return Err(Error::Verification(
                "Plugin build ABI metadata exceeds its limit".into(),
            ));
        }
        let metadata: Value = serde_json::from_slice(&bytes).map_err(|_| {
            Error::Verification("Plugin build returned invalid ABI metadata".into())
        })?;
        let filename = metadata["plugin"]
            .as_str()
            .ok_or_else(|| Error::Verification("Plugin build omitted its filename".into()))?;
        if Path::new(filename)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
            || Path::new(filename).components().count() != 1
        {
            return Err(Error::Verification(
                "Plugin build returned an unsafe filename".into(),
            ));
        }
        let path = directory.join(filename);
        if path.is_file() {
            built.push((tools::plugin(Some(&path), chain)?, metadata));
        }
    }
    if built.len() != 1 {
        return Err(Error::Verification(
            "Plugin build must produce one unambiguous pass artifact with adjacent ABI metadata"
                .into(),
        ));
    }
    Ok(built.remove(0))
}

fn lab(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    work: &Path,
    report: &mut Report,
) -> Result<()> {
    let chain = toolchain(request, work, cancelled)?;
    let key = packet::load_key(request)?
        .ok_or_else(|| Error::Input("Compiler Lab requires an explicit signing identity".into()))?;
    let mut rows = Vec::new();
    let mut failed = false;
    for optimization in ["O0", "O2", "O3", "LTO"] {
        tools::check_cancel(cancelled)?;
        let directory = work.join(optimization);
        fs::create_dir(&directory)
            .map_err(|_| Error::Io("Could not create compiler matrix case".into()))?;
        let result = lab_case(
            request,
            limits,
            cancelled,
            original,
            &chain,
            &key,
            &directory,
            optimization,
        );
        match result {
            Ok(value) => rows.push(value),
            Err(Error::Interrupted(message)) => return Err(Error::Interrupted(message)),
            Err(error) => {
                failed = true;
                rows.push(json!({"optimization":optimization,"status":"failed","error":error.to_string()}));
            }
        }
    }
    let static_passes = rows
        .iter()
        .filter(|row| row["known_carrier_detected"] == true)
        .count();
    let runtime_passes = rows
        .iter()
        .filter(|row| row["runtime"]["witness_matches"] == true)
        .count();
    let negative_cases = rows
        .iter()
        .filter(|row| row["clean_rebuild_detected"] == false)
        .count();
    details_mut(report)["lab"] = json!({"schema":"fileveil.software.lab.v1","llvm_version":chain.version,
        "cases":rows,"case_count":4,"known_carrier_detections":static_passes,
        "runtime_matches":runtime_passes,"negative_clean_rebuild_cases":negative_cases,
        "execution_assessed":request.allow_execution,"target":request.target_triple,
        "false_positive_scope":"four_controlled_unmarked_rebuilds_only",
        "robustness_scope":"compiler_optimizations_strip_and_relink_for_this_compilation_unit",
        "general_semantic_watermark_resistance":"not_assessed"});
    report.result = if failed {
        Outcome::Failed
    } else if request.allow_execution {
        Outcome::VerifiedWithinScope
    } else {
        Outcome::PartiallyVerified
    };
    report.warnings.push("Compiler Lab measures one controlled compilation unit. Its detection and negative-control counts cannot estimate population false-positive rates or resistance to arbitrary program rewrites".into());
    if let Some(output) = request.output_path.as_deref() {
        let bytes = serde_json::to_vec_pretty(&report.advanced)
            .map_err(|_| Error::Io("Could not serialize compiler matrix".into()))?;
        publish_bytes(
            &request.input_path,
            output,
            original,
            &bytes,
            report,
            limits,
            false,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lab_case(
    request: &SoftwareRequest,
    limits: &Limits,
    cancelled: &AtomicBool,
    original: &Snapshot,
    chain: &tools::Toolchain,
    key: &crate::heritage::signing::SigningKey,
    directory: &Path,
    optimization: &str,
) -> Result<Value> {
    let mark_work = directory.join("mark");
    let clean_work = directory.join("clean-work");
    fs::create_dir(&mark_work)
        .and_then(|_| fs::create_dir(&clean_work))
        .map_err(|_| Error::Io("Could not create private compiler case workspaces".into()))?;
    let marked = directory.join(format!("marked{}", std::env::consts::EXE_SUFFIX));
    let clean = directory.join(format!("clean{}", std::env::consts::EXE_SUFFIX));
    let mut mark_request = request.clone();
    mark_request.action = SoftwareAction::Mark;
    mark_request.mode = SoftwareMode::Compiler;
    mark_request.optimization = optimization.into();
    mark_request.output_path = Some(marked.clone());
    let mut mark_report = base_report(&mark_request, original);
    mark(
        &mark_request,
        limits,
        cancelled,
        original,
        &mark_work,
        &mut mark_report,
    )?;
    let marked_snapshot = Snapshot::open(&marked, limits)?;
    let parsed = container::inspect(&marked_snapshot.bytes, limits)?;
    let carrier = parsed
        .carriers
        .first()
        .ok_or_else(|| Error::Verification("Lab compiler case lost its packet".into()))?;
    let decoded = packet::inspect(&carrier.packet, Some(key), &request.trusted_keys, false)?;
    let mut clean_request = mark_request.clone();
    clean_request.action = SoftwareAction::Clean;
    clean_request.input_path = marked.clone();
    clean_request.reference_path = Some(request.input_path.clone());
    clean_request.output_path = Some(clean.clone());
    let mut clean_report = base_report(&clean_request, &marked_snapshot);
    clean_compiler(
        &clean_request,
        limits,
        cancelled,
        &marked_snapshot,
        &clean_work,
        &mut clean_report,
    )?;
    let clean_bytes = checked_bytes(&clean, limits)?;
    let clean_parsed = container::inspect(&clean_bytes, limits)?;
    let stripped = directory.join(format!("stripped{}", std::env::consts::EXE_SUFFIX));
    fs::copy(&marked, &stripped).map_err(|_| Error::Io("Could not prepare strip attack".into()))?;
    tools::run(
        &chain.strip,
        &["--strip-all".into(), stripped.as_os_str().into()],
        directory,
        &[],
        timeout(request)?,
        cancelled,
    )?;
    let stripped_bytes = checked_bytes(&stripped, limits)?;
    let stripped_parsed = container::inspect(&stripped_bytes, limits)?;
    let strip_detected = stripped_parsed
        .carriers
        .iter()
        .any(|value| value.packet == carrier.packet);
    if !strip_detected {
        return Err(Error::Verification(
            "Known software carrier did not survive the measured strip transformation".into(),
        ));
    }
    let relinked = directory.join(format!("relinked{}", std::env::consts::EXE_SUFFIX));
    compile(
        &mark_request,
        limits,
        &request.input_path,
        chain,
        &mark_work.join("marked.ll"),
        &relinked,
        directory,
        false,
        cancelled,
    )?;
    let relinked_parsed = container::inspect(&checked_bytes(&relinked, limits)?, limits)?;
    let relink_detected = relinked_parsed
        .carriers
        .iter()
        .any(|value| value.packet == carrier.packet);
    if !relink_detected {
        return Err(Error::Verification(
            "Known software carrier did not survive measured relinking".into(),
        ));
    }
    let mut value = json!({"optimization":optimization,"status":if request.allow_execution {"verified_within_scope"}else{"partially_verified"},
        "known_carrier_detected":true,"packet_signature":decoded["signature"],
        "strip_detected":strip_detected,"relink_detected":relink_detected,
        "clean_rebuild_detected":!clean_parsed.carriers.is_empty(),
        "marked_bytes":marked_snapshot.bytes.len(),"clean_bytes":clean_bytes.len(),
        "mark":mark_report.advanced.as_ref().map(|value| &value["software"]),
        "clean":clean_report.advanced.as_ref().map(|value| &value["software"])});
    if request.allow_execution {
        if request.target_triple.is_some() {
            return Err(Error::Input(
                "Compiler runtime Lab requires the native target".into(),
            ));
        }
        let challenge = decoded["challenge_hex"]
            .as_str()
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .ok_or_else(|| {
                Error::Verification("Lab could not derive the authorized challenge".into())
            })?;
        let library = directory.join(if cfg!(target_os = "macos") {
            "witness.dylib"
        } else if cfg!(windows) {
            "witness.dll"
        } else {
            "witness.so"
        });
        compile(
            &mark_request,
            limits,
            &request.input_path,
            chain,
            &mark_work.join("marked.ll"),
            &library,
            directory,
            true,
            cancelled,
        )?;
        let runtime = runtime_probe(
            &mark_request,
            chain,
            &library,
            challenge,
            carrier.witness,
            directory,
            cancelled,
        )?;
        value["runtime"] = runtime;
    } else {
        value["runtime"] = json!({"assessed":false,"scope":"execution_not_authorized"});
    }
    Ok(value)
}

const PROBE_SOURCE: &str = r#"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
typedef uint32_t (*probe_function)(uint32_t, uint64_t);
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  probe_function function;
#ifdef _WIN32
  wchar_t name[32768];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[1], -1, name, 32768)) return 3;
  HMODULE library = LoadLibraryW(name);
  if (!library) return 4;
  function = (probe_function)GetProcAddress(library, "fileveil_swm_probe_v1");
#else
  void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) return 4;
  function = (probe_function)dlsym(library, "fileveil_swm_probe_v1");
#endif
  if (!function) return 5;
  uint64_t challenge = strtoull(argv[2], 0, 16);
  if (function(9, challenge) != UINT32_MAX) return 6;
  printf("[");
  for (unsigned index = 0; index < 9; ++index) {
    printf("%s%u", index ? "," : "", function(index, challenge));
  }
  printf("]\n");
  return 0;
}
"#;

fn runtime_probe(
    request: &SoftwareRequest,
    chain: &tools::Toolchain,
    library: &Path,
    challenge: u64,
    witness: u64,
    work: &Path,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let source = work.join("probe.c");
    let program = work.join(format!("probe{}", std::env::consts::EXE_SUFFIX));
    write_private(&source, PROBE_SOURCE.as_bytes())?;
    let mut arguments = tools::native_flags(work, timeout(request)?, cancelled)?;
    arguments.extend([
        source.into_os_string(),
        "-O2".into(),
        "-o".into(),
        program.as_os_str().into(),
    ]);
    #[cfg(target_os = "linux")]
    arguments.push("-ldl".into());
    tools::run(
        &chain.clang,
        &arguments,
        work,
        &[],
        timeout(request)?,
        cancelled,
    )?;
    let actual = tools::run(
        &program,
        &[
            library.as_os_str().into(),
            format!("{challenge:016x}").into(),
        ],
        work,
        &[],
        timeout(request)?,
        cancelled,
    )?;
    let wrong = tools::run(
        &program,
        &[
            library.as_os_str().into(),
            format!("{:016x}", challenge ^ 0x12345678).into(),
        ],
        work,
        &[],
        timeout(request)?,
        cancelled,
    )?;
    let residues: Vec<u32> = serde_json::from_slice(&actual.stdout)
        .map_err(|_| Error::Verification("Runtime probe returned invalid residues".into()))?;
    let wrong_residues: Vec<u32> = serde_json::from_slice(&wrong.stdout).map_err(|_| {
        Error::Verification("Wrong-challenge runtime probe returned invalid residues".into())
    })?;
    let recovered = recover(&residues)?;
    let wrong_matches = recover(&wrong_residues)? == witness as u128;
    if recovered != witness as u128 || wrong_matches {
        return Err(Error::Verification(
            "Actual runtime CRT witness or wrong-challenge control failed".into(),
        ));
    }
    Ok(
        json!({"assessed":true,"scope":"actually_executed_controlled_shared_companion_from_same_marked_ir",
        "witness_matches":true,"wrong_challenge_matches":false,"residues":residues,
        "residue_sha256":digest(&actual.stdout),"execution_metrics":actual.metrics,
        "executable_internal_function_directly_probed":false}),
    )
}

fn recover(residues: &[u32]) -> Result<u128> {
    const PRIMES: [u128; 9] = [251, 241, 239, 233, 229, 227, 223, 211, 199];
    if residues.len() != PRIMES.len() {
        return Err(Error::Verification(
            "Runtime probe requires nine CRT residues".into(),
        ));
    }
    let mut value = 0u128;
    let mut modulus = 1u128;
    for (&residue, prime) in residues.iter().zip(PRIMES) {
        if residue as u128 >= prime {
            return Err(Error::Verification(
                "Runtime residue exceeds its modulus".into(),
            ));
        }
        let inverse = (1..prime)
            .find(|candidate| (modulus % prime) * candidate % prime == 1)
            .ok_or_else(|| Error::Verification("Invalid CRT modulus".into()))?;
        let adjustment = ((residue as u128 + prime - value % prime) * inverse) % prime;
        value += adjustment * modulus;
        modulus *= prime;
    }
    Ok(value)
}

pub(super) fn publish_staged(
    input: &Path,
    stage: &Path,
    output: &Path,
    report: &mut Report,
    limits: &Limits,
    request: &SoftwareRequest,
) -> Result<()> {
    if request.action != SoftwareAction::Clean || request.mode != SoftwareMode::Structure {
        return Err(Error::Blocked(
            "Supervisor software publication requires scoped native Structure Clean".into(),
        ));
    }
    let original = Snapshot::open(input, limits)?;
    let staged = Snapshot::open(stage, limits)?;
    ensure_new_artifact(&original.file, &staged.file)?;
    if report.input_sha256.as_deref() != Some(digest(&original.bytes).as_str())
        || report.output_sha256.as_deref() != Some(digest(&staged.bytes).as_str())
        || report
            .advanced
            .as_ref()
            .and_then(|value| value["software"]["recipe_sha256"].as_str())
            != Some(recipe(request)?.as_str())
        || staged.attributes != original.attributes
    {
        return Err(Error::Verification("Software staged bytes, recipe or security attributes differ from their verified report".into()));
    }
    let expected = container::clean_bytes(&original.bytes, limits)?;
    if expected != staged.bytes {
        return Err(Error::Verification(
            "Software worker modified bytes outside known non-executing carriers".into(),
        ));
    }
    let parsed = container::inspect(&staged.bytes, limits)?;
    if !parsed.carriers.is_empty() || !parsed.descriptors.is_empty() {
        return Err(Error::Verification(
            "Recognized software carriers remain in staged output".into(),
        ));
    }
    if !original.unchanged(input, limits)? || !staged.unchanged(stage, limits)? {
        return Err(Error::Verification(
            "Software publication snapshots changed".into(),
        ));
    }
    let path = tempfile::TempPath::try_from_path(stage)
        .map_err(|_| Error::Io("Could not acquire staged software artifact".into()))?;
    let target = publish(path, input, Some(output))?;
    report.output_name = target
        .file_name()
        .map(|value| value.to_string_lossy().into_owned());
    report.integrity.original_unchanged = Some(true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{heritage::signing::SigningKey, project::ProjectKey};

    #[test]
    fn packaged_pass_sources_resolve_without_the_development_checkout() {
        let directory = tempfile::tempdir().unwrap();
        for (name, executable, relative_sources) in [
            (
                "portable",
                "FileVeil/fileveil",
                "FileVeil/resources/software-watermark",
            ),
            (
                "macos",
                "FileVeil.app/Contents/MacOS/FileVeil",
                "FileVeil.app/Contents/Resources/software-watermark",
            ),
        ] {
            let root = directory.path().join(name);
            let executable = root.join(executable);
            let sources = root.join(relative_sources);
            fs::create_dir_all(executable.parent().unwrap()).unwrap();
            fs::create_dir_all(&sources).unwrap();
            fs::write(sources.join("CMakeLists.txt"), b"synthetic build recipe").unwrap();
            let selected = pass_source_directory(
                Path::new(""),
                None,
                Some(executable),
                root.join("missing-ci-checkout"),
            )
            .unwrap();
            assert_eq!(selected, sources.canonicalize().unwrap());
        }
    }

    #[test]
    fn explicit_pass_sources_and_environment_keep_priority() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("selected-source");
        let configured = directory.path().join("configured-source");
        let development = directory.path().join("development-source");
        for source in [&input, &configured, &development] {
            fs::create_dir_all(source).unwrap();
            fs::write(source.join("CMakeLists.txt"), b"synthetic build recipe").unwrap();
        }
        let selected = pass_source_directory(
            &input,
            Some(configured.clone().into_os_string()),
            None,
            development.clone(),
        )
        .unwrap();
        assert_eq!(selected, input.canonicalize().unwrap());
        let selected = pass_source_directory(
            Path::new(""),
            Some(configured.clone().into_os_string()),
            None,
            development.clone(),
        )
        .unwrap();
        assert_eq!(selected, configured.canonicalize().unwrap());
        assert!(
            pass_source_directory(
                &directory.path().join("missing-selected-source"),
                None,
                None,
                development,
            )
            .is_err()
        );
    }

    #[test]
    fn built_pass_discovery_requires_one_existing_release_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let chain = tools::Toolchain {
            directory: "llvm".into(),
            clang: "clang".into(),
            opt: "opt".into(),
            objdump: "llvm-objdump".into(),
            strip: "llvm-strip".into(),
            version: "23.1.5".into(),
            major: 23,
        };
        let metadata = json!({
            "schema":"fileveil.software.llvm-plugin.v1", "llvm_major":23,
            "plugin":"FileVeilWatermarkDriver", "execution_kind":"standalone_driver",
            "architecture":std::env::consts::ARCH,
            "platform":if cfg!(windows) { "Windows" } else if cfg!(target_os="macos") { "Darwin" } else { "Linux" }
        });
        let encoded = serde_json::to_vec(&metadata).unwrap();
        for config in ["", "Debug", "Release"] {
            let path = directory.path().join(config);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("fileveil-plugin.json"), &encoded).unwrap();
        }
        let release = directory.path().join("Release/FileVeilWatermarkDriver");
        fs::write(&release, b"unexecuted driver fixture").unwrap();
        let (plugin, _) = built_plugin(directory.path(), &chain).unwrap();
        assert_eq!(plugin.path, release.canonicalize().unwrap());
        assert_eq!(
            plugin.execution_kind,
            tools::PassExecutionKind::StandaloneDriver
        );
        fs::write(
            directory.path().join("FileVeilWatermarkDriver"),
            b"ambiguous old driver",
        )
        .unwrap();
        assert!(built_plugin(directory.path(), &chain).is_err());
    }

    #[test]
    fn managed_pass_commands_select_the_declared_backend_with_fixed_arguments() {
        let chain = tools::Toolchain {
            directory: "llvm".into(),
            clang: "clang".into(),
            opt: "opt".into(),
            objdump: "llvm-objdump".into(),
            strip: "llvm-strip".into(),
            version: "23.1.5".into(),
            major: 23,
        };
        let mut plugin = tools::Plugin {
            path: "FileVeilWatermarkDriver".into(),
            execution_kind: tools::PassExecutionKind::StandaloneDriver,
        };
        let input = Path::new("input.ll");
        let output = Path::new("output.ll");
        for action in ["mark", "clean"] {
            let (program, arguments) =
                pass_command(&chain, &plugin, action, input, Some(output)).unwrap();
            assert_eq!(program, plugin.path);
            assert_eq!(
                arguments,
                [
                    "--operation",
                    action,
                    "--input",
                    "input.ll",
                    "--output",
                    "output.ll"
                ]
                .map(OsString::from)
            );
        }
        let (program, arguments) = pass_command(&chain, &plugin, "inspect", input, None).unwrap();
        assert_eq!(program, plugin.path);
        assert_eq!(
            arguments,
            ["--operation", "inspect", "--input", "input.ll"].map(OsString::from)
        );
        plugin.execution_kind = tools::PassExecutionKind::Plugin;
        let (program, arguments) =
            pass_command(&chain, &plugin, "mark", input, Some(output)).unwrap();
        assert_eq!(program, chain.opt);
        assert_eq!(
            arguments,
            [
                "-load-pass-plugin=FileVeilWatermarkDriver",
                "-passes=fileveil-mark",
                "-S",
                "input.ll",
                "-o",
                "output.ll",
            ]
            .map(OsString::from)
        );
        for (action, output) in [
            ("unknown", None),
            ("mark", None),
            ("clean", None),
            ("inspect", Some(output)),
        ] {
            assert!(pass_command(&chain, &plugin, action, input, output).is_err());
        }
    }

    #[test]
    fn runtime_crt_recovers_all_64_bits_and_checks_bounds() {
        const PRIMES: [u64; 9] = [251, 241, 239, 233, 229, 227, 223, 211, 199];
        for witness in [0, 1, 0x123456789abcdef, u64::MAX] {
            let residues: Vec<u32> = PRIMES
                .iter()
                .map(|prime| (witness % prime) as u32)
                .collect();
            assert_eq!(recover(&residues).unwrap(), witness as u128);
        }
        assert!(recover(&[0; 8]).is_err());
        assert!(recover(&[251, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn compiler_arguments_cannot_redirect_managed_outputs() {
        for argument in [
            "-o",
            "-ooutside",
            "--output=outside",
            "@outside",
            "-Wl,-o,outside",
            "-fpass-plugin=outside",
        ] {
            let request = SoftwareRequest {
                compiler_arguments: vec![argument.into()],
                ..Default::default()
            };
            assert!(validate_arguments(&request).is_err(), "{argument}");
        }
        let request = SoftwareRequest {
            compiler_arguments: vec!["-std=c11".into(), "-DVALUE=7".into(), "-Iinclude".into()],
            ..Default::default()
        };
        validate_arguments(&request).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly built matching LLVM plugin and native compiler"]
    fn native_source_ir_compiler_and_lab_close_the_real_loop() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("main.c");
        let source_bytes = br#"#include <stdio.h>
#include <stdlib.h>
static unsigned original_count;
__attribute__((constructor)) static void original_ctor(void) { original_count++; }
int main(int argc,char **argv) {
  unsigned rounds=argc>1?(unsigned)strtoul(argv[1],0,10):3;
  unsigned long long value=0x123456789abcdefULL;
  for(unsigned index=0;index<rounds;index++) value=(value^(value>>7))*0x9e3779b97f4a7c15ULL;
  printf("%016llx %u\n",value,original_count);
  return original_count==1?0:2;
}
"#;
        fs::write(&source, source_bytes).unwrap();
        let key_path = directory.path().join("owner.key");
        SigningKey::generate().unwrap().save_new(&key_path).unwrap();
        let request = SoftwareRequest {
            action: SoftwareAction::Mark,
            input_path: source.clone(),
            key: Some(ProjectKey::File { path: key_path }),
            work_id: "compiler-regression".into(),
            copy_id: "copy-a".into(),
            author: "FileVeil tests".into(),
            version: "1".into(),
            llvm_directory: Some(
                std::env::var_os("FILEVEIL_LLVM_DIR")
                    .map(PathBuf::from)
                    .expect("FILEVEIL_LLVM_DIR"),
            ),
            plugin_path: Some(
                std::env::var_os("FILEVEIL_SOFTWARE_PLUGIN")
                    .map(PathBuf::from)
                    .expect("FILEVEIL_SOFTWARE_PLUGIN"),
            ),
            allow_execution: true,
            test_arguments: vec![vec!["3".into()], vec!["91".into()]],
            ..Default::default()
        };
        let limits = Limits::default();
        let cancelled = AtomicBool::new(false);
        for (mode, filename) in [
            (SoftwareMode::Source, "marked.c"),
            (SoftwareMode::Ir, "marked.ll"),
            (SoftwareMode::Compiler, "marked-program"),
        ] {
            let marked = directory.path().join(filename);
            let mut operation = request.clone();
            operation.mode = mode;
            operation.output_path = Some(marked.clone());
            let report = run(&operation, &limits, &cancelled)
                .unwrap_or_else(|error| panic!("Mark {mode:?}: {error}"));
            assert_eq!(report.result, Outcome::VerifiedWithinScope);
            operation.action = SoftwareAction::Clean;
            operation.input_path = marked;
            operation.reference_path = (mode == SoftwareMode::Compiler).then(|| source.clone());
            let clean = directory.path().join(format!("clean-{filename}"));
            operation.output_path = Some(clean.clone());
            let report = run(&operation, &limits, &cancelled)
                .unwrap_or_else(|error| panic!("Clean {mode:?}: {error}"));
            assert_eq!(report.result, Outcome::VerifiedWithinScope);
            if mode == SoftwareMode::Source {
                assert_eq!(fs::read(clean).unwrap(), source_bytes);
            }
        }
        let mut laboratory = request.clone();
        laboratory.action = SoftwareAction::Lab;
        laboratory.output_path = None;
        let report = run(&laboratory, &limits, &cancelled).unwrap();
        assert_eq!(
            report.result,
            Outcome::VerifiedWithinScope,
            "{:?}",
            report.advanced
        );
        assert_eq!(
            report.advanced.as_ref().unwrap()["software"]["lab"]["runtime_matches"],
            4
        );
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
    }
}

// FVPROV1 86248 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2ZjljMjk5YjcwN2JmMGRlZjg3MjA1NjhjMDE3ZDA4MGRlZmE2NTI0NGI2YzJkNjA3NjY2ODk4Mzc3NTUzNmJjIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3NvZnR3YXJlL3BpcGVsaW5lLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiOTY0NzdiNmMwMjNjODNhNzZiYWE3NDRiY2FlYmMzYjczZDk3Y2E3MjE5MDg4OWRhNzk0MWJmYjllNTI2MGExY2U4ZGI1Yjg4MmVlNTkyNmEwZDdlZGRjODdmNGM4NzliMTUxMmI1YmQwODNmM2RjMDE5OTE1ZWExYjUxM2E0MDUifV19XQ== FVPROV1-END
