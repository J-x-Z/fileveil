// SPDX-License-Identifier: MPL-2.0
//! Explicit MCP directory capabilities and descriptor-bound file operations.
use crate::jobs::{JobKind, JobRequest};
use fileveil_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    path::{Component, Path, PathBuf},
    process::Command,
};

pub(crate) const BINDINGS_ENV: &str = "FILEVEIL_MCP_BOUND_INPUTS";
pub const MAX_AUTHORIZED_ROOTS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpAccessConfig {
    pub read_roots: Vec<PathBuf>,
    pub write_roots: Vec<PathBuf>,
    pub signing_keys: Vec<PathBuf>,
    pub signing_key_refs: Vec<String>,
    pub max_operations: u32,
}
impl Default for McpAccessConfig {
    fn default() -> Self {
        Self {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            signing_keys: Vec::new(),
            signing_key_refs: Vec::new(),
            max_operations: 64,
        }
    }
}
impl McpAccessConfig {
    pub fn validate(&self) -> std::result::Result<(), String> {
        AccessPolicy::new(self)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn denied(message: &str) -> Error {
    Error::Blocked(format!("MCP permission denied. {message}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Identity {
    device: u64,
    file: u64,
}

struct Root {
    path: PathBuf,
    directory: File,
    identity: Identity,
    _namespace: Vec<File>,
}
impl Root {
    fn new(path: &Path) -> Result<Self> {
        let path = normalized_absolute(path)?;
        check_sensitive(&path)?;
        if path.parent().is_none() {
            return Err(denied(
                "Choose a specific directory instead of the filesystem or user-home root",
            ));
        }
        let (directory, namespace) = platform::open_absolute_directory(&path)?;
        let identity = platform::identity(&directory)?;
        let canonical = fs::canonicalize(&path)
            .map_err(|_| denied("Authorized directory cannot be resolved"))?;
        check_sensitive(&canonical)?;
        if home_root(identity)? {
            return Err(denied(
                "Choose a specific directory instead of the filesystem or user-home root",
            ));
        }
        Ok(Self {
            path: canonical,
            directory,
            identity,
            _namespace: namespace,
        })
    }
    fn check_namespace(&self) -> Result<()> {
        let (current, _) = platform::open_absolute_directory(&self.path)?;
        if platform::identity(&current)? != self.identity {
            return Err(denied(
                "An authorized directory changed identity during the operation",
            ));
        }
        Ok(())
    }
}

pub(crate) struct AccessPolicy {
    read: Vec<Root>,
    write: Vec<Root>,
    signers: Vec<BoundInput>,
    key_refs: Vec<String>,
    maximum: u32,
    used: u32,
}
impl AccessPolicy {
    pub(crate) fn new(config: &McpAccessConfig) -> Result<Self> {
        if !(1..=10_000).contains(&config.max_operations) {
            return Err(denied("The operation limit must be between 1 and 10000"));
        }
        if config.read_roots.len()
            + config.write_roots.len()
            + config.signing_keys.len()
            + config.signing_key_refs.len()
            > MAX_AUTHORIZED_ROOTS
        {
            return Err(denied(
                "At most 64 authorized read and write roots may be configured",
            ));
        }
        if config.signing_key_refs.iter().any(|id| {
            id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(denied(
                "System signing-key grants require lower-case public-key SHA-256 references",
            ));
        }
        let mut policy = Self {
            read: config
                .read_roots
                .iter()
                .map(|path| Root::new(path))
                .collect::<Result<_>>()?,
            write: config
                .write_roots
                .iter()
                .map(|path| Root::new(path))
                .collect::<Result<_>>()?,
            signers: Vec::new(),
            key_refs: config.signing_key_refs.clone(),
            maximum: config.max_operations,
            used: 0,
        };
        for path in &config.signing_keys {
            let signer = policy.input(path)?;
            if signer
                .file
                .metadata()
                .map_err(|_| denied("Signing key metadata is unavailable"))?
                .len()
                > 16 * 1024
            {
                return Err(denied("Authorized signing keys must be at most 16 KiB"));
            }
            policy.signers.push(signer);
        }
        Ok(policy)
    }
    pub(crate) fn summary(&self) -> serde_json::Value {
        serde_json::json!({"read_root_count":self.read.len(),"write_root_count":self.write.len(),"max_operations":self.maximum,"operations_used":self.used,"original_writes":false,"signing_key_count":self.signers.len(),"system_signing_key_count":self.key_refs.len(),"symbolic_links":false,"hard_link_inputs":false})
    }
    pub(crate) fn authorize(&mut self, request: JobRequest) -> Result<AuthorizedJob> {
        if self.used >= self.maximum {
            return Err(denied(
                "The configured MCP session operation limit has been reached",
            ));
        }
        self.used += 1;
        let mut job = AuthorizedJob {
            request,
            inputs: Vec::new(),
            output: None,
        };
        match job.request.kind.clone() {
            JobKind::HeritageKeygen { .. } | JobKind::SystemKeygen => {
                return Err(denied("MCP cannot generate or write private signing keys"));
            }
            JobKind::Heritage {
                path,
                output,
                mut request,
            } => {
                request.validate()?;
                if request
                    .key_refs
                    .iter()
                    .chain(request.watermark_key_ref.iter())
                    .any(|reference| !self.key_refs.contains(&reference.key_id))
                {
                    return Err(denied(
                        "This system signing-key reference is not explicitly authorized for MCP",
                    ));
                }
                let input = self.input(&path)?;
                let destination = request
                    .writes_file()
                    .then(|| self.output(&input.original, output.as_deref()))
                    .transpose()?;
                let signing_paths: Vec<_> = request
                    .signing_paths()
                    .into_iter()
                    .map(Path::to_path_buf)
                    .collect();
                for path in request.auxiliary_paths_mut() {
                    let bound = self.input(path)?;
                    if signing_paths.contains(path)
                        && !self
                            .signers
                            .iter()
                            .any(|signer| signer.identity == bound.identity)
                    {
                        return Err(denied(
                            "This signing key is not explicitly authorized for MCP signing",
                        ));
                    }
                    *path = bound.alias.clone();
                    job.inputs.push(bound);
                }
                job.request.kind = JobKind::Heritage {
                    path: input.alias.clone(),
                    output: destination.as_ref().and_then(|value| value.alias.clone()),
                    request,
                };
                job.inputs.push(input);
                job.output = destination;
            }
            JobKind::SanitizeAdvanced {
                input,
                output,
                options,
            } => {
                let input = self.input(&input)?;
                let destination = self.output(&input.original, output.as_deref())?;
                job.request.kind = JobKind::SanitizeAdvanced {
                    input: input.alias.clone(),
                    output: destination.alias.clone(),
                    options,
                };
                job.inputs.push(input);
                job.output = Some(destination);
            }
            JobKind::VerifyAdvanced {
                original,
                output,
                options,
            } => {
                let first = self.input(&original)?;
                let second = self.input(&output)?;
                job.request.kind = JobKind::VerifyAdvanced {
                    original: first.alias.clone(),
                    output: second.alias.clone(),
                    options,
                };
                job.inputs.extend([first, second]);
            }
            JobKind::DetectWatermark { path } => {
                let input = self.input(&path)?;
                job.request.kind = JobKind::DetectWatermark {
                    path: input.alias.clone(),
                };
                job.inputs.push(input);
            }
            JobKind::Lab { paths } | JobKind::LabGrouped { paths, .. } => {
                let groups = match &job.request.kind {
                    JobKind::LabGrouped { groups, .. } => Some(groups.clone()),
                    _ => None,
                };
                if !(2..=8).contains(&paths.len()) {
                    return Err(Error::Input(
                        "Lab requires 2 to 8 authorized samples".into(),
                    ));
                }
                let inputs = paths
                    .iter()
                    .map(|path| self.input(path))
                    .collect::<Result<Vec<_>>>()?;
                let paths = inputs.iter().map(|input| input.alias.clone()).collect();
                job.request.kind = match groups {
                    Some(groups) => JobKind::LabGrouped { paths, groups },
                    None => JobKind::Lab { paths },
                };
                job.inputs.extend(inputs);
            }
            JobKind::Provenance { path, trust_roots } => {
                let input = self.input(&path)?;
                let roots = trust_roots
                    .as_ref()
                    .map(|path| self.input(path))
                    .transpose()?;
                job.request.kind = JobKind::Provenance {
                    path: input.alias.clone(),
                    trust_roots: roots.as_ref().map(|input| input.alias.clone()),
                };
                job.inputs.push(input);
                job.inputs.extend(roots);
            }
            JobKind::Scan { path } => {
                let input = self.input(&path)?;
                job.request.kind = JobKind::Scan {
                    path: input.alias.clone(),
                };
                job.inputs.push(input);
            }
            JobKind::Sanitize { input, output } => {
                let input = self.input(&input)?;
                let destination = self.output(&input.original, output.as_deref())?;
                job.request.kind = JobKind::Sanitize {
                    input: input.alias.clone(),
                    output: destination.alias.clone(),
                };
                job.inputs.push(input);
                job.output = Some(destination);
            }
            JobKind::ProcessImage {
                input,
                output,
                options,
            } => {
                let input = self.input(&input)?;
                let destination = self.output(&input.original, output.as_deref())?;
                job.request.kind = JobKind::ProcessImage {
                    input: input.alias.clone(),
                    output: destination.alias.clone(),
                    options,
                };
                job.inputs.push(input);
                job.output = Some(destination);
            }
            JobKind::Verify { original, output } => {
                let first = self.input(&original)?;
                let second = self.input(&output)?;
                job.request.kind = JobKind::Verify {
                    original: first.alias.clone(),
                    output: second.alias.clone(),
                };
                job.inputs.extend([first, second]);
            }
            JobKind::VerifyImage {
                original,
                output,
                options,
            } => {
                let first = self.input(&original)?;
                let second = self.input(&output)?;
                job.request.kind = JobKind::VerifyImage {
                    original: first.alias.clone(),
                    output: second.alias.clone(),
                    options,
                };
                job.inputs.extend([first, second]);
            }
        }
        for input in &job.inputs {
            if input
                .file
                .metadata()
                .map_err(|_| denied("Authorized input metadata is unavailable"))?
                .len()
                > job.request.limits.max_file_bytes
            {
                return Err(Error::Blocked(
                    "Input exceeds the configured file byte limit".into(),
                ));
            }
        }
        Ok(job)
    }
    fn input(&self, path: &Path) -> Result<BoundInput> {
        let path = normalized_absolute(path)?;
        check_sensitive(&path)?;
        let (root, relative) = root_for(&self.read, &path).ok_or_else(|| {
            denied("The requested input is outside the authorized read directories")
        })?;
        root.check_namespace()?;
        let parent_relative = relative.parent().unwrap_or(Path::new(""));
        let parent = platform::open_directory(&root.directory, parent_relative, &root.path)?;
        let parent_hint = path
            .parent()
            .ok_or_else(|| denied("Input parent is unavailable"))?;
        let namespace = platform::lock_namespace(&platform::directory_path(&parent, parent_hint)?)?;
        let name = relative
            .file_name()
            .ok_or_else(|| denied("Input must name a regular file"))?;
        let file = platform::open_input(&parent, name, &path)?;
        #[cfg(windows)]
        check_sensitive(&platform::directory_path(&file, &path)?)?;
        let identity = platform::identity(&file)?;
        let alias = platform::child_path(&parent, name, &path)?;
        Ok(BoundInput {
            original: path,
            alias,
            file,
            _parent: parent,
            _namespace: namespace,
            identity,
            root_path: root.path.clone(),
            root_identity: root.identity,
        })
    }
    fn output(&self, input: &Path, output: Option<&Path>) -> Result<BoundOutput> {
        let path = normalized_absolute(output.unwrap_or(input))?;
        check_sensitive(&path)?;
        let directory = path
            .parent()
            .ok_or_else(|| denied("Output requires an existing authorized parent directory"))?;
        let (root, relative) = root_for(&self.write, directory).ok_or_else(|| {
            denied("The requested output is outside the authorized write directories")
        })?;
        root.check_namespace()?;
        let parent = platform::open_directory(&root.directory, &relative, &root.path)?;
        #[cfg(windows)]
        check_sensitive(&platform::directory_path(&parent, directory)?)?;
        let namespace = platform::lock_namespace(&platform::directory_path(&parent, directory)?)?;
        let identity = platform::identity(&parent)?;
        let alias = match output {
            Some(_) => {
                let name = path
                    .file_name()
                    .ok_or_else(|| denied("Output must name a new file"))?;
                let candidate = platform::child_path(&parent, name, &path)?;
                if fs::symlink_metadata(&candidate).is_ok() {
                    return Err(denied("Output already exists. Choose a new copy path"));
                }
                Some(candidate)
            }
            None => None,
        };
        Ok(BoundOutput {
            original_parent: directory.to_path_buf(),
            parent,
            _namespace: namespace,
            identity,
            alias,
            root_path: root.path.clone(),
            root_identity: root.identity,
        })
    }
}

fn root_for<'a>(roots: &'a [Root], path: &Path) -> Option<(&'a Root, PathBuf)> {
    roots
        .iter()
        .filter_map(|root| platform::relative(path, &root.path).map(|relative| (root, relative)))
        .max_by_key(|(root, _)| root.path.components().count())
}

struct BoundInput {
    original: PathBuf,
    alias: PathBuf,
    file: File,
    _parent: File,
    _namespace: Vec<File>,
    identity: Identity,
    root_path: PathBuf,
    root_identity: Identity,
}
struct BoundOutput {
    original_parent: PathBuf,
    parent: File,
    _namespace: Vec<File>,
    identity: Identity,
    alias: Option<PathBuf>,
    root_path: PathBuf,
    root_identity: Identity,
}

pub(crate) struct AuthorizedJob {
    pub(crate) request: JobRequest,
    inputs: Vec<BoundInput>,
    output: Option<BoundOutput>,
}
impl AuthorizedJob {
    pub(crate) fn bindings(&self) -> Result<Vec<(PathBuf, File)>> {
        #[cfg(unix)]
        {
            self.inputs
                .iter()
                .map(|input| {
                    input
                        .file
                        .try_clone()
                        .map(|file| (input.alias.clone(), file))
                        .map_err(|_| denied("Authorized input descriptor could not be duplicated"))
                })
                .collect()
        }
        #[cfg(not(unix))]
        {
            Ok(Vec::new())
        }
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        for input in &self.inputs {
            let (root, _) = platform::open_absolute_directory(&input.root_path)?;
            if platform::identity(&root)? != input.root_identity {
                return Err(denied(
                    "An authorized read root changed during the operation",
                ));
            }
            let relative = platform::relative(&input.original, &input.root_path)
                .ok_or_else(|| denied("Input is outside its authorized root"))?;
            let parent = platform::open_directory(
                &root,
                relative.parent().unwrap_or(Path::new("")),
                &input.root_path,
            )?;
            let current = platform::open_input(
                &parent,
                relative
                    .file_name()
                    .ok_or_else(|| denied("Invalid input filename"))?,
                &input.original,
            )?;
            if platform::identity(&current)? != input.identity
                || platform::identity(&input.file)? != input.identity
            {
                return Err(denied(
                    "An input changed filesystem identity during the operation",
                ));
            }
        }
        if let Some(output) = &self.output {
            let (root, _) = platform::open_absolute_directory(&output.root_path)?;
            if platform::identity(&root)? != output.root_identity {
                return Err(denied(
                    "An authorized write root changed during the operation",
                ));
            }
            let relative = platform::relative(&output.original_parent, &output.root_path)
                .ok_or_else(|| denied("Output parent left its authorized root"))?;
            let current = platform::open_directory(&root, &relative, &output.root_path)?;
            if platform::identity(&current)? != output.identity {
                return Err(denied(
                    "Output parent changed filesystem identity during the operation",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn configure_worker(
        &self,
        command: &mut Command,
        staging: Option<&PrivateStaging>,
    ) -> Result<()> {
        command.env_remove(BINDINGS_ENV);
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let inherited: Vec<_> = self
                .inputs
                .iter()
                .map(|input| InheritedInput {
                    alias: input.alias.clone(),
                    descriptor: input.file.as_raw_fd(),
                    identity: input.identity,
                })
                .collect();
            let staging_descriptor = staging.map(|staging| {
                staging
                    .directory
                    .as_ref()
                    .expect("active staging descriptor")
                    .as_raw_fd()
            });
            let bindings = InheritedBindings {
                inputs: inherited,
                staging_descriptor,
            };
            command.env(
                BINDINGS_ENV,
                serde_json::to_string(&bindings)
                    .map_err(|_| denied("Could not encode authorized input descriptors"))?,
            );
            let mut descriptors: Vec<_> = bindings
                .inputs
                .iter()
                .map(|input| input.descriptor)
                .collect();
            if let Some(staging) = staging {
                descriptors.push(
                    staging
                        .directory
                        .as_ref()
                        .expect("active staging descriptor")
                        .as_raw_fd(),
                );
            }
            // The child is single-threaded between fork and exec. Only fcntl is used.
            unsafe {
                command.pre_exec(move || {
                    for descriptor in &descriptors {
                        if libc::fcntl(*descriptor, libc::F_SETFD, 0) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
        #[cfg(not(unix))]
        let _ = staging;
        Ok(())
    }
    pub(crate) fn external_output(&self, filename: &str) -> Option<PathBuf> {
        self.output
            .as_ref()
            .map(|output| output.original_parent.join(filename))
    }
    pub(crate) fn create_staging(&self) -> Result<PrivateStaging> {
        let output = self
            .output
            .as_ref()
            .ok_or_else(|| denied("Write authorization is missing"))?;
        PrivateStaging::new(&output.parent, &output.original_parent)
    }
}

/// An authorized task owns only this private directory and its own direct files.
/// Descriptor addressing prevents a replaced ancestor from redirecting worker IO.
pub(crate) struct PrivateStaging {
    directory: Option<File>,
    parent: File,
    name: OsString,
    path: PathBuf,
    identity: Identity,
}
impl PrivateStaging {
    fn new(parent: &File, hint: &Path) -> Result<Self> {
        let path = platform::directory_path(parent, hint)?;
        let temporary = tempfile::Builder::new()
            .prefix(".fileveil-mcp-job-")
            .tempdir_in(path)
            .map_err(|_| {
                denied("Could not create private output staging in the authorized directory")
            })?;
        let original = temporary.path().to_path_buf();
        let name = original
            .file_name()
            .ok_or_else(|| denied("Private staging has no name"))?
            .to_os_string();
        let directory = platform::open_staging(parent, &name, &original)?;
        let identity = platform::identity(&directory)?;
        let path = platform::directory_path(&directory, &original)?;
        let _ = temporary.keep();
        let parent = parent
            .try_clone()
            .map_err(|_| denied("Could not retain staging parent"))?;
        Ok(Self {
            directory: Some(directory),
            parent,
            name,
            path,
            identity,
        })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for PrivateStaging {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.path) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if (name == "verified-artifact.png"
                    || name.to_string_lossy().starts_with(".fileveil-"))
                    && entry
                        .file_type()
                        .is_ok_and(|kind| kind.is_file() || kind.is_symlink())
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        if let Ok(current) = platform::open_directory(
            &self.parent,
            Path::new(&self.name),
            self.path.parent().unwrap_or(Path::new("")),
        ) && platform::identity(&current).ok() == Some(self.identity)
        {
            drop(current);
            drop(self.directory.take());
            let _ = platform::remove_empty_directory(&self.parent, &self.name);
        }
    }
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
struct InheritedInput {
    alias: PathBuf,
    descriptor: i32,
    identity: Identity,
}
#[cfg(unix)]
#[derive(Serialize, Deserialize)]
struct InheritedBindings {
    inputs: Vec<InheritedInput>,
    staging_descriptor: Option<i32>,
}

pub(crate) fn worker_bindings() -> Result<Vec<(PathBuf, File)>> {
    let Some(encoded) = std::env::var_os(BINDINGS_ENV) else {
        return Ok(Vec::new());
    };
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let bindings: InheritedBindings = serde_json::from_slice(encoded.as_encoded_bytes())
            .map_err(|_| denied("Invalid inherited input descriptor map"))?;
        if bindings.inputs.len() > 8 {
            return Err(denied("Too many inherited input descriptors"));
        }
        if let Some(descriptor) = bindings.staging_descriptor
            && (descriptor < 3
                || unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0)
        {
            return Err(denied("Authorized staging descriptor was not inherited"));
        }
        bindings
            .inputs
            .into_iter()
            .map(|input| {
                if input.descriptor < 3 {
                    return Err(denied("Invalid inherited input descriptor"));
                }
                let duplicate = unsafe { libc::fcntl(input.descriptor, libc::F_DUPFD_CLOEXEC, 3) };
                if duplicate < 0 {
                    return Err(denied("Authorized input descriptor was not inherited"));
                }
                let file = unsafe { File::from_raw_fd(duplicate) };
                unsafe {
                    libc::fcntl(input.descriptor, libc::F_SETFD, libc::FD_CLOEXEC);
                }
                if platform::identity(&file)? != input.identity {
                    return Err(denied("Inherited input descriptor identity differs"));
                }
                platform::check_regular_input(&file)?;
                Ok((input.alias, file))
            })
            .collect()
    }
    #[cfg(not(unix))]
    {
        let _ = encoded;
        Err(denied(
            "Unexpected inherited descriptor map on this platform",
        ))
    }
}

fn normalized_absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(denied(
            "Use an absolute path without parent-directory traversal",
        ));
    }
    #[cfg(windows)]
    if path.components().any(|part| matches!(part, Component::Prefix(prefix) if !matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))) {
        return Err(denied("MCP grants require local drive paths"));
    }
    #[cfg(windows)]
    if path
        .components()
        .any(|part| matches!(part, Component::Normal(name) if name.to_string_lossy().contains(':')))
    {
        return Err(denied(
            "Alternate stream paths cannot be addressed as MCP inputs or outputs",
        ));
    }
    Ok(path.components().collect())
}
fn home_root(identity: Identity) -> Result<bool> {
    let Some(home) = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }) else {
        return Ok(false);
    };
    let home = fs::canonicalize(home)
        .map_err(|_| denied("The user-home directory cannot be resolved for authorization"))?;
    let (mut directory, _) = platform::open_absolute_directory(&home)?;
    #[cfg(target_os = "macos")]
    {
        // The logical '..' chain crosses firmlinks and can skip the Data
        // volume's physical parent directories. Check both namespaces.
        let physical = platform::physical_directory_path(&directory)?;
        for (depth, ancestor) in physical.ancestors().enumerate() {
            if depth >= 512 {
                return Err(denied(
                    "The user-home ancestor chain exceeds the authorization limit",
                ));
            }
            let (ancestor, _) = platform::open_absolute_directory(ancestor)?;
            if platform::identity(&ancestor)? == identity {
                return Ok(true);
            }
        }
    }
    for _ in 0..512 {
        let current = platform::identity(&directory)?;
        if current == identity {
            return Ok(true);
        }
        let parent = platform::parent_directory(&directory)?;
        if platform::identity(&parent)? == current {
            return Ok(false);
        }
        directory = parent;
    }
    Err(denied(
        "The user-home ancestor chain exceeds the authorization limit",
    ))
}
fn check_sensitive(path: &Path) -> Result<()> {
    let components: Vec<_> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    #[cfg(unix)]
    if components
        .first()
        .is_some_and(|name| matches!(name.as_str(), "proc" | "sys" | "dev"))
    {
        return Err(denied("Device and process filesystems are protected"));
    }
    if components.iter().any(|name| {
        matches!(
            name.as_str(),
            ".ssh" | ".gnupg" | ".aws" | ".azure" | ".kube" | ".codex" | ".git" | "keychains"
        ) || name == ".env"
            || name.starts_with(".env.")
    }) {
        return Err(denied(
            "Credential, key-store and private configuration paths are protected",
        ));
    }
    for pair in components.windows(2) {
        if matches!(
            (pair[0].as_str(), pair[1].as_str()),
            (".config", "gcloud") | ("microsoft", "credentials") | ("microsoft", "vault")
        ) {
            return Err(denied(
                "Credential and cloud-account directories are protected",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };
    fn component(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| denied("A filesystem component contains a NUL byte"))
    }
    fn directory_at(parent: &File, name: &OsStr) -> Result<File> {
        let name = component(name)?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(denied(
                "Directory is unavailable or includes a symbolic link",
            ));
        }
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
    pub(super) fn open_absolute_directory(path: &Path) -> Result<(File, Vec<File>)> {
        let mut directory =
            File::open("/").map_err(|_| denied("Could not open the filesystem anchor"))?;
        for part in path.components() {
            match part {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => directory = directory_at(&directory, name)?,
                _ => return Err(denied("Unsupported directory path component")),
            }
        }
        Ok((directory, Vec::new()))
    }
    pub(super) fn lock_namespace(_path: &Path) -> Result<Vec<File>> {
        Ok(Vec::new())
    }
    pub(super) fn open_staging(parent: &File, name: &OsStr, _hint: &Path) -> Result<File> {
        directory_at(parent, name)
    }
    pub(super) fn parent_directory(directory: &File) -> Result<File> {
        directory_at(directory, OsStr::new(".."))
    }
    #[cfg(target_os = "macos")]
    pub(super) fn physical_directory_path(directory: &File) -> Result<PathBuf> {
        use std::{ffi::CStr, os::unix::ffi::OsStringExt};
        let mut bytes = [0u8; libc::MAXPATHLEN as usize];
        if unsafe {
            libc::fcntl(
                directory.as_raw_fd(),
                libc::F_GETPATH_NOFIRMLINK,
                bytes.as_mut_ptr(),
            )
        } < 0
        {
            return Err(denied(
                "The physical user-home path is unavailable for authorization",
            ));
        }
        let path = CStr::from_bytes_until_nul(&bytes)
            .map_err(|_| denied("The physical user-home path is invalid"))?;
        Ok(PathBuf::from(OsString::from_vec(path.to_bytes().to_vec())))
    }
    pub(super) fn open_directory(root: &File, relative: &Path, _hint: &Path) -> Result<File> {
        let mut directory = root
            .try_clone()
            .map_err(|_| denied("Could not duplicate authorized directory"))?;
        for part in relative.components() {
            match part {
                Component::Normal(name) => directory = directory_at(&directory, name)?,
                Component::CurDir => {}
                _ => return Err(denied("Directory traversal is outside the granted root")),
            }
        }
        Ok(directory)
    }
    pub(super) fn open_input(parent: &File, name: &OsStr, _hint: &Path) -> Result<File> {
        let name = component(name)?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(denied("Input is unavailable or is a symbolic link"));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        check_regular_input(&file)?;
        Ok(file)
    }
    pub(super) fn check_regular_input(file: &File) -> Result<()> {
        let metadata = file
            .metadata()
            .map_err(|_| denied("Input metadata could not be inspected"))?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(denied(
                "MCP inputs must be regular files with exactly one filesystem link",
            ));
        }
        Ok(())
    }
    pub(super) fn identity(file: &File) -> Result<Identity> {
        let metadata = file
            .metadata()
            .map_err(|_| denied("A bound filesystem object is unavailable"))?;
        Ok(Identity {
            device: metadata.dev(),
            file: metadata.ino(),
        })
    }
    pub(super) fn directory_path(directory: &File, _hint: &Path) -> Result<PathBuf> {
        // Darwin's fdescfs exposes descriptors but cannot traverse their children.
        // The kernel file-reference namespace remains bound to this held vnode.
        #[cfg(target_os = "macos")]
        let path = {
            let identity = identity(directory)?;
            PathBuf::from(format!("/.vol/{}/{}", identity.device, identity.file))
        };
        #[cfg(not(target_os = "macos"))]
        let path = PathBuf::from(format!("/dev/fd/{}", directory.as_raw_fd()));
        let current = File::open(&path)
            .map_err(|_| denied("Bound directory paths are unavailable on this host"))?;
        if !path.is_dir() || identity(&current)? != identity(directory)? {
            return Err(denied("Bound directory identity could not be verified"));
        }
        Ok(path)
    }
    pub(super) fn child_path(parent: &File, name: &OsStr, hint: &Path) -> Result<PathBuf> {
        Ok(directory_path(parent, hint)?.join(name))
    }
    pub(super) fn relative(path: &Path, root: &Path) -> Option<PathBuf> {
        path.strip_prefix(root).ok().map(Path::to_path_buf)
    }
    pub(super) fn remove_empty_directory(parent: &File, name: &OsStr) -> Result<()> {
        let name = component(name)?;
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(denied("Private staging directory could not be removed"));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle,
    };
    fn information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
        let mut information = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(denied("Bound filesystem identity is unavailable"));
        }
        Ok(information)
    }
    fn open(path: &Path, directory: bool) -> Result<File> {
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
        if directory {
            options.access_mode(FILE_READ_ATTRIBUTES);
        }
        let file = options
            .open(path)
            .map_err(|_| denied("Path is unavailable or cannot be locked against replacement"))?;
        let information = information(&file)?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(denied("Reparse-point paths are not authorized"));
        }
        if directory
            != file
                .metadata()
                .map_err(|_| denied("Path metadata is unavailable"))?
                .is_dir()
        {
            return Err(denied("Unexpected filesystem object type"));
        }
        Ok(file)
    }
    pub(super) fn open_absolute_directory(path: &Path) -> Result<(File, Vec<File>)> {
        let mut prefix = PathBuf::new();
        let mut namespace = Vec::new();
        for part in path.components() {
            prefix.push(part.as_os_str());
            if matches!(part, Component::Normal(_)) {
                namespace.push(open(&prefix, true)?);
            }
        }
        let directory = open(path, true)?;
        Ok((directory, namespace))
    }
    pub(super) fn lock_namespace(path: &Path) -> Result<Vec<File>> {
        let (directory, mut namespace) = open_absolute_directory(path)?;
        namespace.push(directory);
        Ok(namespace)
    }
    pub(super) fn open_staging(_parent: &File, _name: &OsStr, hint: &Path) -> Result<File> {
        open(hint, true)
    }
    pub(super) fn parent_directory(directory: &File) -> Result<File> {
        let path = directory_path(directory, Path::new(""))?;
        match path.parent() {
            Some(parent) => open(parent, true),
            None => directory
                .try_clone()
                .map_err(|_| denied("Could not retain the user-home ancestor")),
        }
    }
    pub(super) fn open_directory(root: &File, relative: &Path, hint: &Path) -> Result<File> {
        // Root ancestor handles remain open without SHARE_DELETE for the full task.
        let path = directory_path(root, hint)?.join(relative);
        let (directory, namespace) = open_absolute_directory(&path)?;
        // The caller must retain each derived ancestor too. Opening the final
        // directory without SHARE_DELETE also prevents moving its ancestors.
        drop(namespace);
        Ok(directory)
    }
    pub(super) fn open_input(parent: &File, name: &OsStr, hint: &Path) -> Result<File> {
        let file = open(&directory_path(parent, hint)?.join(name), false)?;
        check_regular_input(&file)?;
        Ok(file)
    }
    pub(super) fn check_regular_input(file: &File) -> Result<()> {
        if !file
            .metadata()
            .map_err(|_| denied("Input metadata is unavailable"))?
            .is_file()
            || information(file)?.nNumberOfLinks != 1
        {
            return Err(denied(
                "MCP inputs must be regular files with exactly one filesystem link",
            ));
        }
        Ok(())
    }
    pub(super) fn identity(file: &File) -> Result<Identity> {
        let info = information(file)?;
        Ok(Identity {
            device: u64::from(info.dwVolumeSerialNumber),
            file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }
    pub(super) fn directory_path(directory: &File, _hint: &Path) -> Result<PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_GUID,
        };
        let mut path = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                directory.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
            )
        };
        if length == 0 || length as usize >= path.len() {
            return Err(denied(
                "A stable local volume path is unavailable for the authorized directory",
            ));
        }
        Ok(PathBuf::from(OsString::from_wide(&path[..length as usize])))
    }
    pub(super) fn child_path(parent: &File, name: &OsStr, hint: &Path) -> Result<PathBuf> {
        Ok(directory_path(parent, hint)?.join(name))
    }
    pub(super) fn relative(path: &Path, root: &Path) -> Option<PathBuf> {
        let path = fs::canonicalize(path)
            .or_else(|_| {
                path.parent()
                    .and_then(|parent| fs::canonicalize(parent).ok())
                    .map(|parent| parent.join(path.file_name().unwrap_or_default()))
                    .ok_or(std::io::Error::from(std::io::ErrorKind::NotFound))
            })
            .ok()?;
        let path_parts: Vec<_> = path.components().collect();
        let root_parts: Vec<_> = root.components().collect();
        if path_parts.len() < root_parts.len()
            || !path_parts.iter().zip(&root_parts).all(|(a, b)| {
                a.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
            })
        {
            return None;
        }
        Some(
            path_parts[root_parts.len()..]
                .iter()
                .map(|part| part.as_os_str())
                .collect(),
        )
    }
    pub(super) fn remove_empty_directory(parent: &File, name: &OsStr) -> Result<()> {
        let path = directory_path(parent, Path::new(""))?.join(name);
        fs::remove_dir(path).map_err(|_| denied("Private staging directory could not be removed"))
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("MCP directory capabilities require Unix or Windows file handles");

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use fileveil_core::Limits;

    fn directory() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }
    fn config(read: &[&Path], write: &[&Path]) -> McpAccessConfig {
        McpAccessConfig {
            read_roots: read.iter().map(|path| path.to_path_buf()).collect(),
            write_roots: write.iter().map(|path| path.to_path_buf()).collect(),
            ..Default::default()
        }
    }
    fn scan(path: &Path) -> JobRequest {
        JobRequest::new(JobKind::Scan { path: path.into() })
    }
    fn sanitize(input: &Path, output: &Path) -> JobRequest {
        JobRequest::new(JobKind::Sanitize {
            input: input.into(),
            output: Some(output.into()),
        })
    }

    #[test]
    fn empty_grants_and_independent_read_write_permissions() {
        let source = directory();
        let destination = directory();
        let input = source.path().join("source.txt");
        fs::write(&input, "original").unwrap();
        let output = destination.path().join("copy.txt");
        assert!(
            AccessPolicy::new(&McpAccessConfig::default())
                .unwrap()
                .authorize(scan(&input))
                .is_err()
        );
        let mut readonly = AccessPolicy::new(&config(&[source.path()], &[])).unwrap();
        assert!(readonly.authorize(scan(&input)).is_ok());
        assert!(readonly.authorize(sanitize(&input, &output)).is_err());
        let mut writeonly = AccessPolicy::new(&config(&[], &[source.path()])).unwrap();
        assert!(writeonly.authorize(scan(&input)).is_err());
        let mut split =
            AccessPolicy::new(&config(&[source.path()], &[destination.path()])).unwrap();
        assert!(split.authorize(sanitize(&input, &output)).is_ok());
        assert!(
            split
                .authorize(sanitize(&input, &source.path().join("other.txt")))
                .is_err()
        );
        assert!(!output.exists());
    }

    #[test]
    fn traversal_sensitive_paths_and_operation_budget_are_blocked() {
        let source = directory();
        let input = source.path().join("source.txt");
        fs::write(&input, "original").unwrap();
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[source.path()])).unwrap();
        // PathBuf::join folds parent segments on Windows verbatim paths.
        let mut traversal = source.path().as_os_str().to_os_string();
        traversal.push(format!(
            "{s}nested{s}..{s}source.txt",
            s = std::path::MAIN_SEPARATOR
        ));
        assert!(policy.authorize(scan(Path::new(&traversal))).is_err());
        let secret = source.path().join(".aws");
        fs::create_dir(&secret).unwrap();
        fs::write(secret.join("credentials"), "private").unwrap();
        assert!(policy.authorize(scan(&secret.join("credentials"))).is_err());
        assert!(config(&[&secret], &[]).validate().is_err());
        assert!(normalized_absolute(Path::new("relative.txt")).is_err());
        #[cfg(unix)]
        assert!(config(&[Path::new("/")], &[]).validate().is_err());
        let mut limited = config(&[source.path()], &[]);
        limited.max_operations = 1;
        let mut limited = AccessPolicy::new(&limited).unwrap();
        assert!(limited.authorize(scan(&input)).is_ok());
        assert!(limited.authorize(scan(&input)).is_err());
    }

    #[test]
    fn case_alias_of_home_cannot_expand_directory_grants() {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(PathBuf::from)
            .and_then(|path| fs::canonicalize(path).ok())
            .expect("test process has a resolvable home directory");
        let alias: String = home
            .to_string_lossy()
            .chars()
            .map(|character| {
                if character.is_ascii_lowercase() {
                    character.to_ascii_uppercase()
                } else {
                    character.to_ascii_lowercase()
                }
            })
            .collect();
        let alias = PathBuf::from(alias);
        let aliases_same_directory = platform::open_absolute_directory(&alias)
            .ok()
            .and_then(|(directory, _)| platform::identity(&directory).ok())
            .zip(
                platform::open_absolute_directory(&home)
                    .ok()
                    .and_then(|(directory, _)| platform::identity(&directory).ok()),
            )
            .is_some_and(|(alias, home)| alias == home);
        if alias == home || !aliases_same_directory {
            // Case-sensitive filesystems have no corresponding directory alias.
            return;
        }
        assert!(config(&[&alias], &[]).validate().is_err());
        assert!(config(&[], &[&alias]).validate().is_err());
    }

    #[test]
    fn home_ancestors_are_rejected_and_specific_project_directories_remain_allowed() {
        let home = fs::canonicalize(
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap(),
        )
        .unwrap();
        for ancestor in home.ancestors() {
            assert!(config(&[ancestor], &[]).validate().is_err());
            assert!(config(&[], &[ancestor]).validate().is_err());
            let case_alias = PathBuf::from(
                ancestor
                    .to_string_lossy()
                    .chars()
                    .map(|character| {
                        if character.is_ascii_lowercase() {
                            character.to_ascii_uppercase()
                        } else {
                            character.to_ascii_lowercase()
                        }
                    })
                    .collect::<String>(),
            );
            if let Ok((alias_directory, _)) = platform::open_absolute_directory(&case_alias)
                && let Ok((ancestor_directory, _)) = platform::open_absolute_directory(ancestor)
                && platform::identity(&alias_directory).unwrap()
                    == platform::identity(&ancestor_directory).unwrap()
            {
                assert!(config(&[&case_alias], &[]).validate().is_err());
            }
        }
        let project = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert!(config(&[&project], &[&project]).validate().is_ok());
        let specific = directory();
        assert!(
            config(&[specific.path()], &[specific.path()])
                .validate()
                .is_ok()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn physical_home_ancestor_namespaces_cannot_bypass_firmlink_protection() {
        let home = fs::canonicalize(std::env::var_os("HOME").unwrap()).unwrap();
        let (directory, _) = platform::open_absolute_directory(&home).unwrap();
        let physical = platform::physical_directory_path(&directory).unwrap();
        for ancestor in physical.ancestors() {
            assert!(config(&[ancestor], &[]).validate().is_err());
            assert!(config(&[], &[ancestor]).validate().is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn short_names_cannot_bypass_sensitive_directory_protection() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        let source = directory();
        let secret = source.path().join(".aws");
        fs::create_dir(&secret).unwrap();
        fs::write(secret.join("credentials.txt"), "private synthetic value").unwrap();
        let public = source.path().join("public.txt");
        fs::write(&public, "ordinary synthetic value").unwrap();
        let wide: Vec<_> = secret.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut short = vec![0u16; 32768];
        let length =
            unsafe { GetShortPathNameW(wide.as_ptr(), short.as_mut_ptr(), short.len() as u32) };
        if length == 0 || length as usize >= short.len() {
            return;
        }
        let alias = PathBuf::from(OsString::from_wide(&short[..length as usize]));
        if check_sensitive(&alias).is_err() {
            // Volumes with 8.3 creation disabled retain the ordinary long name.
            return;
        }
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[source.path()])).unwrap();
        assert!(config(&[&alias], &[]).validate().is_err());
        assert!(
            policy
                .authorize(scan(&alias.join("credentials.txt")))
                .is_err()
        );
        assert!(
            policy
                .authorize(sanitize(&public, &alias.join("copy.txt")))
                .is_err()
        );
        assert!(!secret.join("copy.txt").exists());
    }

    #[test]
    fn hard_link_inputs_and_existing_outputs_are_protected() {
        let source = directory();
        let input = source.path().join("source.txt");
        let alias = source.path().join("alias.txt");
        let output = source.path().join("existing.txt");
        fs::write(&input, "original").unwrap();
        fs::write(&output, "preserve").unwrap();
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[source.path()])).unwrap();
        assert!(policy.authorize(sanitize(&input, &output)).is_err());
        fs::hard_link(&input, &alias).unwrap();
        assert!(policy.authorize(scan(&input)).is_err());
        assert!(policy.authorize(scan(&alias)).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preserve");
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_inputs_directories_and_roots_are_rejected() {
        use std::os::unix::fs::symlink;
        let source = directory();
        let outside = directory();
        fs::write(outside.path().join("secret.txt"), "private").unwrap();
        symlink(
            outside.path().join("secret.txt"),
            source.path().join("link.txt"),
        )
        .unwrap();
        symlink(outside.path(), source.path().join("directory")).unwrap();
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[source.path()])).unwrap();
        assert!(
            policy
                .authorize(scan(&source.path().join("link.txt")))
                .is_err()
        );
        assert!(
            policy
                .authorize(scan(&source.path().join("directory/secret.txt")))
                .is_err()
        );
        assert!(
            config(&[&source.path().join("directory")], &[])
                .validate()
                .is_err()
        );
        assert!(
            policy
                .authorize(sanitize(
                    &outside.path().join("secret.txt"),
                    &source.path().join("copy.txt")
                ))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_input_path_cannot_redirect_descriptor_bound_reads() {
        use std::os::unix::fs::symlink;
        let source = directory();
        let outside = directory();
        let input = source.path().join("source.txt");
        fs::write(&input, "original text").unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "outside secret").unwrap();
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[])).unwrap();
        let authorized = policy.authorize(scan(&input)).unwrap();
        fs::rename(&input, source.path().join("moved.txt")).unwrap();
        symlink(&secret, &input).unwrap();
        assert!(authorized.revalidate().is_err());
        let JobKind::Scan { path } = &authorized.request.kind else {
            unreachable!()
        };
        let report =
            fileveil_engine::access_guard::with_bound_files(authorized.bindings().unwrap(), || {
                fileveil_engine::scan(path, &Limits::default())
            })
            .unwrap();
        assert_eq!(
            report.input_sha256,
            Some(fileveil_core::digest(b"original text"))
        );
        assert_ne!(
            report.input_sha256,
            Some(fileveil_core::digest(b"outside secret"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_output_parent_cannot_redirect_staging_or_publication() {
        use std::os::unix::fs::symlink;
        let source = directory();
        let outside = directory();
        let input = source.path().join("source.txt");
        fs::write(&input, "original").unwrap();
        let parent = source.path().join("outputs");
        let moved = source.path().join("moved-outputs");
        fs::create_dir(&parent).unwrap();
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[source.path()])).unwrap();
        let authorized = policy
            .authorize(sanitize(&input, &parent.join("copy.txt")))
            .unwrap();
        let staging = authorized.create_staging().unwrap();
        fs::rename(&parent, &moved).unwrap();
        symlink(outside.path(), &parent).unwrap();
        fs::write(staging.path().join("verified-artifact.png"), "staged").unwrap();
        assert!(authorized.revalidate().is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
        drop(staging);
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn replaced_authorized_root_is_detected_before_reading() {
        use std::os::unix::fs::symlink;
        let parent = directory();
        let root = parent.path().join("allowed");
        let moved = parent.path().join("moved");
        let outside = directory();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source.txt"), "original").unwrap();
        fs::write(outside.path().join("source.txt"), "private").unwrap();
        let mut policy = AccessPolicy::new(&config(&[&root], &[])).unwrap();
        fs::rename(&root, &moved).unwrap();
        symlink(outside.path(), &root).unwrap();
        assert!(policy.authorize(scan(&root.join("source.txt"))).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_bound_inputs_and_ancestors_cannot_be_renamed() {
        let source = directory();
        let parent = source.path().join("nested");
        fs::create_dir(&parent).unwrap();
        let input = parent.join("source.txt");
        fs::write(&input, "original").unwrap();
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[source.path()])).unwrap();
        let authorized = policy
            .authorize(sanitize(&input, &parent.join("copy.txt")))
            .unwrap();
        let JobKind::Sanitize { input: bound, .. } = &authorized.request.kind else {
            unreachable!()
        };
        assert!(bound.to_string_lossy().starts_with(r"\\?\Volume{"));
        assert_eq!(fs::read(bound).unwrap(), b"original");
        assert!(fs::rename(&input, parent.join("moved.txt")).is_err());
        assert!(fs::rename(&parent, source.path().join("moved-parent")).is_err());
        assert!(authorized.revalidate().is_ok());
        drop(authorized);
        fs::rename(&input, parent.join("moved.txt")).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_junctions_cannot_expand_grants() {
        use std::process::Stdio;
        let source = directory();
        let outside = directory();
        let junction = source.path().join("redirect");
        fs::write(outside.path().join("private.txt"), "private").unwrap();
        let status = Command::new("cmd")
            .args([
                OsStr::new("/C"),
                OsStr::new("mklink"),
                OsStr::new("/J"),
                junction.as_os_str(),
                outside.path().as_os_str(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "Native NTFS junction fixture could not be created"
        );
        let mut policy = AccessPolicy::new(&config(&[source.path()], &[source.path()])).unwrap();
        assert!(
            policy
                .authorize(scan(&junction.join("private.txt")))
                .is_err()
        );
        assert!(config(&[&junction], &[]).validate().is_err());
        fs::remove_dir(&junction).unwrap();
        assert_eq!(
            fs::read(outside.path().join("private.txt")).unwrap(),
            b"private"
        );
    }
}

// FVPROV1 60810 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIwNjQ1YjIxMDlhNmNlMjc1MjVkNzAwNTRmNmQyYjhmYTYwNDJlNzg3YzVlYmZkNmEzNGRhNjI2OTg1NDdkNWUzIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL21jcF9hY2Nlc3MucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJkNTJhMzRlN2JhMzJmZDIxZjU2Mjk4MjJhODY0NzRlZDcyZDhhZDU3YWUxZDA0ZGYwZmZhOWJmODU0ZWYxMWE4NTcwNzUzYWMyYWE1ODUwNmI3OWFhZjc2NDBjNDYwNmRlMWJjMzE4NWMzN2Y5NTM1ODBiMDUwYWU2N2IwNjcwMCJ9XX1d FVPROV1-END
