// SPDX-License-Identifier: MPL-2.0
//! Secret-free, portable caller configuration for the reusable release workflow.
pub use super::registry::default_asset_rules;
use super::{
    ProjectRule,
    registry::{CompilerBackend, RegistryCompilerConfig, RegistryPolicy},
};
use fileveil_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CiConfig {
    pub name: String,
    pub work_id: String,
    pub author: String,
    pub copy_id: String,
    pub artifact_directory: PathBuf,
    pub output_directory: PathBuf,
    pub build_argv: Vec<String>,
    pub test_argv: Vec<String>,
    pub engine_ref: String,
    pub runner: String,
    pub policy: RegistryPolicy,
    pub rules: Vec<ProjectRule>,
    pub compiler: Option<RegistryCompilerConfig>,
}
impl Default for CiConfig {
    fn default() -> Self {
        Self {
            name: "Project copyright".into(),
            work_id: String::new(),
            author: String::new(),
            copy_id: "release".into(),
            artifact_directory: "dist".into(),
            output_directory: "fileveil-release".into(),
            build_argv: Vec::new(),
            test_argv: Vec::new(),
            engine_ref: "main".into(),
            runner: "ubuntu-latest".into(),
            policy: RegistryPolicy::ManifestOnly,
            rules: default_asset_rules(),
            compiler: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiBundle {
    pub workflow_yaml: String,
    pub local_command: String,
    pub config_json: String,
}

fn relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path
            .to_string_lossy()
            .contains(['\\', ':', '\n', '\r', '\0'])
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

pub fn generate(config: &CiConfig) -> Result<CiBundle> {
    validate_policy(config)?;
    if config.work_id.is_empty()
        || config.author.is_empty()
        || config.copy_id.is_empty()
        || [
            &config.name,
            &config.work_id,
            &config.author,
            &config.copy_id,
        ]
        .iter()
        .any(|v| v.len() > 4096 || v.contains('\0'))
    {
        return Err(Error::Input(
            "CI configuration requires bounded project, author and copy identities".into(),
        ));
    }
    let normalized = |path: &Path| {
        path.components()
            .filter_map(|part| match part {
                Component::Normal(value) => Some(value),
                _ => None,
            })
            .collect::<PathBuf>()
    };
    let input = normalized(&config.artifact_directory);
    let output = normalized(&config.output_directory);
    if !relative(&config.artifact_directory)
        || !relative(&config.output_directory)
        || input.as_os_str().is_empty()
        || output.starts_with(&input)
        || input.starts_with(&output)
    {
        return Err(Error::Input(
            "CI artifact and output directories must be distinct portable relative paths".into(),
        ));
    }
    if config.engine_ref.is_empty()
        || config.engine_ref.len() > 128
        || !config
            .engine_ref
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._/-".contains(&v))
        || config.engine_ref.contains("..")
    {
        return Err(Error::Input(
            "Choose a FileVeil commit, tag or branch reference".into(),
        ));
    }
    if !matches!(
        config.runner.as_str(),
        "ubuntu-latest" | "macos-latest" | "windows-latest"
    ) {
        return Err(Error::Input(
            "CI runner must select a supported native desktop platform".into(),
        ));
    }
    for argv in [&config.build_argv, &config.test_argv] {
        if argv.len() > 128
            || argv
                .iter()
                .any(|v| v.is_empty() || v.len() > 16384 || v.contains('\0'))
        {
            return Err(Error::Input(
                "Build and test commands must be bounded argument arrays".into(),
            ));
        }
    }
    let scalar = |value: &str| {
        serde_json::to_string(value).map_err(|_| Error::Input("Could not encode CI value".into()))
    };
    let workflow_yaml = format!(
        r#"# SPDX-License-Identifier: MPL-2.0
name: {name}
on:
  workflow_dispatch:
    inputs:
      release_tag:
        description: Existing tag at the selected workflow commit
        type: string
        required: false
        default: ''
  push:
    tags: ['v*']
  release:
    types: [created]
  schedule:
    - cron: '17 3 * * 1'
permissions:
  contents: read
  actions: read
concurrency:
  group: fileveil-${{{{ github.ref }}}}
  cancel-in-progress: false
jobs:
  copyright:
    uses: J-x-Z/fileveil/.github/workflows/project-release.yml@{revision}
    with:
      config: fileveil-ci.json
      engine-ref: {revision_scalar}
      runner: {runner}
      policy: {policy}
    secrets:
      signing-key-base64: ${{{{ secrets.FILEVEIL_SIGNING_KEY_BASE64 }}}}
  release-evidence:
    if: github.event_name == 'release' || startsWith(github.ref, 'refs/tags/') || (github.event_name == 'workflow_dispatch' && inputs.release_tag != '')
    needs: copyright
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: ${{{{ needs.copyright.outputs.artifact-name }}}}
          path: fileveil-evidence
      - name: Attach verified copyright evidence
        env:
          GH_TOKEN: ${{{{ github.token }}}}
          GH_REPO: ${{{{ github.repository }}}}
          RELEASE_TAG: ${{{{ github.event.release.tag_name || inputs.release_tag || github.ref_name }}}}
          SOURCE_COMMIT: ${{{{ github.sha }}}}
          EVIDENCE_PREFIX: ${{{{ needs.copyright.outputs.artifact-name }}}}
        shell: python {{0}}
        run: |
          import hashlib, json, os, pathlib, re, subprocess, urllib.parse
          tag = os.environ['RELEASE_TAG']
          assert tag and not tag.startswith('-') and len(tag) <= 256, 'Select an existing release tag'
          repository = os.environ['GH_REPO']
          endpoint = 'repos/' + repository + '/git/ref/tags/' + urllib.parse.quote(tag, safe='')
          reference = json.loads(subprocess.check_output(['gh', 'api', endpoint], text=True))['object']
          for _ in range(8):
              if reference['type'] != 'tag':
                  break
              reference = json.loads(subprocess.check_output(['gh', 'api', 'repos/' + repository + '/git/tags/' + reference['sha']], text=True))['object']
          assert reference['type'] == 'commit' and reference['sha'] == os.environ['SOURCE_COMMIT'], 'Release tag must match the verified build commit'
          exists = subprocess.run(['gh', 'release', 'view', tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
          if not exists:
              notes = pathlib.Path('release-notes.txt')
              notes.write_text('Automated prerelease with verified build artifacts and copyright evidence.\n\nThe attached checksum file binds both ZIP archives. Verification scope and build observations are included in the evidence package.\n', encoding='utf-8')
              subprocess.run(['gh', 'release', 'create', tag, '--verify-tag', '--prerelease', '--title', tag, '--notes-file', str(notes)], check=True)
          prefix = os.environ['EVIDENCE_PREFIX']
          assert len(prefix) <= 180 and re.fullmatch(r'[A-Za-z0-9._-]+', prefix), 'Artifact namespace must be a portable filename'
          directory = pathlib.Path('fileveil-evidence')
          renamed = []
          sums = []
          for original, suffix in [('fileveil-build.zip', '-build.zip'), ('fileveil-evidence.zip', '-evidence.zip')]:
              source = directory / original
              target = directory / (prefix + suffix)
              assert not target.exists(), 'Namespaced release attachment already exists'
              checksum = hashlib.file_digest(source.open('rb'), 'sha256').hexdigest()
              source.rename(target)
              renamed.append(str(target))
              sums.append(checksum + '  ' + target.name + '\n')
          checksums = directory / (prefix + '-SHA256SUMS')
          with checksums.open('x', encoding='ascii') as stream:
              stream.writelines(sums)
          subprocess.run(['gh', 'release', 'upload', tag, *renamed, str(checksums)], check=True)
"#,
        name = scalar(&config.name)?,
        revision = config.engine_ref,
        revision_scalar = scalar(&config.engine_ref)?,
        runner = scalar(&config.runner)?,
        policy = serde_json::to_string(&config.policy)
            .map_err(|_| Error::Input("Could not encode CI policy".into()))?
    );
    Ok(CiBundle {workflow_yaml,
        local_command:"python /path/to/fileveil/tools/project-ci-local.py --fileveil /path/to/fileveil --config fileveil-ci.json --key /path/to/private/author.key".into(),
        config_json:serde_json::to_string_pretty(config).map_err(|_|Error::Input("Could not encode CI configuration".into()))?})
}

fn validate_policy(config: &CiConfig) -> Result<()> {
    if config.rules.len() > 128
        || config.rules.iter().any(|rule| {
            rule.pattern.is_empty()
                || rule.pattern.len() > 512
                || rule.pattern.starts_with('/')
                || rule.pattern.contains(['\\', ':', '\0'])
                || rule.pattern.split('/').any(|part| part == "..")
                || !(1..=40).contains(&rule.strength)
                || glob::Pattern::new(&rule.pattern).is_err()
        })
    {
        return Err(Error::Input(
            "CI asset rules must be bounded relative patterns with supported strengths".into(),
        ));
    }
    if !matches!(
        config.policy,
        RegistryPolicy::CompilerWatermark | RegistryPolicy::Hybrid
    ) {
        return Ok(());
    }
    let compiler = config
        .compiler
        .as_ref()
        .filter(|compiler| !compiler.targets.is_empty())
        .ok_or_else(|| {
            Error::Unsupported(
                "Compiler and Hybrid CI require explicitly selected C/C++ or LLVM targets".into(),
            )
        })?;
    if compiler.targets.len() > 16
        || !matches!(
            compiler.optimization.as_str(),
            "" | "O0" | "O1" | "O2" | "O3" | "Os" | "Oz" | "LTO"
        )
        || compiler.compiler_arguments.len() > 128
        || compiler.test_arguments.len() > 32
        || compiler
            .test_arguments
            .iter()
            .any(|arguments| arguments.len() > 128)
        || compiler
            .compiler_arguments
            .iter()
            .chain(compiler.test_arguments.iter().flatten())
            .any(|value| value.len() > 16384 || value.contains('\0'))
    {
        return Err(Error::Input(
            "CI compiler configuration exceeds its bounded contract".into(),
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for target in &compiler.targets {
        let extension = target
            .input
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let supported = match target.backend {
            CompilerBackend::ClangSource => {
                matches!(extension.as_str(), "c" | "cc" | "cpp" | "cxx" | "c++")
            }
            CompilerBackend::LlvmIr => extension == "ll",
        };
        if !relative(&target.input)
            || !relative(&target.output)
            || !supported
            || target.input == Path::new(".")
            || target.output == Path::new(".")
            || !names.insert(target.output.to_string_lossy().to_lowercase())
        {
            return Err(Error::Input("CI compiler targets require distinct repository-relative C/C++ or LLVM input and release output paths".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_portable_template_has_separate_release_permissions() {
        let config = CiConfig {
            work_id: "work-1".into(),
            author: "Author".into(),
            ..Default::default()
        };
        let bundle = generate(&config).unwrap();
        assert!(!bundle.workflow_yaml.contains("workflow_call"));
        assert!(bundle.workflow_yaml.contains("needs: copyright"));
        assert!(bundle.workflow_yaml.contains("contents: read"));
        assert!(bundle.config_json.contains("\"build_argv\": []"));
        assert!(!bundle.config_json.contains("signing-key"));
    }
    #[test]
    fn template_rejects_path_and_workflow_injection() {
        let mut config = CiConfig {
            work_id: "w".into(),
            author: "a".into(),
            ..Default::default()
        };
        config.engine_ref = "main\npermissions: write-all".into();
        assert!(generate(&config).is_err());
        config.engine_ref = "main".into();
        config.artifact_directory = "../secret".into();
        assert!(generate(&config).is_err());
        config.artifact_directory = "..\\secret".into();
        assert!(generate(&config).is_err());
        config.artifact_directory = "./dist".into();
        config.output_directory = "dist/copyright".into();
        assert!(generate(&config).is_err());
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn selected_policy_and_explicit_empty_asset_rules_survive_pure_generation() {
        let config = CiConfig {
            work_id: "work-ci".into(),
            author: "Author".into(),
            policy: RegistryPolicy::Hybrid,
            rules: Vec::new(),
            compiler: Some(RegistryCompilerConfig {
                targets: vec![super::super::registry::RegistryCompilerTarget {
                    input: "missing/main.c".into(),
                    output: "bin/program".into(),
                    backend: CompilerBackend::ClangSource,
                }],
                llvm_directory: Some("/missing/toolchain".into()),
                plugin_path: Some("/missing/pass".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let bundle = generate(&config).unwrap();
        let serialized: serde_json::Value = serde_json::from_str(&bundle.config_json).unwrap();
        assert_eq!(serialized["policy"], "hybrid");
        assert_eq!(serialized["rules"], serde_json::json!([]));
        assert!(bundle.workflow_yaml.contains("policy: \"hybrid\""));
        assert!(bundle.workflow_yaml.contains("release_tag:"));
        assert!(bundle.workflow_yaml.contains("'--prerelease'"));
        assert!(bundle.workflow_yaml.contains("fileveil-build.zip"));
        assert!(bundle.local_command.contains("project-ci-local.py"));
    }
    #[test]
    fn compiler_without_actual_target_is_unsupported_and_missing_rules_use_shared_defaults() {
        let mut config = CiConfig {
            work_id: "work-ci".into(),
            author: "Author".into(),
            policy: RegistryPolicy::CompilerWatermark,
            ..Default::default()
        };
        assert!(generate(&config).is_err());
        config.policy = RegistryPolicy::AssetWatermark;
        assert_eq!(config.rules, super::super::registry::default_asset_rules());
        let parsed: CiConfig = serde_json::from_value(
            serde_json::json!({"work_id":"work-ci","author":"Author","policy":"asset_watermark"}),
        )
        .unwrap();
        assert_eq!(parsed.rules, config.rules);
    }
}
