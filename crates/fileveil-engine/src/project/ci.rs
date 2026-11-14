// SPDX-License-Identifier: MPL-2.0
//! Secret-free, portable caller configuration for the reusable release workflow.
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
        && !path.to_string_lossy().contains(['\\', ':', '\n', '\r'])
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

pub fn generate(config: &CiConfig) -> Result<CiBundle> {
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
    secrets:
      signing-key-base64: ${{{{ secrets.FILEVEIL_SIGNING_KEY_BASE64 }}}}
  release-evidence:
    if: github.event_name == 'release'
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
          RELEASE_TAG: ${{{{ github.event.release.tag_name }}}}
        run: gh release upload "$RELEASE_TAG" fileveil-evidence/fileveil-evidence.zip fileveil-evidence/SHA256SUMS
"#,
        name = scalar(&config.name)?,
        revision = config.engine_ref,
        revision_scalar = scalar(&config.engine_ref)?,
        runner = scalar(&config.runner)?
    );
    Ok(CiBundle {workflow_yaml,
        local_command:"python /path/to/fileveil/tools/project-postprocess.py --fileveil /path/to/fileveil --config fileveil-ci.json".into(),
        config_json:serde_json::to_string_pretty(config).map_err(|_|Error::Input("Could not encode CI configuration".into()))?})
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
