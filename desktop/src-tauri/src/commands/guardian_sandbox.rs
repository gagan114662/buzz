use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::AppHandle;

use crate::managed_agents::managed_agents_base_dir;

const CONFIG_SCHEMA: &str = "guardian.macos-vm-sandbox/v1";
const HELPER_PROTOCOL: &str = "guardian.sandbox-helper/v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacVmSandboxConfig {
    schema_version: String,
    helper_path: PathBuf,
    helper_sha256: String,
    vm_image_path: PathBuf,
    vm_image_sha256: String,
    expected_team_identifier: String,
    configured_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigureMacVmSandboxInput {
    helper_path: PathBuf,
    helper_sha256: String,
    vm_image_path: PathBuf,
    vm_image_sha256: String,
    expected_team_identifier: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxProfileInput {
    filesystem: String,
    network: String,
    process_tree: bool,
    cpu_limit: bool,
    memory_limit: bool,
    disk_quota: bool,
    disposable_reset: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperProbe {
    protocol: String,
    backend: String,
    virtualization_available: bool,
    filesystem_isolation: bool,
    network_deny: bool,
    network_allowlist: bool,
    process_tree_isolation: bool,
    cpu_limit: bool,
    memory_limit: bool,
    disk_quota: bool,
    disposable_reset: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxStatus {
    schema_version: String,
    backend: String,
    state: String,
    detail: String,
    helper_path: Option<PathBuf>,
    vm_image_path: Option<PathBuf>,
    helper_verified: bool,
    image_verified: bool,
    signature_verified: bool,
    team_identifier: Option<String>,
    capabilities: Option<HelperProbe>,
}

fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(managed_agents_base_dir(app)?.join("guardian-macos-vm-sandbox.json"))
}

fn validate_sha256(value: &str) -> Result<String, String> {
    let value = value.trim().to_lowercase();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("SHA-256 digest must contain exactly 64 hexadecimal characters".into());
    }
    Ok(value)
}

fn validate_team_identifier(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() != 10 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err("Apple team identifier must contain exactly 10 letters or digits".into());
    }
    Ok(value.to_string())
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute"));
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| format!("failed to inspect {label}: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} must be a regular file, not a symbolic link"
        ));
    }
    path.canonicalize()
        .map_err(|e| format!("failed to canonicalize {label}: {e}"))
}

fn digest_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| format!("failed to hash {}: {e}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn verify_digest(path: &Path, expected: &str, label: &str) -> Result<(), String> {
    let actual = digest_file(path)?;
    if actual != expected {
        return Err(format!(
            "{label} digest mismatch: expected {expected}, observed {actual}"
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_apple_signature(path: &Path, team: &str) -> Result<(), String> {
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(path)
        .output()
        .map_err(|e| format!("failed to run Apple signature verification: {e}"))?;
    if !verify.status.success() {
        return Err(format!(
            "sandbox helper has an invalid Apple signature: {}",
            String::from_utf8_lossy(&verify.stderr).trim()
        ));
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|e| format!("failed to read Apple signature authority: {e}"))?;
    let output = String::from_utf8_lossy(&details.stderr);
    let observed = output
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))
        .ok_or_else(|| "sandbox helper signature has no Apple team identifier".to_string())?;
    if observed != team {
        return Err(format!(
            "sandbox helper was signed by Apple team {observed}, expected {team}"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_apple_signature(_path: &Path, _team: &str) -> Result<(), String> {
    Err("the signed macOS virtual-machine sandbox is unavailable on this operating system".into())
}

fn probe_helper(path: &Path) -> Result<HelperProbe, String> {
    let output = Command::new(path)
        .args(["probe", "--protocol", HELPER_PROTOCOL, "--json"])
        .output()
        .map_err(|e| format!("failed to start sandbox helper probe: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "sandbox helper probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let probe: HelperProbe = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("sandbox helper returned an invalid probe: {e}"))?;
    if probe.protocol != HELPER_PROTOCOL {
        return Err(format!(
            "sandbox helper protocol {} is incompatible with {HELPER_PROTOCOL}",
            probe.protocol
        ));
    }
    if probe.backend != "macos-virtualization" || !probe.virtualization_available {
        return Err("sandbox helper cannot provide the macOS Virtualization backend".into());
    }
    Ok(probe)
}

fn compile_profile(
    profile: &SandboxProfileInput,
    capabilities: &HelperProbe,
) -> Result<(), String> {
    if !matches!(profile.filesystem.as_str(), "read_only" | "workspace_write") {
        return Err("filesystem profile must be read_only or workspace_write".into());
    }
    if !capabilities.filesystem_isolation {
        return Err("backend cannot enforce filesystem isolation".into());
    }
    match profile.network.as_str() {
        "deny" if !capabilities.network_deny => {
            return Err("backend cannot enforce network denial".into())
        }
        "allowlist" if !capabilities.network_allowlist => {
            return Err("backend cannot enforce a network allowlist".into())
        }
        "deny" | "allowlist" => {}
        _ => return Err("network profile must be deny or allowlist".into()),
    }
    for (requested, supported, name) in [
        (
            profile.process_tree,
            capabilities.process_tree_isolation,
            "process-tree isolation",
        ),
        (profile.cpu_limit, capabilities.cpu_limit, "CPU limits"),
        (
            profile.memory_limit,
            capabilities.memory_limit,
            "memory limits",
        ),
        (profile.disk_quota, capabilities.disk_quota, "disk quotas"),
        (
            profile.disposable_reset,
            capabilities.disposable_reset,
            "disposable reset",
        ),
    ] {
        if requested && !supported {
            return Err(format!("backend cannot enforce {name}"));
        }
    }
    Ok(())
}

fn read_config(app: &AppHandle) -> Result<MacVmSandboxConfig, String> {
    let path = config_path(app)?;
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("sandbox is not configured at {}: {e}", path.display()))?;
    let config: MacVmSandboxConfig = serde_json::from_slice(&bytes)
        .map_err(|e| format!("sandbox configuration is invalid: {e}"))?;
    if config.schema_version != CONFIG_SCHEMA {
        return Err(format!(
            "sandbox configuration schema {} is unsupported",
            config.schema_version
        ));
    }
    Ok(config)
}

fn verify_config(config: &MacVmSandboxConfig) -> Result<HelperProbe, String> {
    let helper = canonical_regular_file(&config.helper_path, "sandbox helper")?;
    let image = canonical_regular_file(&config.vm_image_path, "virtual-machine image")?;
    verify_digest(&helper, &config.helper_sha256, "sandbox helper")?;
    verify_digest(&image, &config.vm_image_sha256, "virtual-machine image")?;
    verify_apple_signature(&helper, &config.expected_team_identifier)?;
    probe_helper(&helper)
}

#[tauri::command]
pub fn configure_guardian_macos_vm_sandbox(
    app: AppHandle,
    input: ConfigureMacVmSandboxInput,
) -> Result<SandboxStatus, String> {
    let helper = canonical_regular_file(&input.helper_path, "sandbox helper")?;
    let image = canonical_regular_file(&input.vm_image_path, "virtual-machine image")?;
    let helper_sha256 = validate_sha256(&input.helper_sha256)?;
    let vm_image_sha256 = validate_sha256(&input.vm_image_sha256)?;
    let expected_team_identifier = validate_team_identifier(&input.expected_team_identifier)?;
    let config = MacVmSandboxConfig {
        schema_version: CONFIG_SCHEMA.into(),
        helper_path: helper,
        helper_sha256,
        vm_image_path: image,
        vm_image_sha256,
        expected_team_identifier,
        configured_at: Utc::now().to_rfc3339(),
    };
    verify_config(&config)?;
    let path = config_path(&app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "sandbox configuration path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create sandbox configuration directory: {e}"))?;
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|e| format!("failed to encode sandbox configuration: {e}"))?;
    std::fs::write(&path, bytes)
        .map_err(|e| format!("failed to persist sandbox configuration: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to protect sandbox configuration: {e}"))?;
    }
    get_guardian_sandbox_status(app)
}

#[tauri::command]
pub fn get_guardian_sandbox_status(app: AppHandle) -> Result<SandboxStatus, String> {
    let config = match read_config(&app) {
        Ok(config) => config,
        Err(error) => {
            return Ok(SandboxStatus {
                schema_version: CONFIG_SCHEMA.into(),
                backend: "macos-virtualization".into(),
                state: "unconfigured".into(),
                detail: error,
                helper_path: None,
                vm_image_path: None,
                helper_verified: false,
                image_verified: false,
                signature_verified: false,
                team_identifier: None,
                capabilities: None,
            });
        }
    };
    match verify_config(&config) {
        Ok(capabilities) => Ok(SandboxStatus {
            schema_version: CONFIG_SCHEMA.into(),
            backend: capabilities.backend.clone(),
            state: "ready".into(),
            detail: "Signed helper, pinned virtual-machine image, and backend capabilities are verified.".into(),
            helper_path: Some(config.helper_path),
            vm_image_path: Some(config.vm_image_path),
            helper_verified: true,
            image_verified: true,
            signature_verified: true,
            team_identifier: Some(config.expected_team_identifier),
            capabilities: Some(capabilities),
        }),
        Err(error) => Ok(SandboxStatus {
            schema_version: CONFIG_SCHEMA.into(),
            backend: "macos-virtualization".into(),
            state: "refused".into(),
            detail: error,
            helper_path: Some(config.helper_path),
            vm_image_path: Some(config.vm_image_path),
            helper_verified: false,
            image_verified: false,
            signature_verified: false,
            team_identifier: Some(config.expected_team_identifier),
            capabilities: None,
        }),
    }
}

#[tauri::command]
pub fn validate_guardian_sandbox_profile(
    app: AppHandle,
    profile: SandboxProfileInput,
) -> Result<SandboxStatus, String> {
    let config = read_config(&app)?;
    let capabilities = verify_config(&config)?;
    compile_profile(&profile, &capabilities)?;
    get_guardian_sandbox_status(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> HelperProbe {
        HelperProbe {
            protocol: HELPER_PROTOCOL.into(),
            backend: "macos-virtualization".into(),
            virtualization_available: true,
            filesystem_isolation: true,
            network_deny: true,
            network_allowlist: false,
            process_tree_isolation: true,
            cpu_limit: true,
            memory_limit: true,
            disk_quota: true,
            disposable_reset: true,
        }
    }

    #[test]
    fn rejects_malformed_trust_anchors() {
        assert!(validate_sha256("abc").is_err());
        assert!(validate_sha256(&"f".repeat(64)).is_ok());
        assert!(validate_team_identifier("SHORT").is_err());
        assert!(validate_team_identifier("A1B2C3D4E5").is_ok());
    }

    #[test]
    fn profile_compilation_fails_closed_for_missing_capability() {
        let profile = SandboxProfileInput {
            filesystem: "workspace_write".into(),
            network: "allowlist".into(),
            process_tree: true,
            cpu_limit: true,
            memory_limit: true,
            disk_quota: true,
            disposable_reset: true,
        };
        assert_eq!(
            compile_profile(&profile, &capabilities()),
            Err("backend cannot enforce a network allowlist".into())
        );
    }

    #[test]
    fn profile_compilation_accepts_only_enforceable_intent() {
        let profile = SandboxProfileInput {
            filesystem: "read_only".into(),
            network: "deny".into(),
            process_tree: true,
            cpu_limit: true,
            memory_limit: true,
            disk_quota: true,
            disposable_reset: true,
        };
        assert!(compile_profile(&profile, &capabilities()).is_ok());
    }
}
