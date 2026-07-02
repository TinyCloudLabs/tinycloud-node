use crate::runtime;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::Client as BlockingClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command, time::Duration};

use super::paths::{
    dir_to_json_string, KeyBackend, LogMode, Manager, Platform, Profile, ProfilePaths,
    CONTROL_CONTRACT_VERSION, SERVICE_LABEL,
};

const NODE_BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManifest {
    pub contract_version: String,
    pub profile: Profile,
    pub platform: Platform,
    pub manager: Manager,
    pub version: String,
    pub config_path: String,
    pub data_path: String,
    pub log_mode: LogMode,
    pub key_backend: KeyBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ControlManifest {
    pub contract_version: String,
    pub host: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub token_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicApi {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub contract_version: String,
    pub profile: Profile,
    pub platform: Platform,
    pub manager: Manager,
    pub state: ServiceState,
    pub pid: Option<u32>,
    pub enabled_at_login: bool,
    pub version: Option<String>,
    pub public_api: PublicApi,
    pub config_path: String,
    pub data_path: String,
    pub log_mode: Option<LogMode>,
    pub key_backend: Option<KeyBackend>,
    pub identity_ready: bool,
    pub node_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_api: Option<ControlApiAnnotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ControlApiAnnotation {
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub contract_version: String,
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorCheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DoctorCheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub manifest: ServiceManifest,
    pub paths: ProfilePaths,
}

#[derive(Debug, Clone)]
struct ControlSession {
    client: BlockingClient,
    base_url: String,
    token: String,
}

pub fn current_profile_paths() -> ProfilePaths {
    Profile::default_for_host().paths()
}

pub fn default_service_status() -> ServiceStatus {
    let paths = current_profile_paths();
    ServiceStatus {
        contract_version: CONTROL_CONTRACT_VERSION.to_string(),
        profile: paths.profile,
        platform: paths.platform,
        manager: paths.manager,
        state: ServiceState::NotInstalled,
        pid: None,
        enabled_at_login: false,
        version: Some(NODE_BINARY_VERSION.to_string()),
        public_api: public_api_from_config(&paths.config_path),
        config_path: paths.config_path_json(),
        data_path: paths.data_root_json(),
        log_mode: Some(paths.profile.log_mode()),
        key_backend: Some(paths.profile.key_backend()),
        identity_ready: false,
        node_did: None,
        control_api: None,
    }
}

pub fn install() -> Result<()> {
    let paths = current_profile_paths();
    install_for_paths(&paths)
}

pub fn uninstall() -> Result<()> {
    let paths = current_profile_paths();
    uninstall_for_paths(&paths)
}

pub fn start() -> Result<()> {
    let paths = load_installed_paths()?;
    start_for_paths(&paths)
}

pub fn stop() -> Result<()> {
    let paths = load_installed_paths()?;
    stop_for_paths(&paths)
}

pub fn restart() -> Result<()> {
    let paths = load_installed_paths()?;
    restart_for_paths(&paths)
}

pub fn service_status() -> Result<ServiceStatus> {
    match discover_installed_service()? {
        Some(installed) => Ok(service_status_for_installed(installed)),
        None => Ok(default_service_status()),
    }
}

pub fn node_status() -> Result<Value> {
    let session = discover_control_session()?;
    session.get_json("/v1/status")
}

pub fn node_status_body() -> Result<String> {
    let session = discover_control_session()?;
    session.get_text("/v1/status")
}

pub fn node_logs(lines: Option<u32>) -> Result<Value> {
    let session = discover_control_session()?;
    let mut url = String::from("/v1/logs/tail");
    if let Some(lines) = lines {
        url.push_str(&format!("?lines={lines}"));
    }
    session.get_json(&url)
}

pub fn node_logs_body(lines: Option<u32>) -> Result<String> {
    let session = discover_control_session()?;
    let mut url = String::from("/v1/logs/tail");
    if let Some(lines) = lines {
        url.push_str(&format!("?lines={lines}"));
    }
    session.get_text(&url)
}

pub fn node_doctor() -> Result<DoctorReport> {
    let current_paths = current_profile_paths();
    let discovered = discover_installed_service()?;
    let (paths, manifest) = match discovered {
        Some(installed) => (installed.paths, Some(installed.manifest)),
        None => (current_paths, None),
    };
    let session = discover_control_session_for_paths(&paths);
    let mut checks = Vec::new();
    let mut warnings = Vec::new();

    checks.push(check_service_install(&paths, manifest.as_ref()));
    checks.push(check_local_files(&paths, manifest.as_ref()));

    let mut control_status = DoctorCheck {
        name: "control".into(),
        status: DoctorCheckStatus::Fail,
        details: None,
    };
    let mut identity_status = DoctorCheck {
        name: "identity".into(),
        status: DoctorCheckStatus::Fail,
        details: None,
    };
    let mut config_status = DoctorCheck {
        name: "config".into(),
        status: DoctorCheckStatus::Fail,
        details: None,
    };

    match session {
        Ok(session) => {
            match session.get_json("/v1/status") {
                Ok(value) => {
                    control_status.status = DoctorCheckStatus::Pass;
                    control_status.details = Some(value);
                }
                Err(err) => {
                    control_status.status = DoctorCheckStatus::Fail;
                    control_status.details = Some(json!({"error": err.to_string()}));
                }
            }

            match session.get_json("/v1/identity") {
                Ok(value) => {
                    identity_status.status = DoctorCheckStatus::Pass;
                    identity_status.details = Some(value);
                }
                Err(err) => {
                    identity_status.status = DoctorCheckStatus::Fail;
                    identity_status.details = Some(json!({"error": err.to_string()}));
                }
            }

            match session.get_json("/v1/config") {
                Ok(value) => {
                    let public_api = value
                        .get("config")
                        .and_then(|config| config.get("publicApi"))
                        .and_then(|public_api| public_api.get("address"))
                        .and_then(|value| value.as_str());

                    if public_api.map(is_loopback_address).unwrap_or(false) {
                        config_status.status = DoctorCheckStatus::Pass;
                    } else {
                        config_status.status = DoctorCheckStatus::Fail;
                    }
                    config_status.details = Some(value);
                }
                Err(err) => {
                    config_status.status = DoctorCheckStatus::Fail;
                    config_status.details = Some(json!({"error": err.to_string()}));
                }
            }
        }
        Err(err) => {
            control_status.details = Some(json!({"error": err.to_string()}));
            identity_status.details = Some(json!({"error": err.to_string()}));
            config_status.details = Some(json!({"error": err.to_string()}));
        }
    }

    if let Some(manifest) = manifest.as_ref() {
        if matches!(manifest.key_backend, KeyBackend::Static) {
            warnings.push("legacy static key source is deprecated for desktop installs".into());
        }
    } else if std::env::var_os("TINYCLOUD_KEYS_SECRET").is_some() {
        warnings.push("legacy static key source is deprecated for desktop installs".into());
    }

    checks.push(control_status);
    checks.push(identity_status);
    checks.push(config_status);

    let ok = checks
        .iter()
        .all(|check| !matches!(check.status, DoctorCheckStatus::Fail));

    Ok(DoctorReport {
        contract_version: CONTROL_CONTRACT_VERSION.to_string(),
        ok,
        checks,
        warnings,
    })
}

pub fn install_for_paths(paths: &ProfilePaths) -> Result<()> {
    ensure_parent_dir(&paths.service_manifest_path)?;
    ensure_parent_dir(&paths.service_unit_path)?;
    write_bootstrap_config_if_absent(paths)?;
    if !matches!(paths.profile.log_mode(), LogMode::Journald) {
        ensure_dir(&paths.logs_root)?;
    }

    let manifest = ServiceManifest {
        contract_version: CONTROL_CONTRACT_VERSION.to_string(),
        profile: paths.profile,
        platform: paths.platform,
        manager: paths.manager,
        version: NODE_BINARY_VERSION.to_string(),
        config_path: paths.config_path_json(),
        data_path: paths.data_root_json(),
        log_mode: paths.profile.log_mode(),
        key_backend: paths.profile.key_backend(),
    };

    write_service_manifest(&paths.service_manifest_path, &manifest)?;
    write_service_unit(paths)?;
    enable_service(paths)?;
    Ok(())
}

pub fn uninstall_for_paths(paths: &ProfilePaths) -> Result<()> {
    let _ = stop_for_paths(paths);
    disable_service(paths).ok();
    remove_if_exists(&paths.service_unit_path)?;
    remove_if_exists(&paths.service_manifest_path)?;
    remove_if_exists(&paths.control_json_path)?;
    remove_if_exists(&paths.control_token_path)?;
    remove_if_exists(&paths.overlay_path)?;
    remove_dir_if_empty(&paths.runtime_dir)?;
    Ok(())
}

pub fn start_for_paths(paths: &ProfilePaths) -> Result<()> {
    match paths.manager {
        Manager::LaunchdUser | Manager::HomebrewLaunchagent => {
            if is_launchd_loaded(paths)? {
                run_launchctl(&["kickstart", "-k", &launchd_domain(paths), &service_label()])
            } else {
                run_launchctl(&[
                    "bootstrap",
                    &launchd_domain(paths),
                    &paths.service_unit_path.display().to_string(),
                ])
            }
        }
        Manager::SystemdUser => run_systemctl(&["--user", "start", &service_unit_name()]),
        Manager::SystemdSystem => run_systemctl(&["start", &service_unit_name()]),
    }
}

pub fn stop_for_paths(paths: &ProfilePaths) -> Result<()> {
    match paths.manager {
        Manager::LaunchdUser | Manager::HomebrewLaunchagent => run_launchctl(&[
            "bootout",
            &launchd_domain(paths),
            &paths.service_unit_path.display().to_string(),
        ]),
        Manager::SystemdUser => run_systemctl(&["--user", "stop", &service_unit_name()]),
        Manager::SystemdSystem => run_systemctl(&["stop", &service_unit_name()]),
    }
}

pub fn restart_for_paths(paths: &ProfilePaths) -> Result<()> {
    let _ = stop_for_paths(paths);
    start_for_paths(paths)
}

pub fn service_status_for_installed(installed: DiscoveredService) -> ServiceStatus {
    let DiscoveredService { manifest, paths } = installed;
    let control = probe_control_api(&manifest, &paths);
    let public_api = control
        .public_api
        .clone()
        .unwrap_or_else(|| public_api_from_config(Path::new(&manifest.config_path)));
    let contract_version = control
        .contract_version
        .clone()
        .unwrap_or_else(|| manifest.contract_version.clone());
    let version = control
        .version
        .clone()
        .or_else(|| Some(manifest.version.clone()));
    let identity_ready = control.identity_ready.unwrap_or(false);
    let node_did = control.node_did.clone();
    let (state, pid, control_api) = derive_state(&manifest, &paths, &control);

    ServiceStatus {
        contract_version,
        profile: manifest.profile,
        platform: manifest.platform,
        manager: manifest.manager,
        state,
        pid,
        enabled_at_login: manager_enabled_at_login(manifest.manager, &paths),
        version,
        public_api,
        config_path: manifest.config_path,
        data_path: manifest.data_path,
        log_mode: Some(manifest.log_mode),
        key_backend: Some(manifest.key_backend),
        identity_ready,
        node_did,
        control_api,
    }
}

fn derive_state(
    manifest: &ServiceManifest,
    paths: &ProfilePaths,
    control: &ControlProbe,
) -> (ServiceState, Option<u32>, Option<ControlApiAnnotation>) {
    let manager = current_manager_state(paths, manifest);
    match manager {
        ManagerState::NotInstalled => (ServiceState::NotInstalled, None, None),
        ManagerState::Stopped => (ServiceState::Stopped, None, None),
        ManagerState::Running { pid, age_secs } => {
            if let Some(state) = control.state.as_ref() {
                return (state.clone(), Some(pid), control.annotation.clone());
            }
            if control.unavailable {
                if age_secs.map(|age| age < 30).unwrap_or(true) {
                    return (
                        ServiceState::Starting,
                        Some(pid),
                        Some(ControlApiAnnotation::Unavailable),
                    );
                }
                // TC-78 will provide the live control listener; until then we
                // report an available manager with an unavailable control API as running.
                return (
                    ServiceState::Running,
                    Some(pid),
                    Some(ControlApiAnnotation::Unavailable),
                );
            }
            (ServiceState::Running, Some(pid), None)
        }
    }
}

#[derive(Debug, Clone)]
enum ManagerState {
    NotInstalled,
    Stopped,
    Running { pid: u32, age_secs: Option<u64> },
}

#[derive(Debug, Clone)]
struct ControlProbe {
    unavailable: bool,
    state: Option<ServiceState>,
    annotation: Option<ControlApiAnnotation>,
    contract_version: Option<String>,
    version: Option<String>,
    public_api: Option<PublicApi>,
    identity_ready: Option<bool>,
    node_did: Option<String>,
}

fn current_manager_state(paths: &ProfilePaths, manifest: &ServiceManifest) -> ManagerState {
    if !paths.service_unit_path.exists() && !paths.service_manifest_path.exists() {
        return ManagerState::NotInstalled;
    }

    match manifest.manager {
        Manager::LaunchdUser | Manager::HomebrewLaunchagent => {
            let output = run_command_output(&[
                "launchctl",
                "print",
                &format!("{}/{}", launchd_domain(paths), service_label()),
            ]);
            match output {
                Ok(output) => {
                    if let Some(pid) = parse_pid(&output.stdout) {
                        let age_secs = process_age(pid).ok();
                        ManagerState::Running { pid, age_secs }
                    } else {
                        ManagerState::Stopped
                    }
                }
                Err(_) => ManagerState::Stopped,
            }
        }
        Manager::SystemdUser | Manager::SystemdSystem => {
            let unit = service_unit_name();
            let output = if matches!(manifest.manager, Manager::SystemdUser) {
                run_command_output(&["systemctl", "--user", "show", "--property=MainPID", &unit])
            } else {
                run_command_output(&["systemctl", "show", "--property=MainPID", &unit])
            };
            match output {
                Ok(output) => {
                    if let Some(pid) = parse_systemd_pid(&output.stdout) {
                        if pid == 0 {
                            ManagerState::Stopped
                        } else {
                            let age_secs = process_age(pid).ok();
                            ManagerState::Running { pid, age_secs }
                        }
                    } else {
                        ManagerState::Stopped
                    }
                }
                Err(_) => ManagerState::Stopped,
            }
        }
    }
}

fn manager_enabled_at_login(manager: Manager, paths: &ProfilePaths) -> bool {
    match manager {
        Manager::LaunchdUser | Manager::HomebrewLaunchagent => {
            launchd_enabled_at_login(paths).unwrap_or(true)
        }
        Manager::SystemdUser => systemd_enabled_at_login().unwrap_or(false),
        Manager::SystemdSystem => false,
    }
}

fn launchd_enabled_at_login(paths: &ProfilePaths) -> Result<bool> {
    let output = Command::new("launchctl")
        .args(["print-disabled", &launchd_domain(paths)])
        .output()
        .with_context(|| "failed to execute launchctl")?;

    if !output.status.success() {
        bail!("launchctl print-disabled failed");
    }

    Ok(
        launchd_enabled_at_login_from_stdout(&String::from_utf8_lossy(&output.stdout))
            .unwrap_or(true),
    )
}

fn systemd_enabled_at_login() -> Result<bool> {
    let output = Command::new("systemctl")
        .args(["--user", "is-enabled", &service_unit_name()])
        .output()
        .with_context(|| "failed to execute systemctl")?;

    if !output.status.success() {
        return Ok(false);
    }

    Ok(systemd_enabled_at_login_from_stdout(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

fn launchd_enabled_at_login_from_stdout(stdout: &str) -> Option<bool> {
    for line in stdout.lines() {
        if let Some((label, value)) = line.split_once("=>") {
            let label = label.trim().trim_matches('"');
            if label == SERVICE_LABEL {
                let value = value.trim();
                return match value {
                    "false" | "enabled" => Some(true),
                    "true" | "disabled" => Some(false),
                    _ => None,
                };
            }
        }
    }

    None
}

fn systemd_enabled_at_login_from_stdout(stdout: &str) -> bool {
    let state = stdout.trim();
    matches!(
        state,
        "enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias"
    )
}

fn probe_control_api(manifest: &ServiceManifest, paths: &ProfilePaths) -> ControlProbe {
    let control_manifest = match read_control_manifest(&paths.control_json_path) {
        Ok(manifest) => manifest,
        Err(_) => {
            return ControlProbe {
                unavailable: true,
                state: None,
                annotation: Some(ControlApiAnnotation::Unavailable),
                contract_version: None,
                version: Some(manifest.version.clone()),
                public_api: None,
                identity_ready: None,
                node_did: None,
            };
        }
    };

    let token = match fs::read_to_string(&control_manifest.token_path) {
        Ok(token) => token.trim().to_string(),
        Err(_) => {
            return ControlProbe {
                unavailable: true,
                state: None,
                annotation: Some(ControlApiAnnotation::Unavailable),
                contract_version: None,
                version: Some(manifest.version.clone()),
                public_api: None,
                identity_ready: None,
                node_did: None,
            };
        }
    };

    let client = control_client();
    let base_url = control_base_url(&control_manifest.host, control_manifest.port);
    let session = ControlSession {
        client,
        base_url,
        token,
    };

    let status = match session.get_json("/v1/status") {
        Ok(status) => status,
        Err(_) => {
            return ControlProbe {
                unavailable: true,
                state: None,
                annotation: Some(ControlApiAnnotation::Unavailable),
                contract_version: None,
                version: Some(manifest.version.clone()),
                public_api: None,
                identity_ready: None,
                node_did: None,
            };
        }
    };

    let version = session.get_json("/v1/version").ok();
    let identity = session.get_json("/v1/identity").ok();

    ControlProbe {
        unavailable: false,
        state: control_state(&status),
        annotation: None,
        contract_version: version
            .as_ref()
            .and_then(|value| value.get("contractVersion"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        version: version
            .as_ref()
            .and_then(|value| value.get("appVersion"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .or_else(|| Some(manifest.version.clone())),
        public_api: status.get("publicApi").and_then(public_api_from_value),
        identity_ready: identity
            .as_ref()
            .and_then(|value| value.get("identityReady"))
            .and_then(|value| value.as_bool()),
        node_did: identity
            .as_ref()
            .and_then(|value| value.get("nodeDid"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
    }
}

fn discover_installed_service() -> Result<Option<DiscoveredService>> {
    for profile in Profile::discovery_order_for_host() {
        let paths = profile.paths();
        if !paths.service_manifest_path.exists() {
            continue;
        }

        let manifest = read_service_manifest(&paths.service_manifest_path)?;
        return Ok(Some(DiscoveredService { manifest, paths }));
    }

    Ok(None)
}

fn load_installed_paths() -> Result<ProfilePaths> {
    if let Some(installed) = discover_installed_service()? {
        return Ok(installed.paths);
    }

    bail!("service is not installed")
}

fn discover_control_session() -> Result<ControlSession> {
    let installed =
        discover_installed_service()?.ok_or_else(|| anyhow!("service is not installed"))?;
    discover_control_session_for_paths(&installed.paths)
}

fn discover_control_session_for_paths(paths: &ProfilePaths) -> Result<ControlSession> {
    let _manifest = read_service_manifest_if_present(&paths.service_manifest_path)?
        .ok_or_else(|| anyhow!("service is not installed"))?;
    let control = read_control_manifest(&paths.control_json_path).with_context(|| {
        format!(
            "missing control discovery file at {}",
            paths.control_json_path.display()
        )
    })?;
    let token = fs::read_to_string(&control.token_path)
        .with_context(|| format!("missing control token at {}", control.token_path))?
        .trim()
        .to_string();
    let client = control_client();
    let base_url = control_base_url(&control.host, control.port);
    Ok(ControlSession {
        client,
        base_url,
        token,
    })
}

fn control_client() -> BlockingClient {
    BlockingClient::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .expect("blocking reqwest client should build")
}

fn control_base_url(host: &str, port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("http://{host}:{port}")
}

impl ControlSession {
    fn get_text(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .with_context(|| "failed to reach control API")?;

        if !response.status().is_success() {
            bail!("control API returned {}", response.status());
        }

        response.text().context("failed to read control API body")
    }

    fn get_json(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .with_context(|| "failed to reach control API")?;

        if !response.status().is_success() {
            bail!("control API returned {}", response.status());
        }

        response
            .json::<Value>()
            .context("failed to decode control API JSON")
    }
}

fn control_state(value: &Value) -> Option<ServiceState> {
    value
        .get("state")
        .and_then(|value| value.as_str())
        .and_then(|value| match value {
            "not-installed" => Some(ServiceState::NotInstalled),
            "stopped" => Some(ServiceState::Stopped),
            "starting" => Some(ServiceState::Starting),
            "running" => Some(ServiceState::Running),
            "stopping" => Some(ServiceState::Stopping),
            "error" => Some(ServiceState::Error),
            _ => None,
        })
}

fn public_api_from_value(value: &Value) -> Option<PublicApi> {
    Some(PublicApi {
        address: value.get("address")?.as_str()?.to_string(),
        port: value.get("port")?.as_u64()? as u16,
    })
}

fn default_public_api() -> PublicApi {
    PublicApi {
        address: "127.0.0.1".into(),
        port: 8081,
    }
}

fn public_api_from_config(config_path: impl AsRef<Path>) -> PublicApi {
    let config_path = config_path.as_ref();
    let figment = match runtime::serve_config_figment(config_path) {
        Ok(figment) => figment,
        Err(_) => return default_public_api(),
    };
    let rocket_config = match rocket::Config::try_from(figment.clone()) {
        Ok(config) => config,
        Err(_) => return default_public_api(),
    };
    let PublicApi {
        address: default_address,
        port: default_port,
    } = default_public_api();
    let address = match figment.find_metadata(rocket::Config::ADDRESS) {
        Some(metadata) if metadata.name.as_ref() == "rocket::Config::default()" => default_address,
        _ => rocket_config.address.to_string(),
    };
    let port = match figment.find_metadata(rocket::Config::PORT) {
        Some(metadata) if metadata.name.as_ref() == "rocket::Config::default()" => default_port,
        _ => rocket_config.port,
    };

    PublicApi { address, port }
}

fn is_loopback_address(value: &str) -> bool {
    matches!(value, "127.0.0.1" | "::1" | "localhost")
}

fn service_label() -> String {
    SERVICE_LABEL.to_string()
}

fn service_unit_name() -> String {
    format!("{SERVICE_LABEL}.service")
}

fn launchd_domain(_paths: &ProfilePaths) -> String {
    format!("gui/{}", effective_uid())
}

fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }

    #[cfg(not(unix))]
    {
        1
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn remove_dir_if_empty(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn write_service_manifest(path: &Path, manifest: &ServiceManifest) -> Result<()> {
    let rendered = serde_json::to_string_pretty(manifest)?;
    fs::write(path, rendered).with_context(|| format!("failed to write {}", path.display()))
}

fn read_service_manifest(path: &Path) -> Result<ServiceManifest> {
    let rendered =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&rendered).with_context(|| format!("failed to parse {}", path.display()))
}

fn load_service_manifest_if_present(path: &Path) -> Result<Option<ServiceManifest>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_service_manifest(path)?))
}

fn read_service_manifest_if_present(path: &Path) -> Result<Option<ServiceManifest>> {
    load_service_manifest_if_present(path)
}

fn read_control_manifest(path: &Path) -> Result<ControlManifest> {
    let rendered =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&rendered).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_bootstrap_config_if_absent(paths: &ProfilePaths) -> Result<()> {
    if paths.config_path.exists() {
        return Ok(());
    }

    ensure_parent_dir(&paths.config_path)?;
    let public_api = default_public_api();
    let address = serde_json::to_string(&public_api.address)?;
    let datadir = serde_json::to_string(&paths.data_root.display().to_string())?;
    let rendered = format!(
        "# Generated by `tinycloud node service install`.\n[global]\naddress = {address}\nport = {port}\nlog_level = \"info\"\n\n[global.storage]\ndatadir = {datadir}\n",
        port = public_api.port,
    );

    fs::write(&paths.config_path, rendered)
        .with_context(|| format!("failed to write {}", paths.config_path.display()))
}

fn write_service_unit(paths: &ProfilePaths) -> Result<()> {
    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    match paths.manager {
        Manager::LaunchdUser | Manager::HomebrewLaunchagent => {
            let xml = launchd_plist(
                &executable,
                &paths.config_path,
                &paths.logs_file_path,
                &paths.logs_error_path,
            );
            fs::write(&paths.service_unit_path, xml)
                .with_context(|| format!("failed to write {}", paths.service_unit_path.display()))
        }
        Manager::SystemdUser | Manager::SystemdSystem => {
            let unit = systemd_unit(
                &executable,
                &paths.config_path,
                &paths.logs_file_path,
                &paths.logs_error_path,
                paths.manager,
            );
            fs::write(&paths.service_unit_path, unit)
                .with_context(|| format!("failed to write {}", paths.service_unit_path.display()))
        }
    }
}

fn launchd_plist(executable: &Path, config_path: &Path, stdout: &Path, stderr: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>serve</string>
    <string>--config</string>
    <string>{config}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#,
        label = SERVICE_LABEL,
        exe = xml_escape(executable.display().to_string()),
        config = xml_escape(config_path.display().to_string()),
        stdout = xml_escape(stdout.display().to_string()),
        stderr = xml_escape(stderr.display().to_string()),
    )
}

fn systemd_unit(
    executable: &Path,
    config_path: &Path,
    stdout: &Path,
    stderr: &Path,
    manager: Manager,
) -> String {
    let wanted_by = if matches!(manager, Manager::SystemdSystem) {
        "multi-user.target"
    } else {
        "default.target"
    };
    let logging = if matches!(manager, Manager::SystemdSystem) {
        "StandardOutput=journal\nStandardError=journal\n".to_string()
    } else {
        let stdout = stdout.display().to_string();
        let stderr = stderr.display().to_string();
        format!("StandardOutput=append:{stdout}\nStandardError=append:{stderr}\n")
    };
    format!(
        "[Unit]\nDescription=TinyCloud Node\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} serve --config {}\nRestart=on-failure\n{}\n[Install]\nWantedBy={}\n",
        shell_quote(&executable.display().to_string()),
        shell_quote(&config_path.display().to_string()),
        logging,
        wanted_by,
    )
}

fn xml_escape(value: String) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".into();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))
    {
        return value.to_string();
    }
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn enable_service(paths: &ProfilePaths) -> Result<()> {
    match paths.manager {
        Manager::LaunchdUser | Manager::HomebrewLaunchagent => run_launchctl(&[
            "enable",
            &format!("{}/{}", launchd_domain(paths), service_label()),
        ]),
        Manager::SystemdUser => run_systemctl(&["--user", "enable", &service_unit_name()]),
        Manager::SystemdSystem => run_systemctl(&["enable", &service_unit_name()]),
    }
}

fn disable_service(paths: &ProfilePaths) -> Result<()> {
    match paths.manager {
        Manager::LaunchdUser | Manager::HomebrewLaunchagent => run_launchctl(&[
            "disable",
            &format!("{}/{}", launchd_domain(paths), service_label()),
        ]),
        Manager::SystemdUser => run_systemctl(&["--user", "disable", &service_unit_name()]),
        Manager::SystemdSystem => run_systemctl(&["disable", &service_unit_name()]),
    }
}

fn run_launchctl(args: &[&str]) -> Result<()> {
    run_command("launchctl", args)
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    run_command("systemctl", args)
}

fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(anyhow!("{program} {:?} failed: {}", args, stderr.trim()))
}

fn run_command_output(args: &[&str]) -> Result<std::process::Output> {
    let (program, rest) = args
        .split_first()
        .ok_or_else(|| anyhow!("missing command"))?;
    Command::new(program)
        .args(rest)
        .output()
        .with_context(|| format!("failed to execute {program}"))
        .and_then(|output| {
            if output.status.success() {
                Ok(output)
            } else {
                Err(anyhow!(
                    "{program} {:?} failed: {}",
                    rest,
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        })
}

fn is_launchd_loaded(paths: &ProfilePaths) -> Result<bool> {
    let output = Command::new("launchctl")
        .args([
            "print",
            &format!("{}/{}", launchd_domain(paths), service_label()),
        ])
        .output()
        .with_context(|| "failed to execute launchctl")?;
    Ok(output.status.success())
}

fn parse_pid(stdout: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pid =") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn parse_systemd_pid(stdout: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MainPID=") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn process_age(pid: u32) -> Result<u64> {
    let output = Command::new("ps")
        .args(["-o", ps_elapsed_field(), "-p", &pid.to_string()])
        .output()
        .with_context(|| "failed to execute ps")?;
    if !output.status.success() {
        bail!("ps failed")
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let age = parse_process_age(text.trim()).context("failed to parse process age")?;
    Ok(age)
}

fn ps_elapsed_field() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "etime="
    }

    #[cfg(not(target_os = "macos"))]
    {
        "etimes="
    }
}

fn parse_process_age(value: &str) -> Option<u64> {
    if let Ok(age) = value.parse::<u64>() {
        return Some(age);
    }

    let (days, time_part) = match value.split_once('-') {
        Some((days, time_part)) => (days.parse::<u64>().ok()?, time_part),
        None => (0, value),
    };
    let mut parts = time_part.split(':');

    let (hours, minutes, seconds) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(minutes), Some(seconds), None, None) => (
            0,
            minutes.parse::<u64>().ok()?,
            seconds.parse::<u64>().ok()?,
        ),
        (Some(hours), Some(minutes), Some(seconds), None) => (
            hours.parse::<u64>().ok()?,
            minutes.parse::<u64>().ok()?,
            seconds.parse::<u64>().ok()?,
        ),
        _ => return None,
    };

    let mut total = days.checked_mul(24 * 60 * 60)?;
    total = total.checked_add(hours.checked_mul(60 * 60)?)?;
    total = total.checked_add(minutes.checked_mul(60)?)?;
    total.checked_add(seconds)
}

fn check_service_install(paths: &ProfilePaths, manifest: Option<&ServiceManifest>) -> DoctorCheck {
    let installed = manifest.is_some() && paths.service_manifest_path.exists();
    DoctorCheck {
        name: "service".into(),
        status: if installed {
            DoctorCheckStatus::Pass
        } else {
            DoctorCheckStatus::Fail
        },
        details: Some(json!({
            "manifestPath": paths.service_manifest_path.display().to_string(),
            "unitPath": paths.service_unit_path.display().to_string(),
            "installed": installed,
        })),
    }
}

fn check_local_files(paths: &ProfilePaths, manifest: Option<&ServiceManifest>) -> DoctorCheck {
    let config_exists = paths.config_path.exists();
    let data_exists = paths.data_root.exists();
    let runtime_exists = paths.runtime_dir.exists();
    let control_json_exists = paths.control_json_path.exists();
    let control_token_exists = paths.control_token_path.exists();
    let mut status = if config_exists && data_exists {
        DoctorCheckStatus::Pass
    } else {
        DoctorCheckStatus::Warn
    };
    let token_permission_ok = token_permissions_ok(paths, manifest);

    if manifest.is_none() {
        status = DoctorCheckStatus::Warn;
    }
    if control_token_exists && !token_permission_ok {
        status = DoctorCheckStatus::Fail;
    }
    DoctorCheck {
        name: "filesystem".into(),
        status,
        details: Some(json!({
            "configPath": paths.config_path.display().to_string(),
            "configExists": config_exists,
            "dataPath": dir_to_json_string(&paths.data_root),
            "dataExists": data_exists,
            "runtimeExists": runtime_exists,
            "controlJsonPath": paths.control_json_path.display().to_string(),
            "controlJsonExists": control_json_exists,
            "controlTokenPath": paths.control_token_path.display().to_string(),
            "controlTokenExists": control_token_exists,
            "controlTokenPermissionsOk": token_permission_ok,
        })),
    }
}

fn token_permissions_ok(paths: &ProfilePaths, manifest: Option<&ServiceManifest>) -> bool {
    if !paths.control_token_path.exists() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = match fs::metadata(&paths.control_token_path) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };

        let mode = metadata.permissions().mode() & 0o777;
        match manifest
            .map(|manifest| manifest.manager)
            .unwrap_or(paths.manager)
        {
            Manager::SystemdSystem => mode == 0o640 && metadata.uid() == 0,
            _ => mode == 0o600,
        }
    }

    #[cfg(not(unix))]
    {
        let _ = manifest;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        ffi::{OsStr, OsString},
        fs,
        path::Path,
        sync::{Mutex, OnceLock},
    };
    use tempfile::tempdir;

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = env::var_os(key);
            env::set_var(key, value);
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = env::var_os(key);
            env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    fn prepend_path(dir: &Path) -> EnvGuard {
        let previous = env::var_os("PATH");
        let mut rendered = dir.as_os_str().to_os_string();
        if let Some(existing) = &previous {
            rendered.push(":");
            rendered.push(existing);
        }
        env::set_var("PATH", &rendered);
        EnvGuard {
            key: "PATH",
            previous,
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    fn write_script(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).unwrap();
        }
    }

    #[test]
    fn macos_paths_use_override_root() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _guard = EnvGuard::set("TINYCLOUD_NODE_CONFIG_ROOT", temp.path());

        let paths = ProfilePaths::resolve(Profile::MacosUser);

        assert_eq!(paths.config_root, temp.path());
        assert_eq!(paths.data_root, temp.path());
        assert_eq!(paths.config_path, temp.path().join("tinycloud.toml"));
        assert_eq!(
            paths.service_manifest_path,
            temp.path().join("service.json")
        );
        assert_eq!(
            paths.service_unit_path,
            temp.path()
                .join("LaunchAgents")
                .join("xyz.tinycloud.node.plist")
        );
    }

    #[test]
    fn linux_user_paths_respect_xdg() {
        let _lock = env_lock();
        let config = tempdir().unwrap();
        let data = tempdir().unwrap();
        let state = tempdir().unwrap();
        let _c = EnvGuard::set("XDG_CONFIG_HOME", config.path());
        let _d = EnvGuard::set("XDG_DATA_HOME", data.path());
        let _s = EnvGuard::set("XDG_STATE_HOME", state.path());
        let _override = EnvGuard::unset("TINYCLOUD_NODE_CONFIG_ROOT");

        let paths = ProfilePaths::resolve(Profile::LinuxUser);

        assert_eq!(paths.config_root, config.path().join("tinycloud-node"));
        assert_eq!(paths.data_root, data.path().join("tinycloud-node"));
        assert_eq!(paths.logs_root, state.path().join("tinycloud-node"));
        assert_eq!(
            paths.service_manifest_path,
            config.path().join("tinycloud-node").join("service.json")
        );
    }

    #[test]
    fn linux_system_paths_use_system_roots_and_journald() {
        let _lock = env_lock();
        let _override = EnvGuard::unset("TINYCLOUD_NODE_CONFIG_ROOT");

        let paths = ProfilePaths::resolve(Profile::LinuxSystem);

        assert_eq!(paths.config_root, Path::new("/etc/tinycloud-node"));
        assert_eq!(paths.data_root, Path::new("/var/lib/tinycloud-node"));
        assert_eq!(paths.logs_root, Path::new("journald"));
        assert_eq!(
            paths.service_manifest_path,
            Path::new("/etc/tinycloud-node/service.json")
        );
        assert_eq!(paths.profile.log_mode(), LogMode::Journald);
        assert_eq!(paths.manager, Manager::SystemdSystem);
    }

    #[test]
    fn service_manifest_roundtrip() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("service.json");
        let manifest = ServiceManifest {
            contract_version: CONTROL_CONTRACT_VERSION.into(),
            profile: Profile::MacosUser,
            platform: Platform::Macos,
            manager: Manager::LaunchdUser,
            version: "1.4.2".into(),
            config_path: "/tmp/TinyCloud Node/tinycloud.toml".into(),
            data_path: "/tmp/TinyCloud Node/".into(),
            log_mode: LogMode::File,
            key_backend: KeyBackend::MacosKeychain,
        };

        write_service_manifest(&path, &manifest).unwrap();
        let decoded = read_service_manifest(&path).unwrap();

        assert_eq!(decoded, manifest);
    }

    #[test]
    fn public_api_from_config_uses_effective_rocket_bind() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let config = temp.path().join("tinycloud.toml");
        let data = temp.path().join("data");
        fs::create_dir_all(&data).unwrap();
        let _storage_legacy = EnvGuard::unset("TINYCLOUD_STORAGE_DATADIR");
        let _storage_canonical = EnvGuard::unset("TINYCLOUD_STORAGE__DATADIR");
        let _address = EnvGuard::unset("TINYCLOUD_ADDRESS");
        let _port = EnvGuard::unset("TINYCLOUD_PORT");
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");
        fs::write(
            &config,
            format!(
                "[global]\nport = 18098\n\n[global.storage]\ndatadir = \"{}\"\n",
                data.display()
            ),
        )
        .unwrap();

        let public_api = public_api_from_config(&config);

        assert_eq!(public_api.address, "127.0.0.1");
        assert_eq!(public_api.port, 18098);
    }

    #[test]
    fn install_writes_bootstrap_config_and_uninstall_keeps_it() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _config_root = EnvGuard::set("TINYCLOUD_NODE_CONFIG_ROOT", temp.path());
        let _storage_legacy = EnvGuard::unset("TINYCLOUD_STORAGE_DATADIR");
        let _storage_canonical = EnvGuard::unset("TINYCLOUD_STORAGE__DATADIR");
        let _address = EnvGuard::unset("TINYCLOUD_ADDRESS");
        let _port = EnvGuard::unset("TINYCLOUD_PORT");
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        write_script(
            &bin,
            "launchctl",
            r#"#!/bin/sh
cmd="$1"
case "$cmd" in
  enable|disable|bootstrap|kickstart|bootout)
    exit 0
    ;;
  print)
    echo "service = { state = stopped }"
    exit 0
    ;;
  print-disabled)
    echo '"xyz.tinycloud.node" => false'
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#,
        );
        let _path = prepend_path(&bin);

        let paths = ProfilePaths::resolve(Profile::MacosUser);
        install_for_paths(&paths).unwrap();

        assert!(paths.config_path.exists());
        let rendered = fs::read_to_string(&paths.config_path).unwrap();
        assert!(rendered.contains("# Generated by `tinycloud node service install`."));
        assert!(rendered.contains("address = \"127.0.0.1\""));
        assert!(rendered.contains("port = 8081"));
        assert!(rendered.contains("log_level = \"info\""));

        let installed = DiscoveredService {
            manifest: read_service_manifest(&paths.service_manifest_path).unwrap(),
            paths: paths.clone(),
        };
        let status = service_status_for_installed(installed);

        assert_eq!(status.state, ServiceState::Stopped);
        assert_eq!(status.public_api.address, "127.0.0.1");
        assert_eq!(status.public_api.port, 8081);

        uninstall_for_paths(&paths).unwrap();

        assert!(paths.config_path.exists());
    }

    #[test]
    fn derive_state_respects_thirty_second_grace_boundary() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let config_home = temp.path().join("config");
        let data_home = temp.path().join("data");
        let state_home = temp.path().join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config_home).unwrap();
        fs::create_dir_all(&data_home).unwrap();
        fs::create_dir_all(&state_home).unwrap();
        let _home = EnvGuard::set("HOME", &home);
        let _config = EnvGuard::set("XDG_CONFIG_HOME", &config_home);
        let _data = EnvGuard::set("XDG_DATA_HOME", &data_home);
        let _state = EnvGuard::set("XDG_STATE_HOME", &state_home);
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        write_script(
            &bin,
            "systemctl",
            r#"#!/bin/sh
while [ "${1#-}" != "$1" ]; do
  shift
done
case "$1" in
  show)
    echo "MainPID=4242"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#,
        );
        write_script(
            &bin,
            "ps",
            r#"#!/bin/sh
printf '%s\n' "${FAKE_PS_AGE:-29}"
"#,
        );
        let _path = prepend_path(&bin);

        let paths = ProfilePaths::resolve(Profile::LinuxUser);
        fs::create_dir_all(paths.service_manifest_path.parent().unwrap()).unwrap();
        fs::write(&paths.service_manifest_path, "{}").unwrap();
        let manifest = ServiceManifest {
            contract_version: CONTROL_CONTRACT_VERSION.into(),
            profile: Profile::LinuxUser,
            platform: Platform::Linux,
            manager: Manager::SystemdUser,
            version: "1.4.2".into(),
            config_path: paths.config_path_json(),
            data_path: paths.data_root_json(),
            log_mode: LogMode::File,
            key_backend: KeyBackend::EncryptedFile,
        };
        let unavailable = ControlProbe {
            unavailable: true,
            state: None,
            annotation: Some(ControlApiAnnotation::Unavailable),
            contract_version: None,
            version: None,
            public_api: None,
            identity_ready: None,
            node_did: None,
        };
        let error = ControlProbe {
            unavailable: false,
            state: Some(ServiceState::Error),
            annotation: None,
            contract_version: None,
            version: None,
            public_api: None,
            identity_ready: None,
            node_did: None,
        };

        let _age_29 = EnvGuard::set("FAKE_PS_AGE", "29");
        let (state, pid, control_api) = derive_state(&manifest, &paths, &unavailable);
        assert_eq!(state, ServiceState::Starting);
        assert_eq!(pid, Some(4242));
        assert_eq!(control_api, Some(ControlApiAnnotation::Unavailable));

        let _age_30 = EnvGuard::set("FAKE_PS_AGE", "30");
        let (state, pid, control_api) = derive_state(&manifest, &paths, &unavailable);
        assert_eq!(state, ServiceState::Running);
        assert_eq!(pid, Some(4242));
        assert_eq!(control_api, Some(ControlApiAnnotation::Unavailable));

        let (state, pid, control_api) = derive_state(&manifest, &paths, &error);
        assert_eq!(state, ServiceState::Error);
        assert_eq!(pid, Some(4242));
        assert_eq!(control_api, None);
    }

    #[test]
    fn parse_process_age_accepts_ps_elapsed_formats() {
        assert_eq!(parse_process_age("29"), Some(29));
        assert_eq!(parse_process_age("00:29"), Some(29));
        assert_eq!(parse_process_age("01:02:03"), Some(3723));
        assert_eq!(parse_process_age("1-02:03:04"), Some(93_784));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn process_age_uses_etime_on_macos() {
        assert_eq!(ps_elapsed_field(), "etime=");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn process_age_uses_etimes_elsewhere() {
        assert_eq!(ps_elapsed_field(), "etimes=");
    }

    #[test]
    fn systemd_unit_does_not_quote_append_paths() {
        let unit = systemd_unit(
            Path::new("/Applications/TinyCloud Node/bin/tinycloud"),
            Path::new("/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml"),
            Path::new("/Users/me/Library/Logs/TinyCloud Node/tinycloud.log"),
            Path::new("/Users/me/Library/Logs/TinyCloud Node/tinycloud.err.log"),
            Manager::SystemdUser,
        );

        assert!(unit.contains(
            "ExecStart='/Applications/TinyCloud Node/bin/tinycloud' serve --config '/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml'"
        ));
        assert!(unit
            .contains("StandardOutput=append:/Users/me/Library/Logs/TinyCloud Node/tinycloud.log"));
        assert!(unit.contains(
            "StandardError=append:/Users/me/Library/Logs/TinyCloud Node/tinycloud.err.log"
        ));
    }

    #[test]
    fn status_json_shape_serializes_expected_fields() {
        let status = ServiceStatus {
            contract_version: CONTROL_CONTRACT_VERSION.into(),
            profile: Profile::MacosUser,
            platform: Platform::Macos,
            manager: Manager::LaunchdUser,
            state: ServiceState::Running,
            pid: Some(12345),
            enabled_at_login: true,
            version: Some("1.4.2".into()),
            public_api: PublicApi {
                address: "127.0.0.1".into(),
                port: 8081,
            },
            config_path: "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml"
                .into(),
            data_path: "/Users/me/Library/Application Support/TinyCloud Node/".into(),
            log_mode: Some(LogMode::File),
            key_backend: Some(KeyBackend::MacosKeychain),
            identity_ready: true,
            node_did: Some("did:key:z6Mk...".into()),
            control_api: Some(ControlApiAnnotation::Unavailable),
        };

        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["contractVersion"], "1.0.0");
        assert_eq!(value["profile"], "macos-user");
        assert_eq!(value["platform"], "macos");
        assert_eq!(value["manager"], "launchd-user");
        assert_eq!(value["state"], "running");
        assert_eq!(value["enabledAtLogin"], true);
        assert_eq!(value["publicApi"]["address"], "127.0.0.1");
        assert_eq!(value["publicApi"]["port"], 8081);
        assert_eq!(value["controlApi"], "unavailable");
    }

    #[test]
    fn launchd_enabled_at_login_parser_reads_label_state() {
        let stdout = r#"
disabled services = {
		"xyz.tinycloud.node" => false
}
"#;

        assert_eq!(launchd_enabled_at_login_from_stdout(stdout), Some(true));
    }

    #[test]
    fn launchd_enabled_at_login_parser_reads_enabled_state() {
        let stdout = r#"
disabled services = {
		"xyz.tinycloud.node" => enabled
}
"#;

        assert_eq!(launchd_enabled_at_login_from_stdout(stdout), Some(true));
    }

    #[test]
    fn systemd_enabled_at_login_parser_accepts_enabled_states() {
        assert!(systemd_enabled_at_login_from_stdout("enabled\n"));
        assert!(!systemd_enabled_at_login_from_stdout("disabled\n"));
    }
}
