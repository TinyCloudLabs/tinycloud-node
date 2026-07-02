use serde::{Deserialize, Serialize};
use std::{
    env,
    path::{Path, PathBuf},
};

pub const SERVICE_LABEL: &str = "xyz.tinycloud.node";
pub const CONTROL_CONTRACT_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    MacosUser,
    LinuxUser,
    LinuxSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Manager {
    HomebrewLaunchagent,
    LaunchdUser,
    SystemdUser,
    SystemdSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogMode {
    File,
    Journald,
    Stdout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyBackend {
    MacosKeychain,
    EncryptedFile,
    Static,
    Dstack,
}

#[derive(Debug, Clone)]
pub struct ProfilePaths {
    pub profile: Profile,
    pub platform: Platform,
    pub manager: Manager,
    pub config_root: PathBuf,
    pub data_root: PathBuf,
    pub logs_root: PathBuf,
    pub service_manifest_path: PathBuf,
    pub service_unit_path: PathBuf,
    pub config_path: PathBuf,
    pub runtime_dir: PathBuf,
    pub overlay_path: PathBuf,
    pub control_json_path: PathBuf,
    pub control_token_path: PathBuf,
    pub logs_file_path: PathBuf,
    pub logs_error_path: PathBuf,
}

impl Profile {
    pub fn default_for_host() -> Self {
        match current_platform() {
            Platform::Macos => Self::MacosUser,
            Platform::Linux => match effective_uid() {
                0 => Self::LinuxSystem,
                _ => Self::LinuxUser,
            },
        }
    }

    pub fn platform(self) -> Platform {
        match self {
            Self::MacosUser => Platform::Macos,
            Self::LinuxUser | Self::LinuxSystem => Platform::Linux,
        }
    }

    pub fn manager(self) -> Manager {
        match self {
            Self::MacosUser => {
                if env::var_os("HOMEBREW_PREFIX").is_some() {
                    Manager::HomebrewLaunchagent
                } else {
                    Manager::LaunchdUser
                }
            }
            Self::LinuxUser => Manager::SystemdUser,
            Self::LinuxSystem => Manager::SystemdSystem,
        }
    }

    pub fn log_mode(self) -> LogMode {
        match self {
            Self::MacosUser | Self::LinuxUser => LogMode::File,
            Self::LinuxSystem => LogMode::Journald,
        }
    }

    pub fn key_backend(self) -> KeyBackend {
        match self {
            Self::MacosUser => KeyBackend::MacosKeychain,
            Self::LinuxUser | Self::LinuxSystem => KeyBackend::EncryptedFile,
        }
    }

    pub fn paths(self) -> ProfilePaths {
        ProfilePaths::resolve(self)
    }
}

impl ProfilePaths {
    pub fn resolve(profile: Profile) -> Self {
        let platform = profile.platform();
        let manager = profile.manager();
        let (config_root, data_root, logs_root, service_unit_root) = resolve_roots(profile);
        let config_path = config_root.join("tinycloud.toml");
        let service_manifest_path = config_root.join("service.json");
        let runtime_dir = data_root.join("runtime");
        let overlay_path = runtime_dir.join("config.override.toml");
        let control_json_path = runtime_dir.join("control.json");
        let control_token_path = runtime_dir.join("control.token");
        let logs_file_path = logs_root.join("tinycloud.log");
        let logs_error_path = logs_root.join("tinycloud.err.log");
        let service_unit_path = match manager {
            Manager::HomebrewLaunchagent | Manager::LaunchdUser => {
                service_unit_root.join(format!("{SERVICE_LABEL}.plist"))
            }
            Manager::SystemdUser | Manager::SystemdSystem => {
                service_unit_root.join(format!("{SERVICE_LABEL}.service"))
            }
        };

        Self {
            profile,
            platform,
            manager,
            config_root,
            data_root,
            logs_root,
            service_manifest_path,
            service_unit_path,
            config_path,
            runtime_dir,
            overlay_path,
            control_json_path,
            control_token_path,
            logs_file_path,
            logs_error_path,
        }
    }

    pub fn config_root_json(&self) -> String {
        dir_to_json_string(&self.config_root)
    }

    pub fn data_root_json(&self) -> String {
        dir_to_json_string(&self.data_root)
    }

    pub fn logs_root_json(&self) -> String {
        dir_to_json_string(&self.logs_root)
    }

    pub fn overlay_path_json(&self) -> String {
        self.overlay_path.display().to_string()
    }

    pub fn config_path_json(&self) -> String {
        self.config_path.display().to_string()
    }

    pub fn control_token_path_json(&self) -> String {
        self.control_token_path.display().to_string()
    }

    pub fn service_manifest_path_json(&self) -> String {
        self.service_manifest_path.display().to_string()
    }

    pub fn service_unit_path_json(&self) -> String {
        self.service_unit_path.display().to_string()
    }

    pub fn logs_file_path_json(&self) -> String {
        self.logs_file_path.display().to_string()
    }

    pub fn logs_error_path_json(&self) -> String {
        self.logs_error_path.display().to_string()
    }
}

pub fn current_platform() -> Platform {
    #[cfg(target_os = "macos")]
    {
        Platform::Macos
    }
    #[cfg(target_os = "linux")]
    {
        Platform::Linux
    }
}

fn resolve_roots(profile: Profile) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    if let Some(override_root) = env::var_os("TINYCLOUD_NODE_CONFIG_ROOT") {
        let override_root = PathBuf::from(override_root);
        let logs_root = override_root.join("logs");
        let service_unit_root = match profile.platform() {
            Platform::Macos => override_root.join("LaunchAgents"),
            Platform::Linux => override_root.join(match profile {
                Profile::LinuxUser => "systemd/user",
                Profile::LinuxSystem => "systemd/system",
                Profile::MacosUser => unreachable!(),
            }),
        };
        return (
            override_root.clone(),
            override_root,
            logs_root,
            service_unit_root,
        );
    }

    match profile {
        Profile::MacosUser => {
            let root = home_dir().join("Library/Application Support/TinyCloud Node");
            let logs_root = home_dir().join("Library/Logs/TinyCloud Node");
            let service_unit_root = home_dir().join("Library/LaunchAgents");
            (root.clone(), root, logs_root, service_unit_root)
        }
        Profile::LinuxUser => {
            let config_root = xdg_path("XDG_CONFIG_HOME", ".config", "tinycloud-node");
            let data_root = xdg_path("XDG_DATA_HOME", ".local/share", "tinycloud-node");
            let logs_root = xdg_path("XDG_STATE_HOME", ".local/state", "tinycloud-node");
            let service_unit_root = home_dir().join(".config/systemd/user");
            (config_root, data_root, logs_root, service_unit_root)
        }
        Profile::LinuxSystem => {
            let config_root = PathBuf::from("/etc/tinycloud-node");
            let data_root = PathBuf::from("/var/lib/tinycloud-node");
            let logs_root = PathBuf::from("/var/log/tinycloud-node");
            let service_unit_root = PathBuf::from("/etc/systemd/system");
            (config_root, data_root, logs_root, service_unit_root)
        }
    }
}

fn xdg_path(env_key: &str, fallback_parent: &str, leaf: &str) -> PathBuf {
    if let Some(value) = env::var_os(env_key) {
        return PathBuf::from(value).join(leaf);
    }

    home_dir().join(fallback_parent).join(leaf)
}

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
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

pub fn dir_to_json_string(path: &Path) -> String {
    let mut rendered = path.display().to_string();
    if !rendered.ends_with(std::path::MAIN_SEPARATOR) {
        rendered.push(std::path::MAIN_SEPARATOR);
    }
    rendered
}
