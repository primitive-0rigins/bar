//! Typed configuration contract for BAR.
//!
//! Mirrors `docs/spec.md` Appendix C exactly: every section, key, and default
//! value. Loading enforces the appendix's rules:
//!
//! - **Unknown key → startup error.** Every struct uses
//!   `#[serde(deny_unknown_fields)]`, so a stray or misspelled key is rejected
//!   rather than silently ignored.
//! - **Range validation → reject before start.** [`Config::validate`] checks
//!   bounded values (e.g. percentages) and is run by every loader.
//! - **Secrets are never inlined.** Secret values reference the environment or a
//!   host secret store (see the spec's security notes); the values stored here
//!   are non-secret references, so the config is safe to log.
//!
//! Missing keys fall back to the documented defaults via `#[serde(default)]`
//! backed by each section's [`Default`] impl.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use bar_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// The complete runtime configuration (spec Appendix C).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    pub storage: Storage,
    pub resources: Resources,
    pub models: Models,
    pub scan: Scan,
    pub retention: Retention,
    pub security: Security,
    pub verification: Verification,
    pub baseline: Baseline,
}

impl Config {
    /// Parses configuration from a TOML string and validates it.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let config: Config =
            toml::from_str(s).map_err(|e| Error::Config(format!("invalid config: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses, and validates configuration from a file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::from_toml_str(&text)
    }

    /// Rejects out-of-range values before the service starts (spec Appendix C).
    pub fn validate(&self) -> Result<()> {
        check_percent("resources.max_cpu_percent", self.resources.max_cpu_percent)?;
        check_percent(
            "resources.gpu_utilization_ceiling_percent",
            self.resources.gpu_utilization_ceiling_percent,
        )?;
        if self.resources.scan_worker_count == 0 {
            return Err(Error::Config(
                "resources.scan_worker_count must be at least 1".into(),
            ));
        }
        Ok(())
    }
}

fn check_percent(field: &str, value: u8) -> Result<()> {
    if value > 100 {
        return Err(Error::Config(format!(
            "{field} must be 0..=100, got {value}"
        )));
    }
    Ok(())
}

/// `[server]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub listen: SocketAddr,
    pub public_base_url: String,
    pub max_request_bytes: u64,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7878".parse().expect("valid default socket addr"),
            public_base_url: "http://127.0.0.1:7878".into(),
            max_request_bytes: 8_388_608,
        }
    }
}

/// `[storage]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    pub database_url: String,
    pub evidence_dir: PathBuf,
    pub worktree_dir: PathBuf,
    pub disk_quota_gb: u64,
    pub read_only_on_quota_exhaustion: bool,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            database_url: "sqlite:///var/lib/bar/bar.db".into(),
            evidence_dir: PathBuf::from("/var/lib/bar/evidence"),
            worktree_dir: PathBuf::from("/var/lib/bar/worktrees"),
            disk_quota_gb: 20,
            read_only_on_quota_exhaustion: true,
        }
    }
}

/// `[resources]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Resources {
    pub max_cpu_percent: u8,
    pub max_memory_mb: u64,
    pub scan_worker_count: usize,
    pub semantic_worker_count: usize,
    pub max_pending_semantic_jobs: usize,
    pub gpu_enabled: bool,
    pub gpu_utilization_ceiling_percent: u8,
    pub target_reserved_vram_mb: u64,
    pub pressure_sample_seconds: u64,
    pub resume_hysteresis_seconds: u64,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            max_cpu_percent: 10,
            max_memory_mb: 512,
            scan_worker_count: 2,
            semantic_worker_count: 1,
            max_pending_semantic_jobs: 128,
            gpu_enabled: false,
            gpu_utilization_ceiling_percent: 20,
            target_reserved_vram_mb: 0,
            pressure_sample_seconds: 5,
            resume_hysteresis_seconds: 30,
        }
    }
}

/// `[models]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Models {
    pub enabled: bool,
    pub provider: String,
    pub endpoint: String,
    pub default_tier: u8,
    pub timeout_seconds: u64,
    pub max_context_tokens: u32,
    pub max_output_tokens: u32,
    pub repair_attempts: u32,
}

impl Default for Models {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "none".into(),
            endpoint: String::new(),
            default_tier: 0,
            timeout_seconds: 60,
            max_context_tokens: 8192,
            max_output_tokens: 2048,
            repair_attempts: 1,
        }
    }
}

/// `[scan]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scan {
    pub watch: bool,
    pub debounce_ms: u64,
    pub max_file_bytes: u64,
    pub follow_symlinks: bool,
    pub include_hidden: bool,
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            watch: true,
            debounce_ms: 750,
            max_file_bytes: 5_242_880,
            follow_symlinks: false,
            include_hidden: false,
        }
    }
}

/// `[retention]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Retention {
    pub raw_runtime_days: u32,
    pub resolved_finding_days: u32,
    pub audit_days: u32,
    pub artifact_versions_per_path: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            raw_runtime_days: 7,
            resolved_finding_days: 365,
            audit_days: 0,
            artifact_versions_per_path: 5,
        }
    }
}

/// `[security]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Security {
    pub local_auth_required: bool,
    pub session_minutes: u32,
    pub agent_token_minutes: u32,
    pub allow_remote_bind: bool,
    pub tls_required_for_remote: bool,
}

impl Default for Security {
    fn default() -> Self {
        Self {
            local_auth_required: true,
            session_minutes: 60,
            agent_token_minutes: 30,
            allow_remote_bind: false,
            tls_required_for_remote: true,
        }
    }
}

/// `[verification]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Verification {
    pub default_timeout_seconds: u64,
    pub network_enabled: bool,
    pub max_output_bytes: u64,
}

impl Default for Verification {
    fn default() -> Self {
        Self {
            default_timeout_seconds: 900,
            network_enabled: false,
            max_output_bytes: 10_485_760,
        }
    }
}

/// `[baseline]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Baseline {
    pub enabled: bool,
    pub minimum_hours: u32,
    pub operator_review_required: bool,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            enabled: true,
            minimum_hours: 0,
            operator_review_required: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact configuration contract from spec Appendix C.
    const APPENDIX_C: &str = r#"
[server]
listen = "127.0.0.1:7878"
public_base_url = "http://127.0.0.1:7878"
max_request_bytes = 8388608

[storage]
database_url = "sqlite:///var/lib/bar/bar.db"
evidence_dir = "/var/lib/bar/evidence"
worktree_dir = "/var/lib/bar/worktrees"
disk_quota_gb = 20
read_only_on_quota_exhaustion = true

[resources]
max_cpu_percent = 10
max_memory_mb = 512
scan_worker_count = 2
semantic_worker_count = 1
max_pending_semantic_jobs = 128
gpu_enabled = false
gpu_utilization_ceiling_percent = 20
target_reserved_vram_mb = 0
pressure_sample_seconds = 5
resume_hysteresis_seconds = 30

[models]
enabled = false
provider = "none"
endpoint = ""
default_tier = 0
timeout_seconds = 60
max_context_tokens = 8192
max_output_tokens = 2048
repair_attempts = 1

[scan]
watch = true
debounce_ms = 750
max_file_bytes = 5242880
follow_symlinks = false
include_hidden = false

[retention]
raw_runtime_days = 7
resolved_finding_days = 365
audit_days = 0
artifact_versions_per_path = 5

[security]
local_auth_required = true
session_minutes = 60
agent_token_minutes = 30
allow_remote_bind = false
tls_required_for_remote = true

[verification]
default_timeout_seconds = 900
network_enabled = false
max_output_bytes = 10485760

[baseline]
enabled = true
minimum_hours = 0
operator_review_required = true
"#;

    #[test]
    fn appendix_c_parses_and_equals_defaults() {
        let parsed = Config::from_toml_str(APPENDIX_C).unwrap();
        let defaults = Config::default();
        // The appendix values are the defaults; a few representative checks.
        assert_eq!(parsed.server.listen, defaults.server.listen);
        assert_eq!(parsed.resources.max_cpu_percent, 10);
        assert!(!parsed.models.enabled);
        assert_eq!(parsed.storage.evidence_dir, defaults.storage.evidence_dir);
        assert!(parsed.security.local_auth_required);
    }

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn missing_keys_use_defaults() {
        let cfg = Config::from_toml_str("[resources]\nmax_cpu_percent = 25\n").unwrap();
        assert_eq!(cfg.resources.max_cpu_percent, 25);
        // Untouched keys fall back to documented defaults.
        assert_eq!(cfg.resources.scan_worker_count, 2);
        assert_eq!(cfg.server.max_request_bytes, 8_388_608);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = Config::from_toml_str("[resources]\nmax_cpu_pct = 25\n").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn out_of_range_percent_is_rejected() {
        let err = Config::from_toml_str("[resources]\nmax_cpu_percent = 150\n").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }
}
