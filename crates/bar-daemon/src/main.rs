//! The BAR daemon (spec §5.1): the mandatory Rust process that owns watchers,
//! ingestion, workflow, the API, and deterministic verification.
//!
//! This Phase-0 bootstrap establishes the two things every later phase depends
//! on — configuration and structured logging — and demonstrates the hard
//! resource invariant that BAR **starts and remains useful with no model
//! resident** (spec §3.1). The long-running service loop is added with the API
//! phase; today the daemon initializes, reports readiness, and exits cleanly.

use std::path::PathBuf;
use std::process::ExitCode;

use bar_config::Config;
use bar_core::Result;

fn main() -> ExitCode {
    init_logging();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "startup failed");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let (config, source) = load_config()?;

    // Hard invariant (spec §3.1): BAR does not require a model to start.
    if config.models.enabled {
        tracing::info!("model support enabled by configuration");
    } else {
        tracing::info!("model support disabled; running model-free");
    }

    tracing::info!(
        config_source = %source,
        listen = %config.server.listen,
        models_enabled = config.models.enabled,
        gpu_enabled = config.resources.gpu_enabled,
        "bar-daemon initialized"
    );
    Ok(())
}

/// Loads configuration from `$BAR_CONFIG` (or the default path), falling back to
/// built-in defaults when no file is present so the daemon runs out of the box.
fn load_config() -> Result<(Config, String)> {
    let path = std::env::var_os("BAR_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/bar/bar.toml"));

    if path.exists() {
        Ok((Config::load(&path)?, path.display().to_string()))
    } else {
        Ok((Config::default(), "built-in defaults".to_string()))
    }
}

/// Initializes structured logging. Level is controlled by `$BAR_LOG`
/// (default `info`); set `BAR_LOG_FORMAT=json` for machine-readable output.
fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_env("BAR_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = fmt().with_env_filter(filter).with_target(true);

    if matches!(std::env::var("BAR_LOG_FORMAT").as_deref(), Ok("json")) {
        builder.json().init();
    } else {
        builder.init();
    }
}
