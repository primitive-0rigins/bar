//! Resource benchmark regression test (spec §4, §22).
//!
//! Section 22 requires resource targets to be enforced as regression tests, not
//! documentation. This spawns the real daemon binary model-free and asserts two
//! things it must always hold: it boots clean without a model, and its peak
//! resident memory stays within the spec §4 budget.
//!
//! What this proves at Phase 0 is *boot peak RSS*, not the §4 *idle* RAM
//! contract — there is no long-running idle loop yet (it lands with the API
//! phase). At the daemon's true footprint (tens of MB) the 300 MB ceiling's
//! only realistic trip condition is a resident model or a gross leak, so its job
//! today is guarding the model-free invariant (spec §3.1). Idle CPU/RAM under
//! load join the harness with the service loop.

use std::process::Command;

/// Spec §4: idle RAM target upper bound for a single target. Used here as the
/// boot-time ceiling (see module note on what this does and does not prove).
const RSS_CEILING_BYTES: u64 = 300 * 1024 * 1024;

#[test]
fn daemon_boots_model_free_within_resource_budget() {
    let config = tempfile::NamedTempFile::new().expect("create default test config");
    let output = Command::new(env!("CARGO_BIN_EXE_bar-daemon"))
        // An empty, existing file resolves through serde defaults and keeps the
        // test independent of any /etc/bar/bar.toml on the host.
        .env("BAR_CONFIG", config.path())
        .env("BAR_LOG_FORMAT", "json")
        .env("BAR_LOG", "info")
        .output()
        .expect("spawn bar-daemon");

    assert!(
        output.status.success(),
        "daemon exited non-zero: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let readiness = readiness_event(&output.stdout);

    assert_eq!(
        readiness["fields"]["models_enabled"], false,
        "daemon must start model-free under default config",
    );
    assert_eq!(readiness["fields"]["model_state"], "disabled");

    // `peak_rss_bytes` is absent on platforms without /proc; there the RSS
    // assertion is skipped (model-free boot is still asserted above).
    if let Some(peak) = readiness["fields"]["peak_rss_bytes"].as_u64() {
        assert!(
            peak < RSS_CEILING_BYTES,
            "boot peak RSS {peak} bytes exceeds the {RSS_CEILING_BYTES}-byte budget \
             (spec §4); a resident model or leak at startup would cause this",
        );
    }
}

#[test]
fn enabled_model_without_adapter_reports_unavailable_and_does_not_block_startup() {
    let config_path =
        std::env::temp_dir().join(format!("bar-model-unavailable-{}.toml", std::process::id()));
    std::fs::write(
        &config_path,
        "[models]\nenabled = true\nprovider = \"local\"\n",
    )
    .expect("write test config");

    let output = Command::new(env!("CARGO_BIN_EXE_bar-daemon"))
        .env("BAR_CONFIG", &config_path)
        .env("BAR_LOG_FORMAT", "json")
        .env("BAR_LOG", "info")
        .output()
        .expect("spawn bar-daemon");
    std::fs::remove_file(&config_path).expect("remove test config");

    assert!(
        output.status.success(),
        "unavailable optional model blocked startup: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let readiness = readiness_event(&output.stdout);
    assert_eq!(readiness["fields"]["models_enabled"], true);
    assert_eq!(readiness["fields"]["model_state"], "unavailable");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("local"),
        "provider configuration must not be emitted in startup logs"
    );
}

/// Extracts the `"bar-daemon initialized"` readiness event from the daemon's
/// JSON log stream (one JSON object per line, on stdout).
fn readiness_event(stdout: &[u8]) -> serde_json::Value {
    let stdout = std::str::from_utf8(stdout).expect("utf-8 log output");
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|event| event["fields"]["message"] == "bar-daemon initialized")
        .unwrap_or_else(|| panic!("no readiness event in daemon output:\n{stdout}"))
}
