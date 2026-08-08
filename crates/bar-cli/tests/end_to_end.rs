use std::process::Command;

#[test]
fn reference_runtime_scans_from_target_to_report() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bar-demo");
    let output = Command::new(env!("CARGO_BIN_EXE_bar"))
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("run bar scan");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan emits JSON");
    assert_eq!(report["inventory"]["total"], 3);
    assert!(report["analysis"]["contracts"].as_u64().unwrap() >= 4);
    let classes = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["class"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(classes.contains(&"missing_implementation"));
    assert!(classes.contains(&"contract_contradiction"));
    assert!(classes.contains(&"documentation_conflict"));
    assert!(classes.contains(&"dead_mechanism"));
    assert!(classes.contains(&"bypass_path"));
    assert!(classes.contains(&"state_machine_violation"));
    assert!(classes.contains(&"architecture_erosion"));
}

#[test]
fn durable_scan_verifies_and_advances_external_checkpoint() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bar-demo");
    let state = tempfile::tempdir().unwrap();
    let database = state.path().join("bar.db");
    let checkpoint = state.path().join("audit.checkpoint");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_bar"))
            .arg("scan")
            .arg(&fixture)
            .arg("--format")
            .arg("json")
            .arg("--database")
            .arg(&database)
            .arg("--checkpoint")
            .arg(&checkpoint)
            .output()
            .expect("run durable bar scan")
    };
    assert!(run().status.success());
    let first = std::fs::read_to_string(&checkpoint).unwrap();
    assert!(run().status.success());
    let second = std::fs::read_to_string(&checkpoint).unwrap();
    assert_ne!(
        first, second,
        "a later audited scan advances the checkpoint"
    );

    std::fs::write(
        &checkpoint,
        "bar-audit-checkpoint-v1\nlength=999999\ntip=0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();
    assert!(!run().status.success(), "a forged checkpoint fails closed");
}
