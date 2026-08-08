use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bar_audit::AuditCheckpoint;
use bar_contract::{analyze_corpus, ArtifactText};
use bar_discovery::{scan, ArtifactKind, PriorInventory, ScanConfig};
use bar_findings::{
    contradiction_finding, detect_architecture_findings, documentation_conflict_finding,
    promote_candidate,
};
use bar_static::analyze_inventory;
use bar_store::Store;
use bar_target::resolve_target;
use serde::{Deserialize, Serialize};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Serialize, Deserialize)]
struct ScanReport {
    schema_version: u32,
    target: TargetReport,
    inventory: InventoryReport,
    analysis: AnalysisReport,
    findings: Vec<FindingReport>,
    limitations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TargetReport {
    name: String,
    root: String,
    connector: String,
    revision_id: String,
    source_commit: Option<String>,
    dirty: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct InventoryReport {
    total: usize,
    added: usize,
    changed: usize,
    removed: usize,
    hashed: usize,
    oversized: usize,
    skipped: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnalysisReport {
    contracts: usize,
    mapped_contracts: usize,
    partially_mapped_contracts: usize,
    unmapped_contracts: usize,
    ambiguous_contracts: usize,
    analyzed_artifacts: usize,
    analysis_failures: usize,
    uncertainties: usize,
    audit_records: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct FindingReport {
    class: String,
    fingerprint: String,
    summary: String,
    evidence: Vec<String>,
    provisional: bool,
}

#[derive(Debug)]
struct ScanOptions {
    root: PathBuf,
    name: Option<String>,
    database_url: String,
    format: OutputFormat,
    output: Option<PathBuf>,
    checkpoint: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Markdown,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()).await {
        eprintln!("bar: {error}");
        std::process::exit(1);
    }
}

async fn run(args: Vec<String>) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("scan") => scan_command(parse_scan_options(&args[1..])?).await,
        Some("serve") => serve_command(&args[1..]),
        Some("--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown command `{command}`; run `bar --help`").into()),
    }
}

fn print_help() {
    println!(
        "BAR — Behavioral Assurance Runtime\n\n\
         Usage:\n  bar scan <path> [--name NAME] [--database URL] [--checkpoint FILE] [--format json|markdown] [--output FILE]\n  \
         bar serve <report.json> [--listen ADDRESS]\n\n\
         `scan` is read-only with respect to the target. Without --database it uses an in-memory store."
    );
}

fn parse_scan_options(args: &[String]) -> CliResult<ScanOptions> {
    let Some(root) = args.first().filter(|value| !value.starts_with('-')) else {
        return Err("scan requires a target path".into());
    };
    let mut options = ScanOptions {
        root: PathBuf::from(root),
        name: None,
        database_url: "sqlite::memory:".into(),
        format: OutputFormat::Markdown,
        output: None,
        checkpoint: None,
    };
    let mut index = 1;
    while index < args.len() {
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{} requires a value", args[index]))?;
        match args[index].as_str() {
            "--name" => options.name = Some(value.clone()),
            "--database" => options.database_url = normalize_database_url(value),
            "--format" => {
                options.format = match value.as_str() {
                    "json" => OutputFormat::Json,
                    "markdown" => OutputFormat::Markdown,
                    _ => return Err("--format must be `json` or `markdown`".into()),
                }
            }
            "--output" => options.output = Some(PathBuf::from(value)),
            "--checkpoint" => options.checkpoint = Some(PathBuf::from(value)),
            flag => return Err(format!("unknown scan option `{flag}`").into()),
        }
        index += 2;
    }
    Ok(options)
}

fn normalize_database_url(value: &str) -> String {
    if value.starts_with("sqlite:") {
        value.to_string()
    } else {
        format!("sqlite://{}", Path::new(value).display())
    }
}

async fn scan_command(options: ScanOptions) -> CliResult<()> {
    let default_name = options
        .root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target");
    let resolved = resolve_target(
        options.name.as_deref().unwrap_or(default_name),
        &options.root,
    )?;
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let store = Store::connect(&options.database_url).await?;
    store.migrate().await?;
    if let Some(path) = &options.checkpoint {
        if AuditCheckpoint::path_exists(path)? {
            let checkpoint = AuditCheckpoint::load(path)?;
            store
                .load_audit_chain()
                .await?
                .verify_extends_checkpoint(&checkpoint)?;
        }
    }
    let registration = store.register_target(&resolved, now_ms).await?;
    let revision = store
        .record_revision(&registration.target_id, &resolved.revision, now_ms)
        .await?;

    let inventory = scan(
        &resolved.root_locator,
        &ScanConfig::default(),
        &PriorInventory::new(),
    )?;
    store
        .persist_inventory(
            &registration.target_id,
            &revision.revision_id,
            &inventory,
            now_ms,
        )
        .await?;

    let documents = load_documents(&resolved.root_locator, &inventory, &revision.revision_id);
    let corpus = analyze_corpus(&documents)?;
    store
        .persist_contracts(
            &registration.target_id,
            &revision.revision_id,
            &corpus.claims,
            now_ms,
        )
        .await?;
    store
        .persist_analysis_candidates(
            &registration.target_id,
            &revision.revision_id,
            &corpus,
            now_ms,
        )
        .await?;

    let static_batch =
        analyze_inventory(&resolved.root_locator, &inventory, &revision.revision_id)?;
    store
        .persist_static_batch(
            &registration.target_id,
            &revision.revision_id,
            &static_batch,
            now_ms,
        )
        .await?;
    let architecture_candidates = detect_architecture_findings(&static_batch.facts)?;
    store
        .promote_architecture_findings(&registration.target_id, &revision.revision_id, now_ms)
        .await?;
    let traces = store
        .map_contract_traceability(&registration.target_id, &revision.revision_id)
        .await?;
    let candidates = store
        .missing_implementation_candidates(&registration.target_id, &revision.revision_id)
        .await?;
    store
        .persist_static_finding_candidates(
            &registration.target_id,
            &revision.revision_id,
            &candidates,
            now_ms,
        )
        .await?;
    store
        .promote_static_findings(&registration.target_id, &revision.revision_id, now_ms)
        .await?;
    store
        .promote_contradiction_findings(&registration.target_id, &revision.revision_id, now_ms)
        .await?;
    store
        .promote_documentation_conflict_findings(
            &registration.target_id,
            &revision.revision_id,
            now_ms,
        )
        .await?;

    let mut findings = candidates
        .iter()
        .map(|candidate| {
            let finding = promote_candidate(candidate)?;
            Ok(FindingReport {
                class: finding.kind.as_str().into(),
                fingerprint: finding.finding_fingerprint.to_string(),
                summary: format!(
                    "Required contract references missing implementation: {}",
                    finding.missing_references.join(", ")
                ),
                evidence: finding.missing_references,
                provisional: true,
            })
        })
        .collect::<bar_core::Result<Vec<_>>>()?;
    for conflict in &corpus.conflicts {
        let exact_text = |fingerprint: bar_core::Sha256Digest| -> CliResult<_> {
            corpus
                .claims
                .iter()
                .find(|claim| claim.fingerprint == fingerprint)
                .map(|claim| claim.source.exact_text_sha256)
                .ok_or_else(|| "conflict references an unknown claim".into())
        };
        let finding = contradiction_finding(
            exact_text(conflict.left_fingerprint)?,
            exact_text(conflict.right_fingerprint)?,
            &conflict.shared_subject,
        )?;
        findings.push(FindingReport {
            class: "contract_contradiction".into(),
            fingerprint: finding.finding_fingerprint.to_string(),
            summary: format!(
                "Opposing contract claims share subject `{}`",
                conflict.shared_subject
            ),
            evidence: vec![
                conflict.left_fingerprint.to_string(),
                conflict.right_fingerprint.to_string(),
            ],
            provisional: true,
        });
    }
    for ambiguity in &corpus.glossary_ambiguities {
        let definitions = corpus
            .glossary
            .iter()
            .filter(|candidate| candidate.canonical.to_lowercase() == ambiguity.normalized_term)
            .map(|candidate| candidate.definition.clone())
            .collect::<Vec<_>>();
        let finding = documentation_conflict_finding(&ambiguity.normalized_term, &definitions)?;
        findings.push(FindingReport {
            class: "documentation_conflict".into(),
            fingerprint: finding.finding_fingerprint.to_string(),
            summary: format!(
                "Conflicting definitions for `{}`",
                ambiguity.normalized_term
            ),
            evidence: ambiguity
                .sources
                .iter()
                .map(|source| source.artifact_id.to_string())
                .collect(),
            provisional: true,
        });
    }
    findings.extend(
        architecture_candidates
            .into_iter()
            .map(|candidate| FindingReport {
                class: candidate.kind.as_str().into(),
                fingerprint: candidate.fingerprint.to_string(),
                summary: format!(
                    "{}:{} {}",
                    candidate.path, candidate.line, candidate.evidence
                ),
                evidence: vec![candidate
                    .symbol
                    .unwrap_or_else(|| "<artifact scope>".into())],
                provisional: true,
            }),
    );
    findings.sort_by(|left, right| {
        (&left.class, &left.fingerprint).cmp(&(&right.class, &right.fingerprint))
    });

    let mut mapped = 0;
    let mut partial = 0;
    let mut unmapped = 0;
    let mut ambiguous = 0;
    for trace in &traces {
        match format!("{:?}", trace.traceability.status).as_str() {
            "Mapped" => mapped += 1,
            "PartiallyMapped" => partial += 1,
            "Ambiguous" => ambiguous += 1,
            _ => unmapped += 1,
        }
    }
    let uncertainties = static_batch
        .facts
        .iter()
        .map(|artifact| artifact.facts.uncertainty.len())
        .sum();
    let audit_chain = store.load_audit_chain().await?;
    let audit_records = audit_chain.len();
    if let Some(path) = &options.checkpoint {
        AuditCheckpoint::from_chain(&audit_chain)?.save(path)?;
    }
    let report = ScanReport {
        schema_version: 1,
        target: TargetReport {
            name: resolved.name,
            root: resolved.root_locator.display().to_string(),
            connector: resolved.connector_kind.as_str().into(),
            revision_id: revision.revision_id.to_string(),
            dirty: resolved.revision.is_dirty(),
            source_commit: resolved.revision.source_commit.clone(),
        },
        inventory: InventoryReport {
            total: inventory.summary.total,
            added: inventory.summary.added,
            changed: inventory.summary.changed,
            removed: inventory.summary.removed,
            hashed: inventory.summary.hashed,
            oversized: inventory.summary.oversized,
            skipped: inventory.summary.skipped,
        },
        analysis: AnalysisReport {
            contracts: corpus.claims.len(),
            mapped_contracts: mapped,
            partially_mapped_contracts: partial,
            unmapped_contracts: unmapped,
            ambiguous_contracts: ambiguous,
            analyzed_artifacts: static_batch.facts.len(),
            analysis_failures: static_batch.failures.len(),
            uncertainties,
            audit_records,
        },
        findings,
        limitations: vec![
            "Static findings are provisional and cannot authorize repair.".into(),
            "Runtime evidence, deployment identity, and live verification are not collected."
                .into(),
        ],
    };
    let rendered = match options.format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Markdown => render_markdown(&report),
    };
    if let Some(path) = options.output {
        fs::write(&path, rendered)?;
        println!("wrote {}", path.display());
    } else {
        println!("{rendered}");
    }
    Ok(())
}

fn load_documents(
    root: &Path,
    inventory: &bar_discovery::Inventory,
    revision_id: &bar_core::RevisionId,
) -> Vec<ArtifactText> {
    inventory
        .artifacts
        .iter()
        .filter(|artifact| artifact.artifact_kind == ArtifactKind::Documentation)
        .filter_map(|artifact| {
            let bytes = bar_discovery::read_artifact(root, artifact, 5 * 1024 * 1024).ok()?;
            let text = String::from_utf8(bytes).ok()?;
            ArtifactText::new(
                artifact.artifact_id(revision_id),
                artifact.logical_path.clone(),
                artifact.content_sha256.parse().ok()?,
                text,
            )
            .ok()
        })
        .collect()
}

fn render_markdown(report: &ScanReport) -> String {
    let mut output = format!(
        "# BAR scan: {}\n\n- Revision: `{}`\n- Artifacts: {}\n- Contracts: {}\n- Findings: {}\n- Static uncertainties: {}\n- Audit records: {}\n\n## Findings\n",
        report.target.name,
        report.target.revision_id,
        report.inventory.total,
        report.analysis.contracts,
        report.findings.len(),
        report.analysis.uncertainties,
        report.analysis.audit_records
    );
    if report.findings.is_empty() {
        output.push_str(
            "\nNo deterministic static findings. This is not a correctness certification.\n",
        );
    } else {
        for finding in &report.findings {
            output.push_str(&format!(
                "\n- **{}** — {} (`{}`)\n",
                finding.class, finding.summary, finding.fingerprint
            ));
        }
    }
    output.push_str("\n## Limitations\n");
    for limitation in &report.limitations {
        output.push_str(&format!("\n- {limitation}\n"));
    }
    output
}

fn serve_command(args: &[String]) -> CliResult<()> {
    let Some(report_path) = args.first().filter(|value| !value.starts_with('-')) else {
        return Err("serve requires a JSON report path".into());
    };
    let mut listen: SocketAddr = "127.0.0.1:7878".parse()?;
    if args.len() > 1 {
        if args.get(1).map(String::as_str) != Some("--listen") {
            return Err(format!("unknown serve option `{}`", args[1]).into());
        }
        listen = args.get(2).ok_or("--listen requires an address")?.parse()?;
    }
    let json = fs::read_to_string(report_path)?;
    let report: ScanReport = serde_json::from_str(&json)?;
    let html = render_dashboard(&report)?;
    let listener = TcpListener::bind(listen)?;
    println!("BAR report dashboard: http://{}", listener.local_addr()?);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve_connection(stream, &html, &json) {
                    eprintln!("bar: dashboard connection failed: {error}");
                }
            }
            Err(error) => eprintln!("bar: dashboard accept failed: {error}"),
        }
    }
    Ok(())
}

fn serve_connection(mut stream: TcpStream, html: &str, json: &str) -> CliResult<()> {
    let mut request = [0_u8; 2048];
    let size = stream.read(&mut request)?;
    let request = std::str::from_utf8(&request[..size]).unwrap_or("");
    let (status, content_type, body) = if request.starts_with("GET /report.json ") {
        ("200 OK", "application/json; charset=utf-8", json)
    } else if request.starts_with("GET / ") {
        ("200 OK", "text/html; charset=utf-8", html)
    } else {
        ("404 Not Found", "text/plain; charset=utf-8", "not found")
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}

fn render_dashboard(report: &ScanReport) -> CliResult<String> {
    let findings = if report.findings.is_empty() {
        "<p class=empty>No deterministic findings. This is not a certification.</p>".into()
    } else {
        report
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "<article><span>{}</span><h3>{}</h3><code>{}</code></article>",
                    escape_html(&finding.class),
                    escape_html(&finding.summary),
                    escape_html(&finding.fingerprint)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>BAR — {name}</title><style>{css}</style></head><body><main><header><p>BEHAVIORAL ASSURANCE RUNTIME</p><h1>{name}</h1><code>{revision}</code></header><section class=metrics><div><strong>{artifacts}</strong><span>artifacts</span></div><div><strong>{contracts}</strong><span>contracts</span></div><div><strong>{finding_count}</strong><span>findings</span></div><div><strong>{uncertainties}</strong><span>uncertainties</span></div></section><section><h2>Static findings</h2>{findings}</section><footer>Read-only report · static evidence only · <a href=/report.json>JSON</a></footer></main></body></html>",
        name = escape_html(&report.target.name),
        revision = escape_html(&report.target.revision_id),
        artifacts = report.inventory.total,
        contracts = report.analysis.contracts,
        finding_count = report.findings.len(),
        uncertainties = report.analysis.uncertainties,
        css = DASHBOARD_CSS,
    ))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const DASHBOARD_CSS: &str = "
:root{color-scheme:dark;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#090b0f;color:#e8edf2}
body{margin:0;background:radial-gradient(circle at 70% 0,#182737 0,transparent 38%),#090b0f}
main{max-width:960px;margin:auto;padding:64px 24px}header p,article span{color:#65d6ad;letter-spacing:.14em;font-size:.75rem}h1{font-size:clamp(2.5rem,8vw,5rem);margin:.15em 0}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;background:#26313c;margin:48px 0}.metrics div,article{background:#10151c;padding:24px}.metrics strong{font-size:2rem;display:block}.metrics span,footer{color:#91a0af}h2{margin-top:48px}article{border-left:3px solid #65d6ad;margin:12px 0}article h3{font:inherit;font-size:1rem;line-height:1.5}code{overflow-wrap:anywhere;color:#a9b7c6}.empty{padding:24px;border:1px dashed #40505f}footer{margin-top:48px;font-size:.8rem}a{color:#65d6ad}
";

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            target: TargetReport {
                name: "<target>".into(),
                root: "/tmp/target".into(),
                connector: "filesystem".into(),
                revision_id: "rev_test".into(),
                source_commit: None,
                dirty: false,
            },
            inventory: InventoryReport {
                total: 2,
                added: 2,
                changed: 0,
                removed: 0,
                hashed: 2,
                oversized: 0,
                skipped: 0,
            },
            analysis: AnalysisReport {
                contracts: 1,
                mapped_contracts: 0,
                partially_mapped_contracts: 0,
                unmapped_contracts: 1,
                ambiguous_contracts: 0,
                analyzed_artifacts: 1,
                analysis_failures: 0,
                uncertainties: 0,
                audit_records: 4,
            },
            findings: vec![],
            limitations: vec!["static only".into()],
        }
    }

    #[test]
    fn dashboard_escapes_target_controlled_text() {
        let html = render_dashboard(&report()).unwrap();
        assert!(html.contains("&lt;target&gt;"));
        assert!(!html.contains("<target>"));
    }

    #[test]
    fn markdown_is_clear_when_no_findings_exist() {
        let markdown = render_markdown(&report());
        assert!(markdown.contains("not a correctness certification"));
    }

    #[test]
    fn database_paths_become_sqlite_urls() {
        assert_eq!(normalize_database_url("state.db"), "sqlite://state.db");
        assert_eq!(normalize_database_url("sqlite::memory:"), "sqlite::memory:");
    }
}
