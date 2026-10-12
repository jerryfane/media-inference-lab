//! Fixed study analysis, deliberately not a reusable executor or StudyPlan variant.
use anyhow::{Context, Result, ensure};
use media_inference_lab::{capture, maintenance, schema::Workload};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, DirBuilder, File, OpenOptions}, io::{Read, Write}, os::unix::fs::{DirBuilderExt, OpenOptionsExt}, path::{Component, Path, PathBuf}, time::Instant};

pub const PROTOCOL_SHA256: &str = "e01abcc9514db1a75120859db76edfd9feb775ce5f966e5ab2a53cf7fbbf7a42";
const GUARDIAN_COMMIT: &str = "f81795607bd986e1e5d63344021cf7af85c4d400";
const IDS: [&str; 8] = ["Q0", "Q1", "Q2", "Q3", "H0", "H1", "H2", "H3"];
const JSON_LIMIT: u64 = 16 * 1024 * 1024;
const METADATA_LIMIT: u64 = 256 * 1024 * 1024;
const SELECTOR: [&str; 5] = ["phase", "scope", "unit", "method", "boundary"];

struct Reads { remaining: u64, deadline: Instant }
impl Reads {
    fn check(&self) -> Result<()> { ensure!(Instant::now() < self.deadline, "cooperative analysis deadline exceeded"); Ok(()) }
    fn json(&mut self, path: &Path) -> Result<(Value, Value)> {
        self.check()?;
        let path = canonical(path)?;
        let mut file = regular(&path)?;
        let size = file.metadata()?.len();
        ensure!(size <= JSON_LIMIT && size <= self.remaining, "metadata byte limit exceeded");
        self.remaining -= size;
        let mut bytes = Vec::with_capacity(size as usize);
        (&mut file).take(size + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 == size, "metadata changed while reading");
        self.check()?;
        let identity = json!({"path":path,"sha256":sha(&bytes),"bytes":size});
        Ok((serde_json::from_slice(&bytes).context("parsing metadata JSON")?, identity))
    }
}
fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn canonical(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "evidence path must be absolute");
    ensure!(!path.components().any(|c| matches!(c, Component::ParentDir)), "parent path component rejected");
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        ensure!(!fs::symlink_metadata(&prefix)?.file_type().is_symlink(), "symlink evidence path rejected");
    }
    Ok(path.canonicalize()?)
}
fn regular(path: &Path) -> Result<File> {
    ensure!(fs::symlink_metadata(path)?.is_file(), "evidence must be a regular file");
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    ensure!(file.metadata()?.is_file(), "opened evidence is not regular");
    Ok(file)
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> { v[key].as_str().filter(|s| !s.is_empty()).with_context(|| format!("missing string {key}")) }
fn path(v: &Value, key: &str) -> Result<PathBuf> { Ok(PathBuf::from(text(v, key)?)) }
fn digest_string(v: &Value, key: &str) -> Result<()> {
    let s = text(v, key)?;
    ensure!(s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "invalid SHA256 {key}");
    Ok(())
}
fn unavailable(reason: impl Into<String>) -> Value { json!({"status":"unavailable","reason":reason.into()}) }

/// Selection never falls back to a neighboring phase, scope, unit or boundary.
fn primary(timings: &Value, selector: &Value) -> Value {
    if SELECTOR.iter().any(|key| selector[*key].as_str().is_none_or(str::is_empty)) {
        return unavailable("malformed primary metric selector");
    }
    let Some(timings) = timings.as_array() else { return unavailable("missing adapter timing array") };
    let exact: Vec<_> = timings.iter().filter(|t| SELECTOR.iter().all(|k| t[*k] == selector[*k])).collect();
    if exact.len() != 1 { return unavailable(format!("expected one exact primary selector match; observed {}", exact.len())); }
    let observation = &exact[0]["measurement"];
    match observation["status"].as_str() {
        Some("available") => match observation["value"].as_f64() {
            Some(value) if value.is_finite() && value >= 0.0 => json!({"status":"available","value":value}),
            _ => unavailable("primary metric is not a finite nonnegative representable number"),
        },
        Some("unavailable") => unavailable(observation["reason"].as_str().filter(|s| !s.is_empty()).unwrap_or("metric unavailable without reason")),
        _ => unavailable("malformed primary metric observation"),
    }
}
fn pairs() -> Vec<(usize, usize)> {
    [0, 4].into_iter().flat_map(|base| (base..base + 4).flat_map(move |l| (l + 1..base + 4).map(move |r| (l, r)))).collect()
}
fn workload_key(index: usize) -> &'static str { if index < 4 { "qwen" } else { "h3_draft" } }
fn warmup(index: usize) -> bool { index == 0 || index == 4 }
fn validate_slots(value: &Value) -> Result<BTreeMap<String, Value>> {
    let slots = value["slots"].as_array().context("missing eight-slot array")?;
    ensure!(slots.len() == IDS.len(), "ledger/binding must contain exactly eight slots");
    let mut mapped = BTreeMap::new();
    for slot in slots {
        let id = text(slot, "slot_id")?;
        ensure!(IDS.contains(&id), "unplanned slot {id}");
        ensure!(mapped.insert(id.to_owned(), slot.clone()).is_none(), "duplicate slot {id}");
    }
    Ok(mapped)
}
fn globals(protocol: &Value, protocol_id: &Value, ledger: &Value, frozen: &Value, frozen_id: &Value) -> Result<()> {
    ensure!(protocol_id["sha256"] == PROTOCOL_SHA256, "protocol byte SHA256 differs from the approved predeclaration");
    ensure!(ledger["protocol_sha256"] == PROTOCOL_SHA256 && frozen["protocol_sha256"] == PROTOCOL_SHA256, "protocol binding mismatch");
    ensure!(ledger["frozen_binding_sha256"] == frozen_id["sha256"], "frozen binding byte SHA256 mismatch");
    ensure!(frozen["guardian_source_commit"] == GUARDIAN_COMMIT, "guardian source commit mismatch");
    ensure!(frozen["launch_choices"]["qwen"] == "mflux-run --execute" && frozen["launch_choices"]["h3_draft"] == "maintenance-run", "predeclared launch choices changed");
    digest_string(&frozen["guardian"], "sha256")?;
    digest_string(&frozen["analysis"], "source_sha256")?;
    digest_string(&frozen["analysis"], "binary_sha256")?;
    let declared = protocol["slots"].as_array().context("protocol slots missing")?;
    ensure!(declared.len() == 8 && declared.iter().zip(IDS).all(|(s,id)| s["slot_id"] == id), "fixed protocol order differs");
    let expected: Vec<Value> = pairs().iter().map(|(l,r)| json!([IDS[*l],IDS[*r]])).collect();
    ensure!(protocol["numerical_report"]["pairs_per_modality"] == json!(expected), "fixed protocol pairs differ");
    Ok(())
}

/// The report is bound to a capture artifact, never merely to a caller-selected bundle path.
fn bind_bundle(bundle: &Value, artifact: &Value, source: &Path, inspection_id: &Value) -> Result<()> {
    ensure!(bundle["valid"] == true, "derived bundle is invalid");
    ensure!(bundle["source"]["sha256"] == artifact["sha256"] && bundle["source"]["bytes"] == artifact["bytes"], "derived source hash/byte count differs from capture artifact");
    ensure!(canonical(&path(&bundle["source"], "path")?)? == canonical(source)?, "derived source is detached from selected capture artifact");
    ensure!(bundle["inspection"] == *inspection_id, "derived inspection identity differs from original inspection");
    Ok(())
}

fn argument<'a>(argv: &'a [Value], flag: &str) -> Result<&'a str> {
    let mut found = None;
    for (index,arg) in argv.iter().enumerate() {
        let arg = arg.as_str().context("non-string literal CLI argument")?;
        let value = if arg == flag {
            Some(argv.get(index + 1).and_then(Value::as_str).context("CLI flag lacks value")?)
        } else { arg.strip_prefix(flag).and_then(|s|s.strip_prefix('=')) };
        if let Some(value) = value {
            ensure!(found.replace(value).is_none(), "duplicate CLI binding flag {flag}");
        }
    }
    found.with_context(||format!("missing CLI binding flag {flag}"))
}

fn admission_launch(index: usize, admission: &Value, frozen: &Value, transaction: &Value) -> Result<()> {
    let argv = admission["literal_cli_argv"].as_array().context("missing literal CLI argv")?;
    ensure!(argv.len() >= 2 && argv.iter().all(Value::is_string), "invalid literal CLI argv");
    ensure!(argv[0] == frozen["guardian"]["path"] && argv[0].as_str().is_some_and(|p|Path::new(p).is_absolute()), "literal CLI executable differs from frozen guardian");
    let flag = if index < 4 {
        ensure!(argv[1] == "mflux-run" && argv.iter().filter(|a|**a == "--execute").count() == 1
            && !argv.iter().any(|a|a.as_str().is_some_and(|s|s == "--check-only" || s.starts_with("--check-only="))),
            "Qwen launch differs from frozen mflux-run --execute choice");
        "--maintenance-transaction"
    } else {
        ensure!(argv[1] == "maintenance-run", "H3 launch differs from frozen maintenance-run choice");
        "--transaction"
    };
    ensure!(argument(argv,flag)? == text(admission,"transaction_path")?, "literal CLI transaction differs from admitted transaction path");
    ensure!(admission["service_binding"].is_object() && admission["service_binding"] == transaction["services"][0], "admission service binding differs from exact typed Studio ServiceSpec");
    Ok(())
}

fn attempt_binding(index: usize, attempt: &Value, admission: &Value, prepared: &Value, capture_dir: &Path, receipt_path: &Path) -> Result<()> {
    if index < 4 {
        ensure!(attempt["kind"] == "native_mflux_attempt" && attempt["mode"] == "execute" && attempt["native_execution"] == true && attempt["ok"] == true, "original Qwen attempt does not attest successful native execution");
        ensure!(attempt["prepared_plan"] == *prepared, "Qwen attempt prepared plan differs from admitted frozen plan");
        ensure!(canonical(&path(attempt,"capture_directory")?)? == capture_dir && canonical(&path(attempt,"maintenance_receipt")?)? == receipt_path, "Qwen attempt capture/receipt is detached");
    } else {
        ensure!(attempt["argv"] == admission["literal_cli_argv"] && attempt["exit_code"] == 0, "original H3 command receipt argv/exit differs from admitted successful command");
        ensure!(attempt.get("stdout").is_some() && attempt.get("stderr").is_some(), "original H3 stdout/stderr evidence missing");
    }
    Ok(())
}

fn readiness(readiness: &Value, services: &Value) -> Result<()> {
    for key in ["qualified", "helper_accounting_complete", "exact_identity_unchanged"] {
        ensure!(readiness[key] == true, "readiness {key} is not true");
    }
    ensure!(readiness["health"]["http_status"] == 200 && readiness["health"]["ok"] == true, "post-attempt health unavailable");
    let before = &readiness["identity_before"];
    ensure!(before.is_object() && *before == readiness["identity_after"], "readiness bracketing identities differ");
    let identity: media_inference_lab::process_scope::ProcessIdentity = serde_json::from_value(before.clone()).context("readiness requires full original process identity")?;
    ensure!(identity.pid > 0 && identity.pgid == identity.pid
        && identity.state == media_inference_lab::process_scope::ProcessState::Running
        && identity.executable.is_absolute() && identity.cwd.is_absolute(), "readiness target is not the exact running named root");
    let helpers = readiness["helper_accounting"].as_array().context("readiness helper receipts missing")?;
    ensure!(!helpers.is_empty() && helpers.iter().all(|h| h["complete"] == true && h["settlement"]["complete"] == true
        && h["settlement"]["leader_reaped"] == true && h["settlement"]["group_absent"] == true), "readiness helper settlement incomplete");
    let studio: Vec<_> = services.as_array().context("service outcomes missing")?.iter().filter(|s| s["role"] == "studio").collect();
    ensure!(studio.len() == 1 && studio[0]["restored"] == true && studio[0]["root"] == *before, "readiness does not bind the restored Studio root");
    for (target, identity) in [("target_pid","pid"),("target_uid","uid"),("target_birth_seconds","start_seconds"),("target_birth_subseconds","start_subseconds")] {
        ensure!(!before[identity].is_null() && readiness[target] == before[identity], "readiness target identity mismatch");
    }
    ensure!(readiness["studio_listener"]["positive_listener"] == true && readiness["studio_listener"]["owner_birth_unchanged"] == true && readiness["studio_listener"]["pid"] == before["pid"], "receipt-bound listener unavailable");
    Ok(())
}

// Absolute brackets are retained by the command collector, not synthesized from
// guardian elapsed_ms or process birth times. These records are evidence, not authentication.
fn bracket(value: &Value) -> Result<(u64, u64)> {
    ensure!(value["collection_complete"] == true && value["errors"].as_array().is_some_and(Vec::is_empty), "command observation collection incomplete");
    ensure!(value["clock"] == "unix_ms" && value["elapsed_clock"] == "monotonic", "missing explicit wall/monotonic clock labels");
    let start = value["started_unix_ms"].as_u64().context("missing original command wall start")?;
    let end = value["ended_unix_ms"].as_u64().context("missing original command wall end")?;
    ensure!(end >= start && value["elapsed_us"].as_u64().is_some(), "invalid original command bracket");
    ensure!(value["exit_code"] == 0, "command did not settle successfully");
    let mono_start = value["monotonic_started_ns"].as_u64().context("missing command monotonic start")?;
    let mono_end = value["monotonic_ended_ns"].as_u64().context("missing command monotonic end")?;
    ensure!(mono_end >= mono_start && value["elapsed_us"].as_u64() == Some((mono_end-mono_start)/1000), "inconsistent monotonic command bracket");
    text(value,"monotonic_clock_id")?;
    Ok((start,end))
}

fn temporal(value: &Value) -> Result<Value> {
    let evidence = &value["evidence"];
    let manifest = &evidence["manifest"]["raw"];
    let start = manifest["started_unix_ms"].as_u64().context("capture wall start unavailable")?;
    let end = manifest["ended_unix_ms"].as_u64().context("capture wall end unavailable")?;
    ensure!(end >= start, "capture wall clock reversed");
    let execution = &evidence["execution_observation_path"]["raw"];
    let observer = &evidence["readiness_observation_path"]["raw"];
    let (command_start,command_end) = bracket(execution)?;
    let (observer_start,observer_end) = bracket(observer)?;
    ensure!(execution["monotonic_clock_id"] == observer["monotonic_clock_id"], "command and observer monotonic clock domains differ");
    ensure!(observer["monotonic_started_ns"].as_u64() > execution["monotonic_ended_ns"].as_u64(), "observer monotonic bracket overlaps command settlement");
    let argv = observer["literal_cli_argv"].as_array().context("original observer argv missing")?;
    ensure!(!argv.is_empty() && argv.iter().all(|a|a.as_str().is_some_and(|s|!s.is_empty()))
        && argv[0].as_str().is_some_and(|s|Path::new(s).is_absolute()), "invalid original observer argv");
    ensure!(execution["boundary"] == "before_command_spawn_through_command_settlement_and_receipt_read"
        && observer["boundary"] == "before_observer_spawn_through_observer_settlement_and_report_read", "command observation boundary differs");
    ensure!(execution["receipt_identity"] == evidence["receipt_path"]["identity"]
        && execution["attempt_identity"] == evidence["attempt_report_path"]["identity"]
        && execution["literal_cli_argv"] == evidence["admission_binding_path"]["raw"]["literal_cli_argv"], "execution observation detached from receipt/attempt/argv");
    ensure!(observer["receipt_identity"] == evidence["receipt_path"]["identity"]
        && observer["readiness_identity"] == evidence["readiness_path"]["identity"], "observer observation detached from receipt/readiness");
    ensure!(command_start <= start && end <= command_end, "capture outside retained command bracket");
    let transaction_ms = evidence["receipt_path"]["raw"]["elapsed_ms"].as_u64().context("original transaction elapsed unavailable")?;
    ensure!(transaction_ms <= execution["elapsed_us"].as_u64().context("command elapsed unavailable")? / 1000,
        "original transaction duration exceeds its external command bracket");
    ensure!(observer_start > command_end, "readiness observer not freshly started after receipt-bound command settlement");
    let observed = evidence["readiness_path"]["raw"]["observation_unix_ms"].as_u64().context("readiness completion wall observation unavailable")?;
    ensure!(observer_start <= observed && observed <= observer_end, "stale readiness completion outside fresh observer bracket");
    let readiness_us = evidence["readiness_path"]["raw"]["elapsed_us"].as_u64().context("readiness monotonic elapsed unavailable")?;
    ensure!(readiness_us <= observer["elapsed_us"].as_u64().context("observer command elapsed unavailable")?,
        "original readiness duration exceeds its external observer bracket");
    Ok(json!({"status":"available","command_started_unix_ms":command_start,"command_ended_unix_ms":command_end,
        "capture_started_unix_ms":start,"capture_ended_unix_ms":end,"observer_started_unix_ms":observer_start,
        "observer_ended_unix_ms":observer_end,"readiness_observation_unix_ms":observed,
        "command_monotonic_started_ns":execution["monotonic_started_ns"],"observer_monotonic_ended_ns":observer["monotonic_ended_ns"],"monotonic_clock_id":execution["monotonic_clock_id"],
        "boundary":"command spawn through receipt settlement, then fresh receipt-bound observer settlement",
        "clock_limitation":"Separate Unix millisecond wall observations; clock adjustments and sub-ms order cannot be excluded. Monotonic durations are not absolute clock anchors."}))
}

fn chronology(rows: &mut [Row]) -> Value {
    let mut previous_end: Option<Value> = None;
    let mut seen = BTreeSet::new();
    let mut complete = true;
    for row in rows {
        let local = temporal(&row.value);
        row.value["readiness_temporal_validation"] = match &local {
            Ok(details) => details.clone(),
            Err(error) => unavailable(format!("receipt-bound observation freshness: {error:#}")),
        };
        let result = local.and_then(|details| {
            let observer = &row.value["evidence"]["readiness_path"]["identity"];
            let key = observer["sha256"].as_str().context("readiness byte identity unavailable")?;
            if !seen.insert(key.to_owned()) {
                row.value["readiness_temporal_validation"] = unavailable("readiness observer evidence reused across slots");
                anyhow::bail!("readiness observer evidence reused across slots");
            }
            if let Some(previous) = &previous_end {
                ensure!(details["command_started_unix_ms"].as_u64() > previous["observer_ended_unix_ms"].as_u64(), "fixed execution order violated or attempt/readiness intervals overlap");
                ensure!(details["monotonic_clock_id"] == previous["monotonic_clock_id"]
                    && details["command_monotonic_started_ns"].as_u64() > previous["observer_monotonic_ended_ns"].as_u64(), "fixed monotonic execution order unavailable or overlapping");
            }
            Ok(details)
        });
        // Do not bridge a missing interval as though its position had been proved.
        previous_end = result.as_ref().ok().cloned();
        match result {
            Ok(details) => row.value["temporal_validation"] = details,
            Err(error) => {
                complete = false;
                let reason = format!("chronology/freshness: {error:#}");
                row.value["temporal_validation"] = unavailable(&reason);
                row.value["eligible"] = json!(false);
                row.value["exclusion_reasons"].as_array_mut().expect("row reasons").push(json!(reason));
            }
        }
    }
    json!({"status":if complete {"available"} else {"unavailable"},"complete":complete,"fixed_order":IDS,
        "limitations":"Original receipt elapsed_ms has no absolute anchor. Observer observation_unix_ms is completion, not start. Missing retained command brackets remain unavailable; no absolute times inferred from durations."})
}

struct Row { value: Value, image: Option<PathBuf>, bundle: Option<PathBuf> }
fn row(index: usize, slot: Option<&Value>, frozen_slot: Option<&Value>, frozen: &Value, frozen_id: &Value, protocol: &Value, global_errors: &[String], reads: &mut Reads) -> Row {
    let mut out = Row { value: json!({"slot_id":IDS[index],"planned_index":index,"workload":workload_key(index),"warmup":warmup(index),"measured":!warmup(index),"process_policy":"fresh_process","cache_policy":"unspecified","ledger":slot,"state":slot.map(|s|s["state"].clone()).unwrap_or(json!("not_run")),"original_sample_index":null,"primary":unavailable("capture metric unavailable"),"primary_selector":protocol["workloads"][workload_key(index)]["primary_metric"],"eligible":false,"exclusion_reasons":[],"evidence":{},"media_binding":unavailable("validated capture media unavailable")}), image:None, bundle:None };
    let mut errors = global_errors.to_vec();
    let mut evidence = serde_json::Map::new();
    let mut loaded = BTreeMap::new();
    if let Some(slot) = slot {
        for key in ["admission_binding_path","receipt_path","attempt_report_path","readiness_path","service_outcomes_path","saved_inspect_path","inspection_path","execution_observation_path","readiness_observation_path"] {
            if let Some(p) = slot[key].as_str() {
                match reads.json(Path::new(p)) {
                    Ok((raw, identity)) => {
                        if key == "admission_binding_path" && slot["admission_binding_sha256"] != identity["sha256"] { errors.push("admission binding byte SHA256 mismatch".into()); }
                        if key == "service_outcomes_path" && slot["service_outcomes_sha256"] != identity["sha256"] { errors.push("service outcomes byte SHA256 mismatch".into()); }
                        evidence.insert(key.into(), json!({"identity":identity,"raw":raw}));
                        loaded.insert(key, raw);
                    },
                    Err(error) => {
                        if !["execution_observation_path","readiness_observation_path"].contains(&key) { errors.push(format!("{key}: {error:#}")); }
                        evidence.insert(key.into(), json!({"path":p,"unavailable":format!("{error:#}")}));
                    }
                }
            }
        }
    }
    let outcome = (|| -> Result<()> {
        let slot = slot.context("missing or invalid fixed ledger slot")?;
        let state = text(slot, "state")?;
        ensure!(["completed","failed","denied","cancelled","timed_out","incomplete","invalid_media","unavailable_metric","not_run","not_run_due_to_safety_or_authority"].contains(&state), "unrecognized ledger state");
        if state != "completed" { errors.push(format!("original ledger state {state}: {}",slot["reason"].as_str().unwrap_or("reason unavailable"))); }
        let capture_dir = canonical(&path(slot,"capture_path")?)?;
        let (manifest, manifest_id) = reads.json(&capture_dir.join("manifest.json"))?;
        out.value["original_sample_index"] = manifest["sample_index"].clone();
        out.value["primary"] = primary(&manifest["adapter_result"]["timings"], &out.value["primary_selector"]);
        out.value["original_capture_state"] = manifest["state"].clone();
        evidence.insert("manifest".into(),json!({"identity":manifest_id,"raw":manifest}));
        // Keep raw timing and unknown runtime/model/device/cache observations intact in manifest.
        for name in ["requested.json","result.json"] {
            if name == "result.json" && manifest["adapter_result"].is_null() { continue; }
            let (raw,id) = reads.json(&capture_dir.join(name))?;
            evidence.insert(name.into(),json!({"identity":id,"raw":raw}));
        }
        if let Some(relative) = manifest["guard_evidence"]["path"].as_str() {
            ensure!(relative == "guards.json", "guard evidence must name the capture-owned guards.json");
            let (raw,id) = reads.json(&capture_dir.join(relative))?;
            evidence.insert("guard".into(),json!({"identity":id,"raw":raw}));
        }
        // Reserve the shared inspector's second metadata pass and JSON artifact hashes.
        ensure!(manifest["limits"]["max_output_bytes"].as_u64().is_some_and(|n| n <= 64 * 1024 * 1024), "capture output limit exceeds study ceiling");
        let mut charged: u64 = evidence.values().filter_map(|e| e["identity"]["bytes"].as_u64()).sum();
        if let Some(artifacts) = manifest["adapter_result"]["artifacts"].as_array() {
            for artifact in artifacts {
                let relative = text(artifact, "path")?;
                if Path::new(relative).extension().is_some_and(|e| e == "json") {
                    media_inference_lab::schema::validate_artifact_path(relative)?;
                    let p = canonical(&capture_dir.join(relative))?;
                    let size = regular(&p)?.metadata()?.len();
                    ensure!(size <= JSON_LIMIT, "capture JSON artifact exceeds metadata limit");
                    charged = charged.checked_add(size).context("metadata byte count overflow")?;
                }
            }
        }
        ensure!(charged <= reads.remaining, "metadata byte limit before shared inspection");
        reads.remaining -= charged;
        reads.check()?;
        let inspected = capture::inspect(&capture_dir)?;
        reads.check()?;
        ensure!(serde_json::to_value(&inspected)? == manifest, "capture changed during shared inspection");
        ensure!(loaded.get("saved_inspect_path") == Some(&manifest), "saved mil inspect evidence is missing or differs from capture");
        ensure!(slot["saved_inspect_exit_code"] == 0, "original saved mil inspect exit code unavailable or nonzero");
        let expected: Workload = serde_json::from_value(protocol["workloads"][workload_key(index)]["workload"].clone())?;
        ensure!(inspected.request == expected && inspected.workload_identity == expected.identity()?, "requested workload differs from predeclaration");
        ensure!(manifest["workload_identity"] == protocol["workloads"][workload_key(index)]["accepted_typed_workload_identity"], "typed workload identity mismatch");
        let result = inspected.adapter_result.as_ref().context("missing adapter result")?;
        ensure!(result.resolved == expected, "resolved workload differs from exact predeclaration");
        ensure!(inspected.is_success(), "original capture is not completed");
        let binding = frozen_slot.context("missing frozen slot binding")?;
        let root = canonical(&path(binding,"capture_root")?)?;
        ensure!(capture_dir.parent() == Some(root.as_path()), "capture is outside frozen slot capture root");
        ensure!(binding["workload_identity"] == manifest["workload_identity"], "frozen workload mismatch");
        let admission = loaded.get("admission_binding_path").context("missing admission binding")?;
        ensure!(admission["slot_id"] == IDS[index] && admission["protocol_sha256"] == PROTOCOL_SHA256 && admission["frozen_binding_sha256"] == frozen_id["sha256"], "admission protocol/frozen/slot mismatch");
        ensure!(admission["workload_identity"] == manifest["workload_identity"] && admission["guardian_sha256"] == frozen["guardian"]["sha256"] && admission["plan_sha256"] == binding["plan_sha256"], "admission static binding mismatch");
        let (plan, plan_id) = reads.json(&path(binding,"plan_path")?)?;
        ensure!(plan_id["sha256"] == binding["plan_sha256"], "frozen plan byte identity changed");
        evidence.insert("plan".into(),json!({"identity":plan_id,"raw":plan}));
        let native = inspected.invocation.native.as_ref().context("original native invocation missing")?;
        ensure!(admission["transaction_sha256"] == native.transaction_sha256 && admission["invocation_sha256"] == native.invocation_sha256, "capture invocation differs from admission");
        let (transaction, transaction_id) = reads.json(&path(admission,"transaction_path")?)?;
        let typed: maintenance::Transaction = serde_json::from_value(transaction.clone())?;
        typed.validate()?;
        admission_launch(index,admission,frozen,&transaction)?;
        ensure!(maintenance::digest(&typed)? == native.transaction_sha256, "typed transaction SHA256 mismatch");
        ensure!(typed.guardian_sha256 == text(&frozen["guardian"], "sha256")?, "transaction guardian differs from frozen guardian");
        let prepared = if plan["prepared_plan"].is_object() { &plan["prepared_plan"] } else { &plan };
        ensure!(transaction["experiment"]["plan"] == *prepared && prepared["sha256"] == native.invocation_sha256, "transaction plan differs from frozen prepared plan");
        ensure!(transaction["experiment"]["kind"] == if index < 4 { "native" } else { "native_h3" }, "transaction modality differs from slot");
        let receipt_path = canonical(&path(slot,"receipt_path")?)?;
        ensure!(receipt_path == canonical(&typed.evidence_root.join("receipt.json"))?, "receipt outside admitted transaction evidence root");
        ensure!(canonical(&path(slot,"service_outcomes_path")?)? == canonical(&typed.evidence_root.join("service-outcomes.json"))?, "service outcomes detached from receipt transaction");
        evidence.insert("transaction".into(),json!({"identity":transaction_id,"raw":transaction}));
        let receipt = loaded.get("receipt_path").context("missing receipt")?;
        ensure!(receipt["transaction_sha256"] == native.transaction_sha256 && canonical(&path(receipt,"capture_directory")?)? == capture_dir, "receipt/capture transaction binding mismatch");
        for key in ["success","restored","service_accounting_complete","native_helper_accounting_complete"] { ensure!(receipt[key] == true, "original receipt {key} is not true"); }
        ensure!(receipt["settlement"]["complete"] == true, "original root settlement incomplete");
        attempt_binding(index,loaded.get("attempt_report_path").context("original attempt report missing")?,admission,prepared,&capture_dir,&receipt_path)?;
        readiness(loaded.get("readiness_path").context("readiness evidence missing")?,loaded.get("service_outcomes_path").context("service outcomes missing")?)?;
        let role = if index < 4 { "generated-image" } else { "generated-video" };
        let artifacts: Vec<_> = result.artifacts.iter().filter(|a|a.role == role).collect();
        ensure!(artifacts.len() == 1, "expected one {role} artifact");
        let artifact = artifacts[0];
        let source = canonical(&capture_dir.join(&artifact.path))?;
        out.value["selected_artifact"] = json!({"path":source,"sha256":artifact.sha256,"bytes":artifact.bytes,"role":artifact.role});
        if index < 4 { out.image = Some(source); } else {
            let inspection_path = canonical(&path(slot,"inspection_path")?)?;
            let inspection_artifacts: Vec<_> = result.artifacts.iter().filter(|a| a.role == "full-video-audio-validation").collect();
            ensure!(inspection_artifacts.len() == 1, "original full video inspection artifact missing or ambiguous");
            let ia = inspection_artifacts[0];
            ensure!(inspection_path == canonical(&capture_dir.join(&ia.path))?, "inspection report detached from capture");
            let iid = &evidence["inspection_path"]["identity"];
            ensure!(iid["sha256"] == ia.sha256 && iid["bytes"] == ia.bytes, "original inspection artifact identity changed");
            // The original inspection binding belongs to native validation; offline
            // derivation failure below must not rewrite that original acceptance.
        }
        out.value["media_binding"] = if index < 4 { json!({"status":"available"}) } else { unavailable("derived bundle not yet validated") };
        Ok(())
    })();
    if let Err(error) = outcome { errors.push(format!("{error:#}")); }
    out.value["validation_eligible"] = json!(errors.is_empty());
    out.value["validation_exclusion_reasons"] = json!(errors);
    if errors.is_empty() && index >= 4 {
        let derived = (|| -> Result<PathBuf> {
            let bundle_dir = canonical(&path(slot.context("missing slot")?,"media_bundle")?)?;
            super::media::set_metadata_budget(reads.remaining);
            let before = super::media::metadata_bytes_read();
            let validated = super::media::validate_bundle(&bundle_dir,reads.deadline);
            reads.remaining = reads.remaining.saturating_sub(super::media::metadata_bytes_read().saturating_sub(before));
            let validation = validated?;
            let (bundle,bundle_id) = reads.json(&bundle_dir.join("report.json"))?;
            bind_bundle(&bundle,&out.value["selected_artifact"],&path(&out.value["selected_artifact"],"path")?,&evidence["inspection_path"]["identity"])?;
            evidence.insert("derived_bundle".into(),json!({"identity":bundle_id,"raw":bundle,"validation":validation}));
            Ok(bundle_dir)
        })();
        match derived {
            Ok(bundle) => { out.bundle = Some(bundle); out.value["media_binding"] = json!({"status":"available"}); }
            Err(error) => out.value["media_binding"] = unavailable(format!("{error:#}")),
        }
    }
    if out.value["primary"]["status"] != "available" { errors.push(format!("primary metric: {}",out.value["primary"]["reason"].as_str().unwrap_or("unavailable"))); }
    out.value["eligible"] = json!(errors.is_empty());
    out.value["exclusion_reasons"] = json!(errors);
    out.value["evidence"] = Value::Object(evidence);
    out
}

fn summary(rows: &[Row], base: usize) -> Value {
    let mut values = Vec::new();
    let mut ordered = Vec::new();
    let mut exclusions = Vec::new();
    let selected = &rows[base..base + 4];
    for (offset,row) in selected.iter().enumerate() {
        let eligible = offset > 0 && row.value["eligible"] == true;
        let mut reasons = row.value["exclusion_reasons"].as_array().cloned().unwrap_or_default();
        if offset == 0 { reasons.insert(0,json!("predeclared retained warmup")); }
        ordered.push(json!({"slot_id":IDS[base+offset],"warmup":offset==0,"primary":row.value["primary"],"eligible_for_measured_summary":eligible,"exclusion_reasons":reasons}));
        if eligible { if let Some(v) = row.value["primary"]["value"].as_f64().filter(|v|v.is_finite() && *v >= 0.0) { values.push(v); } }
        else { exclusions.push(json!({"slot_id":IDS[base+offset],"reasons":reasons})); }
    }
    values.sort_by(f64::total_cmp);
    let stats = if values.is_empty() { unavailable("no eligible measured values") } else {
        let n = values.len();
        let median = if n % 2 == 1 { values[n/2] } else { values[n/2-1] + (values[n/2]-values[n/2-1])/2.0 };
        let median_unavailable = median == 0.0 && values[n/2] > 0.0;
        json!({"status":"available","median":if median_unavailable {None}else{Some(median)},"median_unavailable_reason":if median_unavailable{Some("positive median underflows finite numeric range")}else{None},"min":values[0],"max":values[n-1],"range":values[n-1]-values[0]})
    };
    let missing = selected.iter().filter(|r| r.value["state"].as_str().is_some_and(|s|s.starts_with("not_run"))).count();
    let failed = selected.iter().filter(|r| r.value["state"] != "completed" && !r.value["state"].as_str().is_some_and(|s|s.starts_with("not_run"))).count();
    json!({"workload":workload_key(base),"selector":rows[base].value["primary_selector"],"complete":values.len()==3,"counts":{"planned":4,"measured":3,"warmup":1,"failed":failed,"missing":missing,"unavailable":selected.iter().filter(|r|r.value["primary"]["status"]!="available").count(),"eligible_measured":values.len(),"excluded_measured":3-values.len(),"excluded_including_warmup":4-values.len()},"ordered_individuals":ordered,"exclusions":exclusions,"descriptive":stats})
}

fn retained_intervals(row: &Row) -> Vec<Value> {
    let manifest = &row.value["evidence"]["manifest"]["raw"];
    let receipt = &row.value["evidence"]["receipt_path"]["raw"];
    let readiness = &row.value["evidence"]["readiness_path"]["raw"];
    let wall = manifest["started_unix_ms"].as_u64().zip(manifest["ended_unix_ms"].as_u64())
        .and_then(|(start,end)|end.checked_sub(start)).map(Value::from).unwrap_or(Value::Null);
    let inspection_boundary = if row.value["workload"] == "h3_draft" {
        "whole guarded acceptance: ffprobe/ffmpeg full RGB/PCM inspection and helper settlement, profile processing/publication, artifact collection/hashing, result validation and final authority check"
    } else {
        "adapter-result read, contract/artifact inspection and hashing"
    };
    [
        ("capture_host","manifest.host_elapsed_ms","milliseconds","monotonic Instant elapsed","capture execution_start through leader exit or stop decision; excludes subsequent cleanup and inspection",manifest["host_elapsed_ms"].clone()),
        ("capture_wall","manifest.ended_unix_ms - manifest.started_unix_ms","milliseconds","Unix wall clock difference; clock adjustments possible","initial running capture record through terminal record before publication",wall),
        ("artifact_inspection","manifest.artifact_inspection_ms","milliseconds","monotonic Instant elapsed",inspection_boundary,manifest["artifact_inspection_ms"].clone()),
        ("capture_cleanup","manifest.cleanup_elapsed_ms","milliseconds","monotonic Instant elapsed","owned child process-group cleanup and leader reaping",manifest["cleanup_elapsed_ms"].clone()),
        ("transaction","receipt.elapsed_ms","milliseconds","guardian monotonic clock elapsed","guardian clock initialization after arming through receipt construction after service restoration/accounting; excludes final receipt write",receipt["elapsed_ms"].clone()),
        ("readiness_observer","readiness.elapsed_us","microseconds","observer monotonic Instant elapsed","observer active start through identity/listener/health and helper settlement, before observation_unix_ms sampling and publication",readiness["elapsed_us"].clone()),
    ].into_iter().map(|(phase,source,unit,method,boundary,value)| {
        json!({"phase":phase,"scope":"host","unit":unit,"method":method,"boundary":boundary,"source":source,
            "measurement":if value.as_u64().is_some(){json!({"status":"available","value":value})}else{unavailable(format!("{source}: missing or invalid original interval"))}})
    }).collect()
}

fn secondary_summaries(rows: &[Row], base: usize, deadline: Instant) -> Result<Vec<Value>> {
    let mut selectors = BTreeMap::new();
    for row in &rows[base..base + 4] {
        let mut timings = row.value["evidence"]["manifest"]["raw"]["adapter_result"]["timings"].as_array().cloned().unwrap_or_default();
        timings.extend(retained_intervals(row));
        {
            for timing in &timings {
                ensure!(Instant::now() < deadline, "secondary summary cooperative deadline exceeded");
                let selector: Value = Value::Object(SELECTOR.iter().copied().chain(timing.get("source").map(|_|"source")).map(|key|(key.to_owned(),timing[key].clone())).collect());
                if selector != rows[base].value["primary_selector"] {
                    selectors.entry(selector.to_string()).or_insert(selector);
                }
            }
        }
    }
    selectors.into_values().map(|selector| {
        ensure!(Instant::now() < deadline, "secondary summary cooperative deadline exceeded");
        let projected: Vec<_> = rows.iter().map(|row| {
            let timings = if selector.get("source").is_some() { json!(retained_intervals(row)) } else { row.value["evidence"]["manifest"]["raw"]["adapter_result"]["timings"].clone() };
            let metric = primary(&timings,&selector);
            let mut reasons = row.value["validation_exclusion_reasons"].as_array().cloned().unwrap_or_default();
            if metric["status"] != "available" { reasons.push(metric["reason"].clone()); }
            let fresh = selector["source"] != "readiness.elapsed_us"
                || row.value["readiness_temporal_validation"]["status"] == "available";
            if !fresh { reasons.push(json!(row.value["readiness_temporal_validation"]["reason"].as_str().unwrap_or("receipt-bound readiness freshness unavailable"))); }
            Row {value:json!({"state":row.value["state"],"eligible":row.value["validation_eligible"] == true && metric["status"] == "available" && fresh,"primary":metric,"primary_selector":selector,"exclusion_reasons":reasons}),image:None,bundle:None}
        }).collect();
        let mut group = summary(&projected,base);
        group["metric_kind"] = json!(if selector.get("source").is_some() {"secondary_retained_interval"} else {"secondary_adapter_observation"});
        for (offset,row) in rows[base..base + 4].iter().enumerate() {
            let timings = if selector.get("source").is_some() { json!(retained_intervals(row)) } else { row.value["evidence"]["manifest"]["raw"]["adapter_result"]["timings"].clone() };
            let raw = timings.as_array().map(|ts|ts.iter().filter(|t|SELECTOR.iter().all(|key|t[*key] == selector[*key])).cloned().collect::<Vec<_>>()).unwrap_or_default();
            group["ordered_individuals"][offset]["raw_observations"] = json!(raw);
            let individual = group["ordered_individuals"][offset].as_object_mut().expect("summary individual object");
            if let Some(observation) = individual.remove("primary") { individual.insert("observation".into(),observation); }
        }
        Ok(group)
    }).collect()
}
fn pair_rows(rows: &[Row], reads: &mut Reads) -> Vec<Value> {
    pairs().into_iter().map(|(l,r)| {
        let contains_warmup = warmup(l) || warmup(r);
        let deadline = reads.deadline;
        super::media::set_metadata_budget(reads.remaining);
        let before = super::media::metadata_bytes_read();
        let result = (|| -> Result<Value> {
            ensure!(Instant::now() < deadline, "cooperative analysis deadline exceeded");
            ensure!(rows[l].value["validation_eligible"] == true && rows[r].value["validation_eligible"] == true
                && rows[l].value["media_binding"]["status"] == "available" && rows[r].value["media_binding"]["status"] == "available",
                "one or both slots lack independently validated original/media evidence; see validation and media_binding reasons");
            if l < 4 { super::media::compare_images(rows[l].image.as_deref().context("left image unavailable")?, rows[r].image.as_deref().context("right image unavailable")?,deadline) }
            else { super::media::compare_videos(rows[l].bundle.as_deref().context("left video bundle unavailable")?,rows[r].bundle.as_deref().context("right video bundle unavailable")?,deadline) }
        })();
        let charged = super::media::metadata_bytes_read().saturating_sub(before);
        reads.remaining = reads.remaining.saturating_sub(charged);
        json!({"left_slot":IDS[l],"right_slot":IDS[r],"workload":workload_key(l),"contains_warmup":contains_warmup,"variation_group":if contains_warmup{"warmup_containing"}else{"measured_only"},"metrics":match result {Ok(value)=>json!({"status":"available","value":value}),Err(error)=>unavailable(format!("{error:#}"))}})
    }).collect()
}

struct BoundedWriter { file: File, remaining: u64 }
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining { return Err(std::io::Error::other("report output byte limit")); }
        let n = self.file.write(bytes)?; self.remaining -= n as u64; Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> { self.file.flush() }
}
fn private_file(path: &Path, limit: u64) -> Result<BoundedWriter> {
    Ok(BoundedWriter {file:OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?,remaining:limit})
}
fn safe_markdown(value: &Value) -> String {
    let s = value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string());
    let mut escaped = String::new();
    for (index,c) in s.chars().enumerate() {
        if index == 2048 { escaped.push_str(" [display truncated; exact value in JSON]"); break; }
        match c {
            '&' => escaped.push_str("&amp;"), '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"), '|' => escaped.push_str("&#124;"),
            '`' => escaped.push_str("&#96;"), '\\' => escaped.push_str("&#92;"),
            '[' => escaped.push_str("&#91;"), ']' => escaped.push_str("&#93;"),
            c if c.is_control() => escaped.push(' '), c => escaped.push(c),
        }
    }
    escaped
}
fn markdown(report: &Value, output: &Path) -> Result<()> {
    let mut f = private_file(&output.join("report.md"),1024*1024)?;
    writeln!(f,"# Unchanged baseline descriptive precursor\n\nNot baseline/candidate/control acceptance or same-work eligibility. No speedup, tolerance or quality verdict. Warmups remain separate; unknown evidence remains unknown. Original sample indices are not study slot indices.\n\n| Slot | Original state | Original sample index | Exact primary selector (phase/scope/unit/method/boundary) | Primary observation | Eligible | Exclusions |\n|---|---|---|---|---|---|---|")?;
    for row in report["slots"].as_array().context("report rows missing")? {
        writeln!(f,"| {} | {} | {} | {} | {} | {} | {} |",safe_markdown(&row["slot_id"]),safe_markdown(&row["state"]),safe_markdown(&row["original_sample_index"]),safe_markdown(&row["primary_selector"]),safe_markdown(&row["primary"]),safe_markdown(&row["eligible"]),safe_markdown(&row["exclusion_reasons"]))?;
    }
    writeln!(f,"\n## Measured-only summaries\n")?;
    for s in report["summaries"].as_array().context("summaries missing")? { writeln!(f,"- {} exact selector {}: complete {}; counts {}; descriptive {}",safe_markdown(&s["workload"]),safe_markdown(&s["selector"]),safe_markdown(&s["complete"]),safe_markdown(&s["counts"]),safe_markdown(&s["descriptive"]))?; }
    writeln!(f,"\n## Secondary observations\n\nEach full phase/scope/unit/method/boundary selector and source field is separate; overlapping spans are never summed. Missing clocks are not inferred from another metric.")?;
    for s in report["secondary_summaries"].as_array().context("secondary summaries missing")? {
        writeln!(f,"- {} selector {}: complete {}; counts {}; descriptive {}",safe_markdown(&s["workload"]),safe_markdown(&s["selector"]),safe_markdown(&s["complete"]),safe_markdown(&s["counts"]),safe_markdown(&s["descriptive"]))?;
    }
    writeln!(f,"\n## All predeclared pairs\n\n| Left | Right | Group | Status | Unavailable reason |\n|---|---|---|---|---|")?;
    for p in report["pairs"].as_array().context("pairs missing")? { writeln!(f,"| {} | {} | {} | {} | {} |",safe_markdown(&p["left_slot"]),safe_markdown(&p["right_slot"]),safe_markdown(&p["variation_group"]),safe_markdown(&p["metrics"]["status"]),safe_markdown(&p["metrics"]["reason"]))?; }
    writeln!(f,"\nFull neutral numerical records and all original evidence references/hashes, raw secondary intervals, helper/service/restoration/readiness outcomes are in report.json. Empty service helper dispositions do not establish that no helpers ran. Metadata hashes do not establish model payload identity. Cooperative time and filesystem bounds are not hard OS quotas.\n\nGlobal validation errors: {}",safe_markdown(&report["errors"]))?;
    f.file.sync_all()?;
    Ok(())
}

pub fn run(protocol_path: &Path, ledger_path: &Path, output: &Path, deadline: Instant) -> Result<bool> {
    let output = if output.is_absolute() { output.to_path_buf() } else { std::env::current_dir()?.join(output) };
    canonical(output.parent().context("output requires parent directory")?)?;
    DirBuilder::new().mode(0o700).create(&output).context("creating new private report directory (no overwrite)")?;
    let mut reads = Reads { remaining:METADATA_LIMIT, deadline };
    let mut errors = Vec::new();
    let mut inputs = serde_json::Map::new();
    let mut load = |name: &str,p: &Path| -> (Value,Value) {
        match reads.json(p) { Ok((raw,id))=> { inputs.insert(name.into(),json!({"identity":id,"raw":raw})); (raw,id) },Err(e)=> { errors.push(format!("{name}: {e:#}")); (Value::Null,Value::Null) } }
    };
    let (protocol,protocol_id) = load("protocol",protocol_path);
    let (ledger,_) = load("ledger",ledger_path);
    let (frozen,frozen_id) = match path(&ledger,"frozen_binding_path") { Ok(p)=>load("frozen_binding",&p),Err(e)=>{errors.push(format!("{e:#}"));(Value::Null,Value::Null)} };
    if let Err(e) = globals(&protocol,&protocol_id,&ledger,&frozen,&frozen_id) { errors.push(format!("{e:#}")); }
    let slots = match validate_slots(&ledger) {Ok(v)=>v,Err(e)=>{errors.push(format!("ledger: {e:#}"));BTreeMap::new()}};
    let frozen_slots = match validate_slots(&frozen) {Ok(v)=>v,Err(e)=>{errors.push(format!("frozen binding: {e:#}"));BTreeMap::new()}};
    let mut seen = BTreeSet::new();
    for slot in slots.values() {
        if let Some(p) = slot["capture_path"].as_str() {
            match canonical(Path::new(p)) {
                Ok(p) => if !seen.insert(p) { errors.push("capture reused across fixed slots".into()); },
                Err(_) => {} // The corresponding row retains its own path failure.
            }
        }
    }
    let mut rows: Vec<_> = IDS.iter().enumerate().map(|(i,id)| row(i,slots.get(*id),frozen_slots.get(*id),&frozen,&frozen_id,&protocol,&errors,&mut reads)).collect();
    let chronology = chronology(&mut rows);
    let summaries = vec![summary(&rows,0),summary(&rows,4)];
    let mut secondary = Vec::new();
    for base in [0,4] {
        match secondary_summaries(&rows,base,deadline) {
            Ok(groups) => secondary.extend(groups),
            Err(error) => errors.push(format!("{} secondary summaries unavailable: {error:#}",workload_key(base))),
        }
    }
    let pair_records = pair_rows(&rows,&mut reads);
    let complete = errors.is_empty() && chronology["complete"] == true && summaries.iter().all(|s|s["complete"]==true) && rows.iter().all(|r|r.value["eligible"]==true) && pair_records.iter().all(|p|p["metrics"]["status"]=="available");
    let report = json!({"schema_version":1,"kind":"unchanged_baseline_descriptive_precursor","protocol_sha256":PROTOCOL_SHA256,"complete":complete,"same_work_eligibility":"not established","errors":errors,"inputs":inputs,"slots":rows.into_iter().map(|r|r.value).collect::<Vec<_>>(),"summaries":summaries,"secondary_summaries":secondary,"pairs":pair_records,"metadata_bytes_charged":METADATA_LIMIT-reads.remaining,"limitations":["Baseline-only precursor, not full baseline/candidate/control acceptance.","No native invocation, model import, lease, service operation or implicit decoder execution.","Original observations are retained, including unknown model/device/runtime/cache evidence; equal unknowns are not comparability proof.","Numeric output variation is not a quality verdict; warmup-containing pairs are separate.","Filesystem and total analysis deadlines are cooperative, not hard operating-system quotas."]});
    let mut report = report;
    report["chronology"] = chronology;
    let mut f = private_file(&output.join("report.json"),JSON_LIMIT)?;
    serde_json::to_writer_pretty(&mut f,&report)?;
    f.write_all(b"\n")?;
    f.file.sync_all()?;
    markdown(&report,&output)?;
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selector() -> Value {json!({"phase":"generation","scope":"host","unit":"seconds","method":"monotonic","boundary":"synchronized"})}
    fn timing(value: Value) -> Value {let mut v=selector();v["measurement"]=json!({"status":"available","value":value});v}
    fn test_row(i: usize, eligible: bool, value: f64) -> Row {Row{value:json!({"slot_id":IDS[i],"state":"completed","eligible":eligible,"primary":{"status":"available","value":value},"primary_selector":selector(),"exclusion_reasons":if eligible{vec![]}else{vec!["readiness unavailable"]}}),image:None,bundle:None}}
    #[test]
    fn fixed_slots_pairs_and_warmups_survive_missing_evidence() {
        let rows:Vec<_>=(0..8).map(|i|test_row(i,false,1.0)).collect();
        let mut reads=Reads {remaining:METADATA_LIMIT,deadline:Instant::now()+std::time::Duration::from_secs(1)};
        let p=pair_rows(&rows,&mut reads);
        assert_eq!(p.len(),12);
        assert_eq!(p.iter().filter(|v|v["contains_warmup"]==true).count(),6);
        assert!(p.iter().all(|v|v["metrics"]["status"]=="unavailable"));
        assert_eq!(p[0]["left_slot"],"Q0");assert_eq!(p[11]["right_slot"],"H3");
        let duplicate=json!({"slots":IDS.iter().map(|_|json!({"slot_id":"Q0"})).collect::<Vec<_>>()});
        assert!(validate_slots(&duplicate).is_err());
    }
    #[test]
    fn exact_primary_selector_rejects_missing_duplicate_and_changed_boundaries() {
        let t=timing(json!(0.0));
        assert_eq!(primary(&json!([t.clone()]),&selector())["value"],0.0);
        assert_eq!(primary(&json!([t.clone(),t]),&selector())["status"],"unavailable");
        let mut changed=timing(json!(3.0));changed["boundary"]=json!("without synchronization");
        assert_eq!(primary(&json!([changed]),&selector())["status"],"unavailable");
        assert_eq!(primary(&json!([]),&selector())["status"],"unavailable");
        let mut malformed=selector();malformed["scope"]=Value::Null;
        assert_eq!(primary(&json!([timing(json!(1))]),&malformed)["status"],"unavailable");
    }
    #[test]
    fn finite_nonnegative_metric_boundaries_and_original_reason() {
        for invalid in [json!(-1.0),Value::Null,json!("NaN"),json!("Infinity")] {assert_eq!(primary(&json!([timing(invalid)]),&selector())["status"],"unavailable");}
        assert_eq!(primary(&json!([timing(json!(f64::MAX))]),&selector())["value"],f64::MAX);
        let mut t=selector();t["measurement"]=json!({"status":"unavailable","reason":"not observed"});
        assert_eq!(primary(&json!([t]),&selector())["reason"],"not observed");
    }
    #[test]
    fn partial_summary_retains_order_raw_values_and_exclusions_without_overflow() {
        let rows=vec![test_row(0,true,99.0),test_row(1,true,f64::MAX),test_row(2,false,5.0),test_row(3,true,f64::MAX)];
        let s=summary(&rows,0);
        assert_eq!(s["complete"],false);assert_eq!(s["counts"]["eligible_measured"],2);
        assert_eq!(s["counts"]["excluded_including_warmup"],2);assert_eq!(s["descriptive"]["median"],f64::MAX);
        assert_eq!(s["ordered_individuals"][2]["primary"]["value"],5.0);
        assert_eq!(s["ordered_individuals"][0]["eligible_for_measured_summary"],false);
        let empty:Vec<_>=(0..4).map(|i|test_row(i,false,0.0)).collect();
        assert_eq!(summary(&empty,0)["descriptive"]["status"],"unavailable");
    }
    #[test]
    fn bundle_requires_original_source_hash_count_path_and_inspection() {
        let dir=tempfile::tempdir().unwrap();
        let root=dir.path().canonicalize().unwrap();
        let source=root.join("original.mp4");let detached=root.join("detached.mp4");
        fs::write(&source,b"original").unwrap();fs::write(&detached,b"original").unwrap();
        let artifact=json!({"sha256":sha(b"original"),"bytes":8});let inspection=json!({"path":"/inspection.json","sha256":sha(b"inspection"),"bytes":10});
        let bundle=json!({"valid":true,"source":{"path":source.canonicalize().unwrap(),"sha256":artifact["sha256"],"bytes":8},"inspection":inspection});
        assert!(bind_bundle(&bundle,&artifact,&source,&inspection).is_ok());
        let mut wrong=bundle.clone();wrong["source"]["path"]=json!(detached.canonicalize().unwrap());assert!(bind_bundle(&wrong,&artifact,&source,&inspection).is_err());
        wrong=bundle.clone();wrong["source"]["sha256"]=json!(sha(b"changed"));assert!(bind_bundle(&wrong,&artifact,&source,&inspection).is_err());
        wrong=bundle.clone();wrong["source"]["bytes"]=json!(7);assert!(bind_bundle(&wrong,&artifact,&source,&inspection).is_err());
        wrong=bundle;wrong["inspection"]["sha256"]=json!(sha(b"changed"));assert!(bind_bundle(&wrong,&artifact,&source,&inspection).is_err());
    }
    #[test]
    fn protocol_and_frozen_hashes_are_not_adopted_from_ledger() {
        let protocol=json!({"slots":IDS.iter().map(|id|json!({"slot_id":id})).collect::<Vec<_>>(),"numerical_report":{"pairs_per_modality":pairs().iter().map(|(l,r)|json!([IDS[*l],IDS[*r]])).collect::<Vec<_>>()}});
        let digest=sha(b"frozen");
        let ledger=json!({"protocol_sha256":PROTOCOL_SHA256,"frozen_binding_sha256":digest});
        let frozen=json!({"protocol_sha256":PROTOCOL_SHA256,"guardian_source_commit":GUARDIAN_COMMIT,"guardian":{"sha256":sha(b"guardian")},"analysis":{"source_sha256":sha(b"source"),"binary_sha256":sha(b"binary")},"launch_choices":{"qwen":"mflux-run --execute","h3_draft":"maintenance-run"}});
        let identity=json!({"sha256":PROTOCOL_SHA256});
        assert!(globals(&protocol,&identity,&ledger,&frozen,&json!({"sha256":digest})).is_ok());
        assert!(globals(&protocol,&json!({"sha256":sha(b"changed protocol")}),&ledger,&frozen,&json!({"sha256":digest})).is_err());
        assert!(globals(&protocol,&identity,&ledger,&frozen,&json!({"sha256":sha(b"changed binding")})).is_err());
    }
    #[test]
    fn real_report_failure_keeps_all_rows_pairs_and_private_nonoverwriting_output() {
        use std::os::unix::fs::PermissionsExt;
        let dir=tempfile::tempdir().unwrap();
        let root=dir.path().canonicalize().unwrap();
        let protocol=root.join("protocol.json");
        let ledger=root.join("ledger.json");
        fs::write(&protocol,b"{}").unwrap();
        fs::write(&ledger,serde_json::to_vec(&json!({"slots":IDS.iter().map(|id|json!({"slot_id":id,"state":"not_run","reason":"authority not granted"})).collect::<Vec<_>>()})).unwrap()).unwrap();
        let out=root.join("report");
        assert!(!run(&protocol,&ledger,&out,Instant::now()+std::time::Duration::from_secs(5)).unwrap());
        let report:Value=serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["slots"].as_array().unwrap().len(),8);
        assert_eq!(report["pairs"].as_array().unwrap().len(),12);
        assert_eq!(report["slots"][7]["slot_id"],"H3");
        assert_eq!(report["slots"][7]["ledger"]["reason"],"authority not granted");
        assert_eq!(report["summaries"][0]["counts"]["missing"],4);
        assert_eq!(report["summaries"][0]["counts"]["eligible_measured"],0);
        assert_eq!(fs::metadata(&out).unwrap().permissions().mode() & 0o777,0o700);
        assert_eq!(fs::metadata(out.join("report.json")).unwrap().permissions().mode() & 0o777,0o600);
        assert!(run(&protocol,&ledger,&out,Instant::now()+std::time::Duration::from_secs(5)).is_err());
        assert!(!safe_markdown(&json!("<script>|[link](x)\n")).contains("<script>"));
    }
    #[test]
    fn restored_identity_and_original_helper_settlement_are_required() {
        let identity=json!({"pid":12,"ppid":1,"pgid":12,"sid":12,"uid":501,"start_seconds":100,"start_subseconds":3,"executable":"/runtime/python","cwd":"/studio","state":"running"});
        let services=json!([{"role":"studio","restored":true,"root":identity}]);
        let report=json!({"qualified":true,"helper_accounting_complete":true,"exact_identity_unchanged":true,"health":{"http_status":200,"ok":true},"identity_before":identity,"identity_after":identity,"helper_accounting":[{"complete":true,"settlement":{"complete":true,"leader_reaped":true,"group_absent":true}}],"target_pid":12,"target_uid":501,"target_birth_seconds":100,"target_birth_subseconds":3,"studio_listener":{"positive_listener":true,"owner_birth_unchanged":true,"pid":12}});
        assert!(readiness(&report,&services).is_ok());
        let mut changed=services.clone();changed[0]["root"]["start_subseconds"]=json!(4);
        assert!(readiness(&report,&changed).is_err());
        for key in ["leader_reaped","group_absent"] {
            let mut unsettled=report.clone();unsettled["helper_accounting"][0]["settlement"][key]=json!(false);
            assert!(readiness(&unsettled,&services).is_err());
        }
        let mut incomplete=report;incomplete["helper_accounting"][0]["settlement"]["complete"]=json!(false);
        assert!(readiness(&incomplete,&services).is_err());
    }
    #[test]
    fn bounded_metadata_rejects_budget_overflow_and_symlinks() {
        let dir=tempfile::tempdir().unwrap();let root=dir.path().canonicalize().unwrap();
        let p=root.join("evidence.json");fs::write(&p,b"{}").unwrap();
        let mut reads=Reads{remaining:1,deadline:Instant::now()+std::time::Duration::from_secs(1)};
        assert!(reads.json(&p).is_err());
        reads.remaining=10;
        let link=root.join("link.json");std::os::unix::fs::symlink(&p,&link).unwrap();
        assert!(reads.json(&link).is_err());
    }
    #[test]
    fn positive_midpoint_underflow_is_unavailable_not_zero() {
        let rows=vec![test_row(0,true,1.0),test_row(1,true,0.0),test_row(2,true,f64::from_bits(1)),test_row(3,false,9.0)];
        let s=summary(&rows,0);
        assert!(s["descriptive"]["median"].is_null());
        assert_eq!(s["descriptive"]["median_unavailable_reason"],"positive median underflows finite numeric range");
        assert_eq!(s["counts"]["eligible_measured"],2);
        assert_eq!(s["descriptive"]["min"],0.0);
        assert_eq!(s["descriptive"]["max"],f64::from_bits(1));
    }
    #[test]
    fn secondary_groups_preserve_changed_boundaries_duplicates_and_order() {
        let mut rows:Vec<_>=(0..8).map(|i|test_row(i,true,i as f64)).collect();
        for (i,row) in rows.iter_mut().enumerate().take(4) {
            row.value["validation_eligible"]=json!(true);
            row.value["validation_exclusion_reasons"]=json!([]);
            let mut t=timing(json!(i as f64));t["phase"]=json!("import");
            if i==2 { t["boundary"]=json!("changed"); }
            row.value["evidence"]=json!({"manifest":{"raw":{"adapter_result":{"timings":if i==3{vec![t.clone(),t]}else{vec![t]}}}}});
        }
        let groups=secondary_summaries(&rows,0,Instant::now()+std::time::Duration::from_secs(1)).unwrap();
        assert_eq!(groups.iter().filter(|g|g["metric_kind"]=="secondary_adapter_observation").count(),2);
        let original=groups.iter().find(|g|g["selector"]["boundary"]=="synchronized").unwrap();
        assert_eq!(original["counts"]["eligible_measured"],1);
        assert_eq!(original["ordered_individuals"][3]["raw_observations"].as_array().unwrap().len(),2);
        assert_eq!(original["ordered_individuals"][3]["observation"]["status"],"unavailable");
        assert_eq!(original["ordered_individuals"][0]["slot_id"],"Q0");
        assert_eq!(original["ordered_individuals"][0]["eligible_for_measured_summary"],false);
        let changed=groups.iter().find(|g|g["selector"]["boundary"]=="changed").unwrap();
        assert_eq!(changed["counts"]["eligible_measured"],1);
        assert_eq!(changed["descriptive"]["median"],2.0);
    }
}

#[cfg(test)]
#[path = "report_review_tests.rs"]
mod review_tests;
