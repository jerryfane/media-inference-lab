use super::*;
use std::time::Duration;
fn selector() -> Value { json!({"phase":"generation","scope":"host","unit":"seconds","method":"synthetic monotonic","boundary":"synthetic synchronized generation"}) }
fn collector() -> Value {
    json!({"study_root":"/SYNTHETIC","protocol_sha256":PROTOCOL_SHA256,
        "source_identity":{"path":"/SYNTHETIC/observation_clock.py","sha256":sha(b"SYNTHETIC collector source"),"bytes":26},
        "monotonic_clock_id":"SYNTHETIC-session"})
}
fn rows() -> Vec<Row> {
    (0..IDS.len()).map(|i| {
        let t=1000+i as u64*1000;
        let rid=json!({"path":format!("/SYNTHETIC/{i}/receipt"),"sha256":format!("receipt-{i}"),"bytes":1});
        let oid=json!({"path":format!("/SYNTHETIC/{i}/readiness"),"sha256":format!("observer-{i}"),"bytes":1});
        let aid=json!({"path":format!("/SYNTHETIC/{i}/attempt"),"sha256":format!("attempt-{i}"),"bytes":1});
        let bracket=|start:u64,end:u64|json!({
            "study_root":collector()["study_root"],"protocol_sha256":PROTOCOL_SHA256,"source_identity":collector()["source_identity"],
            "collection_complete":true,"errors":[],"clock":"unix_ms","elapsed_clock":"monotonic",
            "started_unix_ms":start,"ended_unix_ms":end,"elapsed_us":(end-start)*1000,
            "monotonic_started_ns":start*1_000_000,"monotonic_ended_ns":end*1_000_000,
            "monotonic_clock_id":"SYNTHETIC-session","exit_code":0,"literal_cli_argv":["/SYNTHETIC/command"]});
        let mut execution=bracket(t,t+400);
        execution["event"]=json!(format!("{}/execution",IDS[i]));
        execution["boundary"]=json!("before_command_spawn_through_command_settlement_and_receipt_read");
        execution["receipt_identity"]=rid.clone();execution["attempt_identity"]=aid.clone();
        let mut observer=bracket(t+500,t+600);
        observer["event"]=json!(format!("{}/readiness",IDS[i]));
        observer["boundary"]=json!("before_observer_spawn_through_observer_settlement_and_report_read");
        observer["receipt_identity"]=rid.clone();observer["readiness_identity"]=oid.clone();
        Row{value:json!({
            "slot_id":IDS[i],"workload":WORKLOAD_KEY,"state":"completed","eligible":true,"validation_eligible":true,
            "validation_exclusion_reasons":[],"exclusion_reasons":[],"media_binding":{"status":"available"},
            "primary_selector":selector(),"primary":{"status":"available","value":i+1},
            "evidence":{
                "manifest":{"raw":{"started_unix_ms":t+100,"ended_unix_ms":t+300,"host_elapsed_ms":100,"artifact_inspection_ms":20,"cleanup_elapsed_ms":1}},
                "receipt_path":{"identity":rid,"raw":{"elapsed_ms":350}},"attempt_report_path":{"identity":aid},
                "admission_binding_path":{"raw":{"literal_cli_argv":["/SYNTHETIC/command"]}},
                "readiness_path":{"identity":oid,"raw":{"observation_unix_ms":t+550,"elapsed_us":50_000}},
                "execution_observation_path":{"raw":execution},"readiness_observation_path":{"raw":observer}
            }}),bundle:None}
    }).collect()
}
#[test]
fn review_fixed_order_overlap_missing_clocks_and_stale_readiness() {
    let mut ordered=rows(); assert_eq!(chronology(&mut ordered,&collector())["complete"],true);
    let mut reversed=rows(); reversed.swap(1,2); assert_eq!(chronology(&mut reversed,&collector())["complete"],false);
    let mut overlap=rows();
    let execution=&mut overlap[1].value["evidence"]["execution_observation_path"]["raw"];
    execution["started_unix_ms"]=json!(1500);execution["monotonic_started_ns"]=json!(1_500_000_000u64);execution["elapsed_us"]=json!(900_000);
    assert_eq!(chronology(&mut overlap,&collector())["complete"],false);
    assert!(overlap[1].value["temporal_validation"]["reason"].as_str().unwrap().contains("overlap"));
    let mut missing=rows(); missing[1].value["evidence"]["execution_observation_path"]["raw"]["monotonic_started_ns"]=Value::Null; assert_eq!(chronology(&mut missing,&collector())["complete"],false);
    let mut stale=rows(); stale[1].value["evidence"]["readiness_path"]["raw"]["observation_unix_ms"]=json!(100); assert_eq!(chronology(&mut stale,&collector())["complete"],false);assert_eq!(stale[1].value["validation_eligible"],true);assert_eq!(stale[1].value["media_binding"]["status"],"available");
}
#[test]
fn review_original_durations_fit_external_observation_brackets() {
    let mut r=rows();
    assert!(temporal(&r[1].value,&collector()).is_ok());
    r[1].value["evidence"]["receipt_path"]["raw"]["elapsed_ms"]=json!(401);
    assert!(temporal(&r[1].value,&collector()).unwrap_err().to_string().contains("transaction duration"));
    r[1].value["evidence"]["receipt_path"]["raw"]["elapsed_ms"]=json!(350);
    r[1].value["evidence"]["readiness_path"]["raw"]["elapsed_us"]=json!(100_001);
    assert!(temporal(&r[1].value,&collector()).unwrap_err().to_string().contains("readiness duration"));
}
#[test]
fn review_stale_readiness_excludes_only_its_own_secondary_interval() {
    let mut r=rows();
    r[1].value["primary"]=unavailable("missing primary");
    r[1].value["eligible"]=json!(false);
    r[3].value["evidence"]["readiness_path"]["raw"]["observation_unix_ms"]=json!(1);
    assert_eq!(chronology(&mut r,&collector())["complete"],false);
    let groups=secondary_summaries(&r,Instant::now()+Duration::from_secs(5)).unwrap();
    let observer=groups.iter().find(|g|g["selector"]["source"]=="readiness.elapsed_us").unwrap();
    assert_eq!(observer["counts"]["eligible_measured"],2);
    assert_eq!(observer["ordered_individuals"][3]["observation"]["status"],"available");
    assert_eq!(observer["ordered_individuals"][3]["eligible_for_measured_summary"],false);
    let host=groups.iter().find(|g|g["selector"]["source"]=="manifest.host_elapsed_ms").unwrap();
    assert_eq!(host["counts"]["eligible_measured"],3);
    assert_eq!(r[3].value["media_binding"]["status"],"available");
}
#[test]
fn review_reused_observer_identity_and_temporal_evidence_are_distinct() {
    let mut reused=rows();let first=reused[0].value["evidence"]["readiness_path"]["identity"].clone();reused[1].value["evidence"]["readiness_path"]["identity"]=first.clone();reused[1].value["evidence"]["readiness_observation_path"]["raw"]["readiness_identity"]=first;
    assert_eq!(chronology(&mut reused,&collector())["complete"],false); assert!(reused[1].value["temporal_validation"]["reason"].as_str().unwrap().contains("reused"));
    let identity=json!({"pid":100,"ppid":1,"pgid":100,"sid":1,"uid":501,"start_seconds":100,"start_subseconds":1,"executable":"/SYNTHETIC/studio","cwd":"/SYNTHETIC","state":"running"});
    let ready=json!({"qualified":true,"helper_accounting_complete":true,"exact_identity_unchanged":true,"health":{"http_status":200,"ok":true},"identity_before":identity,"identity_after":identity,"target_pid":100,"target_uid":501,"target_birth_seconds":100,"target_birth_subseconds":1,"helper_accounting":[{"complete":true,"settlement":{"complete":true,"leader_reaped":true,"group_absent":true}}],"studio_listener":{"positive_listener":true,"owner_birth_unchanged":true,"pid":100}});
    assert!(readiness(&ready,&json!([{"role":"studio","restored":true,"root":identity}])).is_ok());let mut changed=identity;changed["start_subseconds"]=json!(2);assert!(readiness(&ready,&json!([{"role":"studio","restored":true,"root":changed}])).is_err());
}
#[test]
fn review_secondary_intervals_exclude_independently_of_primary() {
    let mut r=rows();r[1].value["primary"]=unavailable("missing exact primary");r[1].value["eligible"]=json!(false);r[2].value["evidence"]["receipt_path"]["raw"]["elapsed_ms"]=Value::Null;
    let groups=secondary_summaries(&r,Instant::now()+Duration::from_secs(5)).unwrap();
    let host=groups.iter().find(|g|g["selector"]["source"]=="manifest.host_elapsed_ms").unwrap();assert_eq!(host["counts"]["eligible_measured"],3);
    let transaction=groups.iter().find(|g|g["selector"]["source"]=="receipt.elapsed_ms").unwrap();assert_eq!(transaction["counts"]["eligible_measured"],2);assert_eq!(transaction["ordered_individuals"][2]["observation"]["status"],"unavailable");
    assert!(groups.iter().any(|g|g["selector"]["unit"]=="microseconds"));
}
#[test]
fn h3_only_command_dispatch_requires_maintenance_and_original_command_receipt() {
    let service=json!({"role":"studio","name":"SYNTHETIC"});
    let frozen=json!({"guardian":{"path":"/SYNTHETIC/mil"}});
    let transaction=json!({"services":[service.clone()]});
    let admission=json!({"literal_cli_argv":["/SYNTHETIC/mil","maintenance-run","--transaction","/SYNTHETIC/transaction.json"],
        "transaction_path":"/SYNTHETIC/transaction.json","service_binding":service});
    let attempt=json!({"argv":admission["literal_cli_argv"],"exit_code":0,"stdout":"SYNTHETIC","stderr":""});
    assert!(admission_launch(&admission,&frozen,&transaction).is_ok());
    assert!(attempt_binding(&attempt,&admission).is_ok());
    let mut qwen=admission.clone();
    qwen["literal_cli_argv"]=json!(["/SYNTHETIC/mil","mflux-run","--execute","--maintenance-transaction","/SYNTHETIC/transaction.json"]);
    assert!(admission_launch(&qwen,&frozen,&transaction).is_err());
    assert!(attempt_binding(&json!({"kind":"native_mflux_attempt","mode":"execute","native_execution":true,"ok":true}),&admission).is_err());
    let mut failed=attempt.clone();failed["exit_code"]=json!(1);
    assert!(attempt_binding(&failed,&admission).is_err());
    let mut detached=attempt;detached["argv"][3]=json!("/SYNTHETIC/other.json");
    assert!(attempt_binding(&detached,&admission).is_err());
}
#[test]
fn review_markdown_labels_primary_units_methods_and_boundaries() {
    let dir=tempfile::tempdir().unwrap();let mut r=rows();for row in &mut r{row.value["primary_selector"]["unit"]=json!("milliseconds");}let report=json!({"slots":r.iter().map(|r|r.value.clone()).collect::<Vec<_>>(),"summaries":[summary(&r)],"secondary_summaries":[],"pairs":[],"errors":[]});markdown(&report,dir.path()).unwrap();let text=fs::read_to_string(dir.path().join("report.md")).unwrap();for label in ["milliseconds","synthetic monotonic","synthetic synchronized generation"]{assert!(text.contains(label),"missing {label}");}
}

#[test]
fn h3_only_secondary_groups_and_missing_media_preserve_timing_counts() {
    let mut r=rows();
    assert_eq!(chronology(&mut r,&collector())["complete"],true);
    r[2].value["media_binding"]=unavailable("mandatory all56-frame contact sheet missing");
    let s=summary(&r);
    assert_eq!(s["workload"],"h3_draft");
    assert_eq!(s["counts"]["planned"],4);
    assert_eq!(s["counts"]["warmup"],1);
    assert_eq!(s["counts"]["eligible_measured"],3);
    assert_eq!(s["ordered_individuals"][0]["slot_id"],"H0");
    assert_eq!(s["ordered_individuals"][0]["eligible_for_measured_summary"],false);
    let groups=secondary_summaries(&r,Instant::now()+Duration::from_secs(5)).unwrap();
    assert_eq!(groups.len(),6);
    assert!(groups.iter().all(|g|g["workload"]=="h3_draft" && g["counts"]["eligible_measured"]==3));
    let inspection=groups.iter().find(|g|g["selector"]["source"]=="manifest.artifact_inspection_ms").unwrap();
    assert!(inspection["selector"]["boundary"].as_str().unwrap().contains("whole guarded acceptance: ffprobe/ffmpeg full RGB/PCM"));
    let p=pair_rows(&r,&mut Reads{remaining:METADATA_LIMIT,deadline:Instant::now()+Duration::from_secs(5)});
    assert_eq!(p.len(),6);
    for pair in &p {
        let reason=pair["metrics"]["reason"].as_str().unwrap();
        if pair["left_slot"]=="H2" || pair["right_slot"]=="H2" {
            assert!(reason.contains("independently validated original/media evidence"));
        } else {
            assert!(reason.contains("video bundle unavailable"),"{reason}");
        }
    }
}

#[test]
fn h3_only_stopped_cohort_retains_missing_slots_without_resumed_chronology() {
    let mut r=rows();
    for row in &mut r[2..] {
        row.value["state"]=json!("not_run_due_to_safety_or_authority");
        row.value["eligible"]=json!(false);
        row.value["validation_eligible"]=json!(false);
        row.value["primary"]=unavailable("original collector unavailable; not run");
        row.value["exclusion_reasons"]=json!(["original collector unavailable; not run"]);
        row.value["evidence"]=json!({});
        row.value["media_binding"]=unavailable("no original H3 capture");
    }
    assert_eq!(chronology(&mut r,&collector())["complete"],false);
    let s=summary(&r);
    assert_eq!(s["complete"],false);
    assert_eq!(s["counts"]["missing"],2);
    assert_eq!(s["counts"]["failed"],0);
    assert_eq!(s["counts"]["eligible_measured"],1);
    assert_eq!(s["descriptive"]["median"],2.0);
    assert_eq!(s["ordered_individuals"][3]["slot_id"],"H3");
    let pairs=pair_rows(&r,&mut Reads{remaining:METADATA_LIMIT,deadline:Instant::now()+Duration::from_secs(5)});
    assert_eq!(pairs.len(),6);
    assert!(pairs.iter().all(|p|p["metrics"]["status"]=="unavailable" && p["metrics"]["reason"].as_str().is_some_and(|s|!s.is_empty())));
    let mut resumed=rows();
    resumed[1].value["evidence"]["execution_observation_path"]["raw"]["collection_complete"]=json!(false);
    assert_eq!(chronology(&mut resumed,&collector())["complete"],false);
    assert!(resumed[2..].iter().all(|r|r.value["eligible"]==false
        && r.value["temporal_validation"]["reason"].as_str().unwrap().contains("cannot resume")));
}

#[test]
fn h3_only_collector_binding_rejects_legacy_clocks_without_excluding_media() {
    let mut legacy=rows();
    for row in &mut legacy {
        for kind in ["execution_observation_path","readiness_observation_path"] {
            let observation=row.value["evidence"][kind]["raw"].as_object_mut().unwrap();
            for key in ["study_root","protocol_sha256","source_identity","event"] { observation.remove(key); }
        }
    }
    assert_eq!(chronology(&mut legacy,&collector())["complete"],false);
    assert_eq!(summary(&legacy)["counts"]["eligible_measured"],0);
    assert!(legacy.iter().all(|r|r.value["validation_eligible"]==true
        && r.value["media_binding"]["status"]=="available" && r.value["primary"]["status"]=="available"));
    let groups=secondary_summaries(&legacy,Instant::now()+Duration::from_secs(5)).unwrap();
    for group in groups {
        assert_eq!(group["counts"]["eligible_measured"],
            if group["selector"]["source"]=="readiness.elapsed_us" {json!(0)} else {json!(3)});
    }
    let pairs=pair_rows(&legacy,&mut Reads{remaining:METADATA_LIMIT,deadline:Instant::now()+Duration::from_secs(5)});
    assert_eq!(pairs.len(),6);
    // Pair processing still reaches the video bundle, not original/media eligibility rejection.
    assert!(pairs.iter().all(|p|p["metrics"]["reason"].as_str().unwrap().contains("video bundle unavailable")));
    let mut unbound=rows();
    assert_eq!(chronology(&mut unbound,&Value::Null)["complete"],false);
    assert!(unbound.iter().all(|r|r.value["validation_eligible"]==true && r.value["eligible"]==false));
}

#[test]
fn h3_only_collector_binding_rejects_mismatched_source_root_protocol_domain_and_event() {
    let original=rows();
    assert!(temporal(&original[1].value,&collector()).is_ok());
    for kind in ["execution_observation_path","readiness_observation_path"] {
        for (key,wrong) in [
            ("study_root",json!("/OTHER-SYNTHETIC")),
            ("protocol_sha256",json!("e01abcc9514db1a75120859db76edfd9feb775ce5f966e5ab2a53cf7fbbf7a42")),
            ("source_identity",json!({"path":"/SYNTHETIC/other.py","sha256":sha(b"other"),"bytes":5})),
            ("monotonic_clock_id",json!("SYNTHETIC-replacement-domain")),
            ("event",json!("H2/execution")),
            ("event",json!("H1/wrong-kind")),
        ] {
            let mut wrong_row=original[1].value.clone();
            wrong_row["evidence"][kind]["raw"][key]=wrong;
            assert!(temporal(&wrong_row,&collector()).is_err(),"{kind} {key}");
        }
        for key in ["path","sha256","bytes"] {
            let mut wrong_row=original[1].value.clone();
            wrong_row["evidence"][kind]["raw"]["source_identity"][key]=Value::Null;
            assert!(temporal(&wrong_row,&collector()).is_err(),"{kind} source {key}");
        }
        let mut swapped=original[1].value.clone();
        swapped["evidence"][kind]["raw"]["event"]=json!(if kind=="execution_observation_path" {"H1/readiness"} else {"H1/execution"});
        assert!(temporal(&swapped,&collector()).is_err());
    }
}

#[test]
fn h3_only_collector_binding_requires_well_formed_common_identity_without_live_source() {
    let r=rows();
    // The synthetic source/domain need not exist or be alive for saved-evidence reporting.
    assert!(temporal(&r[0].value,&collector()).is_ok());
    for key in ["study_root","protocol_sha256","source_identity","monotonic_clock_id"] {
        let mut missing=collector();missing.as_object_mut().unwrap().remove(key);
        assert!(temporal(&r[0].value,&missing).is_err(),"{key}");
    }
    for (pointer,wrong) in [
        ("/study_root",json!("relative")),
        ("/study_root",json!("/SYNTHETIC/../OTHER")),
        ("/source_identity/path",json!("/SYNTHETIC-other/source.py")),
        ("/source_identity/path",json!("/SYNTHETIC/../other.py")),
        ("/source_identity/path",json!("/SYNTHETIC")),
        ("/source_identity/sha256",json!("not-a-sha256")),
        ("/source_identity/bytes",json!(0)),
        ("/source_identity/bytes",json!(-1)),
        ("/source_identity/bytes",json!("26")),
        ("/monotonic_clock_id",json!(" ")),
        ("/protocol_sha256",json!(sha(b"other protocol"))),
    ] {
        let mut malformed=collector();
        *malformed.pointer_mut(pointer).unwrap()=wrong;
        let mut matching=r[0].value.clone();
        for kind in ["execution_observation_path","readiness_observation_path"] {
            for key in ["study_root","protocol_sha256","source_identity","monotonic_clock_id"] {
                matching["evidence"][kind]["raw"][key]=malformed[key].clone();
            }
        }
        assert!(temporal(&matching,&malformed).is_err(),"{pointer}: {malformed}");
    }
}
