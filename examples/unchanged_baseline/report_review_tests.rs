use super::*;
use std::time::Duration;
fn selector() -> Value { json!({"phase":"generation","scope":"host","unit":"seconds","method":"synthetic monotonic","boundary":"synthetic synchronized generation"}) }
fn rows() -> Vec<Row> {
    (0..8).map(|i| {
        let t=1000+i as u64*1000;
        let rid=json!({"path":format!("/SYNTHETIC/{i}/receipt"),"sha256":format!("receipt-{i}"),"bytes":1});
        let oid=json!({"path":format!("/SYNTHETIC/{i}/readiness"),"sha256":format!("observer-{i}"),"bytes":1});
        let aid=json!({"path":format!("/SYNTHETIC/{i}/attempt"),"sha256":format!("attempt-{i}"),"bytes":1});
        let bracket=|start:u64,end:u64|json!({
            "collection_complete":true,"errors":[],"clock":"unix_ms","elapsed_clock":"monotonic",
            "started_unix_ms":start,"ended_unix_ms":end,"elapsed_us":(end-start)*1000,
            "monotonic_started_ns":start*1_000_000,"monotonic_ended_ns":end*1_000_000,
            "monotonic_clock_id":"SYNTHETIC-session","exit_code":0,"literal_cli_argv":["/SYNTHETIC/command"]});
        let mut execution=bracket(t,t+400);
        execution["boundary"]=json!("before_command_spawn_through_command_settlement_and_receipt_read");
        execution["receipt_identity"]=rid.clone();execution["attempt_identity"]=aid.clone();
        let mut observer=bracket(t+500,t+600);
        observer["boundary"]=json!("before_observer_spawn_through_observer_settlement_and_report_read");
        observer["receipt_identity"]=rid.clone();observer["readiness_identity"]=oid.clone();
        Row{value:json!({
            "slot_id":IDS[i],"state":"completed","eligible":true,"validation_eligible":true,
            "validation_exclusion_reasons":[],"exclusion_reasons":[],"media_binding":{"status":"available"},
            "primary_selector":selector(),"primary":{"status":"available","value":i+1},
            "evidence":{
                "manifest":{"raw":{"started_unix_ms":t+100,"ended_unix_ms":t+300,"host_elapsed_ms":100,"artifact_inspection_ms":20,"cleanup_elapsed_ms":1}},
                "receipt_path":{"identity":rid,"raw":{"elapsed_ms":350}},"attempt_report_path":{"identity":aid},
                "admission_binding_path":{"raw":{"literal_cli_argv":["/SYNTHETIC/command"]}},
                "readiness_path":{"identity":oid,"raw":{"observation_unix_ms":t+550,"elapsed_us":50_000}},
                "execution_observation_path":{"raw":execution},"readiness_observation_path":{"raw":observer}
            }}),image:None,bundle:None}
    }).collect()
}
#[test]
fn review_fixed_order_overlap_missing_clocks_and_stale_readiness() {
    let mut ordered=rows(); assert_eq!(chronology(&mut ordered)["complete"],true);
    let mut reversed=rows(); reversed.swap(1,2); assert_eq!(chronology(&mut reversed)["complete"],false);
    let mut overlap=rows();
    let execution=&mut overlap[1].value["evidence"]["execution_observation_path"]["raw"];
    execution["started_unix_ms"]=json!(1500);execution["monotonic_started_ns"]=json!(1_500_000_000u64);execution["elapsed_us"]=json!(900_000);
    assert_eq!(chronology(&mut overlap)["complete"],false);
    assert!(overlap[1].value["temporal_validation"]["reason"].as_str().unwrap().contains("overlap"));
    let mut missing=rows(); missing[1].value["evidence"]["execution_observation_path"]["raw"]["monotonic_started_ns"]=Value::Null; assert_eq!(chronology(&mut missing)["complete"],false);
    let mut stale=rows(); stale[1].value["evidence"]["readiness_path"]["raw"]["observation_unix_ms"]=json!(100); assert_eq!(chronology(&mut stale)["complete"],false);assert_eq!(stale[1].value["validation_eligible"],true);assert_eq!(stale[1].value["media_binding"]["status"],"available");
}
#[test]
fn review_original_durations_fit_external_observation_brackets() {
    let mut r=rows();
    assert!(temporal(&r[1].value).is_ok());
    r[1].value["evidence"]["receipt_path"]["raw"]["elapsed_ms"]=json!(401);
    assert!(temporal(&r[1].value).unwrap_err().to_string().contains("transaction duration"));
    r[1].value["evidence"]["receipt_path"]["raw"]["elapsed_ms"]=json!(350);
    r[1].value["evidence"]["readiness_path"]["raw"]["elapsed_us"]=json!(100_001);
    assert!(temporal(&r[1].value).unwrap_err().to_string().contains("readiness duration"));
}
#[test]
fn review_stale_readiness_excludes_only_its_own_secondary_interval() {
    let mut r=rows();
    r[1].value["primary"]=unavailable("missing primary");
    r[1].value["eligible"]=json!(false);
    r[3].value["evidence"]["readiness_path"]["raw"]["observation_unix_ms"]=json!(1);
    assert_eq!(chronology(&mut r)["complete"],false);
    let groups=secondary_summaries(&r,0,Instant::now()+Duration::from_secs(5)).unwrap();
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
    assert_eq!(chronology(&mut reused)["complete"],false); assert!(reused[1].value["temporal_validation"]["reason"].as_str().unwrap().contains("reused"));
    let identity=json!({"pid":100,"ppid":1,"pgid":100,"sid":1,"uid":501,"start_seconds":100,"start_subseconds":1,"executable":"/SYNTHETIC/studio","cwd":"/SYNTHETIC","state":"running"});
    let ready=json!({"qualified":true,"helper_accounting_complete":true,"exact_identity_unchanged":true,"health":{"http_status":200,"ok":true},"identity_before":identity,"identity_after":identity,"target_pid":100,"target_uid":501,"target_birth_seconds":100,"target_birth_subseconds":1,"helper_accounting":[{"complete":true,"settlement":{"complete":true,"leader_reaped":true,"group_absent":true}}],"studio_listener":{"positive_listener":true,"owner_birth_unchanged":true,"pid":100}});
    assert!(readiness(&ready,&json!([{"role":"studio","restored":true,"root":identity}])).is_ok());let mut changed=identity;changed["start_subseconds"]=json!(2);assert!(readiness(&ready,&json!([{"role":"studio","restored":true,"root":changed}])).is_err());
}
#[test]
fn review_secondary_intervals_exclude_independently_of_primary() {
    let mut r=rows();r[1].value["primary"]=unavailable("missing exact primary");r[1].value["eligible"]=json!(false);r[2].value["evidence"]["receipt_path"]["raw"]["elapsed_ms"]=Value::Null;
    let groups=secondary_summaries(&r,0,Instant::now()+Duration::from_secs(5)).unwrap();
    let host=groups.iter().find(|g|g["selector"]["source"]=="manifest.host_elapsed_ms").unwrap();assert_eq!(host["counts"]["eligible_measured"],3);
    let transaction=groups.iter().find(|g|g["selector"]["source"]=="receipt.elapsed_ms").unwrap();assert_eq!(transaction["counts"]["eligible_measured"],2);assert_eq!(transaction["ordered_individuals"][2]["observation"]["status"],"unavailable");
    assert!(groups.iter().any(|g|g["selector"]["unit"]=="microseconds"));
}
#[test]
fn review_missing_duplicate_primary_preserve_available_image_pairs() {
    let dir=tempfile::tempdir().unwrap();
    let mut r=rows();
    for (index,row) in r[..4].iter_mut().enumerate() {
        let image=dir.path().join(format!("SYNTHETIC-{index}.png"));
        let mut bytes=Vec::new();
        {
            let mut encoder=png::Encoder::new(&mut bytes,1,1);
            encoder.set_color(png::ColorType::Rgb);encoder.set_depth(png::BitDepth::Eight);
            let mut writer=encoder.write_header().unwrap();
            writer.write_image_data(&[index as u8*10,0,0]).unwrap();writer.finish().unwrap();
        }
        fs::write(&image,bytes).unwrap();
        row.image=Some(image);
    }
    let mut timing=selector();timing["measurement"]=json!({"status":"available","value":1.0});r[1].value["primary"]=primary(&json!([]),&selector());r[2].value["primary"]=primary(&json!([timing.clone(),timing]),&selector());for i in [1,2]{r[i].value["eligible"]=json!(false);}
    let p=pair_rows(&r,&mut Reads{remaining:METADATA_LIMIT,deadline:Instant::now()+Duration::from_secs(10)});assert!(p[..6].iter().all(|v|v["metrics"]["status"]=="available"));assert_eq!(summary(&r,0)["complete"],false);
}
#[test]
fn review_markdown_labels_primary_units_methods_and_boundaries() {
    let dir=tempfile::tempdir().unwrap();let mut r=rows();for row in &mut r[4..]{row.value["primary_selector"]["unit"]=json!("milliseconds");}let report=json!({"slots":r.iter().map(|r|r.value.clone()).collect::<Vec<_>>(),"summaries":[summary(&r,0),summary(&r,4)],"secondary_summaries":[],"pairs":[],"errors":[]});markdown(&report,dir.path()).unwrap();let text=fs::read_to_string(dir.path().join("report.md")).unwrap();for label in ["seconds","milliseconds","synthetic monotonic","synthetic synchronized generation"]{assert!(text.contains(label),"missing {label}");}
}
