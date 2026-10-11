#![cfg(unix)]

use media_inference_lab::{png_image, schema::Artifact};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

// These tests never resolve media tools through PATH. Only the ignored test
// reads MIL_FFMPEG/MIL_FFPROBE, and every spawned command has a finite deadline.
struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            // The unreaped direct child anchors this newly created process group.
            let pid = child.id();
            unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => thread::sleep(Duration::from_millis(10)),
                    Err(error) => {
                        eprintln!("owned test child {pid} reap unavailable: {error}");
                        return;
                    }
                }
            }
            eprintln!("owned test child {pid} not reaped within cleanup bound");
        }
    }
}

fn run(command: &mut Command, root: &Path, timeout: Duration) -> (ExitStatus, String) {
    let stdout = tempfile::tempfile().unwrap();
    let stderr = tempfile::tempfile().unwrap();
    let mut stderr_reader = stderr.try_clone().unwrap();
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("HOME", root)
        .env("TMPDIR", root)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .process_group(0);
    let description = format!("{command:?}");
    let mut child = OwnedChild(Some(command.spawn().unwrap()));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            child.0.take();
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "command timed out: {description}"
        );
        thread::sleep(Duration::from_millis(10));
    };
    use std::io::{Read, Seek, SeekFrom};
    stderr_reader.seek(SeekFrom::Start(0)).unwrap();
    let mut diagnostics = String::new();
    stderr_reader
        .take(64 * 1024)
        .read_to_string(&mut diagnostics)
        .unwrap();
    (status, diagnostics)
}

fn expect_exit(command: &mut Command, root: &Path, code: i32) {
    // The inspector's own 20-second deadline gets ample time for owned cleanup.
    let (status, diagnostics) = run(command, root, Duration::from_secs(45));
    assert_eq!(status.code(), Some(code), "{diagnostics}");
}

fn workload() -> Value {
    json!({
        "schema_version": 1,
        "id": "cpu-codec-validation-not-inference",
        "model": {"name": "no-model-executed", "revision": null, "sha256": null},
        "settings": {
            "modality": "video",
            "generation": {
                "prompt": "Synthetic codec fixture, not generated model evidence",
                "negative_prompt": null,
                "seed": 1,
                "resolution": {"width": 32, "height": 16},
                "steps": 1,
                "scheduler": "linear",
                "guidance": 1.0,
                "precision": "float32",
                "compute_precision": null,
                "quantization": {"kind": "none"},
                "batch_size": 1,
                "references": [],
                "strength": null,
                "optimizations": {
                    "use_kv_cache": null,
                    "step_cache_ratio": null,
                    "step_cache_threshold": null
                }
            },
            "frames": 56,
            "layers": 1,
            "playback_fps": 24.0,
            "render_resolution": null,
            "reuse": {"kind": "disabled"},
            "audio": {"kind": "generate", "sample_rate_hz": 32000, "channels": 2}
        },
        "process_policy": "fresh_process",
        "cache_policy": "unspecified"
    })
}

fn inspection(
    root: &Path,
    name: &str,
    request: &Value,
    video: &Path,
    ffmpeg: &Path,
    ffprobe: &Path,
) -> Command {
    let request_path = root.join(format!("{name}-workload.json"));
    fs::write(&request_path, serde_json::to_vec(request).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_mil"));
    command
        .arg("inspect-video")
        .arg("--workload")
        .arg(request_path)
        .arg("--video")
        .arg(video)
        .arg("--ffmpeg")
        .arg(ffmpeg)
        .arg("--ffprobe")
        .arg(ffprobe)
        .arg("--output-dir")
        .arg(root.join(name))
        .args(["--inspection-seconds", "20"]);
    command
}

fn report(bundle: &Path, valid: bool) -> Value {
    let report: Value =
        serde_json::from_slice(&fs::read(bundle.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["kind"], "offline_h3_video_inspection");
    assert_eq!(report["valid"], valid);
    assert_eq!(report["errors"].as_array().unwrap().is_empty(), valid);
    report
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn verify_inventory(bundle: &Path, report: &Value) -> Vec<Artifact> {
    let artifacts: Vec<Artifact> = serde_json::from_value(report["artifacts"].clone()).unwrap();
    let mut paths = BTreeSet::new();
    for artifact in &artifacts {
        let path = Path::new(&artifact.path);
        assert!(
            path.components()
                .all(|part| matches!(part, Component::Normal(_)))
        );
        assert!(paths.insert(&artifact.path), "duplicate artifact path");
        let path = bundle.join(path);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(artifact.bytes, bytes.len() as u64);
        assert_eq!(artifact.sha256, digest(&bytes));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        fs::metadata(bundle).unwrap().permissions().mode() & 0o777,
        0o700
    );
    artifacts
}

#[test]
fn invalid_requests_are_reported_before_source_or_media_tool_access() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("input.mp4");
    fs::write(&source, b"request validation must precede media parsing").unwrap();
    let mut cases = Vec::new();
    for frames in [55, 57, 363] {
        let mut request = workload();
        request["settings"]["frames"] = json!(frames);
        cases.push((format!("frames-{frames}"), request));
    }
    for (name, pointer, value) in [
        ("batch", "/settings/generation/batch_size", json!(2)),
        ("fps-bound", "/settings/playback_fps", json!(121.0)),
        (
            "disabled-audio",
            "/settings/audio",
            json!({"kind": "disabled"}),
        ),
        (
            "reference-audio",
            "/settings/audio",
            json!({"kind": "reference", "input": {
                "path": "reference.wav", "sha256": "0".repeat(64),
                "bytes": 1, "role": "audio", "strength": null
            }}),
        ),
    ] {
        let mut request = workload();
        *request.pointer_mut(pointer).unwrap() = value;
        cases.push((name.into(), request));
    }
    let mut image = workload();
    image["settings"] = json!({
        "modality": "image", "generation": image["settings"]["generation"].clone()
    });
    cases.push(("image".into(), image));
    for (name, request) in cases {
        let mut command = inspection(
            root.path(),
            &name,
            &request,
            &source,
            &root.path().join("absent-ffmpeg"),
            &root.path().join("absent-ffprobe"),
        );
        expect_exit(&mut command, root.path(), 1);
        let bundle = root.path().join(&name);
        let report = report(&bundle, false);
        assert!(report["source"].is_null(), "{name}");
        assert!(!bundle.join("source.mp4").exists(), "{name}");
        verify_inventory(&bundle, &report);
    }
}

#[test]
fn existing_output_is_never_overwritten_even_without_media_tools() {
    let root = TempDir::new().unwrap();
    let bundle = root.path().join("existing");
    fs::create_dir(&bundle).unwrap();
    let sentinel = b"preexisting user report, not owned by this command";
    fs::write(bundle.join("report.json"), sentinel).unwrap();
    let mut command = inspection(
        root.path(),
        "existing",
        &workload(),
        &root.path().join("absent.mp4"),
        &root.path().join("absent-ffmpeg"),
        &root.path().join("absent-ffprobe"),
    );
    expect_exit(&mut command, root.path(), 2);
    assert_eq!(fs::read(bundle.join("report.json")).unwrap(), sentinel);
    let entries: BTreeSet<_> = fs::read_dir(&bundle)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, BTreeSet::from(["report.json".into()]));
}

fn tool(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")));
    assert!(path.is_absolute(), "{name} must be an absolute binary path");
    assert!(path.is_file(), "{name} must identify an existing binary");
    path
}

fn ffmpeg_command(ffmpeg: &Path) -> Command {
    let mut command = Command::new(ffmpeg);
    command.args([
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostats",
        "-n",
        "-threads",
        "1",
        "-filter_threads",
        "1",
        "-filter_complex_threads",
        "1",
    ]);
    command
}

fn source_fixture(root: &Path, ffmpeg: &Path) -> PathBuf {
    let path = root.join("fixture.mp4");
    let mut command = ffmpeg_command(ffmpeg);
    command
        .args([
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=32x16:rate=24:duration=2.333333333",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=32000:duration=2.333333333",
            "-map",
            "0:v:0",
            "-map",
            "1:a:0",
            "-frames:v",
            "56",
            "-c:v",
            "mpeg4",
            "-q:v",
            "2",
            "-pix_fmt",
            "yuv420p",
            "-threads",
            "1",
            "-c:a",
            "aac",
            "-ac",
            "2",
            "-b:a",
            "64k",
            "-t",
            "2.333333333",
            "-movflags",
            "+faststart",
        ])
        .arg(&path);
    expect_exit(&mut command, root, 0);
    path
}

fn decode_reference(root: &Path, ffmpeg: &Path, source: &Path, audio: bool) -> Vec<u8> {
    let path = root.join(if audio {
        "reference.f32le"
    } else {
        "reference.rgb"
    });
    let mut command = ffmpeg_command(ffmpeg);
    command
        .args(["-protocol_whitelist", "file", "-f", "mov", "-i"])
        .arg(source);
    if audio {
        command.args(["-map", "0:a:0", "-vn", "-c:a", "pcm_f32le", "-f", "f32le"]);
    } else {
        command.args([
            "-map",
            "0:v:0",
            "-an",
            "-c:v",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-threads",
            "1",
            "-fps_mode",
            "passthrough",
            "-f",
            "rawvideo",
        ]);
    }
    command.arg(&path);
    expect_exit(&mut command, root, 0);
    fs::read(path).unwrap()
}

#[test]
#[ignore = "CPU-only real codecs: set absolute MIL_FFMPEG and MIL_FFPROBE paths"]
fn real_mp4_full_decode_evidence_and_invalid_media_cases() {
    let ffmpeg = tool("MIL_FFMPEG");
    let ffprobe = tool("MIL_FFPROBE");
    let root = TempDir::new().unwrap();
    let root = root.path();
    let source = source_fixture(root, &ffmpeg);
    let rgb = decode_reference(root, &ffmpeg, &source, false);
    let pcm = decode_reference(root, &ffmpeg, &source, true);
    const FRAME_BYTES: usize = 32 * 16 * 3;
    assert_eq!(rgb.len(), 56 * FRAME_BYTES);
    assert_eq!(pcm.len() % (2 * 4), 0);
    let samples = pcm.len() / (2 * 4);
    let audio_seconds = samples as f64 / 32000.0;
    let ratio = audio_seconds / (56.0 / 24.0);
    assert!((0.75..=1.25).contains(&ratio));

    let mut command = inspection(root, "valid", &workload(), &source, &ffmpeg, &ffprobe);
    expect_exit(&mut command, root, 0);
    let bundle = root.join("valid");
    let observed = report(&bundle, true);
    let artifacts = verify_inventory(&bundle, &observed);
    assert_eq!(observed["video"]["frames"], 56);
    assert_eq!(observed["video"]["width"], 32);
    assert_eq!(observed["video"]["height"], 16);
    assert_eq!(observed["video"]["playback_fps"], 24.0);
    assert_eq!(observed["video"]["decoded_rgb_bytes"], rgb.len() as u64);
    assert_eq!(observed["video"]["decoded_rgb_sha256"], digest(&rgb));
    assert_eq!(observed["audio"]["validation"], "passed");
    assert_eq!(observed["audio"]["sample_rate_hz"], 32000);
    assert_eq!(observed["audio"]["channels"], 2);
    assert_eq!(observed["audio"]["sample_frames"], samples as u64);
    assert_eq!(observed["audio"]["decoded_pcm_bytes"], pcm.len() as u64);
    assert_eq!(observed["audio"]["decoded_pcm_sha256"], digest(&pcm));
    assert!((observed["audio"]["duration_seconds"].as_f64().unwrap() - audio_seconds).abs() < 1e-9);
    assert!((observed["audio"]["video_duration_ratio"].as_f64().unwrap() - ratio).abs() < 1e-9);
    let original = fs::read(&source).unwrap();
    assert_eq!(observed["source"]["path"], "source.mp4");
    assert_eq!(observed["source"]["sha256"], digest(&original));
    assert_eq!(observed["source"]["bytes"], original.len() as u64);
    assert_eq!(fs::read(bundle.join("source.mp4")).unwrap(), original);

    let pngs: Vec<_> = artifacts
        .iter()
        .filter(|a| a.path.ends_with(".png"))
        .collect();
    assert_eq!(pngs.len(), 3, "first frame must also serve as poster");
    let mut actual_samples: Vec<_> = pngs
        .iter()
        .map(|artifact| {
            let decoded = png_image::decode(&bundle.join(&artifact.path)).unwrap();
            assert_eq!(decoded.identity().width, 32);
            assert_eq!(decoded.identity().height, 16);
            decoded.samples().to_vec()
        })
        .collect();
    let mut expected_samples: Vec<_> = [0, 28, 55]
        .into_iter()
        .map(|index| rgb[index * FRAME_BYTES..(index + 1) * FRAME_BYTES].to_vec())
        .collect();
    actual_samples.sort();
    expected_samples.sort();
    assert_eq!(actual_samples, expected_samples);
    let poster = observed["video"]["poster"].as_str().unwrap();
    assert!(pngs.iter().any(|artifact| artifact.path == poster));
    assert_eq!(
        png_image::decode(&bundle.join(poster)).unwrap().samples(),
        &rgb[..FRAME_BYTES]
    );

    let inspection_seconds = observed["timings"]["inspection_wall_seconds"]
        .as_f64()
        .unwrap();
    assert!(inspection_seconds.is_finite() && inspection_seconds >= 0.0);
    for metric in [
        "native_total_host_seconds",
        "text_encoding",
        "model_load",
        "denoising",
        "audio_vae",
        "video_vae",
        "mux_encode",
        "seconds_per_generated_clip",
        "generated_frames_per_second",
        "generated_media_seconds_per_second",
    ] {
        assert_eq!(
            observed["timings"][metric]["status"], "unavailable",
            "{metric}"
        );
        assert!(
            observed["timings"][metric].get("value").is_none(),
            "{metric}"
        );
    }

    let tools = observed["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    for (name, path) in [("ffmpeg", &ffmpeg), ("ffprobe", &ffprobe)] {
        let recorded = tools.iter().find(|tool| tool["name"] == name).unwrap();
        assert_eq!(recorded["sha256"], digest(&fs::read(path).unwrap()));
        assert_eq!(
            fs::canonicalize(recorded["path"].as_str().unwrap()).unwrap(),
            fs::canonicalize(path).unwrap()
        );
    }

    // A declared render size, not a draft's internal generation size, is the
    // consumer-visible size that the encoded stream must actually contain.
    let mut rendered = workload();
    rendered["settings"]["generation"]["resolution"] = json!({"width": 16, "height": 16});
    rendered["settings"]["render_resolution"] = json!({"width": 32, "height": 16});
    let mut command = inspection(root, "rendered", &rendered, &source, &ffmpeg, &ffprobe);
    expect_exit(&mut command, root, 0);
    let rendered_report = report(&root.join("rendered"), true);
    assert_eq!(rendered_report["video"]["decoded_rgb_sha256"], digest(&rgb));

    // Display rotation must not silently reinterpret the raw decoded raster.
    let rotated = root.join("rotated.mp4");
    let mut command = ffmpeg_command(&ffmpeg);
    command
        .arg("-i")
        .arg(&source)
        .args(["-map", "0", "-c", "copy", "-metadata:s:v:0", "rotate=90"])
        .arg(&rotated);
    expect_exit(&mut command, root, 0);
    let mut command = inspection(root, "rotation", &workload(), &rotated, &ffmpeg, &ffprobe);
    expect_exit(&mut command, root, 0);
    let rotation = report(&root.join("rotation"), true);
    assert_eq!(rotation["video"]["width"], 32);
    assert_eq!(rotation["video"]["height"], 16);
    assert_eq!(rotation["video"]["decoded_rgb_sha256"], digest(&rgb));

    for (name, pointer, value) in [
        ("wrong-count", "/settings/frames", json!(73)),
        (
            "wrong-size",
            "/settings/generation/resolution/width",
            json!(64),
        ),
        ("wrong-rate", "/settings/audio/sample_rate_hz", json!(44100)),
        ("wrong-channels", "/settings/audio/channels", json!(1)),
        ("wrong-fps", "/settings/playback_fps", json!(30.0)),
    ] {
        let mut request = workload();
        *request.pointer_mut(pointer).unwrap() = value;
        let mut command = inspection(root, name, &request, &source, &ffmpeg, &ffprobe);
        expect_exit(&mut command, root, 1);
        let observed = report(&root.join(name), false);
        verify_inventory(&root.join(name), &observed);
        assert_eq!(observed["source"]["sha256"], digest(&original), "{name}");
    }

    let silent = root.join("silent.mp4");
    let mut command = ffmpeg_command(&ffmpeg);
    command
        .args(["-protocol_whitelist", "file", "-f", "mov", "-i"])
        .arg(&source)
        .args(["-map", "0:v:0", "-c:v", "copy", "-an"])
        .arg(&silent);
    expect_exit(&mut command, root, 0);
    let truncated = root.join("truncated.mp4");
    fs::write(&truncated, &original[..original.len() * 3 / 4]).unwrap();
    let malformed = root.join("malformed.mp4");
    fs::write(&malformed, b"not an ISO base media container\0\xff").unwrap();
    for (name, input) in [
        ("no-audio", silent),
        ("truncated", truncated),
        ("malformed", malformed),
    ] {
        let mut command = inspection(root, name, &workload(), &input, &ffmpeg, &ffprobe);
        expect_exit(&mut command, root, 1);
        let observed = report(&root.join(name), false);
        verify_inventory(&root.join(name), &observed);
        assert_eq!(
            observed["source"]["sha256"],
            digest(&fs::read(&input).unwrap()),
            "{name}"
        );
        if name == "malformed" {
            assert!(observed["video"].is_null());
            assert!(observed["audio"].is_null());
        }
    }
}
