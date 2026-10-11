use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(command: &mut Command) {
    let status = command.status().expect("launch owned C build tool");
    assert!(
        status.success(),
        "owned C build command failed: {command:?}"
    );
}

fn main() {
    for source in [
        "adapters/h3_owned_helpers.h",
        "adapters/h3_owned_helpers.c",
        "adapters/h3_cpu_fixture.c",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let target = env::var("TARGET").expect("Cargo target");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let mut objects = Vec::new();
    for stem in ["h3_owned_helpers", "h3_cpu_fixture"] {
        let object = out.join(format!("{stem}.o"));
        run(Command::new("/usr/bin/clang")
            .arg("-target")
            .arg(&target)
            .args([
                "-std=c11",
                "-D_DARWIN_C_SOURCE",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-c",
            ])
            .arg(format!("adapters/{stem}.c"))
            .arg("-o")
            .arg(&object));
        objects.push(object);
    }
    let archive = out.join("libmil_h3_owned.a");
    run(Command::new("/usr/bin/ar")
        .arg("crs")
        .arg(&archive)
        .args(&objects));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=mil_h3_owned");
}
