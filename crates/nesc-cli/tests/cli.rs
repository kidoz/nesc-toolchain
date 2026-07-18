use std::fs;
use std::process::Command;

use tempfile::tempdir;

fn nesc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nesc"))
}

#[test]
fn new_then_check_generated_project() {
    let temporary = tempdir().expect("temporary directory");
    let created = nesc()
        .current_dir(temporary.path())
        .args(["new", "demo"])
        .output()
        .expect("run nesc new");
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(temporary.path().join("demo/NesC.toml").is_file());
    assert!(temporary.path().join("demo/src/main.c").is_file());

    let checked = nesc()
        .current_dir(temporary.path().join("demo"))
        .arg("check")
        .output()
        .expect("run nesc check");
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Checked `demo` v0.1.0"));
}

#[test]
fn check_rejects_unimplemented_mapper() {
    let temporary = tempdir().expect("temporary directory");
    let created = nesc()
        .current_dir(temporary.path())
        .args(["new", "mapper-demo"])
        .output()
        .expect("run nesc new");
    assert!(created.status.success());

    let manifest_path = temporary.path().join("mapper-demo/NesC.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .expect("read manifest")
        .replace("mapper = 0", "mapper = 2");
    fs::write(&manifest_path, manifest).expect("write manifest");

    let checked = nesc()
        .current_dir(temporary.path().join("mapper-demo"))
        .arg("check")
        .output()
        .expect("run nesc check");
    assert!(!checked.status.success());
    assert!(String::from_utf8_lossy(&checked.stderr).contains("error[E0103]"));
}
