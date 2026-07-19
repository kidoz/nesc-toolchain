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

#[test]
fn check_reports_source_diagnostics() {
    let temporary = tempdir().expect("temporary directory");
    let created = nesc()
        .current_dir(temporary.path())
        .args(["new", "invalid-source"])
        .output()
        .expect("run nesc new");
    assert!(created.status.success());

    fs::write(
        temporary.path().join("invalid-source/src/main.c"),
        "#include <nes.h>\nNES_MAIN int main(void) { u8 color = 300; return 0; }\n",
    )
    .expect("write source");
    let checked = nesc()
        .current_dir(temporary.path().join("invalid-source"))
        .arg("check")
        .output()
        .expect("run nesc check");

    assert!(!checked.status.success());
    let stderr = String::from_utf8_lossy(&checked.stderr);
    assert!(stderr.contains("error[E1204]"), "{stderr}");
    assert!(stderr.contains("src/main.c:2:"), "{stderr}");
}

#[test]
fn build_and_inspect_generated_project() {
    let temporary = tempdir().expect("temporary directory");
    let created = nesc()
        .current_dir(temporary.path())
        .args(["new", "rom-demo"])
        .output()
        .expect("run nesc new");
    assert!(created.status.success());
    let project = temporary.path().join("rom-demo");

    let built = nesc()
        .current_dir(&project)
        .arg("build")
        .output()
        .expect("run nesc build");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    for extension in [
        "nes",
        "asm",
        "map",
        "sym",
        "source-map",
        "zero-page",
        "stack",
    ] {
        assert!(
            project
                .join(format!("target/rom-demo.{extension}"))
                .is_file()
        );
    }

    let inspected = nesc()
        .current_dir(&project)
        .args(["inspect", "target/rom-demo.nes"])
        .output()
        .expect("run nesc inspect");
    assert!(inspected.status.success());
    let stdout = String::from_utf8_lossy(&inspected.stdout);
    assert!(stdout.contains("Mapper 0"), "{stdout}");
    assert!(stdout.contains("32 KiB PRG"), "{stdout}");

    let disassembly_dir = project.join("target/recovered");
    let disassembled = nesc()
        .current_dir(&project)
        .args([
            "disasm",
            "target/rom-demo.nes",
            "--output",
            disassembly_dir.to_str().expect("UTF-8 test path"),
            "--round-trip-check",
        ])
        .output()
        .expect("run nesc disasm");
    assert!(
        disassembled.status.success(),
        "{}",
        String::from_utf8_lossy(&disassembled.stderr)
    );
    let disassembled_stdout = String::from_utf8_lossy(&disassembled.stdout);
    assert!(
        disassembled_stdout.contains("PRG recovery verified"),
        "{disassembled_stdout}"
    );
    for artifact in [
        "analysis.txt",
        "cartridge.toml",
        "chr.bin",
        "header.bin",
        "prg.asm",
    ] {
        assert!(disassembly_dir.join(artifact).is_file(), "{artifact}");
    }
    let recovered_assembly =
        fs::read_to_string(disassembly_dir.join("prg.asm")).expect("read recovered assembly");
    assert!(recovered_assembly.contains("reset_prg"));

    let repeated = nesc()
        .current_dir(&project)
        .args([
            "disassemble",
            "target/rom-demo.nes",
            "--output",
            disassembly_dir.to_str().expect("UTF-8 test path"),
        ])
        .output()
        .expect("repeat nesc disassemble");
    assert!(!repeated.status.success());
    assert!(String::from_utf8_lossy(&repeated.stderr).contains("error[E4103]"));
}

#[test]
fn disassemble_rejects_a_malformed_rom() {
    let temporary = tempdir().expect("temporary directory");
    let rom = temporary.path().join("invalid.nes");
    fs::write(&rom, b"not a ROM").expect("write invalid ROM");
    let output = nesc()
        .current_dir(temporary.path())
        .args(["disassemble", "invalid.nes"])
        .output()
        .expect("run nesc disassemble");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("error[E4101]"));
}
