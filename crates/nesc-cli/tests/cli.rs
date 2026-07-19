use std::fs;
use std::process::Command;

use nesc_rom::{Format, Metadata, Mirroring, Region, Rom};
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
        disassembled_stdout.contains("exact ROM round trip verified"),
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

#[test]
fn round_trips_exact_nrom_container_with_mirrored_code() {
    let temporary = tempdir().expect("temporary directory");
    let mut prg = vec![0xff; 16 * 1024];
    prg[..5].copy_from_slice(&[0xd0, 0x02, 0x02, 0xaa, 0x60]);
    let vectors = prg.len() - 6;
    for offset in [0, 2, 4] {
        prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0x8000_u16.to_le_bytes());
    }
    let cartridge = Rom {
        metadata: Metadata {
            format: Format::Ines,
            mapper: 0,
            submapper: 0,
            mirroring: Mirroring::Vertical,
            battery: true,
            region: Region::Ntsc,
            prg_rom_len: prg.len(),
            chr_rom_len: 8 * 1024,
        },
        trainer: Some(vec![0x5a; 512]),
        prg_rom: prg,
        chr_rom: vec![0x3c; 8 * 1024],
    };
    let mut original = nesc_rom::build(&cartridge).expect("ROM");
    original[10] = 0xa5;
    original.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    fs::write(temporary.path().join("mirrored.nes"), &original).expect("write ROM");

    let disassembled = nesc()
        .current_dir(temporary.path())
        .args([
            "disassemble",
            "mirrored.nes",
            "--output",
            "recovered",
            "--round-trip-check",
        ])
        .output()
        .expect("run nesc disassemble");
    assert!(
        disassembled.status.success(),
        "{}",
        String::from_utf8_lossy(&disassembled.stderr)
    );
    assert!(
        String::from_utf8_lossy(&disassembled.stdout).contains("exact ROM round trip verified")
    );
    assert_eq!(
        fs::read(temporary.path().join("recovered/header.bin")).expect("header"),
        &original[..16]
    );
    assert_eq!(
        fs::read(temporary.path().join("recovered/trailing.bin")).expect("trailing"),
        [0xde, 0xad, 0xbe, 0xef]
    );
    assert!(temporary.path().join("recovered/trainer.bin").is_file());
    assert!(temporary.path().join("recovered/chr.bin").is_file());
    let assembly =
        fs::read_to_string(temporary.path().join("recovered/prg.asm")).expect("assembly");
    assert!(assembly.contains("bne *+4"));
    assert!(assembly.contains(".byte $02, $AA"));
}
