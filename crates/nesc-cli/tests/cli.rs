use std::fs;
use std::process::Command;

use nesc_rom::{Format, Metadata, Mirroring, Region, Rom};
use tempfile::tempdir;

fn nesc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nesc"))
}

fn uxrom_with_banked_call(known_bank: bool) -> Vec<u8> {
    let mut prg = vec![0xff; 4 * 16 * 1024];
    prg[16 * 1024..16 * 1024 + 3].copy_from_slice(&[0xa9, 0x2a, 0x60]);
    let fixed = 3 * 16 * 1024;
    let program: &[u8] = if known_bank {
        &[
            0xa9, 0x01, // lda #1
            0x8d, 0x00, 0x80, // sta $8000
            0x20, 0x00, 0x80, // jsr $8000
            0x60, // rts
        ]
    } else {
        &[
            0xad, 0x00, 0x00, // lda $0000
            0x8d, 0x00, 0x80, // sta $8000
            0x20, 0x00, 0x80, // jsr $8000
            0x60, // rts
        ]
    };
    prg[fixed..fixed + program.len()].copy_from_slice(program);
    let vectors = prg.len() - 6;
    for offset in [0, 2, 4] {
        prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
    }
    nesc_rom::build(&Rom {
        metadata: Metadata {
            format: Format::Nes2,
            mapper: 2,
            submapper: 0,
            mirroring: Mirroring::Horizontal,
            battery: false,
            region: Region::Ntsc,
            prg_rom_len: prg.len(),
            chr_rom_len: 0,
        },
        trainer: None,
        prg_rom: prg,
        chr_rom: Vec::new(),
    })
    .expect("UxROM")
}

fn uxrom_with_duplicate_fallback_addresses() -> Vec<u8> {
    let mut prg = vec![0xff; 4 * 16 * 1024];
    prg[..3].copy_from_slice(&[
        0x6c, 0x00, 0x02, // jmp ($0200) in bank 0
    ]);
    prg[16 * 1024..16 * 1024 + 3].copy_from_slice(&[
        0x6c, 0x00, 0x02, // jmp ($0200) in bank 1
    ]);
    let fixed = 3 * 16 * 1024;
    let program = [
        0xa9, 0x00, // lda #0
        0x8d, 0x00, 0x80, // sta $8000
        0x20, 0x00, 0x80, // jsr $8000
        0xa9, 0x01, // lda #1
        0x8d, 0x00, 0x80, // sta $8000
        0x20, 0x00, 0x80, // jsr $8000
        0x60, // rts
    ];
    prg[fixed..fixed + program.len()].copy_from_slice(&program);
    let vectors = prg.len() - 6;
    for offset in [0, 2, 4] {
        prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
    }
    nesc_rom::build(&Rom {
        metadata: Metadata {
            format: Format::Nes2,
            mapper: 2,
            submapper: 0,
            mirroring: Mirroring::Horizontal,
            battery: false,
            region: Region::Ntsc,
            prg_rom_len: prg.len(),
            chr_rom_len: 0,
        },
        trainer: None,
        prg_rom: prg,
        chr_rom: Vec::new(),
    })
    .expect("UxROM")
}

fn rom_with_interrupts_and_frame_boundary(mapper: u16) -> Vec<u8> {
    let prg_banks = if mapper == 2 { 4 } else { 1 };
    let mut prg = vec![0xff; prg_banks * 16 * 1024];
    let fixed = (prg_banks - 1) * 16 * 1024;
    prg[fixed..fixed + 14].copy_from_slice(&[
        0xa2, 0x00, // ldx #0
        0x58, // cli
        0xa9, 0x00, // loop: lda #0
        0x8d, 0x14, 0x40, // sta $4014
        0xe8, // inx
        0xe0, 0x3c, // cpx #60
        0xd0, 0xf6, // bne loop
        0x60, // rts
    ]);
    prg[fixed + 0x20..fixed + 0x23].copy_from_slice(&[
        0xe6, 0x10, // inc $10
        0x40, // rti
    ]);
    prg[fixed + 0x30..fixed + 0x33].copy_from_slice(&[
        0xe6, 0x11, // inc $11
        0x40, // rti
    ]);
    let vectors = prg.len() - 6;
    prg[vectors..vectors + 2].copy_from_slice(&0xc020_u16.to_le_bytes());
    prg[vectors + 2..vectors + 4].copy_from_slice(&0xc000_u16.to_le_bytes());
    prg[vectors + 4..vectors + 6].copy_from_slice(&0xc030_u16.to_le_bytes());
    nesc_rom::build(&Rom {
        metadata: Metadata {
            format: Format::Nes2,
            mapper,
            submapper: 0,
            mirroring: Mirroring::Horizontal,
            battery: false,
            region: Region::Ntsc,
            prg_rom_len: prg.len(),
            chr_rom_len: 0,
        },
        trainer: None,
        prg_rom: prg,
        chr_rom: Vec::new(),
    })
    .expect("interrupt verification ROM")
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
        .replace("\nmapper = 0\n", "\nmapper = 3\n");
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

#[test]
fn round_trips_exact_uxrom_container_with_banked_code() {
    let temporary = tempdir().expect("temporary directory");
    let mut prg = vec![0xff; 4 * 16 * 1024];
    prg[16 * 1024..16 * 1024 + 3].copy_from_slice(&[0xa9, 0x2a, 0x60]);
    let fixed = 3 * 16 * 1024;
    prg[fixed..fixed + 9].copy_from_slice(&[
        0xa9, 0x01, // lda #1
        0x8d, 0x00, 0x80, // sta $8000
        0x20, 0x00, 0x80, // jsr $8000
        0x60, // rts
    ]);
    let vectors = prg.len() - 6;
    for offset in [0, 2, 4] {
        prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
    }
    let cartridge = Rom {
        metadata: Metadata {
            format: Format::Nes2,
            mapper: 2,
            submapper: 0,
            mirroring: Mirroring::Horizontal,
            battery: false,
            region: Region::Ntsc,
            prg_rom_len: prg.len(),
            chr_rom_len: 0,
        },
        trainer: None,
        prg_rom: prg,
        chr_rom: Vec::new(),
    };
    let mut original = nesc_rom::build(&cartridge).expect("ROM");
    original.extend_from_slice(&[0xde, 0xad]);
    fs::write(temporary.path().join("banked.nes"), &original).expect("write ROM");

    let disassembled = nesc()
        .current_dir(temporary.path())
        .args([
            "disassemble",
            "banked.nes",
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
    let assembly =
        fs::read_to_string(temporary.path().join("recovered/prg.asm")).expect("assembly");
    assert!(assembly.contains(".nesc_prg_bank 1, $8000"));
    assert!(assembly.contains(".nesc_prg_bank 3, $C000"));
    assert!(assembly.contains("jsr L_prg01_8000"));
    let analysis =
        fs::read_to_string(temporary.path().join("recovered/analysis.txt")).expect("analysis");
    assert!(analysis.contains("mapper-writes: 1"));
    assert!(analysis.contains("resulting-bank=01"));
    assert_eq!(
        fs::read(temporary.path().join("recovered/trailing.bin")).expect("trailing"),
        [0xde, 0xad]
    );
}

#[test]
fn round_trips_compiler_generated_uxrom() {
    let temporary = tempdir().expect("temporary directory");
    let created = nesc()
        .current_dir(temporary.path())
        .args(["new", "compiled-uxrom"])
        .output()
        .expect("run nesc new");
    assert!(created.status.success());
    let project = temporary.path().join("compiled-uxrom");
    let manifest_path = project.join("NesC.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .expect("manifest")
        .replace("\nmapper = 0\n", "\nmapper = 2\n")
        .replace("prg-rom-kib = 32", "prg-rom-kib = 64");
    fs::write(&manifest_path, manifest).expect("Mapper 2 manifest");
    fs::write(
        project.join("src/main.c"),
        r#"#include <nes.h>

NES_BANK(1) NES_NOINLINE u8 banked_color(void) { return 0x2Au8; }

NES_MAIN int main(void) {
    nes_wait_vblank();
    nes_set_background_color(banked_color());
    while (true) { nes_wait_frame(); }
}
"#,
    )
    .expect("source");
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
    let disassembled = nesc()
        .current_dir(&project)
        .args([
            "disassemble",
            "target/compiled-uxrom.nes",
            "--output",
            "target/recovered-uxrom",
            "--round-trip-check",
        ])
        .output()
        .expect("run nesc disassemble");
    assert!(
        disassembled.status.success(),
        "{}",
        String::from_utf8_lossy(&disassembled.stderr)
    );
    let assembly = fs::read_to_string(project.join("target/recovered-uxrom/prg.asm"))
        .expect("recovered assembly");
    assert!(assembly.contains(".nesc_prg_bank 1, $8000"));
    assert!(assembly.contains("jsr L_prg01_8000"));
    let analysis =
        fs::read_to_string(project.join("target/recovered-uxrom/analysis.txt")).expect("analysis");
    assert!(analysis.contains("mapper-write:"));
    assert!(analysis.contains("resulting-bank=01"));
}

#[test]
fn decompiles_mapper_zero_to_a_stable_rust_project() {
    let temporary = tempdir().expect("temporary directory");
    let mut prg = vec![0xff; 16 * 1024];
    prg[..12].copy_from_slice(&[
        0xa5, 0x00, // lda $00
        0xf0, 0x05, // beq $c009
        0xa9, 0x01, // lda #1
        0x4c, 0x0b, 0xc0, // jmp $c00b
        0xa9, 0x02, // lda #2
        0x60, // rts
    ]);
    let vectors = prg.len() - 6;
    for offset in [0, 2, 4] {
        prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
    }
    let rom = nesc_rom::build(&Rom {
        metadata: Metadata {
            format: Format::Nes2,
            mapper: 0,
            submapper: 0,
            mirroring: Mirroring::Horizontal,
            battery: false,
            region: Region::Ntsc,
            prg_rom_len: prg.len(),
            chr_rom_len: 0,
        },
        trainer: None,
        prg_rom: prg,
        chr_rom: Vec::new(),
    })
    .expect("ROM");
    fs::write(temporary.path().join("structured.nes"), rom).expect("write ROM");

    let output = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "structured.nes",
            "--emit",
            "rust",
            "--output",
            "translated",
            "--high-level-only",
            "--verify",
        ])
        .output()
        .expect("run nesc decompile");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(temporary.path().join("translated/Cargo.toml").is_file());
    assert!(temporary.path().join("translated/src/lib.rs").is_file());
    assert!(
        temporary
            .path()
            .join("translated/decompilation.json")
            .is_file()
    );
    assert!(
        temporary
            .path()
            .join("translated/tests/decompilation_verification.rs")
            .is_file()
    );
    assert!(
        temporary
            .path()
            .join("translated/verification.json")
            .is_file()
    );
    let source =
        fs::read_to_string(temporary.path().join("translated/src/lib.rs")).expect("generated Rust");
    assert!(source.contains("if state.status.get"));
    assert!(source.contains("Host-side semantic translation"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("verified"));

    let nesc_output = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "structured.nes",
            "--emit",
            "nesc",
            "--output",
            "translated-nesc",
            "--high-level-only",
        ])
        .output()
        .expect("run NesC decompilation");
    assert!(
        nesc_output.status.success(),
        "{}",
        String::from_utf8_lossy(&nesc_output.stderr)
    );
    assert!(temporary.path().join("translated-nesc/NesC.toml").is_file());
    assert!(
        temporary
            .path()
            .join("translated-nesc/src/main.c")
            .is_file()
    );
    let built_nesc = nesc()
        .current_dir(temporary.path())
        .args(["build", "--manifest-path", "translated-nesc/NesC.toml"])
        .output()
        .expect("build generated NesC");
    assert!(
        built_nesc.status.success(),
        "{}",
        String::from_utf8_lossy(&built_nesc.stderr)
    );

    let verified_nesc = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "structured.nes",
            "--emit",
            "nesc",
            "--verify",
            "--output",
            "verified-nesc",
        ])
        .output()
        .expect("verify generated NesC");
    assert!(
        verified_nesc.status.success(),
        "{}",
        String::from_utf8_lossy(&verified_nesc.stderr)
    );
    let report = fs::read_to_string(temporary.path().join("verified-nesc/verification.json"))
        .expect("NesC verification report");
    assert!(report.contains("\"mode\": \"original-6502-vs-nesc\""));
    assert!(report.contains("\"status\": \"passed\""));
    assert!(report.contains("\"prg_ram_bytes_compared_per_completed_execution\": 4096"));
    assert!(report.contains("\"verification_workspace\": \"0x7000..0x7fff\""));
    let verified_source = fs::read_to_string(temporary.path().join("verified-nesc/src/main.c"))
        .expect("instrumented NesC source");
    assert!(verified_source.contains("verification_store(0x7f0c, 1)"));
    assert!(temporary.path().join("verified-nesc/target").is_dir());

    let repeated = nesc()
        .current_dir(temporary.path())
        .args(["decompile", "structured.nes", "--output", "translated"])
        .output()
        .expect("repeat nesc decompile");
    assert!(!repeated.status.success());
    assert!(String::from_utf8_lossy(&repeated.stderr).contains("error[E4207]"));
}

#[test]
fn decompiles_mapper_two_to_stable_rust_and_hybrid_nesc() {
    let temporary = tempdir().expect("temporary directory");
    fs::write(
        temporary.path().join("banked.nes"),
        uxrom_with_banked_call(true),
    )
    .expect("write UxROM");

    let output = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "banked.nes",
            "--emit",
            "rust",
            "--output",
            "translated",
            "--high-level-only",
            "--verify",
        ])
        .output()
        .expect("decompile UxROM");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let source =
        fs::read_to_string(temporary.path().join("translated/src/lib.rs")).expect("Rust source");
    assert!(source.contains("pub const MAPPER: u16 = 2;"));
    assert!(source.contains("fn_prg0001_8000"));
    let verification = fs::read_to_string(
        temporary
            .path()
            .join("translated/tests/decompilation_verification.rs"),
    )
    .expect("verification source");
    assert!(verification.contains("selected_prg_bank"));
    assert!(verification.contains("SWITCHABLE_PRG_BANKS"));
    let report = fs::read_to_string(temporary.path().join("translated/verification.json"))
        .expect("verification report");
    assert!(report.contains("\"mapper\": 2"));
    assert!(report.contains("\"prg_banks\": 4"));
    assert!(report.contains("\"switchable_bank_contexts\": 3"));

    let nesc_output = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "banked.nes",
            "--emit",
            "nesc",
            "--output",
            "translated-nesc",
            "--high-level-only",
            "--verify",
        ])
        .output()
        .expect("decompile UxROM to NesC");
    assert!(
        nesc_output.status.success(),
        "{}",
        String::from_utf8_lossy(&nesc_output.stderr)
    );
    let manifest = fs::read_to_string(temporary.path().join("translated-nesc/NesC.toml"))
        .expect("NesC manifest");
    assert!(manifest.contains("mapper = 2"));
    assert!(manifest.contains("submapper = 0"));
    assert!(manifest.contains("prg-rom-kib = 64"));
    let source = fs::read_to_string(temporary.path().join("translated-nesc/src/main.c"))
        .expect("NesC source");
    assert!(source.contains("NES_BANK(1) NES_NOINLINE"));
    assert!(source.contains("fn_prg0001_8000"));
    let report = fs::read_to_string(temporary.path().join("translated-nesc/verification.json"))
        .expect("NesC verification report");
    assert!(report.contains("\"mapper\": 2"));
    assert!(report.contains("\"switchable_bank_contexts\": 3"));

    let built = nesc()
        .current_dir(temporary.path())
        .args(["build", "--manifest-path", "translated-nesc/NesC.toml"])
        .output()
        .expect("build generated Mapper 2 NesC");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

#[test]
fn verifies_interrupt_schedules_and_frame_boundaries_for_supported_mappers() {
    let temporary = tempdir().expect("temporary directory");
    for (mapper, expected_contexts) in [(0_u16, 1_usize), (2, 3)] {
        let rom_name = format!("interrupts-mapper-{mapper}.nes");
        let output_name = format!("verified-mapper-{mapper}");
        fs::write(
            temporary.path().join(&rom_name),
            rom_with_interrupts_and_frame_boundary(mapper),
        )
        .expect("write interrupt verification ROM");

        let verified = nesc()
            .current_dir(temporary.path())
            .args([
                "decompile",
                &rom_name,
                "--emit",
                "nesc",
                "--high-level-only",
                "--verify",
                "--output",
                &output_name,
            ])
            .output()
            .expect("verify scheduled interrupts and frame boundary");
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        let report = fs::read_to_string(
            temporary
                .path()
                .join(&output_name)
                .join("verification.json"),
        )
        .expect("verification report");
        assert!(
            report.contains(&format!("\"nmi_schedule_executions\": {expected_contexts}")),
            "{report}"
        );
        assert!(
            report.contains(&format!("\"irq_schedule_executions\": {expected_contexts}")),
            "{report}"
        );
        assert!(
            report.contains(&format!(
                "\"frame_boundary_executions\": {expected_contexts}"
            )),
            "{report}"
        );
        let source = fs::read_to_string(temporary.path().join(&output_name).join("src/main.c"))
            .expect("instrumented source");
        assert!(source.contains("verification_observe(5, 0xfffa, 0)"));
        assert!(source.contains("verification_observe(5, 0xfffe, 0)"));
        assert!(source.contains("verification_store(0x7f0d, 1)"));
    }
}

#[test]
fn keeps_unknown_mapper_two_bank_state_in_rust_fallback() {
    let temporary = tempdir().expect("temporary directory");
    fs::write(
        temporary.path().join("unknown-bank.nes"),
        uxrom_with_banked_call(false),
    )
    .expect("write UxROM");

    let output = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "unknown-bank.nes",
            "--emit",
            "rust",
            "--output",
            "fallback",
        ])
        .output()
        .expect("decompile unknown bank state");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let source =
        fs::read_to_string(temporary.path().join("fallback/src/lib.rs")).expect("Rust source");
    assert!(source.contains("Interpreter fallback: unresolved control flow"));
    assert!(source.contains("runtime::interpret_function"));

    let rejected = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "unknown-bank.nes",
            "--emit",
            "rust",
            "--output",
            "high-level-only",
            "--high-level-only",
        ])
        .output()
        .expect("reject unknown bank state");
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("error[E4206]"));
    assert!(!temporary.path().join("high-level-only").exists());

    let nesc_output = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "unknown-bank.nes",
            "--emit",
            "nesc",
            "--output",
            "nesc-fallback",
        ])
        .output()
        .expect("decompile unknown bank state to hybrid NesC");
    assert!(
        nesc_output.status.success(),
        "{}",
        String::from_utf8_lossy(&nesc_output.stderr)
    );
    let source = fs::read_to_string(temporary.path().join("nesc-fallback/src/main.c"))
        .expect("NesC fallback source");
    assert!(source.contains("static u8 cpu_selected_prg_bank;"));
    assert!(source.contains("static void decompile_fallback(u16 entry)"));
    assert!(source.contains("cpu_selected_prg_bank = (u8)(value % 3)"));

    let built = nesc()
        .current_dir(temporary.path())
        .args(["build", "--manifest-path", "nesc-fallback/NesC.toml"])
        .output()
        .expect("build Mapper 2 fallback NesC");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );

    let nesc_rejected = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "unknown-bank.nes",
            "--emit",
            "nesc",
            "--output",
            "nesc-high-level-only",
            "--high-level-only",
        ])
        .output()
        .expect("reject Mapper 2 fallback in high-level-only mode");
    assert!(!nesc_rejected.status.success());
    assert!(String::from_utf8_lossy(&nesc_rejected.stderr).contains("error[E4211]"));
    assert!(!temporary.path().join("nesc-high-level-only").exists());

    let verification_rejected = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "unknown-bank.nes",
            "--emit",
            "nesc",
            "--output",
            "nesc-unverified",
            "--verify",
        ])
        .output()
        .expect("report unverifiable Mapper 2 fallback");
    assert!(!verification_rejected.status.success());
    let stderr = String::from_utf8_lossy(&verification_rejected.stderr);
    assert!(stderr.contains("error[E4212]"), "{stderr}");
    assert!(stderr.contains("original execution failed"), "{stderr}");
    assert!(
        !temporary
            .path()
            .join("nesc-unverified/verification.json")
            .exists()
    );
}

#[test]
fn bank_qualifies_mapper_two_nesc_fallback_dispatch() {
    let temporary = tempdir().expect("temporary directory");
    fs::write(
        temporary.path().join("duplicate-window.nes"),
        uxrom_with_duplicate_fallback_addresses(),
    )
    .expect("write UxROM");

    let emitted = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "duplicate-window.nes",
            "--emit",
            "nesc",
            "--output",
            "translated",
        ])
        .output()
        .expect("decompile duplicate Mapper 2 window addresses");
    assert!(
        emitted.status.success(),
        "{}",
        String::from_utf8_lossy(&emitted.stderr)
    );
    let source = fs::read_to_string(temporary.path().join("translated/src/main.c"))
        .expect("NesC fallback source");
    assert!(source.contains("(cpu_selected_prg_bank == 0) && (cpu_pc == 0x8000)"));
    assert!(source.contains("(cpu_selected_prg_bank == 1) && (cpu_pc == 0x8000)"));

    let built = nesc()
        .current_dir(temporary.path())
        .args(["build", "--manifest-path", "translated/NesC.toml"])
        .output()
        .expect("build bank-qualified fallback NesC");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

#[test]
fn emits_a_bounded_nesc_dispatcher_for_unresolved_control_flow() {
    let temporary = tempdir().expect("temporary directory");
    let mut prg = vec![0xff; 16 * 1024];
    prg[..3].copy_from_slice(&[
        0x6c, 0x00, 0x02, // jmp ($0200)
    ]);
    let vectors = prg.len() - 6;
    for offset in [0, 2, 4] {
        prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
    }
    let rom = nesc_rom::build(&Rom {
        metadata: Metadata {
            format: Format::Nes2,
            mapper: 0,
            submapper: 0,
            mirroring: Mirroring::Horizontal,
            battery: false,
            region: Region::Ntsc,
            prg_rom_len: prg.len(),
            chr_rom_len: 0,
        },
        trainer: None,
        prg_rom: prg,
        chr_rom: Vec::new(),
    })
    .expect("ROM");
    fs::write(temporary.path().join("indirect.nes"), rom).expect("write ROM");

    let emitted = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "indirect.nes",
            "--emit",
            "nesc",
            "--output",
            "fallback",
        ])
        .output()
        .expect("emit fallback NesC");
    assert!(
        emitted.status.success(),
        "{}",
        String::from_utf8_lossy(&emitted.stderr)
    );
    let source =
        fs::read_to_string(temporary.path().join("fallback/src/main.c")).expect("generated NesC");
    assert!(source.contains("static void decompile_fallback(u16 entry)"));
    assert!(source.contains("cpu_pc = (u16)(cpu_read(0x0200)"));

    let built = nesc()
        .current_dir(temporary.path())
        .args(["build", "--manifest-path", "fallback/NesC.toml"])
        .output()
        .expect("build fallback NesC");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );

    let verified_rust = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "indirect.nes",
            "--emit",
            "rust",
            "--verify",
            "--output",
            "fallback-rust",
        ])
        .output()
        .expect("verify fallback Rust");
    assert!(
        verified_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&verified_rust.stderr)
    );
    assert!(
        temporary
            .path()
            .join("fallback-rust/verification.json")
            .is_file()
    );

    let rejected = nesc()
        .current_dir(temporary.path())
        .args([
            "decompile",
            "indirect.nes",
            "--emit",
            "nesc",
            "--output",
            "high-level-only",
            "--high-level-only",
        ])
        .output()
        .expect("reject fallback");
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("error[E4211]"));
    assert!(!temporary.path().join("high-level-only").exists());
}
