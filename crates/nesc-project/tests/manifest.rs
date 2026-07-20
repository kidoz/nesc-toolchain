use std::fs;

use nesc_project::{Project, create_project, load_manifest};
use tempfile::tempdir;

fn generated_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempdir().expect("temporary directory");
    let project = temporary.path().join("demo");
    create_project("demo", &project).expect("project generation");
    (temporary, project)
}

#[test]
fn rejects_unknown_manifest_fields_with_source_diagnostic() {
    let (_temporary, project) = generated_project();
    let manifest_path = project.join("NesC.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("read manifest");
    fs::write(&manifest_path, format!("{manifest}\nunknown = true\n")).expect("write manifest");

    let diagnostics = load_manifest(&manifest_path).expect_err("unknown field rejected");
    assert_eq!(diagnostics[0].code(), "E0002");
    assert!(diagnostics[0].render().contains("unknown field"));
}

#[test]
fn rejects_overlapping_zero_page_ranges() {
    let (_temporary, project) = generated_project();
    let manifest_path = project.join("NesC.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .expect("read manifest")
        .replace("0xF0..0xFF", "0xEF..0xFF");
    fs::write(&manifest_path, manifest).expect("write manifest");

    let diagnostics = load_manifest(&manifest_path).expect_err("overlap rejected");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code() == "E0105")
    );
}

#[test]
fn rejects_parent_traversal_in_entry_path() {
    let (_temporary, project) = generated_project();
    let manifest_path = project.join("NesC.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .expect("read manifest")
        .replace("src/main.c", "../main.c");
    fs::write(&manifest_path, manifest).expect("write manifest");

    let diagnostics = load_manifest(&manifest_path).expect_err("traversal rejected");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code() == "E0102")
    );
}

#[test]
fn project_load_reports_missing_entry_file() {
    let (_temporary, project) = generated_project();
    fs::remove_file(project.join("src/main.c")).expect("remove entry fixture");

    let diagnostics = Project::load(project.join("NesC.toml")).expect_err("missing entry rejected");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code() == "E0111")
    );
}

#[test]
fn rejects_unsafe_and_missing_assembly_sources() {
    let (_temporary, project) = generated_project();
    let manifest_path = project.join("NesC.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .expect("read manifest")
        .replace("assembly = []", "assembly = [\"../outside.s\"]");
    fs::write(&manifest_path, manifest).expect("write manifest");
    let diagnostics = Project::load(&manifest_path).expect_err("unsafe assembly path rejected");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code() == "E0107")
    );

    let manifest = fs::read_to_string(&manifest_path)
        .expect("read manifest")
        .replace("../outside.s", "src/missing.s");
    fs::write(&manifest_path, manifest).expect("write manifest");
    let diagnostics = Project::load(&manifest_path).expect_err("missing assembly source rejected");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code() == "E0112")
    );
}
