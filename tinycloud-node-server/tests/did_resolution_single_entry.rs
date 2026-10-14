use std::path::{Path, PathBuf};
fn source_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            source_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}
#[test]
fn ucan_resolution_has_one_production_entry_point() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let helper = root.join("tinycloud-core/src/did_resolution.rs");
    let mut files = Vec::new();
    for dir in ["tinycloud-core/src", "tinycloud-node-server/src"] {
        source_files(&root.join(dir), &mut files);
    }
    let mut calls = 0;
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        let production = source.split("#[cfg(test)]").next().unwrap();
        if path == helper {
            continue;
        }
        assert!(
            !production.contains("AnyDidMethod") && !production.contains(".verify_signature("),
            "UCAN resolver bypass in {}",
            path.display()
        );
        calls += production.matches("verify_ucan_signature(").count()
            + production
                .matches("verify_ucan_revocation_signature(")
                .count();
    }
    assert!(
        calls >= 5,
        "expected at least five production helper calls, found {calls}"
    );
}
