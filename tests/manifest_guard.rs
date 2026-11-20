//! Manifest guard test for `mesh-identity`.
//!
//! Enforces the architectural invariant:
//! As a public, standalone crate, `mesh-identity` must never contain
//! any `path` or `git` dependencies. All dependencies must come from crates.io.

use std::fs;

#[test]
fn manifest_has_no_path_or_git_dependencies() {
    let manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let content = fs::read_to_string(manifest_path).expect("Cargo.toml must exist and be readable");

    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        assert!(
            !trimmed.contains("path =") && !trimmed.contains("path="),
            "Line {}: Forbidden `path` dependency found in Cargo.toml: {}",
            line_no + 1,
            line
        );

        assert!(
            !trimmed.contains("git =") && !trimmed.contains("git="),
            "Line {}: Forbidden `git` dependency found in Cargo.toml: {}",
            line_no + 1,
            line
        );
    }
}
