//! Guard: the identity store must resolve a real OS keyring backend on every desktop OS.
//!
//! `bitfort-core` depends on `keyring` with an explicit `v1` feature; if someone trims
//! `default-features` or drops a store feature, keyring silently falls back to keyring-core's
//! no-op mock store and the local identity never persists - a regression that unit tests on the
//! developer's own (working) macOS keychain would not catch. This resolves the dependency graph
//! per target, the same mechanism invariant 5 uses by hand for `tauri`, and fails if the expected
//! native backend crate is absent from the tree.

use std::process::Command;

/// (target triple, backend crate that must appear in the resolved dependency tree).
const BACKENDS: &[(&str, &str)] = &[
    ("aarch64-apple-darwin", "apple-native-keyring-store"),
    ("x86_64-apple-darwin", "apple-native-keyring-store"),
    ("x86_64-pc-windows-msvc", "windows-native-keyring-store"),
    (
        "x86_64-unknown-linux-gnu",
        "zbus-secret-service-keyring-store",
    ),
    (
        "x86_64-unknown-linux-musl",
        "zbus-secret-service-keyring-store",
    ),
];

#[test]
fn each_desktop_os_resolves_a_native_keyring_backend() {
    // `cargo tree --target` only resolves the graph, so it works for triples that are not
    // installed and needs no network beyond the (already warm) registry cache.
    let cargo = env!("CARGO");
    for (triple, backend) in BACKENDS {
        let out = Command::new(cargo)
            .args([
                "tree",
                "-p",
                "bitfort-core",
                "--target",
                triple,
                "-e",
                "no-dev",
                "--locked",
            ])
            .output()
            .unwrap_or_else(|e| panic!("failed to run `cargo tree` for {triple}: {e}"));
        assert!(
            out.status.success(),
            "`cargo tree` failed for {triple}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(backend),
            "{triple} does not resolve the `{backend}` keyring backend - the identity store would \
             fall back to keyring-core's no-op mock. Keep the `v1` feature on the `keyring` \
             dependency in crates/core/Cargo.toml.\n\nresolved tree:\n{stdout}"
        );
    }
}
