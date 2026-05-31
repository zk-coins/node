//! Guardrail: production Rust source must not embed literal chain
//! URLs.
//!
//! ## Why
//!
//! The bias removed in PR `feat/require-explicit-chain-config` was
//! exactly this: a default URL literal in code (`pub const
//! DEFAULT_ESPLORA_WS_URL: &str = "wss://mutinynet.com/api/v1/ws";`)
//! made the wrong chain reachable from a silent fallback path. The
//! single hardest part of preventing the same class of bug from
//! recurring is mechanical: a literal URL in production code is the
//! one footgun-class a reviewer cannot easily catch on a one-line
//! diff that "moves a default into a sensible place".
//!
//! This test fails the build if any of the eight URL-prefix patterns
//! below appear as a string literal anywhere under `node/src/`
//! except `*_tests.rs` and inside comments (`//`, `///`, `//!`).
//! Doc-comments and inline comments are allowed because they
//! frequently reference public URLs for operator context — none of
//! those strings ever reach a runtime read.
//!
//! ## Scope
//!
//! - Scans every `.rs` file under `node/src/` (recursive).
//! - Skips files ending in `_tests.rs` — tests legitimately
//!   instantiate URLs to exercise builder shapes and mock servers.
//! - Skips comment lines after a textual prefix strip.
//! - Forbids the eight `<scheme>://<host>` prefixes that would
//!   silently bind to one of the public Mutinynet or mempool.space
//!   hosts. Other chain URLs (e.g. self-hosted electrs hostnames
//!   like `electrs-mainnet:3000`) are not on this list because they
//!   are stage-specific config values, not public-internet
//!   defaults.
//!
//! ## When this fails
//!
//! 1. Move the literal into a panic message describing the env var
//!    that should be set instead — see
//!    `lib::build_network_config_from_env`.
//! 2. Or move it behind a `//` comment if it is operator guidance.
//! 3. Or place it in a `*_tests.rs` file if it is a test fixture.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_PREFIXES: &[&str] = &[
    "\"https://mutinynet.com",
    "\"http://mutinynet.com",
    "\"wss://mutinynet.com",
    "\"ws://mutinynet.com",
    "\"https://mempool.space",
    "\"http://mempool.space",
    "\"wss://mempool.space",
    "\"ws://mempool.space",
];

#[test]
fn no_chain_url_literals_in_production_node_source() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = crate_root.join("src");
    assert!(
        src_root.is_dir(),
        "expected `{}` to exist; guardrail must run against the live source tree",
        src_root.display()
    );

    let mut offenders: Vec<String> = Vec::new();
    visit_rs_files(&src_root, &mut |path| {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("source path should be valid UTF-8");
        if name.ends_with("_tests.rs") {
            return;
        }
        let body = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        for (lineno, line) in body.lines().enumerate() {
            // Strip leading whitespace and skip comment lines so
            // doc-comments and inline comments are allowed to
            // reference public URLs for operator context. We do not
            // attempt to skip mid-line comments — a `//` after code
            // on the same line is rare in this crate and false
            // positives there would be the right kind of noise.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for forbidden in FORBIDDEN_PREFIXES {
                if line.contains(forbidden) {
                    offenders.push(format!(
                        "{}:{}: forbidden chain URL literal `{}` in production source",
                        path.display(),
                        lineno + 1,
                        forbidden.trim_start_matches('"')
                    ));
                }
            }
        }
    });

    if !offenders.is_empty() {
        panic!(
            "\n\nGuardrail violation — literal chain URLs in production source.\n\n\
             Chain URLs must be sourced from `ESPLORA_URL` / `ESPLORA_WS_URL` env vars \
             via `lib::build_network_config_from_env`, never hardcoded. Move offending \
             strings into:\n  - a panic / expect message (referring to the env var), or\n  \
             - a comment line, or\n  - a `*_tests.rs` test fixture.\n\nOffending sites:\n{}\n",
            offenders.join("\n"),
        );
    }
}

fn visit_rs_files(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("failed to read dir {}: {}", dir.display(), e));
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            visit_rs_files(&path, visit);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            visit(&path);
        }
    }
}
