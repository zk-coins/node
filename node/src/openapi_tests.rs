//! Tests for the bundled OpenAPI spec.
//!
//! Smoke-level: confirm the YAML round-trips through serde_yaml +
//! serde_json, identifies itself as OpenAPI 3.x, and documents the
//! five production-critical endpoints the wallet calls. The full
//! end-to-end check (handler + HTTP layer) lives in
//! `tests/openapi_smoke.rs`.

#![cfg_attr(coverage_nightly, coverage(off))]

use super::*;

#[test]
fn yaml_parses_to_openapi_3x_json() {
    let json = openapi_json();
    let value: serde_json::Value = serde_json::from_str(json).expect("cached blob is JSON");
    let openapi_field = value
        .get("openapi")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        openapi_field.starts_with("3."),
        "bundled spec must be OpenAPI 3.x, got {openapi_field:?}"
    );
    let paths = value
        .get("paths")
        .and_then(|v| v.as_object())
        .expect("paths object");
    assert!(!paths.is_empty(), "paths must be non-empty");
    for required in [
        "/api/info",
        "/api/balance",
        "/api/mint",
        "/api/send",
        "/api/commit",
    ] {
        assert!(
            paths.contains_key(required),
            "spec must document {required}"
        );
    }
}

#[test]
fn docs_html_references_openapi_json_and_swagger_ui() {
    assert!(DOCS_HTML.contains("/openapi.json"));
    assert!(DOCS_HTML.contains("swagger-ui-dist@5"));
}
