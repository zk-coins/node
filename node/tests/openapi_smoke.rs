//! End-to-end smoke test for the bundled OpenAPI spec.
//!
//! Invokes `openapi_json_handler` (the same function the live route
//! `GET /openapi.json` registers) and verifies the returned body
//! parses as an OpenAPI 3.x JSON document with a non-empty `paths`
//! object. Catches "swapped a working YAML for a broken one" before
//! the binary ships.
//!
//! Issue zk-coins/node#155.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use http_body_util::BodyExt;

#[tokio::test]
async fn openapi_endpoint_serves_openapi_3x_json() {
    // Invoke the handler directly — the route registration is just
    // `.route("/openapi.json", get(openapi_json_handler))`, so a
    // unit-level call exercises the full body the live route emits.
    let response = node::openapi::openapi_json_handler().await.into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(content_type, "application/json");

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).expect("body is JSON");

    let openapi_field = parsed
        .get("openapi")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        openapi_field.starts_with("3."),
        "expected OpenAPI 3.x, got {openapi_field:?}"
    );

    let paths = parsed
        .get("paths")
        .and_then(|v| v.as_object())
        .expect("paths object");
    assert!(!paths.is_empty(), "paths must be non-empty");

    // Endpoints called by the wallet client must all appear.
    for required in [
        "/api/info",
        "/api/balance",
        "/api/mint",
        "/api/send",
        "/api/commit",
        "/api/username/resolve/{username}",
    ] {
        assert!(
            paths.contains_key(required),
            "spec must document {required}"
        );
    }
}
