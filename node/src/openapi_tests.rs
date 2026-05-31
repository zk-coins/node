//! Unit-level coverage for the async HTTP handlers and the Swagger UI
//! asset path in [`super`].
//!
//! The integration-level smoke test in `node/tests/openapi_smoke.rs`
//! exercises the in-memory spec (`openapi_json()`) and the static HTML
//! string (`DOCS_HTML`) — both synchronous paths. The async handlers
//! (`openapi_json_handler`, `docs_handler`, `swagger_asset_handler`)
//! and the cached `swagger_ui_config()` singleton are not entered by
//! that suite, so the lines that build the `(StatusCode, headers,
//! body)` tuples and dispatch into `utoipa_swagger_ui::serve` go
//! uncovered.
//!
//! These tests call each handler directly, convert the
//! `impl IntoResponse` result into a concrete `axum::response::Response`
//! and inspect status, headers, and body. No HTTP round-trip is
//! involved — the handlers contain no extractor logic beyond the
//! `Path<String>` parameter on `swagger_asset_handler`, so a direct
//! call is sufficient to drive every branch.

use super::*;
use axum::body::to_bytes;
use axum::response::IntoResponse;
use serde_json::Value;

/// The cached JSON body must come back as `200 OK` with an
/// `application/json` content type, and the bytes must parse as an
/// OpenAPI 3.x document. This drives the tuple-construction lines in
/// `openapi_json_handler` and re-enters the `cached_openapi_json`
/// `OnceLock` path that the smoke test also relies on.
#[tokio::test]
async fn openapi_json_handler_returns_cached_json_with_application_json_content_type() {
    let response = openapi_json_handler().await.into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("openapi_json_handler must set a content-type header")
        .to_str()
        .expect("content-type must be ASCII");
    assert_eq!(content_type, "application/json");

    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must collect");
    let parsed: Value = serde_json::from_slice(&bytes).expect("response body must be valid JSON");
    let version = parsed["openapi"]
        .as_str()
        .expect("`openapi` field must be a string");
    assert!(
        version.starts_with("3."),
        "expected OpenAPI 3.x, got `{version}`"
    );
}

/// The static Swagger UI HTML must come back as `200 OK` with the
/// `text/html; charset=utf-8` content type and the exact byte-for-byte
/// content of `DOCS_HTML`. Drives the tuple-construction lines in
/// `docs_handler`.
#[tokio::test]
async fn docs_handler_returns_html_with_correct_content_type() {
    let response = docs_handler().await.into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("docs_handler must set a content-type header")
        .to_str()
        .expect("content-type must be ASCII");
    assert_eq!(content_type, "text/html; charset=utf-8");

    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must collect");
    let body = std::str::from_utf8(&bytes).expect("body must be UTF-8");
    assert_eq!(body, DOCS_HTML);
}

/// The bundled CSS asset must be served as `200 OK` with a non-empty
/// body and a content-type header set by `utoipa_swagger_ui::serve`.
/// Drives the `Ok(Some(asset))` arm of `swagger_asset_handler`.
#[tokio::test]
async fn swagger_asset_handler_serves_bundled_css() {
    let response = swagger_asset_handler(axum::extract::Path("swagger-ui.css".to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);

    assert!(
        response.headers().get(header::CONTENT_TYPE).is_some(),
        "bundled CSS asset must carry a content-type header"
    );

    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must collect");
    assert!(
        !bytes.is_empty(),
        "bundled swagger-ui.css must have non-empty body"
    );
}

/// The bundled Swagger UI JS bundle must be served as `200 OK` with a
/// non-empty body. Same code path as the CSS test but covers a
/// different asset key so a regression that only affects one MIME
/// family still surfaces.
#[tokio::test]
async fn swagger_asset_handler_serves_bundled_js_bundle() {
    let response =
        swagger_asset_handler(axum::extract::Path("swagger-ui-bundle.js".to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);

    assert!(
        response.headers().get(header::CONTENT_TYPE).is_some(),
        "bundled JS bundle must carry a content-type header"
    );

    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must collect");
    assert!(
        !bytes.is_empty(),
        "bundled swagger-ui-bundle.js must have non-empty body"
    );
}

/// Unknown asset names must produce a `404 Not Found`, not a `500`.
/// Drives the `Ok(None)` arm of `swagger_asset_handler`.
#[tokio::test]
async fn swagger_asset_handler_returns_404_for_unknown_file() {
    let response =
        swagger_asset_handler(axum::extract::Path("does-not-exist.txt".to_string())).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// `swagger_ui_config` caches its `Arc<Config<'static>>` in a
/// process-wide `OnceLock` so subsequent calls share the same
/// allocation rather than re-building the config on every asset
/// request. Drives the `get_or_init` + `.clone()` lines.
#[test]
fn swagger_ui_config_caches_arc_singleton() {
    let first = swagger_ui_config();
    let second = swagger_ui_config();
    assert!(
        Arc::ptr_eq(&first, &second),
        "swagger_ui_config must hand out the same Arc on every call"
    );
}
