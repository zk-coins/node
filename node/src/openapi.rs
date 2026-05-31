//! Bundled OpenAPI spec served at runtime.
//!
//! The canonical artifact lives in `zk-coins/app` (see
//! `openapi/README.md`). This module embeds the YAML at compile time
//! via `include_str!`, parses it once into JSON on first use, and
//! caches the resulting string so the per-request hot path is a
//! `Arc<String>` clone.
//!
//! Two HTTP surfaces consume it:
//!
//! - `GET /openapi.json` — `openapi_json_handler`
//! - `GET /docs` — `docs_handler` returns a tiny HTML page that loads
//!   Swagger UI from the unpkg CDN and points its loader at
//!   `/openapi.json` via the (origin-relative) URL the browser is on.
//!
//! Issue #155.

use std::sync::OnceLock;

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;

/// Embed the YAML at compile time so the binary is self-contained;
/// no per-request file I/O, no separate file to ship in the image.
const OPENAPI_YAML: &str = include_str!("../openapi/zkcoins.yaml");

/// Lazily compute the YAML → JSON conversion. Parsed once on the
/// first request, then served verbatim. `OnceLock` avoids a
/// `RwLock` for what is effectively read-only state, and keeps the
/// module's public API free of the lazy_static macro the rest of
/// the crate uses for cross-cutting globals.
pub(crate) fn openapi_json() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE.get_or_init(|| {
        // Parse YAML → serde_json::Value via serde_yaml so any
        // valid OpenAPI document round-trips losslessly. Failure
        // would mean the bundled YAML is broken at build time —
        // the smoke test in `tests/openapi_smoke.rs` catches that
        // before deploy, so panicking here is the right shape.
        let value: serde_json::Value = serde_yaml::from_str(OPENAPI_YAML)
            .expect("bundled openapi/zkcoins.yaml is valid YAML and convertible to JSON");
        serde_json::to_string(&value).expect("serde_json::Value always serialises to a String")
    })
}

/// `GET /openapi.json` — emit the cached JSON view of the bundled
/// spec. `pub` (not `pub(crate)`) so the integration smoke test in
/// `tests/openapi_smoke.rs` can invoke the handler directly.
pub async fn openapi_json_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        openapi_json(),
    )
}

/// `GET /docs` — Swagger UI. Hosted from unpkg so the binary stays
/// small and there is no `swagger-ui-dist` build dependency. The
/// loader's `url` is the relative `/openapi.json` path so the page
/// works behind any reverse proxy without configuration.
pub async fn docs_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DOCS_HTML,
    )
}

const DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>zkCoins API</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>
      body { margin: 0; background: #fafafa; }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
    <script>
      window.addEventListener('load', function () {
        window.ui = SwaggerUIBundle({
          url: '/openapi.json',
          dom_id: '#swagger-ui',
          deepLinking: true,
          presets: [SwaggerUIBundle.presets.apis],
        });
      });
    </script>
  </body>
</html>
"#;

#[cfg(test)]
#[path = "openapi_tests.rs"]
mod tests;
