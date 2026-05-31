//! Structural smoke test for the generated OpenAPI 3.x document.
//!
//! Unlike `api_remote`, this suite does not touch the network and does
//! not need a running node. It calls [`node::openapi::openapi_json`]
//! directly — the same code path that backs `GET /openapi.json` — and
//! asserts the shape of the resulting document.
//!
//! The point is to catch drift between the handler annotations and the
//! wire contract before the build ships:
//!
//!   - every always-on `/api/*` route is listed under `paths`
//!   - the request and response envelopes the wallet app depends on
//!     (`SendCoinResponse`, `LnurlErrorResponse`) appear under
//!     `components.schemas`
//!   - `InfoResponse` carries the `username_domain` field — its
//!     absence in an earlier Zod-driven mirror is what motivated the
//!     switch to annotation-driven generation in the first place
//!   - the static Swagger UI page served at `/docs` pins the exact
//!     `SWAGGER_UI_VERSION` constant, so a future bump to the version
//!     constant cannot diverge from the `<script src="…">` tag
//!
//! Read by: `cargo test -p node --test openapi_smoke` (CI, both the
//! slim PR job and the full release job).

use serde_json::Value;

/// Parse the cached spec once per test process. Each test calls this
/// at its top so a parse failure surfaces as the failing test's panic
/// instead of a shared lazy-static initialisation error.
fn parse_spec() -> Value {
    let json = node::openapi::openapi_json();
    serde_json::from_str::<Value>(json)
        .expect("openapi_json() must return a serialisable OpenAPI document")
}

#[test]
fn spec_is_valid_openapi_3_x() {
    let v = parse_spec();
    let version = v["openapi"]
        .as_str()
        .expect("`openapi` field must be a string");
    assert!(
        version.starts_with("3."),
        "expected OpenAPI 3.x, got `{version}`"
    );
}

#[test]
fn spec_paths_is_non_empty() {
    let v = parse_spec();
    let paths = v["paths"]
        .as_object()
        .expect("`paths` must be a JSON object");
    assert!(
        !paths.is_empty(),
        "`paths` must list at least one annotated handler"
    );
}

#[test]
fn spec_lists_every_always_on_route() {
    let v = parse_spec();
    let paths = v["paths"]
        .as_object()
        .expect("`paths` must be a JSON object");

    // Every always-on (non-feature-gated) route on the wire surface
    // that the wallet app talks to. Feature-gated routes
    // (`/api/address`, `/api/username/claim`, the LNURL pair) are not
    // checked here because the default build does not enable them and
    // the document must reflect the running binary.
    let required = [
        "/api/info",
        "/api/balance",
        "/api/send",
        "/api/receive",
        "/api/commit",
        "/api/mint",
        "/api/proof/{id}",
        "/api/inscriptions/{txid}",
        "/api/username/resolve/{username}",
    ];

    for path in required {
        assert!(
            paths.contains_key(path),
            "spec is missing the always-on path `{path}` — \
             handler annotation is probably missing from `ApiDoc::paths(...)`"
        );
    }
}

#[test]
fn spec_registers_critical_schemas() {
    let v = parse_spec();
    let schemas = v["components"]["schemas"]
        .as_object()
        .expect("`components.schemas` must be a JSON object");

    // `LnurlErrorResponse` is the LUD-style error envelope returned
    // by the username and LNURL endpoints. It is distinct from
    // `SendCoinResponse` (the zkCoins-style envelope used by the coin
    // endpoints) and the Zod mirror previously declared them as one
    // — that bug is what this assertion guards against.
    assert!(
        schemas.contains_key("LnurlErrorResponse"),
        "`LnurlErrorResponse` must be registered separately from `SendCoinResponse`"
    );

    // `SendCoinResponse` is the canonical zkCoins envelope: every
    // coin endpoint uses it for both 2xx and 4xx/5xx bodies. Missing
    // here means the spec cannot describe any non-200 response on
    // those endpoints.
    assert!(
        schemas.contains_key("SendCoinResponse"),
        "`SendCoinResponse` must be registered under components.schemas"
    );
}

#[test]
fn info_response_carries_username_domain() {
    // Drift guard: `username_domain` was missing from the previous
    // Zod-driven attempt and only surfaced under review. The whole
    // point of generating the spec from the Rust type is that this
    // field cannot go missing without removing it from `InfoResponse`
    // itself, which would break the wallet app.
    let v = parse_spec();
    let info = &v["components"]["schemas"]["InfoResponse"];
    let properties = info["properties"]
        .as_object()
        .expect("`InfoResponse.properties` must be a JSON object");
    assert!(
        properties.contains_key("username_domain"),
        "`InfoResponse` is missing the `username_domain` property — \
         did someone drop the field from the Rust struct?"
    );
}

#[test]
fn docs_html_pins_the_swagger_ui_version_constant() {
    // The HTML is a `concat!` literal and the version is a separate
    // `pub const`. A future bump must update both — this test fails
    // if the constant and the literal drift apart.
    let html = node::openapi::DOCS_HTML;
    let version = node::openapi::SWAGGER_UI_VERSION;
    assert!(
        html.contains(version),
        "`DOCS_HTML` must embed the `SWAGGER_UI_VERSION` constant (`{version}`) verbatim"
    );
}

#[test]
fn docs_html_loads_swagger_ui_assets() {
    let html = node::openapi::DOCS_HTML;
    assert!(
        html.contains("swagger-ui-bundle.js"),
        "`DOCS_HTML` must load the Swagger UI JS bundle"
    );
    assert!(
        html.contains("swagger-ui.css"),
        "`DOCS_HTML` must load the Swagger UI stylesheet"
    );
    // Relative URL so the page works behind any reverse proxy that
    // preserves the path. A leading `https://` here would couple the
    // docs page to a specific deployment URL.
    assert!(
        html.contains("url: '/openapi.json'"),
        "`DOCS_HTML` must point Swagger UI at the relative `/openapi.json` URL"
    );
}
