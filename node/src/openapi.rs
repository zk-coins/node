//! OpenAPI 3.x spec for the zkCoins node REST API.
//!
//! The spec is generated at compile time from `#[utoipa::path]`
//! annotations on the handlers in [`crate::router`] and `ToSchema`
//! impls on the request / response types. There is no separately
//! maintained YAML or JSON — drift between the wire format and the
//! documentation is structurally impossible because the same Rust
//! type drives both serde and the schema.
//!
//! Two routes are wired in [`crate::router::create_router`]:
//!
//! - `GET /openapi.json` — returns the generated spec as JSON. The
//!   serialised bytes are produced once at first call into
//!   [`openapi_json`] and cached in a process-wide `OnceLock<String>`;
//!   subsequent calls return the same slice without re-serialising.
//! - `GET /docs` — serves a static HTML page that loads Swagger UI
//!   from the `unpkg.com` CDN with the asset version pinned. The
//!   embedded spec URL is `/openapi.json` (relative), so the docs page
//!   keeps working behind any reverse proxy that preserves path order.
//!
//! Feature-gated handlers are conditionally registered via
//! `#[cfg(feature = "...")]` on both the `paths(...)` list and the
//! handler's own annotation, so the spec describes exactly the routes
//! that exist in the running binary — not a superset.

use std::sync::OnceLock;

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use utoipa::OpenApi;

use crate::db::{InscriptionKind, InscriptionSummary};
use crate::router::{
    BalanceResponse, Capabilities, CommitRequest, InfoResponse, LnurlErrorResponse, MintRequest,
    SendCoinRequest, SendCoinResponse, UsernameResponse,
};

#[cfg(any(feature = "address-list", feature = "lnurl"))]
use crate::router::AddressesResponse;
#[cfg(feature = "username-claim")]
use crate::router::ClaimUsernameRequest;
#[cfg(feature = "lnurl")]
use crate::router::LnurlpResponse;

/// CDN-pinned Swagger UI asset version. Bumped intentionally; never
/// use a major-range (`@5`) or `@latest`. Verified against `npm view
/// swagger-ui-dist version` before each bump. Exposed so the smoke
/// test can assert the [`DOCS_HTML`] string carries this exact pin.
pub const SWAGGER_UI_VERSION: &str = "5.32.6";

/// Pinned Swagger UI HTML page served at `GET /docs`. Loads the CSS
/// and bundle from `unpkg.com/swagger-ui-dist@<version>/` and points
/// the renderer at the relative `/openapi.json` URL so the page works
/// behind any reverse proxy that preserves path ordering.
pub const DOCS_HTML: &str = concat!(
    "<!DOCTYPE html>\n",
    "<html lang=\"en\">\n",
    "<head>\n",
    "<meta charset=\"UTF-8\">\n",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    "<title>zkCoins API</title>\n",
    "<link rel=\"stylesheet\" href=\"https://unpkg.com/swagger-ui-dist@5.32.6/swagger-ui.css\">\n",
    "</head>\n",
    "<body>\n",
    "<div id=\"swagger-ui\"></div>\n",
    "<script src=\"https://unpkg.com/swagger-ui-dist@5.32.6/swagger-ui-bundle.js\" charset=\"UTF-8\"></script>\n",
    "<script>\n",
    "window.onload = function() {\n",
    "  window.ui = SwaggerUIBundle({\n",
    "    url: '/openapi.json',\n",
    "    dom_id: '#swagger-ui',\n",
    "    deepLinking: true,\n",
    "    presets: [SwaggerUIBundle.presets.apis],\n",
    "  });\n",
    "};\n",
    "</script>\n",
    "</body>\n",
    "</html>\n",
);

/// Compile-time root of the OpenAPI 3.x spec. The `#[openapi]`
/// attribute lists every handler whose `#[utoipa::path]` annotation
/// should appear under `paths`, plus every type registered under
/// `components.schemas`. Feature-gated handlers and feature-only
/// schemas are conditionally listed below.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "zkCoins API",
        description = "REST API of the zkCoins node (Shielded CSV on Bitcoin). \
                       This spec is generated from the handler annotations in the \
                       running binary, so it describes the exact wire contract this \
                       node serves. Interactive Swagger UI: `/docs`.",
        license(name = "MIT"),
    ),
    servers(
        (url = "https://api.zkcoins.app", description = "Production node (Bitcoin Mainnet)"),
        (url = "https://dev-api.zkcoins.app", description = "DEV node (Mutinynet)"),
    ),
    paths(
        crate::router::info_handler,
        crate::router::get_balance_handler,
        crate::router::send_coin_handler,
        crate::router::receive_coin_handler,
        crate::router::commit_handler,
        crate::router::mint_handler,
        crate::router::get_proof_handler,
        crate::router::get_inscription_handler,
        crate::router::resolve_username_handler,
    ),
    components(schemas(
        InfoResponse,
        Capabilities,
        BalanceResponse,
        SendCoinRequest,
        SendCoinResponse,
        MintRequest,
        CommitRequest,
        UsernameResponse,
        LnurlErrorResponse,
        InscriptionSummary,
        InscriptionKind,
    )),
)]
pub struct ApiDoc;

/// Feature-gated path additions and schema registrations. Implemented
/// as a thin compile-time-conditional extension of [`ApiDoc`] so the
/// always-on derive above stays readable and the gated handlers carry
/// their own `paths(...)` entries next to the feature flag that
/// controls them.
#[cfg(feature = "address-list")]
#[derive(OpenApi)]
#[openapi(
    paths(crate::router::get_address_handler),
    components(schemas(AddressesResponse))
)]
struct AddressListDoc;

#[cfg(feature = "username-claim")]
#[derive(OpenApi)]
#[openapi(
    paths(crate::router::claim_username_handler),
    components(schemas(ClaimUsernameRequest))
)]
struct UsernameClaimDoc;

#[cfg(feature = "lnurl")]
#[derive(OpenApi)]
#[openapi(
    paths(crate::router::lnurlp_handler, crate::router::lnurl_callback_handler,),
    components(schemas(LnurlpResponse))
)]
struct LnurlDoc;

/// Build the complete OpenAPI document for this binary, merging in
/// every feature-gated sub-doc that the build enables.
pub fn build_openapi() -> utoipa::openapi::OpenApi {
    #[allow(unused_mut)]
    let mut doc = ApiDoc::openapi();
    #[cfg(feature = "address-list")]
    doc.merge(AddressListDoc::openapi());
    #[cfg(feature = "username-claim")]
    doc.merge(UsernameClaimDoc::openapi());
    #[cfg(feature = "lnurl")]
    doc.merge(LnurlDoc::openapi());
    doc
}

/// Cached JSON serialisation of [`build_openapi`]. Populated on first
/// access and reused for every subsequent `GET /openapi.json` so we
/// pay the serde cost once per process, not per request.
fn cached_openapi_json() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE.get_or_init(|| {
        build_openapi()
            .to_json()
            .expect("OpenApi::to_json is infallible for a #[derive(OpenApi)] document")
    })
}

/// Re-export for callers that want the raw JSON string (e.g. the
/// integration smoke test) without going through the HTTP handler.
pub fn openapi_json() -> &'static str {
    cached_openapi_json()
}

/// `GET /openapi.json` — return the cached OpenAPI 3.x document.
pub async fn openapi_json_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        cached_openapi_json(),
    )
}

/// `GET /docs` — return the static Swagger UI page.
pub async fn docs_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DOCS_HTML,
    )
}

// Foreign types like `bitcoin::secp256k1::PublicKey` cannot derive
// `ToSchema` here (orphan rule). Each use site overrides the schema
// with `#[schema(value_type = String)]` so the spec describes the
// hex-encoded wire form instead of the in-process representation.
