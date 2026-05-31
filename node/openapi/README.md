# OpenAPI spec

`zkcoins.yaml` is bundled into the node binary via `include_str!` and served at runtime by:

- `GET /openapi.json` — JSON representation, parsed once at startup
- `GET /docs` — Swagger UI rendered from the JSON above

Source of truth: [`zk-coins/app/openapi/zkcoins.yaml`](https://github.com/zk-coins/app/blob/develop/openapi/zkcoins.yaml) (generated from the Zod schemas in that repo via `npm run generate:openapi`).

This copy is **manually synchronised** with the app repo for each spec update — cross-repo automation is intentionally out of scope for the issue that introduced this directory (zk-coins/node#155). Drift between the two copies is operationally visible because the served JSON differs from the app-generated YAML on the same SHA; the smoke test in `node/tests/openapi_smoke.rs` catches structural breakage (missing `openapi:` / `paths:` keys, invalid YAML).

When updating: regenerate in `zk-coins/app` first (`npm run generate:openapi`), commit there, then copy the new `openapi/zkcoins.yaml` over this file and bump the node PR.
