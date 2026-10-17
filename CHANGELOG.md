# Changelog — `armature-http-client`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.3.0] - 2026-10-17

### Added

- `egress` module: `EgressPolicy`, a shared SSRF guard for outbound requests to
  untrusted URLs (lifted and generalized from `armature-push`'s Web Push host
  guard). Literal URL checks (https unless relaxed, deny-listed names such as
  `.internal`/`.local`/`localhost`), resolve-all-then-reject DNS vetting with a
  bounded lookup, and a `GuardedResolver` for reqwest that vets every answer at
  connect time (so connections are pinned to vetted addresses and DNS
  rebinding is refused). `EgressPolicy::apply` also disables redirects and
  proxies. Address classification (`is_internal_v4`/`is_internal_v6`) covers
  the IANA special-purpose registries, now including `192.88.99.0/24`,
  documentation ranges, `127.0.0.0/8`, `64:ff9b:1::/48`, `100::/64`,
  `2001:2::/48`, `3fff::/20`, `5f00::/16`, `fec0::/10` and IPv6 multicast, plus
  every IPv4-embedding IPv6 form (mapped, compatible, translated, NAT64, 6to4,
  Teredo).
- `HttpClientConfig::egress` / `HttpClientConfigBuilder::egress_policy`: opt-in
  egress guard for every request and redirect hop.
- `HttpClientConfig::https_only`, `max_response_size` (default 10 MiB) and
  `allow_cross_origin_redirects`; `HttpClientError::{ResponseTooLarge, Egress,
  RedirectRefused}`.

### Security

- `base_url` can no longer be escaped: request URLs carrying a scheme or
  authority (`https://other/`, `//169.254.169.254/`, `\\host`, tab/newline
  variants) are rejected, and `..`/`%2e%2e` segments may not climb out of the
  base path.
- Response bodies are read in a streaming fashion and capped on the *decoded*
  size, so a small gzip/brotli body that inflates to gigabytes (decompression
  bomb) fails with `ResponseTooLarge` instead of exhausting memory.
- When redirects are enabled, an https→http downgrade is always refused and a
  cross-origin hop is refused unless explicitly allowed (custom credential
  headers such as `X-Api-Key` would otherwise be forwarded to the new origin).

### Changed

- **Breaking:** `follow_redirects` now defaults to `false`. Migration: call
  `.follow_redirects(true)` (and `.allow_cross_origin_redirects(true)` if you
  need cross-origin hops).
- **Breaking:** with `base_url`, paths are appended to the base path
  (`base_url("https://api/v1")` + `get("/users")` → `https://api/v1/users`)
  instead of being resolved with `Url::join` (which replaced the last segment
  or the whole path). Migration: pass paths relative to the base.
- **Breaking:** `HttpClientConfig` has new public fields; struct-literal
  construction must add them (or use `..Default::default()` / the builder).
- `tokio` now also enables the `net` feature (DNS lookups for the egress guard).

## [0.2.3] - 2026-09-15

### Changed

- Bumped `tokio` (1.52 → 1.53), `http` (1.4 → 1.5), and `base64` (0.22 → 0.23). No source changes were needed: all three are drop-in for the APIs this crate uses.

## [0.2.2] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
