# Changelog — `armature-http-client`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Added

- Adopted the `http_client` criterion benchmark (config, retry, circuit breaker, request building) from the root package's `benches/`. Run it with `cargo bench -p armature-http-client --bench http_client`. The crate now sets `autobenches = false`, so a new file under `benches/` needs an explicit `[[bench]]` entry.

### Fixed

- An invalid per-request header name or value is warned about rather than dropped in silence — this had been silently stripping `bearer_auth` when a token contained a stray newline.
- `max_attempts = 0` no longer underflows into effectively infinite retries.

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
