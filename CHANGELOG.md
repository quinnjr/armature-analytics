# Changelog — `armature-analytics`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Security

- **Breaking:** `AnalyticsMiddleware` no longer trusts `X-Client-Id`, the leftmost `X-Forwarded-For` hop or `X-Real-IP`. The client is identified by `HttpRequest::client_address(trusted_proxy_depth)` (socket peer at the default depth `0`), or by a header only when explicitly configured with `AnalyticsConfig::client_id_header`. Migration: set `trusted_proxy_depth` to your proxy count, and `client_id_header` only for a header your gateway sets and strips from client input.
- Client addresses are anonymized by default (IPv4 `/24`, IPv6 `/48`), both for request records and for IP-shaped client ids of rate-limit events (`anonymize_client_ips`, default `true`).
- **Breaking:** `include_query_params` (also on in the `development()` preset) now appends query parameter **names** only (`/search?page&q`); values are never recorded.

### Added

- `AnalyticsConfig::{trusted_proxy_depth, client_id_header, anonymize_client_ips}` with matching builder methods (all `#[serde(default)]`), and the `anonymize_ip` / `anonymize_client_id` helpers.

## [0.4.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- Dependencies bumped to their latest releases: `tokio` 1.52 → 1.53.

## [0.3.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.

## [0.2.3] - 2026-08-04

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
