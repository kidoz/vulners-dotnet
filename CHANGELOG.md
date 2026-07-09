# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-10

Initial stable release — a fully-featured .NET SDK for the Vulners vulnerability-intelligence
API, multi-targeting `net10.0`, `net8.0`, and `netstandard2.0`, with first-class
dependency-injection support.

### Added

- **Search** — Lucene search with auto-pagination (`SearchAsync`/`SearchAllAsync`), exploit
  search, bulletin lookup by ID, references, history, Microsoft KB seeds/updates, autocomplete,
  CPE lookup and batch CPE resolution, and web-path vulnerabilities.
- **Audit** — Linux package audit (V3 and V4), CPE-based software and host audit, single/batch
  CVE audit, library/smart/manifest/SBOM audit, package metadata, and Windows KB/software audit.
- **Archive** — OS CVE archive download (ZIP), collection and family download, incremental
  updates, and archive state.
- **Subscriptions & webhooks** — V4 subscriptions, legacy email subscriptions, and webhook
  subscription management.
- **Reports & STIX** — Linux Audit reports and STIX 2.1 bundle export.
- **Miscellaneous** — API-key/license info and field-value suggestions.
- **Infrastructure** — `AddVulners()` DI extension, `IVulnersClient`, `VulnersOptions` with a
  version-agnostic base URL, strongly-typed models with forward-compatible extension data, and a
  uniform `VulnersException`.

### Security

- The API key is attached via the `X-Api-Key` header and is not placed in URLs or request bodies
  except for the legacy endpoints that require it (documented in code).
- HTTPS is enforced for all non-loopback endpoints.
- HTTP error bodies are redacted and truncated before being surfaced in exceptions.
- Public methods validate documented input bounds before making a network call.

[Unreleased]: https://github.com/kidoz/vulners-dotnet/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kidoz/vulners-dotnet/releases/tag/v1.0.0
