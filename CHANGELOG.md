# Changelog

## [3.0.1] - 2026-09-26

### Added

- Threat scoring engine with confidence-tagged detections.
- IOC extraction for sanitized IPs, domains, URLs, hashes and file names.
- Regex detection for reverse shells, obfuscation and download chains.
- Session intelligence with a bounded cache, profile and structured history.
- Test bootstrap validation before pytest collection.
- JSONL writer-order SHA-256 hash chain and standalone verification/summary tool.
- Container TCP healthcheck, configuration flags and targeted regression tests.
- Makefile shortcuts for the test suite and Docker Compose build.

### Changed

- Unified log metadata while preserving v3 command, analysis, alert and SQLite report fields.
- Corrected deployment documentation: the Compose bridge alone does not isolate outbound traffic.
- Changed fresh-install published bind default to loopback until an operator explicitly enables public ingress.

## 3.0.0 - 2026-09-26

- correlated a downloaded artifact name with later attempted execution in the same session;
- added bounded host/IP/artifact indicators without URL credentials or query strings;
- added per-session deduplicated JSONL alerts and configurable risk threshold;
- added a separate offline SQLite ingest/report tool that omits passwords and raw commands by default;
- added regression checks for correlation, isolation, alert deduplication, bounded state, and report privacy.

## 2.1.0 - 2026-09-26

- added bounded rule-based Intelligence Engine for interactive and SSH exec commands;
- added per-command category, risk level, score, rule IDs and parse diagnostics;
- added per-session intelligence summary to the disconnect event;
- added regression tests for detection, bounded input, logging paths and session isolation.

## 2.0.0 - 2026-09-19

Production hardening release:

- added a stateful fake Ubuntu 22.04 terminal and isolated in-memory VFS;
- implemented simulated system, filesystem, network and management commands;
- added bounded terminal editing, history and tab completion;
- added stable in-memory host-key loading and modern SSH algorithm policy;
- rejected forwarding, SFTP, agent, X11 and environment requests;
- added global/per-IP rate limiting and active-connection limits;
- added VFS, command, output, history, package and session quotas;
- added asynchronous bounded JSON logging and credential privacy modes;
- added graceful shutdown, runtime metrics and structured failure events;
- added a non-root, read-only, egress-isolated Compose deployment profile;
- pinned Python dependencies with hashes and added CI/security tests.

The core invariant remains unchanged: attacker input is never passed to a
real shell, process launcher, host filesystem API or outbound network client.
