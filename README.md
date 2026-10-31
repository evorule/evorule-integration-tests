# evorule-integration-tests

Cross-repo contract gate tests for the evorule ecosystem: hash-domain, version-compatibility, and serialization-contract enforcement, run at the ecosystem tip.

[![CI][badge-ci]][ci-link]
[![License: AGPL-3.0-or-later][badge-license]][license-link]

**License**: [AGPL-3.0-or-later](LICENSE) with [dual licensing](DUAL_LICENSE.md)

Part of the [evorule](https://github.com/evorule/evorule) ecosystem — see the main repo's Repository Map. The crates under test are path dependencies, and two gates read frozen golden fixtures across repos via `include_str!`, so a **sibling-checkout layout is required**: `evorule`, `evorule-hash`, `evorule-bundle`, `evorule-context-inspector`, `evorule-rule`, and `evorule-server` checked out side by side with this repo. Gates fail fast when a sibling is missing or unparseable — the gate itself never degrades.

## Gate inventory

| Gate | What it locks |
|---|---|
| `blake3_gate` | source equivalence — `evorule_hash::digest` is byte-identical to `blake3::hash(bytes).to_hex()` (the frozen reactor's unprefixed 64-hex form); the `blake3:` self-describing prefix contract; the bundle consumption contract (`DatasetBundle::compute_content_hash`) |
| `version_gate` | the evorule-hash version requirement is identical across the bundle / rule / server manifests and meets the contract floor — no stale pins (an old release briefly shipped under a different license) |
| `server_hash_gate` | the server session-anchor hash formula (`blake3(serde_json compact).hex`, unprefixed), recomputed with an independent Python blake3 implementation |
| `ssot_fact_contract_gate` | SSOT-side Fact serialization recomputed against the server's vendored-copy frozen golden vector (read cross-repo via `include_str!`) |
| `audit_export_contract_gate` | the audit-export contract verified with export fields alone — no Fact-type knowledge, no network: per-item hashes, tamper detection, and chain folding (a dry run of the offline EVID verifier) |
| `context_chain_gate` | the context inspector's standalone audit chain: `chain_hash` / `record_hash` recomputed byte-for-byte with the blake3 crate |

## Prerequisites

- Rust stable
- Sibling checkouts as described above — no other setup

## Run

```bash
cargo test
```

The default branch is `master`. This repo's own CI runs the ecosystem license gate (a shared reusable workflow pinned to a root-repo commit, floating the path-dependency siblings) plus a TS-validator alignment job that compares the console-cloud pre-validator against the server's authoritative `_shared` schema — drift turns red here instead of silently diverging.

## License

**AGPL-3.0-or-later**: [LICENSE](LICENSE) / [NOTICE.md](NOTICE.md); dual-licensing guidance in [DUAL_LICENSE.md](DUAL_LICENSE.md), with [FREE_COMMERCIAL_LICENSE.md](FREE_COMMERCIAL_LICENSE.md) (free waiver for eligible entities) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

[badge-ci]: https://github.com/evorule/evorule-integration-tests/actions/workflows/ci.yml/badge.svg
[ci-link]: https://github.com/evorule/evorule-integration-tests/actions/workflows/ci.yml
[badge-license]: https://img.shields.io/badge/license-AGPL--3.0--or--later-blue?style=flat-square
[license-link]: LICENSE
