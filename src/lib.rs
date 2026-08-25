//! evorule-integration-tests — 跨仓 BLAKE3 一致性闸门（库占位，真实测试见 `tests/`）。
//!
//! 设计原则：本 crate **不依赖冻结仓** `evorule-reactor` / `evorule-governance`。
//! 我们直接引入 `blake3` crate 复算，与 `evorule-hash` 的 `digest` 对照，
//! 证明 `evorule-hash` 的字节语义与冻结仓审计链源头（reactor 的 `blake3::hash(bytes).to_hex()`）
//! 完全一致 —— 即「全链路 BLAKE3 迁移后审计链不断裂」这一核心契约。
pub fn placeholder() {}
