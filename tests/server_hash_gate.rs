//! server 侧哈希黄金向量闸门（审计⑥ C14）
//!
//! 锁定 server 会话锚的哈希口径：`Session.initial_content_hash` 优先走
//! `ContentHashScheme::AuditChainCompact`（evorule-governance/session.rs
//! `compute_initial_hash` → `evorule_reactor::content_hash`），即
//! `blake3(serde_json 紧凑序列化).hex`（64-hex 无前缀）。
//!
//! 本仓不依赖冻结仓（reactor/governance），故黄金值以**独立 Python
//! blake3 实现**复算取证（sort_keys + 紧凑分隔符 + UTF-8 不转义），
//! 与 `evorule_hash::json_digest` 对照。若 serde_json/blake3 升级或
//! 有人开启 `preserve_order` 导致键序漂移，本测试变红——这是期望的防护。
//!
//! 范围说明（诚实边界）：
//! - 旧口径 `TcbDisplay` 仅存量会话双读使用，其 TCB Display 序列化
//!   依赖冻结仓 tcb，不在本轻量仓复制；正确性由 server/governance 仓内
//!   测试自管。
//! - 发布链 manifest 的 `content_hash`（"blake3:" 前缀 + json_digest）
//!   已由 blake3_gate.rs 用例 5 锁定消费契约，此处不重复。

use evorule_hash::json_digest;
use serde_json::json;

/// server 会话锚黄金向量（AuditChainCompact 口径，C14）。
///
/// payload 为代表性会话快照：嵌套对象 + 数组 + 空数组 + 中文值
/// （锁定 UTF-8 不转义、键序规范化两个口径）。
#[test]
fn session_anchor_audit_chain_compact_golden() {
    let payload = json!({
        "dataset_id": "ds-tax-2024",
        "entries": [{"entry_id": "entry-tax-001", "title": "数据条目"}],
        "queue": [],
        "step": 3,
        "tenant_id": "org-evorule",
        "version": 3,
    });
    // Python 独立复算：blake3(json.dumps(payload, sort_keys=True,
    //   separators=(',',':'), ensure_ascii=False).encode('utf-8'))
    let golden = "3fafdb7a18d2405d11e2b644e651ef97d3db806efd9257efcb3a45e9245ee4e9";
    assert_eq!(
        json_digest(&payload),
        golden,
        "会话锚口径漂移：json_digest 必须等于独立复算的 blake3(紧凑+键序规范化) 值"
    );
    // 键序无关（与 C11 hash 仓乱序键向量同口径，跨仓一致性）
    let reordered = json!({
        "version": 3,
        "tenant_id": "org-evorule",
        "step": 3,
        "queue": [],
        "entries": [{"title": "数据条目", "entry_id": "entry-tax-001"}],
        "dataset_id": "ds-tax-2024",
    });
    assert_eq!(json_digest(&reordered), golden, "乱序键必须得到同一锚哈希");
    // 会话锚为 64-hex 无前缀（与审计链 content_hash 同构，server 侧直接入库比对）
    let h = json_digest(&payload);
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!h.starts_with("blake3:"), "会话锚不带前缀（区别于 bundle content_hash）");
}
