// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 EvoRule Project
// This file is part of EvoRule, licensed under GNU Affero General Public License v3 or later.

//! 审计导出契约对账闸门（SSOT 侧棘轮，EVID 移动端验证器预演）
//!
//! （对账物）server 仓冻结黄金向量 `patches/evorule-governance/tests/fixtures/
//! audit_export_golden.json`：由 server vendored governance 副本 `Auditor::export()`
//! 生成（自证闸门在 server 仓 CI），本闸经 include_str! 跨仓读取（兄弟检出布局，
//! CI 由 evorule-bundle 仓 cross-repo-gates 提供），SSOT 侧（evorule-audit-chain）
//! 活体复算后逐条比对。
//!
//! （EVID 判定预演）移动端/第三方离线验证器的完整判定路径在 CI 中的零知识预演——
//! 仅凭导出物字段（无 Fact 类型知识、无网络）：
//! 1. 逐条 `blake3(fact_json_stable 字节) == content_hash`（本闸以 SSOT hash 面
//!    等价重算）；
//! 2. `fact_json_stable` 与 `fact` 原文深比一致（篡改信号检测）；
//! 3. 链折叠 `genesis → chain_step(prev, content) → … == last_hash`。
//!
//! （双端同构）样本构造面与 server 侧 Fact 契约闸/导出黄金向量逐字段对齐
//! （9 变体 + u64::MAX-1 哨兵 id + u64 值通道 = 11 条）。

use evorule_audit_chain as ssot;
use evorule_tcb::JsonValue;

/// 按样本 label 构造 SSOT 侧同构事实（与 server 侧导出黄金向量生成器逐字段对齐）
fn make_fact(label: &str) -> ssot::fact::Fact {
    use ssot::fact::{Fact, FactId, IoType};
    let noop = || JsonValue::object_from_pairs(&[("type", JsonValue::string("noop"))]);
    let empty = || JsonValue::object_from_pairs(&[]);
    match label {
        "Command" => Fact::Command {
            id: FactId(1),
            instruction: noop(),
        },
        "PayloadUpdate(sentinel)" => Fact::PayloadUpdate {
            id: FactId(u64::MAX - 1),
            path: "__ruleset__.version".into(),
            value: JsonValue::String("c7b6fab66f0ea645".into()),
        },
        "PayloadUpdate(u64-value)" => Fact::PayloadUpdate {
            id: FactId(11),
            path: "__ruleset__.anchor".into(),
            value: JsonValue::u64(u64::MAX - 3),
        },
        "StateTransition(sentinel-cause)" => Fact::StateTransition {
            id: FactId(u64::MAX - 2),
            cause: FactId(1),
            new_payload: empty(),
            new_queue: vec![],
        },
        "IoRequest" => Fact::IoRequest {
            id: FactId(4),
            cause: FactId(1),
            io_type: IoType::call_external(),
            params: empty(),
        },
        "IoResponse(ok)" => Fact::IoResponse {
            id: FactId(5),
            request_id: FactId(4),
            result: empty(),
            error: None,
        },
        "IoResponse(error)" => Fact::IoResponse {
            id: FactId(6),
            request_id: FactId(4),
            result: empty(),
            error: Some("io failed".into()),
        },
        "Stable" => Fact::Stable {
            id: FactId(7),
            version: 3,
        },
        "Error" => Fact::Error {
            id: FactId(8),
            message: "timeout".into(),
        },
        "TransitionTrace" => Fact::TransitionTrace {
            id: FactId(9),
            cause: FactId(u64::MAX - 2),
            rule_hits: vec![],
        },
        "Violation" => Fact::Violation {
            id: FactId(10),
            cause: FactId(1),
            rule_index: 2,
            reason: "enforced".into(),
            instruction: empty(),
        },
        other => panic!("导出黄金向量样本 {other} 缺少 SSOT 侧构造：server 侧样本面演进须同步本闸"),
    }
}

/// 向量样本 label 序（与 server 侧 all_samples 顺序一致，构成导出条目序）
const SAMPLE_LABELS: [&str; 11] = [
    "Command",
    "PayloadUpdate(sentinel)",
    "PayloadUpdate(u64-value)",
    "StateTransition(sentinel-cause)",
    "IoRequest",
    "IoResponse(ok)",
    "IoResponse(error)",
    "Stable",
    "Error",
    "TransitionTrace",
    "Violation",
];

/// 跨仓契约对账：SSOT live 复算 == server 冻结导出黄金向量（EVID 三步判定全跑）
#[test]
fn audit_export_contract_ssot_matches_frozen_vendored_golden() {
    const GOLDEN: &str = include_str!(
        "../../evorule-server/patches/evorule-governance/tests/fixtures/audit_export_golden.json"
    );
    let fx: serde_json::Value = serde_json::from_str(GOLDEN).expect("黄金向量文件非法 JSON");
    let export = &fx["export"];
    assert_eq!(export["version"], "1.0", "导出版本漂移");
    assert_eq!(
        export["entry_count"].as_u64(),
        Some(11),
        "条目数与构造面不同步（9 变体 + 哨兵 id + u64 值通道 = 11）"
    );
    let entries = export["entries"].as_array().expect("导出缺 entries 数组");
    assert_eq!(entries.len(), 11, "向量条目数与样本面不同步");

    for (entry, label) in entries.iter().zip(SAMPLE_LABELS.iter()) {
        let fact = make_fact(label);

        // EVID 判定①：fact_json_stable == SSOT 稳定序列化原字节，
        // content_hash == SSOT fact_hash（blake3 语义等价重算）
        let stable = ssot::hash::fact_to_stable_json(&fact)
            .unwrap_or_else(|e| panic!("样本 {label}: SSOT 稳定序列化不得失败: {e:?}"));
        let compact = serde_json::to_string(&stable).expect("紧凑序列化不得失败");
        assert_eq!(
            compact,
            entry["fact_json_stable"]
                .as_str()
                .unwrap_or_else(|| panic!("样本 {label}: 缺 fact_json_stable")),
            "样本 {label}: fact_json_stable 与 SSOT 原字节漂移（EVID 契约断裂）"
        );
        let hash = ssot::hash::fact_hash(&fact)
            .unwrap_or_else(|e| panic!("样本 {label}: SSOT fact_hash 不得失败: {e:?}"));
        assert_eq!(
            hash,
            entry["content_hash"]
                .as_str()
                .unwrap_or_else(|| panic!("样本 {label}: 缺 content_hash")),
            "样本 {label}: SSOT content_hash 与导出黄金向量漂移"
        );

        // EVID 判定②：fact 原文与 fact_json_stable 深比一致（篡改信号语义镜像）
        assert_eq!(
            serde_json::to_string(&entry["fact"]).expect("fact 重序列化不得失败"),
            entry["fact_json_stable"].as_str().expect("缺 fact_json_stable"),
            "样本 {label}: fact 原文与 fact_json_stable 不一致（导出物自相矛盾）"
        );
    }

    // EVID 判定③：链折叠 genesis → … == last_hash（语义与 verify() 一致：
    // prev_hash 是先验链接，chain_step 结果即该条目链哈希=下一条目先验 prev）
    let mut prev = String::from("genesis");
    for entry in entries {
        assert_eq!(
            entry["prev_hash"]
                .as_str()
                .unwrap_or_else(|| panic!("fact_id={} 缺 prev_hash", entry["fact_id"])),
            prev,
            "fact_id={} 链接断裂",
            entry["fact_id"]
        );
        prev = ssot::hash::chain_step(
            prev.as_str(),
            entry["content_hash"]
                .as_str()
                .expect("缺 content_hash"),
        );
    }
    assert_eq!(
        prev,
        export["last_hash"].as_str().expect("缺 last_hash"),
        "链折叠终值与 last_hash 不一致"
    );
}
