// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 EvoRule Project
// This file is part of EvoRule, licensed under GNU Affero General Public License v3 or later.

//! SSOT 侧 Fact 契约黄金向量对账闸门（server vendored 副本跨仓锚）
//!
//! （背景）server 仓以 vendored 补丁副本形态自持审计链序列化面
//! （`fact_to_stable_json` 为 content_hash 的输入正身），与主仓 SSOT
//! （`evorule-audit-chain`）之间无依赖关系，单方漂移不在任何一侧仓内测试暴露。
//!
//! （对账物）冻结黄金向量 `evorule-server/patches/evorule-reactor/tests/
//! fixtures/ssot_fact_contract_golden.json`：由副本侧正身生成，副本侧自证闸门
//! 在 server 仓 CI 常规强阻塞。本闸经 `include_str!` 跨仓读取（要求兄弟检出
//! 布局，CI 由 evorule-bundle 仓 cross-repo-gates 提供），SSOT 侧活体复算后
//! 与向量逐样本比对。
//!
//! （形态选型）活体双端依赖图（同图引入 vendored `evorule-reactor` 0.8.4）
//! 经实证不可行：双 reactor 同名 lib 目标的构建产物互相覆盖，rustc `--extern`
//! 解析到被覆盖产物即混型崩溃（cargo#6313 同族）。冻结向量形态下双向棘轮：
//! 副本漂移由 server 仓 CI 自证闸门检出，SSOT 漂移由本闸检出，共同契约物
//! 变更必须双仓同批留痕。
//!
//! （覆盖面）与副本侧同构 11 样本：9 个 Fact 变体 + u64::MAX-1 哨兵 id +
//! u64 值通道（`JsonValue::u64` 双端无损对账）。

use evorule_audit_chain as ssot;
use evorule_tcb::JsonValue;

/// 按向量样本 label 构造 SSOT 侧同构事实（与副本侧生成器逐字段对齐）
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
        other => panic!("黄金向量样本 {other} 缺少 SSOT 侧构造：副本侧新增样本须同步本闸"),
    }
}

/// 跨仓契约对账：SSOT live 复算 == 副本冻结黄金向量（稳定序列化 + content_hash）
#[test]
fn fact_contract_ssot_matches_frozen_vendored_golden() {
    const GOLDEN: &str = include_str!(
        "../../evorule-server/patches/evorule-reactor/tests/fixtures/ssot_fact_contract_golden.json"
    );
    let fx: serde_json::Value = serde_json::from_str(GOLDEN).expect("黄金向量文件非法 JSON");
    let arr = fx["samples"].as_array().expect("黄金向量缺 samples 数组");
    assert_eq!(
        arr.len(),
        11,
        "黄金向量样本数与构造面不同步（9 变体 + 哨兵 id + u64 值通道 = 11）"
    );
    for s in arr {
        let label = s["label"].as_str().expect("样本缺 label");
        let fact = make_fact(label);

        let stable = ssot::hash::fact_to_stable_json(&fact)
            .unwrap_or_else(|e| panic!("样本 {label}: SSOT 稳定序列化不得失败: {e:?}"));
        let compact = serde_json::to_string(&stable).expect("紧凑序列化不得失败");
        assert_eq!(
            compact,
            s["stable_json"]
                .as_str()
                .unwrap_or_else(|| panic!("样本 {label}: 缺 stable_json")),
            "样本 {label}: SSOT 与副本冻结黄金向量漂移（跨仓契约断裂）"
        );

        let hash = ssot::hash::fact_hash(&fact)
            .unwrap_or_else(|e| panic!("样本 {label}: SSOT fact_hash 不得失败: {e:?}"));
        assert_eq!(
            hash,
            s["fact_hash"]
                .as_str()
                .unwrap_or_else(|| panic!("样本 {label}: 缺 fact_hash")),
            "样本 {label}: SSOT content_hash 与副本冻结黄金向量漂移"
        );
    }
}
