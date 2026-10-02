//! 跨仓门禁：evorule-llm-context-inspector 独立审计链 × BLAKE3 字节语义
//! （新仓接入 checklist#6；对齐 blake3_gate/server_hash_gate 模式）。
//!
//! 仓设计纪律延续：本 crate **不依赖冻结仓**（reactor/governance），
//! 链步以 blake3 crate 直接复算对照——inspector 链上的
//! `chain_hash = blake3(prev_hash + record_hash)` 必须与本仓独立复算逐字节一致。
//! 同时验证 B 族口径：record_hash（全快照 canonical）==
//! `evorule_hash::json_digest`（serde_json 紧凑 + BTreeMap 键序）。

use evorule_llm_context_inspector::chain::{
    verify_wal_file, InspectorLog, InspectorRecord, GENESIS,
};
use evorule_llm_context_inspector::model::{
    Composition, ContextSkeleton, ContextSnapshot, MessageEntry, SessionLink, ToolEntry,
};
use evorule_llm_context_inspector::{BindingKind, ContentKind, ProviderKind, TokenSource};

fn snapshot(seq: u64, msg: &[u8]) -> ContextSnapshot {
    let skeleton = ContextSkeleton::new(
        ProviderKind::DeepSeek,
        "deepseek-chat",
        b"gate-system",
        vec![ToolEntry::new("gate-tool", b"{}")],
        vec![MessageEntry::new("user", ContentKind::Text, msg, 0)],
    );
    let composition = Composition::new(3, 2, 7, 0, 1, 1, TokenSource::Estimated)
        .expect("组成核账");
    ContextSnapshot::new(
        uuid::Uuid::from_u128(u128::from(seq)),
        SessionLink::new(Some(1), BindingKind::PortBinding, None),
        1_000 + seq,
        ProviderKind::DeepSeek,
        "deepseek-chat",
        Some(128_000),
        composition,
        skeleton,
    )
    .expect("快照合法")
}

#[test]
fn context_chain_matches_independent_blake3_recomputation() {
    let dir = std::env::temp_dir().join(format!(
        "context_gate_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("inspector.log");

    let log = InspectorLog::open(&wal).expect("open");
    let s1 = snapshot(1, b"record-one");
    let s2 = snapshot(2, b"record-two");
    log.append(InspectorRecord::Snapshot(s1.clone())).expect("append 1");
    log.append(InspectorRecord::Snapshot(s2.clone())).expect("append 2");
    let head_via_api = log.anchor_head().expect("anchor_head");
    drop(log);

    // 独立复算：逐行（record_hash 与链步均不信任实现，用原语重算）
    let raw = std::fs::read_to_string(&wal).expect("read wal");
    let mut prev = GENESIS.to_owned();
    for (i, line) in raw.lines().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSONL 合法");
        // B 族：record_hash == json_digest(全快照)（serde_json 紧凑 + BTreeMap 键序）
        let record_hash = v["record_hash"].as_str().expect("record_hash 字段");
        // 快照 canonical 重算：经 evorule-hash 同一原语（从行内 record 重建 Value）
        let recomputed_record = {
            let mut full = v.clone();
            for envelope in ["record_hash", "prev_hash", "chain_hash", "seq", "type"] {
                full.as_object_mut().unwrap().remove(envelope);
            }
            evorule_hash::json_digest(&full)
        };
        assert_eq!(
            record_hash, recomputed_record,
            "line {i}: record_hash 必须等于 json_digest(canonical 快照)"
        );
        // 链步：blake3(prev + record_hash) 独立复算（不依赖 inspector/reactor 实现）
        let mut preimage = prev.clone().into_bytes();
        preimage.extend_from_slice(record_hash.as_bytes());
        let expected = blake3::hash(&preimage).to_hex().to_string();
        let chain_hash = v["chain_hash"].as_str().expect("chain_hash 字段");
        assert_eq!(
            chain_hash, expected,
            "line {i}: chain_hash 必须等于独立复算的 blake3(prev+record)"
        );
        assert_eq!(v["prev_hash"].as_str().unwrap(), prev, "line {i}: prev 接续");
        prev = chain_hash.to_owned();
    }
    assert_eq!(prev, head_via_api, "独立复算链头必须等于 anchor_head");

    // inspector 自身强语义校验同过
    let report = verify_wal_file(&wal).expect("verify");
    assert!(report.ok, "reason={:?}", report.reason);
    assert_eq!(report.records, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn context_chain_genesis_and_tamper_detection_across_repos() {
    let dir = std::env::temp_dir().join(format!(
        "context_gate_tamper_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("inspector.log");

    let log = InspectorLog::open(&wal).expect("open");
    log.append(InspectorRecord::Snapshot(snapshot(1, b"intact")))
        .expect("append");
    drop(log);

    // 首行 genesis 链接（跨仓语义一致：hash.rs genesis 同款）
    let raw = std::fs::read_to_string(&wal).unwrap();
    assert!(raw.lines().next().unwrap().contains("\"prev_hash\":\"genesis\""));

    // 篡改 record_hash 字段 → 强语义校验跨仓拦截
    let v: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    let mut tampered = v.clone();
    tampered["record_hash"] = serde_json::json!("0".repeat(64));
    std::fs::write(&wal, serde_json::to_string(&tampered).unwrap() + "\n").unwrap();
    let report = verify_wal_file(&wal).expect("verify");
    assert!(!report.ok, "跨仓篡改必须被拦截");
    assert_eq!(report.first_bad_seq, Some(1));

    let _ = std::fs::remove_dir_all(&dir);
}
