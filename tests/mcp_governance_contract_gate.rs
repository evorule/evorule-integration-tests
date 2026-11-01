//! MCP 治理链契约闸门（治理原生线：提案→审批→生效面）
//!
//! 跨仓锁定两件事，防单侧静默漂移：
//!
//! 1. **server_key 规范哈希契约**：`canonical_server_key` 的黄金向量（与
//!    执行侧 agent 装载门的镜像实现通过双侧同字面量单测对齐；本闸把治理侧
//!    实现钉进跨仓 CI——治理侧单测被单方修改时此处即红）。规范序列 =
//!    JSON 数组 `[command, 段...]`（args_pattern 缺省 = 空数组），serde_json
//!    紧凑序列化后 blake3 + `blake3:` 前缀；command 不做归一化。
//! 2. **治理数据集生命周期契约**（`org.evorule.mcp.servers`）：提案形态
//!    （Draft 无批准归因三态）合法落账；提案态不进生效面（导出过滤）；
//!    晋升 Active 时归因完备性闸死（人工通路与机器闸通路一致拒绝）；按
//!    审批者身份补全归因后晋升通过且生效条目携带归因。
//!
//! 布局要求：evorule-rule 兄弟仓平级检出（bundle CI cross-repo-gates 已保证；
//! 本地运行需 evorule-rule 与 integration-tests 平级且在 main 及以上）。

use evorule_rule::model::mcp_servers::{
    approval_attribution_missing, canonical_server_key, fill_approval_attribution,
    validate_mcp_server_entry, validate_mcp_server_payload, MCP_SERVER_SCHEMA_REF,
    MCP_SERVERS_DATASET_ID,
};
use evorule_rule::model::{DatasetKind, LifecycleStatus, RuleDataset, Visibility};
use evorule_rule::store::RuleStore;

// 注意：BundleTests 必须经 evorule_rule 的再导出取用——本仓对 evorule-bundle 是
// path 依赖（兄弟检出），而 rule 消费 crates.io 注册表版；两者是不同 crate 实例，
// 类型不互通（export_bundle 签名以 rule 侧实例为准）。

// ===== server_key 规范哈希黄金向量（与 rule/agent 双侧单测同字面量） =====

#[test]
fn server_key_golden_vectors() {
    let segs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        canonical_server_key("my-fixed-server.exe", None),
        "blake3:d5c3446a9fd2ae9dc68e6ffbaeb619e0e675f0572bffd04de9a9afce2d28ed87"
    );
    assert_eq!(
        canonical_server_key("npx", Some(&segs(&["-y", "@modelcontextprotocol/server-*"]))),
        "blake3:f890f2b86546855e48b14db28ab97d7ef06e411ed0a21fb003911a3e1a36c953"
    );
    // 字面精确：不做归一化
    assert_ne!(
        canonical_server_key("npx", Some(&segs(&["-y"]))),
        canonical_server_key("npx ", Some(&segs(&["-y"])))
    );
    // 形态自证：blake3: 前缀 + 64-hex + 同输入双跑一致
    let k1 = canonical_server_key("my-fixed-server.exe", None);
    assert_eq!(k1, canonical_server_key("my-fixed-server.exe", None));
    assert!(k1.starts_with("blake3:"));
    let hex = k1.trim_start_matches("blake3:");
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

// ===== 治理数据集生命周期契约 =====

fn mcp_store() -> RuleStore {
    let store = RuleStore::in_memory().expect("in-memory store");
    store
        .seed_mcp_servers_dataset_if_empty("org-evorule", "2026-11-01T00:00:00Z")
        .expect("seed");
    store
}

fn proposal_payload(command: &str) -> serde_json::Value {
    serde_json::json!({
        "server_key": canonical_server_key(command, None),
        "command": command,
        "comment": "自动提案：会话首次尝试"
    })
}

fn mcp_entry(payload: serde_json::Value) -> evorule_rule::model::KnowledgeEntry {
    let key = payload["server_key"].as_str().expect("server_key").to_string();
    evorule_rule::model::KnowledgeEntry {
        entry_id: key,
        dataset_id: MCP_SERVERS_DATASET_ID.to_string(),
        version: 1,
        status: Some(LifecycleStatus::Draft),
        provenance: evorule_rule::model::Provenance {
            source: "contract gate".into(),
            clause: None,
            document_id: None,
            effective_from: None,
            effective_to: None,
            last_verified: None,
            verified_by: None,
        },
        domain: "mcp".into(),
        tags: vec![],
        payload,
        schema_ref: MCP_SERVER_SCHEMA_REF.to_string(),
        governance: None,
        knowledge_kind: None,
        trust_level: None,
        license_ref: None,
        execution_contract: None,
    }
}

fn seed_dataset_kind(store: &RuleStore) {
    // seed 数据集已存在（kind knowledge / public）；此处仅断言契约前提成立
    let ds = store
        .get_dataset(MCP_SERVERS_DATASET_ID)
        .expect("query")
        .expect("seeded dataset");
    assert_eq!(ds.dataset_kind, DatasetKind::Knowledge);
    assert_eq!(ds.visibility, Visibility::Public);
}

#[test]
fn mcp_proposal_to_effective_surface_contract() {
    let store = mcp_store();
    seed_dataset_kind(&store);
    let tests = evorule_rule::bundle::BundleTests::unverified();

    // ① 提案形态落 Draft 合法（归因三态缺席 = 请求而非批准）
    let key = canonical_server_key("contract-server.exe", None);
    let proposal = proposal_payload("contract-server.exe");
    assert!(validate_mcp_server_entry(&proposal, false).is_ok());
    assert!(approval_attribution_missing(&proposal));
    store
        .add_knowledge_entry(&mcp_entry(proposal))
        .expect("proposal intake");

    // ② 提案态不进生效面（导出过滤）
    let b = store
        .export_bundle(MCP_SERVERS_DATASET_ID, &tests, "gate", "now", "inst", None)
        .expect("export");
    assert!(b.entries.is_empty(), "proposal must stay off the live surface");

    // ③ 晋升 Active（人工通路）：无归因 → 完备性闸拒绝
    store
        .transition_knowledge_entry_status(
            MCP_SERVERS_DATASET_ID,
            &key,
            LifecycleStatus::Candidate,
            "gate",
            "t1",
            "候选提交",
        )
        .expect("candidate");
    let err = store
        .transition_knowledge_entry_status(
            MCP_SERVERS_DATASET_ID,
            &key,
            LifecycleStatus::Active,
            "gate",
            "t2",
            "归因缺席晋升必须被拒",
        )
        .expect_err("completeness gate");
    assert!(err.to_string().contains("approved_by"), "gate: {err}");

    // ④ 机器闸通路同口径拒绝
    let err = store
        .transition_knowledge_entry_status_machine(
            MCP_SERVERS_DATASET_ID,
            &key,
            LifecycleStatus::Active,
            "machine",
            "t3",
            "机器闸晋升必须被拒",
            "T1",
        )
        .expect_err("machine completeness gate");
    assert!(err.to_string().contains("approved_by"), "machine gate: {err}");

    // ⑤ 按审批者身份补全 → 晋升通过 → 生效条目携带归因
    let mut entry = store
        .get_latest_knowledge_entry(MCP_SERVERS_DATASET_ID, &key)
        .expect("query")
        .expect("entry");
    assert!(!entry.is_frozen(), "candidate must stay editable");
    fill_approval_attribution(&mut entry.payload, "approver-1", "2026-11-01T00:00:00Z", "ref@v1");
    store.update_draft_knowledge_entry(&entry).expect("fill");
    assert!(validate_mcp_server_payload(&entry.payload).is_ok());
    store
        .transition_knowledge_entry_status(
            MCP_SERVERS_DATASET_ID,
            &key,
            LifecycleStatus::Active,
            "approver-1",
            "t4",
            "批准",
        )
        .expect("promote");
    let b = store
        .export_bundle(MCP_SERVERS_DATASET_ID, &tests, "gate", "now", "inst", None)
        .expect("export");
    assert_eq!(b.entries.len(), 1);
    assert_eq!(b.entries[0].entry_id, key);
    assert_eq!(b.entries[0].rule_body["approved_by"], "approver-1");
    assert_eq!(b.entries[0].rule_body["approval_ref"], "ref@v1");
}
