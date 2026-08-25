//! 跨仓 BLAKE3 一致性闸门
//!
//! 三个层次的断言：
//! 1. **源等价（最关键）**：`evorule_hash::digest` 必须字节级等于 `blake3::hash(bytes).to_hex()`。
//!    `evorule-reactor`（冻结仓审计链源头）正是用 `blake3::hash(bytes).to_hex()`（无前缀 64-hex）。
//!    这一步证明迁移后治理三仓（rule/bundle/server）产出的哈希与冻结仓同源，审计链不断裂。
//! 2. **前缀契约**：`evorule_hash::prefixed` 必须产出 `blake3:` 自描述前缀，与 bundle/entry 一致。
//! 3. **消费契约**：`evorule-bundle::DatasetBundle::compute_content_hash` 必须产出 `blake3:` 前缀哈希，
//!    且内部值等于 `json_digest(canonical)`（content_hash 字段本身被排除在规范化之外）。

use blake3;
use evorule_bundle::{
    BundleAudit, BundleDatasetMeta, BundleEntry, BundleTests, BUNDLE_SCHEMA_VERSION, DatasetBundle,
    Provenance, TestVerdict, Versioning,
};
use evorule_hash;
use serde_json::json;

/// 用例 1：源等价 —— evorule-hash 字节级等于 reactor 的 blake3 原语
#[test]
fn hash_digest_matches_frozen_reactor_blake3() {
    let cases: &[&[u8]] = &[
        b"",
        b"evorule",
        b"hello world",
        b"audit-chain-must-not-break",
        &[0u8; 64],
        &[0xffu8; 128],
    ];
    for c in cases {
        let reactor = blake3::hash(c).to_hex().to_string();
        let ours = evorule_hash::digest(c);
        assert_eq!(
            reactor, ours,
            "BLAKE3 primitive must byte-match evorule-reactor (frozen audit-chain source of truth); input len = {}",
            c.len()
        );
    }
}

/// 用例 2：前缀契约 —— prefixed 必须包装为 `blake3:` 自描述前缀
#[test]
fn prefixed_wraps_blake3_prefix() {
    let d = evorule_hash::digest(b"x");
    let p = evorule_hash::prefixed(&d);
    assert!(p.starts_with("blake3:"), "expected blake3: prefix, got {p}");
    assert_eq!(p, format!("blake3:{d}"));
    // 内部值确为纯 64-hex BLAKE3（无前缀）
    assert_eq!(d.len(), 64);
    assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
}

/// 用例 3：json_digest 内部一致性 —— 等于对规范化 JSON 字符串的 digest
#[test]
fn json_digest_is_blake3_of_canonical_json() {
    let v = json!({"b": 1, "a": 2, "nested": {"z": true, "y": null}});
    let s = serde_json::to_string(&v).unwrap();
    assert_eq!(
        evorule_hash::json_digest(&v),
        evorule_hash::digest(s.as_bytes())
    );
}

/// 用例 4：黄金向量锁定（与 evorule-hash 自身单测一致，防止静默算法漂移）
#[test]
fn golden_vectors_locked() {
    assert_eq!(
        evorule_hash::digest(b"evorule"),
        "7758f03680f4593e860eb2fc5257cc78d78563d315debde26be7bdb82f18bed4"
    );
    assert_eq!(
        evorule_hash::json_digest(&json!("evorule")),
        "c729d1c3521cd898b82af3808bbcc747758fc8b87b0236354cb232e3dde18236"
    );
}

/// 用例 5：消费契约 —— bundle 正确消费 evorule-hash，产出 blake3: 前缀且内部等于 json_digest(canonical)
#[test]
fn bundle_consumes_evorule_hash() {
    let mut b = DatasetBundle {
        bundle_schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: "bundle-itest-1".into(),
        dataset: BundleDatasetMeta {
            dataset_id: "ds-itest".into(),
            name: "itest".into(),
            tenant_id: "org-evorule".into(),
            instance_id: "org-evorule".into(),
            versioning: Versioning::default(),
            version_selection: None,
            law_ref: None,
            view_of: None,
        },
        entries: vec![BundleEntry {
            entry_id: "e1".into(),
            rule_body: json!({"transform": [{"type": "set", "params": {"attr": "x", "value": 1}}]}),
            provenance: Provenance {
                source: "itest-source".into(),
                clause: None,
                document_id: None,
                effective_from: None,
                effective_to: None,
                last_verified: None,
                verified_by: None,
            },
            domain: "d".into(),
            tags: vec![],
            dependencies: vec![],
        }],
        data_dependencies: None,
        tests: BundleTests {
            subset: vec![],
            fixtures: vec![],
            verdict: TestVerdict::Pass,
        },
        audit: BundleAudit {
            exported_at: "2026-08-25T00:00:00Z".into(),
            exported_by: "itest".into(),
            source_version: "v1".into(),
            content_hash: String::new(),
            hash_algo: "blake3".into(),
        },
    };

    let h = b.compute_content_hash();
    assert!(
        h.starts_with("blake3:"),
        "bundle content_hash must be blake3-prefixed, got {h}"
    );

    // 内部值必须等于规范化（content_hash 清空）后的 json_digest
    b.audit.content_hash.clear();
    let inner = evorule_hash::json_digest(&b);
    assert_eq!(h, format!("blake3:{inner}"));

    // 回填后可被 verify_content_hash 校验通过（自洽）
    b.audit.content_hash = h.clone();
    assert!(
        b.verify_content_hash().is_ok(),
        "recomputed hash must verify_content_hash"
    );
}
