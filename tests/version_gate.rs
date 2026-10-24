//! 跨仓 evorule-hash 版本一致性闸
//!
//! 断言 bundle / rule / server 三仓全部 Cargo.toml 中对 evorule-hash 的
//! 版本要求完全一致且 >= 0.1.4（契约层下限），防止钉旧版导致的口径/
//! 许可漂移（0.1.3 曾以 Apache-2.0 短暂发布，钉旧版注意许可口径）。
//! 兄弟仓缺失或无可解析声明即红（fail-fast，门禁自身不可降级）。
//! 布局要求：兄弟仓平级检出（bundle CI cross-repo-gates 已保证；
//! 本地运行需各仓与 integration-tests 平级）。

use std::fs;
use std::path::{Path, PathBuf};

const SIBLINGS: [&str; 3] = ["evorule-bundle", "evorule-rule", "evorule-server"];
const FLOOR: (u64, u64, u64) = (0, 1, 4);

fn sibling_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration-tests manifest must have a parent dir")
        .to_path_buf()
}

/// 提取单个 Cargo.toml 中 evorule-hash 的版本要求。注释行与无 version 的
/// path/patch 形态不计；支持 `evorule-hash = "x.y.z"` 与
/// `evorule-hash = { version = "x.y.z", ... }`。
fn extract_hash_req(text: &str) -> Vec<String> {
    let mut reqs = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || !t.starts_with("evorule-hash") {
            continue;
        }
        let rest = match t["evorule-hash".len()..].trim_start().strip_prefix('=') {
            Some(r) => r.trim(),
            None => continue, // 形如 evorule-hash.workspace = true，无独立版本要求
        };
        let version = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next().map(str::to_string)
        } else if let Some(idx) = rest.find("version") {
            rest[idx..].split('"').nth(1).map(str::to_string)
        } else {
            None // { path = ... } patch 形态，无版本要求
        };
        if let Some(v) = version {
            reqs.push(v);
        }
    }
    reqs
}

fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim_start_matches('^').trim_start_matches('~');
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// 遍历兄弟仓全部 Cargo.toml（跳 .git / target* / node_modules），
/// 收集 (文件路径, evorule-hash 版本要求)。
fn collect_repo_reqs(repo: &str) -> Vec<(String, String)> {
    let root = sibling_root().join(repo);
    assert!(
        root.join("Cargo.toml").is_file(),
        "兄弟仓未平级检出: {repo}（CI 需 checkout；本地需平级布局）——version_gate 无法验证即拒绝"
    );
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if path.is_dir() {
                if matches!(name.as_str(), ".git" | "node_modules") || name.starts_with("target") {
                    continue;
                }
                stack.push(path);
            } else if name == "Cargo.toml" {
                let text = fs::read_to_string(&path).expect("read Cargo.toml");
                for req in extract_hash_req(&text) {
                    found.push((path.display().to_string(), req));
                }
            }
        }
    }
    found
}

#[test]
fn evorule_hash_version_requirements_are_consistent() {
    let mut all: Vec<(String, String)> = Vec::new();
    for repo in SIBLINGS {
        let reqs = collect_repo_reqs(repo);
        assert!(
            !reqs.is_empty(),
            "{repo} 未找到任何 evorule-hash 版本要求声明——契约层要求 hash >= 0.1.4"
        );
        all.extend(reqs);
    }
    let first = all[0].1.clone();
    for (path, req) in &all {
        assert_eq!(
            req, &first,
            "evorule-hash 版本要求漂移: {path} 声明 {req}，基准 {first}——钉旧版会引入口径/许可漂移"
        );
    }
    let parsed = parse_semver(&first).unwrap_or_else(|| panic!("版本要求不可解析: {first}"));
    assert!(
        parsed >= FLOOR,
        "evorule-hash 版本要求 {first} 低于契约层下限 0.1.4"
    );
}
