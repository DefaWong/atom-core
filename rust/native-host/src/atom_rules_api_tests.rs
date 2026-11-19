use atomdns_upstream_core::TransportCancellation;

use super::{handle, mutates, path_segments};
use crate::assembly::{HostAssembly, HostOptions};

const YAML: &str = r"log: {level: error}
plugins:
  - tag: cache_all
    type: cache
    args: {size: 64}
  - tag: blocked
    type: domain_set
    args: {exps: ['full:blocked.example']}
  - tag: domestic
    type: forward
    args: {upstreams: [{addr: 'udp://127.0.0.1:15000'}]}
  - tag: atom_rules
    type: atom_rules
    args:
      marks: {proxy: 41, direct: 42, block: 40}
      builtin: [blocked]
  - tag: main
    type: sequence
    args:
      - exec: $atom_rules
      - exec: $cache_all
      - exec: $domestic
  - tag: listener
    type: udp_server
    args: {entry: main, listen: '127.0.0.1:3099'}
";

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("atom-rules-api-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Api {
    assembly: HostAssembly,
    root: std::path::PathBuf,
}

impl Api {
    fn new(name: &str) -> Self {
        Self::with_yaml(name, YAML)
    }

    fn with_yaml(name: &str, yaml: &str) -> Self {
        let root = scratch(name);
        let config = crate::config::compile_yaml_with_base(yaml, &root).expect("config");
        let assembly = HostAssembly::with_options(config, HostOptions::default()).unwrap();
        Self { assembly, root }
    }

    fn call(&self, method: &str, target: &str, body: &str) -> (u16, serde_json::Value) {
        let reply = self
            .assembly
            .block_on(handle(
                None,
                self.assembly.config(),
                self.assembly.cache(),
                method,
                target,
                body.as_bytes(),
                &TransportCancellation::new(),
            ))
            .expect("an atom route");
        let value = serde_json::from_slice(&reply.body).unwrap_or(serde_json::Value::Null);
        (reply.status, value)
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn only_writes_take_the_management_lease() {
    assert!(mutates("POST", "/api/v1/atom/rules"));
    assert!(mutates("POST", "/api/v1/atom/rules/move"));
    assert!(mutates("PUT", "/api/v1/atom/rules/r-1"));
    assert!(mutates("DELETE", "/api/v1/atom/rulesets/rs-1"));
    assert!(!mutates("POST", "/api/v1/atom/rules/test"));
    assert!(!mutates("GET", "/api/v1/atom/rules"));
    assert!(!mutates("POST", "/api/v1/upstream/config"));
}

#[test]
fn crud_move_and_test_over_http_shapes() {
    let api = Api::new("crud");
    let (status, list) = api.call("GET", "/api/v1/atom/rules", "");
    assert_eq!(status, 200);
    assert_eq!(list["version"], 0);
    assert_eq!(
        list["rules"].as_array().unwrap().len(),
        0,
        "no defaults without the corrections"
    );

    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"remark": "视频", "match": {"suffix": ["video.example"]},
            "action": {"type": "proxy", "group_id": "g-v"}, "version": 0}"#,
    );
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["version"], 1);
    let proxied = created["rule"]["id"].as_str().unwrap().to_owned();
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"domain": ["www.video.example"], "ruleset": ["blocked"]},
            "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201, "{created}");
    let direct = created["rule"]["id"].as_str().unwrap().to_owned();

    let test = |name: &str| {
        api.call(
            "POST",
            "/api/v1/atom/rules/test",
            &format!(r#"{{"domain": "{name}"}}"#),
        )
        .1
    };
    let hit = test("www.video.example");
    assert_eq!(
        (hit["action"].clone(), hit["group_id"].clone()),
        ("proxy".into(), "g-v".into())
    );
    assert_eq!(
        test("blocked.example")["action"],
        "direct",
        "builtin domain_set"
    );
    assert_eq!(test("nothing.example")["matched"], false);

    // A stale move is refused in the host error form, with the version.
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules/move",
        &format!(r#"{{"id": "{direct}", "before_id": "{proxied}", "version": 1}}"#),
    );
    assert_eq!(status, 409);
    assert!(refused["error"].is_string());
    assert_eq!(refused["version"], 2);
    let (status, moved) = api.call(
        "POST",
        "/api/v1/atom/rules/move",
        &format!(r#"{{"id": "{direct}", "before_id": "{proxied}", "version": 2}}"#),
    );
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["version"], 3);
    assert_eq!(moved["rules"][0]["id"], direct.as_str());
    assert_eq!(test("www.video.example")["action"], "direct");
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/rules/move",
        &format!(r#"{{"id": "{direct}", "before_id": "{proxied}"}}"#),
    );
    assert_eq!(status, 400, "move needs a version");

    let (status, replaced) = api.call(
        "PUT",
        &format!("/api/v1/atom/rules/{proxied}"),
        r#"{"enabled": false, "match": {"suffix": ["video.example"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(test("a.video.example")["matched"], false, "disabled");
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_cidr": ["1.2.3.0/24"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 400);
    assert!(refused["error"].as_str().unwrap().contains("ip_cidr"));
    let (status, _) = api.call(
        "DELETE",
        &format!("/api/v1/atom/rules/{proxied}?version=1"),
        "",
    );
    assert_eq!(status, 409);
    let (status, deleted) = api.call(
        "DELETE",
        &format!("/api/v1/atom/rules/{proxied}?version=4"),
        "",
    );
    assert_eq!((status, deleted["version"].clone()), (200, 5.into()));
    let (status, _) = api.call("PATCH", "/api/v1/atom/rules", "");
    assert_eq!(status, 405);
    assert!(api.root.join(crate::atom_rules::RULES_FILE).exists());
}

#[test]
fn a_proxy_rule_with_a_client_is_refused_in_chinese() {
    let api = Api::new("client-proxy");
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["video.example"], "client": ["192.168.1.0/24"]},
            "action": {"type": "proxy", "group_id": "g-v"}}"#,
    );
    assert_eq!(status, 400);
    let message = refused["error"].as_str().unwrap();
    assert!(
        message.contains("client") && message.contains("直连或屏蔽"),
        "{message}"
    );
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["video.example"], "client": ["192.168.1.0/24"]},
            "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201, "{created}");
    let id = created["rule"]["id"].as_str().unwrap().to_owned();
    let (status, _) = api.call(
        "PUT",
        &format!("/api/v1/atom/rules/{id}"),
        r#"{"match": {"client": ["192.168.1.0/24"]}, "action": {"type": "proxy", "group_id": "g-v"}}"#,
    );
    assert_eq!(status, 400);
}

/// A cache with a dump file, so a flush has to persist.
const DUMP_YAML: &str = r"log: {level: error}
plugins:
  - tag: cache_all
    type: cache
    args: {size: 64, dump_file: cache/all.dump}
  - tag: domestic
    type: forward
    args: {upstreams: [{addr: 'udp://127.0.0.1:15000'}]}
  - tag: atom_rules
    type: atom_rules
    args:
      marks: {proxy: 41, direct: 42, block: 40}
  - tag: main
    type: sequence
    args:
      - exec: $atom_rules
      - exec: $cache_all
      - exec: $domestic
  - tag: listener
    type: udp_server
    args: {entry: main, listen: '127.0.0.1:3098'}
";

fn query_and_answer() -> (Vec<u8>, Vec<u8>) {
    let mut raw = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    raw.extend_from_slice(b"\x01a\x07example\x00\x00\x01\x00\x01");
    let mut wire = raw.clone();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[7] = 1;
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
    (raw, wire)
}

#[test]
fn a_flush_that_cannot_persist_still_drops_the_old_entries() {
    let api = Api::with_yaml("flush-fallback", DUMP_YAML);
    let dump = api.assembly.config().caches[0].dump_file.clone().unwrap();
    std::fs::create_dir_all(dump.parent().unwrap()).unwrap();
    let store = api.assembly.cache().get(crate::config::CacheId(0)).unwrap();
    let (raw, response) = query_and_answer();
    if let Some(token) = store.begin_store(&raw).unwrap() {
        token.publish(&response).unwrap();
    }
    api.assembly.block_on(store.save()).unwrap();
    assert!(dump.exists(), "the old entry is on disk too");
    // The flush fails to write its empty dump; the change still succeeds,
    // with the cache discarded in memory and on disk.
    store.inject_persist_fault(crate::managed::PersistFault::Rename);
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["example"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201, "{created}");
    assert!(
        store.lookup_entry(&raw).unwrap().is_none(),
        "memory cleared"
    );
    assert!(!dump.exists(), "a restart cannot load the old entry");

    // When even the discard cannot remove the dump (here a directory), the
    // caller is told: the change is in force, the cache is not fully gone.
    if let Some(token) = store.begin_store(&raw).unwrap() {
        token.publish(&response).unwrap();
    }
    std::fs::create_dir_all(dump.join("blocker")).unwrap();
    let (status, failed) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["other.example"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 500, "{failed}");
    assert!(
        failed["error"].as_str().unwrap().contains("清空缓存失败"),
        "{failed}"
    );
    assert!(
        store.lookup_entry(&raw).unwrap().is_none(),
        "memory still cleared"
    );
    assert_eq!(api.call("GET", "/api/v1/atom/rules", "").1["version"], 2);
}

#[test]
fn rulesets_and_cache_flush() {
    let api = Api::new("rulesets");
    let (status, set) = api.call(
        "POST",
        "/api/v1/atom/rulesets",
        r#"{"name": "mine", "type": "local", "rules": ["mine.example"]}"#,
    );
    assert_eq!(status, 201, "{set}");
    let id = set["id"].as_str().unwrap().to_owned();
    let (_, list) = api.call("GET", "/api/v1/atom/rulesets", "");
    let types: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["type"].clone())
        .collect();
    assert_eq!(types, vec!["builtin", "local"]);
    let (_, shown) = api.call("GET", &format!("/api/v1/atom/rulesets/{id}"), "");
    assert_eq!(shown["rules"], serde_json::json!(["mine.example"]));

    // Fill the cache, then a change must empty it.
    let raw = {
        let mut raw = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        raw.extend_from_slice(b"\x01a\x07example\x00\x00\x01\x00\x01");
        raw
    };
    let response = {
        let mut wire = raw.clone();
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[7] = 1;
        wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
        wire
    };
    let store = api.assembly.cache().get(crate::config::CacheId(0)).unwrap();
    if let Some(token) = store.begin_store(&raw).unwrap() {
        token.publish(&response).unwrap();
    }
    assert!(store.lookup_entry(&raw).unwrap().is_some(), "cached");
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/rules",
        &format!(r#"{{"match": {{"ruleset": ["{id}"]}}, "action": {{"type": "block"}}}}"#),
    );
    assert_eq!(status, 201);
    assert!(
        store.lookup_entry(&raw).unwrap().is_none(),
        "flushed by the change"
    );
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/atom/rules/test",
            r#"{"domain": "x.mine.example"}"#
        )
        .1["action"],
        "block"
    );

    let (status, refused) = api.call("DELETE", &format!("/api/v1/atom/rulesets/{id}"), "");
    assert_eq!(status, 409);
    assert_eq!(refused["rules"].as_array().unwrap().len(), 1);
    let (status, _) = api.call(
        "PUT",
        &format!("/api/v1/atom/rulesets/{id}"),
        r#"{"rules": ["other.example"]}"#,
    );
    assert_eq!(status, 200);
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/atom/rules/test",
            r#"{"domain": "x.mine.example"}"#
        )
        .1["matched"],
        false
    );
    let (status, _) = api.call("POST", &format!("/api/v1/atom/rulesets/{id}/refresh"), "");
    assert_eq!(status, 400, "a local set has nothing to download");
    let (status, _) = api.call("POST", "/api/v1/atom/rulesets", r#"{"name": "x"}"#);
    assert_eq!(status, 400, "type is required");
}

/// Builtin sets (atom step 6b): one the original judgement needs cannot go;
/// another goes once no rule names it, or with `confirm=true`, which takes
/// it out of the rules first (a rule left with only a client condition goes
/// too). The removal survives a reload. An `ip_builtin` set is listed but
/// not usable in rules.
#[test]
fn builtin_sets_are_removed_and_confirmed_deletions_edit_the_rules() {
    let yaml = YAML
        .replace(
            "  - tag: domestic\n",
            "  - tag: geosite_cn\n    type: domain_set\n    args: {exps: ['full:cn.example']}\n  - tag: ips\n    type: domain_set\n    args: {exps: ['full:ip.example']}\n  - tag: domestic\n",
        )
        .replace(
            "      builtin: [blocked]\n",
            "      builtin: [blocked, geosite_cn]\n      ip_builtin: [ips]\n",
        );
    let api = Api::with_yaml("builtin-remove", &yaml);
    let (_, sets) = api.call("GET", "/api/v1/atom/rulesets", "");
    let view = |id: &str| sets.as_array().unwrap().iter().find(|s| s["id"] == id).cloned().unwrap();
    assert_eq!((&view("blocked")["required"], &view("blocked")["usable"]), (&serde_json::json!(false), &serde_json::json!(true)));
    assert_eq!(view("geosite_cn")["required"], true);
    assert_eq!(view("ips")["usable"], false);
    let (status, _) = api.call("POST", "/api/v1/atom/rules", r#"{"match": {"ruleset": ["ips"]}, "action": {"type": "block"}}"#);
    assert_eq!(status, 400, "an IP builtin is not for rules");
    assert_eq!(api.call("DELETE", "/api/v1/atom/rulesets/geosite_cn", "").0, 400);
    assert_eq!(
        api.call("PUT", "/api/v1/atom/rulesets/blocked", r#"{"url": "https://example.com/x.txt"}"#).0,
        400,
        "a domain_set has no download address"
    );

    let rule = |body: &str| {
        let (status, value) = api.call("POST", "/api/v1/atom/rules", body);
        assert_eq!(status, 201, "{value}");
        value["rule"]["id"].as_str().unwrap().to_owned()
    };
    let only = rule(r#"{"match": {"ruleset": ["blocked"]}, "action": {"type": "block"}}"#);
    let with_name = rule(r#"{"match": {"ruleset": ["blocked"], "suffix": ["a.example"]}, "action": {"type": "block"}}"#);
    let with_client = rule(r#"{"match": {"ruleset": ["blocked"], "client": ["192.168.1.9"]}, "action": {"type": "direct"}}"#);
    let (status, refused) = api.call("DELETE", "/api/v1/atom/rulesets/blocked", "");
    assert_eq!(status, 409, "{refused}");
    assert_eq!(refused["rules"].as_array().unwrap().len(), 3);
    let (status, deleted) = api.call("DELETE", "/api/v1/atom/rulesets/blocked?confirm=true", "");
    assert_eq!(status, 200, "{deleted}");
    let (_, table) = api.call("GET", "/api/v1/atom/rules", "");
    let ids: Vec<&str> = table["rules"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert!(!ids.contains(&only.as_str()) && !ids.contains(&with_client.as_str()), "{table}");
    let kept = table["rules"].as_array().unwrap().iter().find(|r| r["id"] == with_name.as_str()).unwrap();
    assert_eq!(kept["match"], serde_json::json!({"suffix": ["a.example"]}));
    let (_, sets) = api.call("GET", "/api/v1/atom/rulesets", "");
    assert!(sets.as_array().unwrap().iter().all(|s| s["id"] != "blocked"), "{sets}");
    assert_eq!(
        api.call("POST", "/api/v1/atom/rules", r#"{"match": {"ruleset": ["blocked"]}, "action": {"type": "block"}}"#).0,
        400
    );
    let again = crate::config::compile_yaml_with_base(&yaml, &api.root).expect("reloads");
    let rules = again.local.atom_rules.as_deref().unwrap();
    assert!(!rules.builtin_names().contains(&"blocked".to_owned()), "the removal is saved");

    // A custom set, confirmed: the same edit of the rules.
    let (status, local) = api.call("POST", "/api/v1/atom/rulesets", r#"{"name": "名单", "type": "local", "rules": ["b.example"]}"#);
    assert_eq!(status, 201, "{local}");
    let id = local["id"].as_str().unwrap().to_owned();
    rule(&format!(r#"{{"match": {{"ruleset": ["{id}"]}}, "action": {{"type": "direct"}}}}"#));
    assert_eq!(api.call("DELETE", &format!("/api/v1/atom/rulesets/{id}"), "").0, 409);
    assert_eq!(api.call("DELETE", &format!("/api/v1/atom/rulesets/{id}?confirm=true"), "").0, 200);
    assert_eq!(api.call("GET", &format!("/api/v1/atom/rulesets/{id}"), "").0, 404);
}

#[test]
fn path_segments_are_decoded_after_the_split() {
    let segments = |path: &str| path_segments(path).unwrap();
    assert_eq!(segments("rulesets/bm7%3AClaude/refresh"), ["rulesets", "bm7:Claude", "refresh"]);
    // A decoded `/` stays inside its segment; `+` is itself in a path.
    assert_eq!(segments("rulesets/a%2Fb+c"), ["rulesets", "a/b+c"]);
    assert_eq!(segments("upstreams/%E5%9B%BD%E5%86%85"), ["upstreams", "国内"]);
    assert_eq!(segments("upstreams/%EF%BF%BD"), ["upstreams", "\u{fffd}"]);
    // Not UTF-8, or a broken escape: refused.
    assert_eq!(path_segments("upstreams/%FF"), None);
    assert_eq!(path_segments("upstreams/a%2"), None);
    // The lease decision reads the same decoded segments as the dispatch: an
    // encoded `settings` still takes no outer lease.
    assert!(!mutates("PUT", "/api/v1/atom/%73ettings"));
    assert!(!mutates("POST", "/api/v1/atom/rules/%74est"));
    assert!(mutates("PUT", "/api/v1/atom/rulesets/bm7%3AClaude"));
    assert!(!mutates("PUT", "/api/v1/atom/rulesets/corp%FF"));
}

/// A plain HTTP server for downloads: `/list.txt` is a domain list, anything
/// else 404.
fn serve_lists() -> u16 {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 2048];
            let read = stream.read(&mut request).unwrap_or(0);
            let head = String::from_utf8_lossy(&request[..read]);
            let reply = if head.starts_with("GET /list.txt ") {
                let body = "a.example\nb.example\n";
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    port
}

/// A builtin set with one source: its auto-update settings are edited and
/// saved in the manifest; a download through a proxy that does not answer is
/// tried directly; a failed one names its reason.
#[test]
fn builtin_sources_are_edited_and_downloads_fall_back_to_direct() {
    let port = serve_lists();
    let root = scratch("builtin-source");
    std::fs::create_dir_all(root.join("srs")).unwrap();
    std::fs::write(
        root.join("srs/cn.json"),
        format!(
            r#"[{{"name": "cn", "type": "geositecn", "files": "srs/cn.txt", "url": "http://127.0.0.1:{port}/list.txt", "format": "text", "enabled": true, "auto_update": false, "update_interval_hours": 24}}]"#
        ),
    )
    .unwrap();
    let with_proxy = |proxy: &str| {
        YAML.replace(
            "  - tag: domestic\n",
            // Port 1 refuses: the proxy is down.
            &format!("  - tag: main_proxy\n    type: socks5_proxy\n    args: {{addr: '127.0.0.1:1'}}\n  - tag: cn_sites\n    type: sd_set_light\n    args: {{{proxy}, local_config: 'srs/cn.json'}}\n  - tag: unified\n    type: domain_mapper\n    args: {{rules: [{{tag: cn_sites, mark: 9, output_tag: cn}}]}}\n  - tag: domestic\n"),
        )
        .replace("      builtin: [blocked]\n", "      mapper: unified\n      builtin: [blocked, cn_sites]\n")
    };
    // A proxy of its own is not `main_proxy`: its failure is the answer.
    {
        let own = scratch("builtin-source-own-proxy");
        std::fs::create_dir_all(own.join("srs")).unwrap();
        std::fs::copy(root.join("srs/cn.json"), own.join("srs/cn.json")).unwrap();
        let config = crate::config::compile_yaml_with_base(&with_proxy("socks5: '127.0.0.1:1'"), &own).expect("config");
        let assembly = HostAssembly::with_options(config, HostOptions::default()).unwrap();
        let api = Api { assembly, root: own };
        let (status, failed) = api.call("POST", "/api/v1/atom/rulesets/cn_sites/refresh", "");
        assert_eq!(status, 502, "{failed}");
        assert!(!failed["error"].as_str().unwrap().contains("直连"), "{failed}");
        assert!(!api.root.join("srs/cn.txt").exists());
    }
    let config = crate::config::compile_yaml_with_base(&with_proxy("proxy: $main_proxy"), &root).expect("config");
    let assembly = HostAssembly::with_options(config, HostOptions::default()).unwrap();
    let api = Api { assembly, root };

    let view = || {
        let (_, sets) = api.call("GET", "/api/v1/atom/rulesets", "");
        sets.as_array().unwrap().iter().find(|s| s["id"] == "cn_sites").cloned().unwrap()
    };
    assert_eq!((&view()["auto_update"], &view()["update_interval_hours"]), (&serde_json::json!(false), &serde_json::json!(24)));

    let (status, edited) = api.call(
        "PUT",
        "/api/v1/atom/rulesets/cn_sites",
        r#"{"auto_update": true, "update_interval_hours": 6}"#,
    );
    assert_eq!(status, 200, "{edited}");
    assert_eq!((&edited["auto_update"], &edited["update_interval_hours"]), (&serde_json::json!(true), &serde_json::json!(6)));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(api.root.join("srs/cn.json")).unwrap()).unwrap();
    assert_eq!((&manifest[0]["auto_update"], &manifest[0]["update_interval_hours"]), (&serde_json::json!(true), &serde_json::json!(6)));
    assert!(!api.root.join("srs/cn.txt").exists(), "no new address: nothing downloaded");
    for hours in [0, 8761] {
        let body = format!(r#"{{"update_interval_hours": {hours}}}"#);
        assert_eq!(api.call("PUT", "/api/v1/atom/rulesets/cn_sites", &body).0, 400, "{hours}");
    }

    let (status, refreshed) = api.call("POST", "/api/v1/atom/rulesets/cn_sites/refresh", "");
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(refreshed["updated"], 1, "the direct retry downloaded it: {refreshed}");
    assert!(api.root.join("srs/cn.txt").exists());

    let missing = format!(r#"{{"url": "http://127.0.0.1:{port}/missing.txt"}}"#);
    let (status, failed) = api.call("PUT", "/api/v1/atom/rulesets/cn_sites", &missing);
    assert_eq!(status, 502, "{failed}");
    let reason = failed["error"].as_str().unwrap();
    assert!(reason.contains("经代理") && reason.contains("直连: bad status: 404"), "{reason}");
    assert!(!reason.contains("见日志"), "{reason}");
    let (status, failed) = api.call("POST", "/api/v1/atom/rulesets/cn_sites/refresh", "");
    assert_eq!(status, 502, "{failed}");
    assert!(failed["error"].as_str().unwrap().contains("cn: "), "{failed}");
    assert_eq!(view()["url"], format!("http://127.0.0.1:{port}/missing.txt"), "the address is kept");
    assert_eq!(api.call("GET", "/api/v1/atom/rulesets/cn_sites%FF", "").0, 400);
}
