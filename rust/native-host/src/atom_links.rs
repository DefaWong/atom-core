//! atom fork: node import (design §5.1). Three inputs, one output, the
//! sing-box outbound (without `tag`) and a display name:
//!
//! - `json`: one sing-box outbound, an array of them, or a whole sing-box
//!   configuration (its proxy outbounds are taken, groups and the like
//!   skipped). The `tag` becomes the name.
//! - `yaml`: Clash/mihomo `proxies` (a whole configuration, the list, or one
//!   proxy).
//! - `link`: share links, one per line: `vless://`, `vmess://`, `trojan://`,
//!   `ss://`, `hysteria2://` (`hy2://`), `tuic://`, `anytls://`, `socks://`
//!   (`socks5://`, `socks5h://`).
//!
//! An import is all or nothing: the first entry that cannot be converted is
//! the error, with its position.

use serde_json::{Map, Value, json};

use crate::atom_proxy::Node;

pub(crate) type Imported = (String, Map<String, Value>);

fn obj(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

// ---------------------------------------------------------------------------
// Small decoders
// ---------------------------------------------------------------------------

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Standard or URL-safe base64, padding optional.
fn base64_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let trimmed = cleaned.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .ok()
}

fn base64_text(value: &str) -> Option<String> {
    String::from_utf8(base64_decode(value)?).ok()
}

// ---------------------------------------------------------------------------
// Shared sing-box pieces
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Tls {
    enabled: bool,
    server_name: String,
    insecure: bool,
    alpn: Vec<String>,
    fingerprint: String,
    reality_key: String,
    reality_short_id: String,
    disable_sni: bool,
}

impl Tls {
    fn value(&self) -> Option<Value> {
        if !self.enabled {
            return None;
        }
        let mut tls = Map::new();
        tls.insert("enabled".into(), json!(true));
        if !self.server_name.is_empty() {
            tls.insert("server_name".into(), json!(self.server_name));
        }
        if self.insecure {
            tls.insert("insecure".into(), json!(true));
        }
        if self.disable_sni {
            tls.insert("disable_sni".into(), json!(true));
        }
        if !self.alpn.is_empty() {
            tls.insert("alpn".into(), json!(self.alpn));
        }
        // REALITY needs uTLS; sing-box refuses it without.
        let fingerprint = if self.fingerprint.is_empty() && !self.reality_key.is_empty() {
            "chrome"
        } else {
            self.fingerprint.as_str()
        };
        if !fingerprint.is_empty() {
            tls.insert(
                "utls".into(),
                json!({"enabled": true, "fingerprint": fingerprint}),
            );
        }
        if !self.reality_key.is_empty() {
            let mut reality = Map::new();
            reality.insert("enabled".into(), json!(true));
            reality.insert("public_key".into(), json!(self.reality_key));
            if !self.reality_short_id.is_empty() {
                reality.insert("short_id".into(), json!(self.reality_short_id));
            }
            tls.insert("reality".into(), Value::Object(reality));
        }
        Some(Value::Object(tls))
    }
}

fn alpn_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A V2Ray transport: `ws`, `grpc`, `httpupgrade`, `http` (h2); plain TCP
/// has none.
fn transport(kind: &str, host: &str, path: &str, service: &str) -> Result<Option<Value>, String> {
    Ok(match kind {
        "" | "tcp" | "raw" | "none" => None,
        "ws" | "websocket" => {
            let mut ws = Map::new();
            ws.insert("type".into(), json!("ws"));
            if !path.is_empty() {
                ws.insert("path".into(), json!(path));
            }
            if !host.is_empty() {
                ws.insert("headers".into(), json!({"Host": host}));
            }
            Some(Value::Object(ws))
        }
        "grpc" => Some(json!({"type": "grpc", "service_name": service})),
        "httpupgrade" => {
            let mut upgrade = Map::new();
            upgrade.insert("type".into(), json!("httpupgrade"));
            if !host.is_empty() {
                upgrade.insert("host".into(), json!(host));
            }
            if !path.is_empty() {
                upgrade.insert("path".into(), json!(path));
            }
            Some(Value::Object(upgrade))
        }
        "h2" | "http" => {
            let mut http = Map::new();
            http.insert("type".into(), json!("http"));
            if !host.is_empty() {
                http.insert("host".into(), json!(alpn_list(host)));
            }
            if !path.is_empty() {
                http.insert("path".into(), json!(path));
            }
            Some(Value::Object(http))
        }
        other => return Err(format!("不支持的传输方式 `{other}`")),
    })
}

fn base(kind: &str, server: &str, port: u16) -> Result<Map<String, Value>, String> {
    let server = server.trim().trim_start_matches('[').trim_end_matches(']');
    if server.is_empty() {
        return Err("缺少服务器地址".into());
    }
    if port == 0 && kind != "hysteria2" {
        return Err("缺少端口".into());
    }
    let mut outbound = Map::new();
    outbound.insert("type".into(), json!(kind));
    outbound.insert("server".into(), json!(server));
    if port != 0 {
        outbound.insert("server_port".into(), json!(port));
    }
    Ok(outbound)
}

fn put(outbound: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        outbound.insert(key.into(), value);
    }
}

fn default_name(outbound: &Map<String, Value>) -> String {
    let kind = outbound
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("node");
    let server = outbound.get("server").and_then(Value::as_str).unwrap_or("");
    let port = outbound
        .get("server_port")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if server.is_empty() {
        kind.to_owned()
    } else {
        format!("{kind} {server}:{port}")
    }
}

/// A display name: trimmed, control characters removed, at most 64 chars.
fn clean_name(name: &str, outbound: &Map<String, Value>) -> String {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(64)
        .collect();
    let name = name.trim().to_owned();
    if name.is_empty() {
        default_name(outbound)
    } else {
        name
    }
}

// ---------------------------------------------------------------------------
// Share links
// ---------------------------------------------------------------------------

struct Link {
    user: String,
    password: String,
    host: String,
    port: u16,
    query: Vec<(String, String)>,
    name: String,
}

impl Link {
    fn get(&self, key: &str) -> &str {
        self.query
            .iter()
            .find(|(name, _)| name == key)
            .map_or("", |(_, value)| value.as_str())
    }

    fn any(&self, keys: &[&str]) -> &str {
        keys.iter()
            .map(|key| self.get(key))
            .find(|value| !value.is_empty())
            .unwrap_or("")
    }

    fn flag(&self, keys: &[&str]) -> bool {
        matches!(self.any(keys), "1" | "true" | "True" | "TRUE")
    }

    fn tls_common(&self, enabled: bool) -> Tls {
        Tls {
            enabled,
            server_name: self.any(&["sni", "peer", "servername"]).to_owned(),
            insecure: self.flag(&[
                "allowInsecure",
                "insecure",
                "allow_insecure",
                "skip-cert-verify",
            ]),
            alpn: alpn_list(self.get("alpn")),
            fingerprint: self.get("fp").to_owned(),
            ..Tls::default()
        }
    }
}

fn parse_link_url(link: &str) -> Result<Link, String> {
    let parsed = url::Url::parse(link).map_err(|error| format!("链接无法解析: {error}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "链接缺少服务器地址".to_owned())?
        .to_owned();
    let port = parsed.port().ok_or_else(|| "链接缺少端口".to_owned())?;
    Ok(Link {
        user: percent_decode(parsed.username()),
        password: percent_decode(parsed.password().unwrap_or("")),
        host,
        port,
        query: parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
        name: percent_decode(parsed.fragment().unwrap_or("")),
    })
}

fn vless_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("vless 链接缺少 uuid".into());
    }
    let mut outbound = base("vless", &link.host, link.port)?;
    outbound.insert("uuid".into(), json!(link.user));
    let flow = link.get("flow");
    if !flow.is_empty() {
        outbound.insert("flow".into(), json!(flow));
    }
    let security = link.get("security");
    let mut tls = link.tls_common(matches!(security, "tls" | "reality" | "xtls"));
    if security == "reality" {
        tls.reality_key = link.get("pbk").to_owned();
        tls.reality_short_id = link.get("sid").to_owned();
        if tls.reality_key.is_empty() {
            return Err("reality 链接缺少 pbk".into());
        }
    }
    put(&mut outbound, "tls", tls.value());
    let kind = link.get("type");
    let path = link.get("path");
    let service = link.any(&["serviceName", "service_name"]);
    put(
        &mut outbound,
        "transport",
        transport(
            kind,
            link.get("host"),
            path,
            if service.is_empty() { path } else { service },
        )?,
    );
    outbound.insert("packet_encoding".into(), json!("xudp"));
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn trojan_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("trojan 链接缺少密码".into());
    }
    let mut outbound = base("trojan", &link.host, link.port)?;
    outbound.insert("password".into(), json!(link.user));
    // TLS unless explicitly off.
    let security = link.get("security");
    let mut tls = link.tls_common(security != "none");
    if security == "reality" {
        tls.reality_key = link.get("pbk").to_owned();
        tls.reality_short_id = link.get("sid").to_owned();
    }
    put(&mut outbound, "tls", tls.value());
    let path = link.get("path");
    let service = link.any(&["serviceName", "service_name"]);
    put(
        &mut outbound,
        "transport",
        transport(
            link.get("type"),
            link.get("host"),
            path,
            if service.is_empty() { path } else { service },
        )?,
    );
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn hysteria2_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    let password = if link.password.is_empty() {
        link.user.clone()
    } else {
        format!("{}:{}", link.user, link.password)
    };
    let mut outbound = base("hysteria2", &link.host, link.port)?;
    if !password.is_empty() {
        outbound.insert("password".into(), json!(password));
    }
    let obfs = link.get("obfs");
    if !obfs.is_empty() && obfs != "none" {
        outbound.insert(
            "obfs".into(),
            json!({"type": obfs, "password": link.get("obfs-password")}),
        );
    }
    put(&mut outbound, "tls", link.tls_common(true).value());
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn tuic_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("tuic 链接缺少 uuid".into());
    }
    let mut outbound = base("tuic", &link.host, link.port)?;
    outbound.insert("uuid".into(), json!(link.user));
    if !link.password.is_empty() {
        outbound.insert("password".into(), json!(link.password));
    }
    let congestion = link.any(&["congestion_control", "congestion-control"]);
    if !congestion.is_empty() {
        outbound.insert("congestion_control".into(), json!(congestion));
    }
    let relay = link.any(&["udp_relay_mode", "udp-relay-mode"]);
    if !relay.is_empty() {
        outbound.insert("udp_relay_mode".into(), json!(relay));
    }
    let mut tls = link.tls_common(true);
    tls.disable_sni = link.flag(&["disable_sni", "disable-sni"]);
    put(&mut outbound, "tls", tls.value());
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn anytls_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("anytls 链接缺少密码".into());
    }
    let mut outbound = base("anytls", &link.host, link.port)?;
    outbound.insert("password".into(), json!(link.user));
    put(&mut outbound, "tls", link.tls_common(true).value());
    Ok((clean_name(&link.name, &outbound), outbound))
}

/// `socks://`, `socks5://`, `socks5h://`: a SOCKS5 outbound (the name is
/// resolved by the server either way). The userinfo is `user:pass`, or
/// base64 of it (V2RayN).
fn socks_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    let (username, password) = if link.password.is_empty() && !link.user.is_empty() {
        match base64_text(&link.user).and_then(|text| {
            text.split_once(':')
                .map(|(user, pass)| (user.to_owned(), pass.to_owned()))
        }) {
            Some(pair) => pair,
            None => (link.user.clone(), String::new()),
        }
    } else {
        (link.user.clone(), link.password.clone())
    };
    let mut outbound = base("socks", &link.host, link.port)?;
    outbound.insert("version".into(), json!("5"));
    if !username.is_empty() {
        outbound.insert("username".into(), json!(username));
    }
    if !password.is_empty() {
        outbound.insert("password".into(), json!(password));
    }
    Ok((clean_name(&link.name, &outbound), outbound))
}

/// `vmess://` + base64 of the V2RayN JSON (`add`, `port`, `id`, `aid`,
/// `scy`, `net`, `host`, `path`, `tls`, `sni`, `alpn`, `fp`, `ps`).
fn vmess_link(link: &str) -> Result<Imported, String> {
    let body = link.trim_start_matches("vmess://");
    let body = body.split('#').next().unwrap_or("");
    let text = base64_text(body).ok_or_else(|| "vmess 链接不是 base64".to_owned())?;
    let value: Value =
        serde_json::from_str(&text).map_err(|error| format!("vmess 链接的 JSON 无效: {error}"))?;
    let field = |key: &str| -> String {
        match value.get(key) {
            Some(Value::String(text)) => text.trim().to_owned(),
            Some(Value::Number(number)) => number.to_string(),
            _ => String::new(),
        }
    };
    let port: u16 = field("port")
        .parse()
        .map_err(|_| "vmess 端口无效".to_owned())?;
    let mut outbound = base("vmess", &field("add"), port)?;
    let uuid = field("id");
    if uuid.is_empty() {
        return Err("vmess 链接缺少 id".into());
    }
    outbound.insert("uuid".into(), json!(uuid));
    let security = field("scy");
    outbound.insert(
        "security".into(),
        json!(if security.is_empty() {
            "auto"
        } else {
            security.as_str()
        }),
    );
    let alter: u64 = field("aid").parse().unwrap_or(0);
    if alter != 0 {
        outbound.insert("alter_id".into(), json!(alter));
    }
    let tls = Tls {
        enabled: field("tls") == "tls",
        server_name: field("sni"),
        alpn: alpn_list(&field("alpn")),
        fingerprint: field("fp"),
        ..Tls::default()
    };
    put(&mut outbound, "tls", tls.value());
    let net = field("net");
    let path = field("path");
    put(
        &mut outbound,
        "transport",
        transport(&net, &field("host"), &path, &path)?,
    );
    outbound.insert("packet_encoding".into(), json!("xudp"));
    Ok((clean_name(&field("ps"), &outbound), outbound))
}

/// `ss://`: SIP002 (`ss://base64(method:password)@host:port/?plugin=#name`,
/// or the userinfo percent-encoded in clear for 2022 ciphers) and the
/// legacy `ss://base64(method:password@host:port)#name`.
fn ss_link(link: &str) -> Result<Imported, String> {
    let rest = &link["ss://".len()..];
    let (rest, name) = match rest.split_once('#') {
        Some((rest, name)) => (rest, percent_decode(name)),
        None => (rest, String::new()),
    };
    let sip002 = if rest.contains('@') {
        rest.to_owned()
    } else {
        // Standard base64 may contain `/`: only `?` starts the tail. A `/`
        // right before `?` is most likely the SIP002-style path, so it is
        // tried without it first; either way the decoded text must name a
        // server.
        let (encoded, tail) = match rest.find('?') {
            Some(at) => rest.split_at(at),
            None => (rest, ""),
        };
        let stripped = encoded.strip_suffix('/');
        let candidates = if tail.is_empty() {
            [Some(encoded), stripped]
        } else {
            [stripped, Some(encoded)]
        };
        let decoded = candidates
            .into_iter()
            .flatten()
            .filter_map(base64_text)
            .find(|text| text.contains('@'))
            .ok_or_else(|| "ss 链接不是 base64".to_owned())?;
        let (userinfo, server) = decoded
            .rsplit_once('@')
            .ok_or_else(|| "ss 链接缺少服务器地址".to_owned())?;
        // Re-encode the clear userinfo so the URL parser keeps it intact.
        let userinfo: String = userinfo
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || byte == b':' {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect();
        format!("{userinfo}@{server}{tail}")
    };
    let parsed = parse_link_url(&format!("ss://{sip002}"))?;
    let (method, password) = if parsed.password.is_empty() {
        // base64(method:password) in the user part.
        let decoded =
            base64_text(&parsed.user).ok_or_else(|| "ss 链接的用户信息无效".to_owned())?;
        let (method, password) = decoded
            .split_once(':')
            .ok_or_else(|| "ss 链接缺少加密方式或密码".to_owned())?;
        (method.to_owned(), password.to_owned())
    } else {
        (parsed.user.clone(), parsed.password.clone())
    };
    if method.is_empty() || password.is_empty() {
        return Err("ss 链接缺少加密方式或密码".into());
    }
    let mut outbound = base("shadowsocks", &parsed.host, parsed.port)?;
    outbound.insert("method".into(), json!(method));
    outbound.insert("password".into(), json!(password));
    let plugin = parsed.get("plugin");
    if !plugin.is_empty() {
        let (plugin, options) = plugin.split_once(';').unwrap_or((plugin, ""));
        let plugin = match plugin {
            "obfs-local" | "simple-obfs" => "obfs-local",
            "v2ray-plugin" => "v2ray-plugin",
            other => return Err(format!("不支持的 ss 插件 `{other}`")),
        };
        outbound.insert("plugin".into(), json!(plugin));
        if !options.is_empty() {
            outbound.insert("plugin_opts".into(), json!(options));
        }
    }
    let name = if name.is_empty() {
        parsed.name.clone()
    } else {
        name
    };
    Ok((clean_name(&name, &outbound), outbound))
}

pub(crate) fn parse_link(link: &str) -> Result<Imported, String> {
    let link = link.trim();
    let scheme = link
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| "不是分享链接".to_owned())?;
    match scheme.as_str() {
        "vless" => vless_link(link),
        "vmess" => vmess_link(link),
        "trojan" => trojan_link(link),
        "ss" => ss_link(link),
        "hysteria2" | "hy2" => hysteria2_link(link),
        "tuic" => tuic_link(link),
        "anytls" => anytls_link(link),
        "socks" | "socks5" | "socks5h" => socks_link(link),
        other => Err(format!("不支持的链接协议 `{other}://`")),
    }
}

// ---------------------------------------------------------------------------
// Clash / mihomo proxies
// ---------------------------------------------------------------------------

fn text(proxy: &Map<String, Value>, key: &str) -> String {
    match proxy.get(key) {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

/// A credential field verbatim (no trimming: spaces may be part of it).
fn raw(proxy: &Map<String, Value>, key: &str) -> String {
    match proxy.get(key) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn truthy(proxy: &Map<String, Value>, key: &str) -> bool {
    matches!(proxy.get(key), Some(Value::Bool(true)))
        || matches!(text(proxy, key).as_str(), "true" | "1")
}

fn strings(proxy: &Map<String, Value>, key: &str) -> Vec<String> {
    match proxy.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(value)) => alpn_list(value),
        _ => Vec::new(),
    }
}

fn section(proxy: &Map<String, Value>, key: &str) -> Map<String, Value> {
    proxy
        .get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn smux_carries_udp(smux: &Map<String, Value>) -> bool {
    truthy(smux, "enabled") && !truthy(smux, "only-tcp")
}

/// mihomo `smux` (and `brutal-opts`) to sing-box `multiplex`; both are
/// sing-mux. A switched-off block is dropped.
fn clash_smux(proxy: &Map<String, Value>, kind: &str) -> Result<Option<Value>, String> {
    let smux = section(proxy, "smux");
    if !truthy(&smux, "enabled") {
        return Ok(None);
    }
    if !matches!(kind, "ss" | "vmess" | "vless" | "trojan") {
        return Err(format!("sing-box 的 {kind} 节点不支持多路复用（smux）"));
    }
    if truthy(&smux, "only-tcp") && truthy(proxy, "udp") {
        return Err("Mihomo 的 smux.only-tcp 允许独立 UDP，sing-box 无法保留这种组合".into());
    }
    if truthy(&smux, "only_tcp") {
        return Err("不支持 smux.only_tcp，请使用 Mihomo 的 only-tcp 字段".into());
    }
    let mut multiplex = Map::from_iter([("enabled".to_owned(), json!(true))]);
    let protocol = text(&smux, "protocol");
    if !protocol.is_empty() {
        multiplex.insert("protocol".into(), json!(protocol));
    }
    for (source, target) in [
        ("max-connections", "max_connections"),
        ("min-streams", "min_streams"),
        ("max-streams", "max_streams"),
    ] {
        let value = text(&smux, source);
        if !value.is_empty() {
            let number: u64 = value.parse().map_err(|_| format!("smux 的 {source} 必须是整数"))?;
            multiplex.insert(target.into(), json!(number));
        }
    }
    if truthy(&smux, "padding") {
        multiplex.insert("padding".into(), json!(true));
    }
    let brutal = section(&smux, "brutal-opts");
    if truthy(&brutal, "enabled") {
        let mut out = Map::from_iter([("enabled".to_owned(), json!(true))]);
        for (source, target) in [("up", "up_mbps"), ("down", "down_mbps")] {
            let mbps = clash_rate_mbps(&text(&brutal, source))
                .ok_or_else(|| format!("brutal-opts 的 {source} 不是有效速率"))?;
            out.insert(target.into(), json!(mbps));
        }
        multiplex.insert("brutal".into(), Value::Object(out));
    }
    Ok(Some(Value::Object(multiplex)))
}

fn packet_encoding(proxy: &Map<String, Value>, kind: &str) -> Result<&'static str, String> {
    let packet_addr = truthy(proxy, "packet-addr");
    let xudp = truthy(proxy, "xudp");
    let encoding = text(proxy, "packet-encoding");
    match (kind, encoding.as_str()) {
        ("vless", "packet" | "packetaddr") => Ok("packetaddr"),
        ("vless", "" | "xudp") => Ok(if xudp || !packet_addr { "xudp" } else { "packetaddr" }),
        ("vmess", "" | "packet" | "packetaddr" | "xudp") => {
            Ok(if xudp || encoding == "xudp" { "xudp" }
                else if packet_addr || matches!(encoding.as_str(), "packet" | "packetaddr") { "packetaddr" }
                else { "" })
        }
        _ => Err(format!("无法转换 {kind} 的 packet-encoding `{encoding}`")),
    }
}

/// A mihomo rate (`StringToBps`: a bare integer is Mbps, otherwise
/// `<n>[ ][K|M|G|T](bps|Bps)`) in whole Mbps; `None` for what mihomo reads
/// as zero or anything below 1 Mbps.
fn clash_rate_mbps(value: &str) -> Option<u64> {
    if let Ok(mbps) = value.parse::<u64>() {
        return (mbps > 0).then_some(mbps);
    }
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    let number: u64 = value[..digits].parse().ok()?;
    let rest = value[digits..].trim_start();
    let (scale, unit) = match rest.as_bytes().first()? {
        b'K' => (1e3, &rest[1..]),
        b'M' => (1e6, &rest[1..]),
        b'G' => (1e9, &rest[1..]),
        b'T' => (1e12, &rest[1..]),
        _ => (1.0, rest),
    };
    let bits = match unit {
        "bps" => number as f64 * scale,
        "Bps" => number as f64 * scale * 8.0,
        _ => return None,
    };
    let mbps = (bits / 1e6) as u64;
    (mbps > 0).then_some(mbps)
}

fn clash_tls(proxy: &Map<String, Value>, enabled: bool) -> Tls {
    let reality = section(proxy, "reality-opts");
    let mut server_name = text(proxy, "servername");
    if server_name.is_empty() {
        server_name = text(proxy, "sni");
    }
    Tls {
        enabled,
        server_name,
        insecure: truthy(proxy, "skip-cert-verify"),
        alpn: strings(proxy, "alpn"),
        fingerprint: text(proxy, "client-fingerprint"),
        reality_key: text(&reality, "public-key"),
        reality_short_id: text(&reality, "short-id"),
        disable_sni: truthy(proxy, "disable-sni"),
    }
}

fn clash_tls_options(proxy: &Map<String, Value>, enabled: bool) -> Option<Value> {
    let mut settings = clash_tls(proxy, enabled);
    let tuic = text(proxy, "type") == "tuic";
    if tuic && settings.disable_sni && !proxy.contains_key("skip-cert-verify") {
        settings.insecure = true;
    }
    let mut tls = settings.value()?;
    if let Some(pins) = proxy.get("fingerprint").and_then(Value::as_str)
        .and_then(|fingerprint| fingerprint.strip_prefix(crate::atom_mihomo::PUBLIC_KEY_PIN_PREFIX))
    {
        tls["certificate_public_key_sha256"] = json!(pins.split(',').collect::<Vec<_>>());
    }
    if tuic && proxy.contains_key("disable-sni") {
        tls["disable_sni"] = json!(settings.disable_sni);
    }

    // Mihomo uses these fields for the client identity. Its file paths are
    // relative to its own data directory, so only inline PEM is portable.
    let cert = raw(proxy, "certificate");
    let key = raw(proxy, "private-key");
    if cert.contains("-----BEGIN CERTIFICATE-----") && key.contains("PRIVATE KEY-----") {
        tls["client_certificate"] = json!(cert);
        tls["client_key"] = json!(key);
    }

    let opts = section(proxy, "ech-opts");
    if !opts.is_empty() {
        let mut ech = json!({"enabled": truthy(&opts, "enable")});
        if let Some(name) = opts.get("query-server-name") {
            ech["query_server_name"] = name.clone();
        }
        if let Some(Value::String(config)) = opts.get("config").filter(|value| *value != "") {
            ech["config"] = json!(format!("-----BEGIN ECH CONFIGS-----\n{config}\n-----END ECH CONFIGS-----\n"));
        }
        tls["ech"] = ech;
    }
    Some(tls)
}

fn clash_transport(proxy: &Map<String, Value>) -> Result<Option<Value>, String> {
    let network = text(proxy, "network");
    match network.as_str() {
        "ws" => {
            let ws = section(proxy, "ws-opts");
            let mut converted = Map::new();
            let mut headers = section(&ws, "headers");
            if truthy(&ws, "v2ray-http-upgrade") {
                converted.insert("type".into(), json!("httpupgrade"));
                if let Some(host) = headers.remove("Host") {
                    converted.insert("host".into(), host);
                }
            } else {
                converted.insert("type".into(), json!("ws"));
                for (source, target) in [("max-early-data", "max_early_data"), ("early-data-header-name", "early_data_header_name")] {
                    if let Some(value) = ws.get(source) {
                        converted.insert(target.into(), value.clone());
                    }
                }
            }
            if let Some(path) = ws.get("path") {
                converted.insert("path".into(), path.clone());
            }
            if !headers.is_empty() {
                converted.insert("headers".into(), Value::Object(headers));
            }
            Ok(Some(Value::Object(converted)))
        }
        "grpc" => {
            let grpc = section(proxy, "grpc-opts");
            transport("grpc", "", "", &text(&grpc, "grpc-service-name"))
        }
        "h2" => {
            let h2 = section(proxy, "h2-opts");
            transport(
                "http",
                &strings(&h2, "host").join(","),
                &text(&h2, "path"),
                "",
            )
        }
        "http" => {
            let http = section(proxy, "http-opts");
            let paths = strings(&http, "path");
            if paths.len() > 1 {
                return Err("sing-box 的 HTTP transport 只支持一个 path".into());
            }
            let mut headers = section(&http, "headers");
            let host = headers.remove("Host");
            let mut result = json!({"type":"http", "method":http.get("method").and_then(Value::as_str)
                .filter(|method| !method.is_empty()).unwrap_or("GET")});
            if let Some(path) = paths.first() {
                result["path"] = json!(path);
            }
            if let Some(host) = host {
                result["host"] = host;
            }
            if !headers.is_empty() {
                result["headers"] = Value::Object(headers);
            }
            Ok(Some(result))
        }
        other => transport(other, "", "", ""),
    }
}

/// A Clash `wireguard` proxy as a sing-box WireGuard endpoint.
fn clash_wireguard(proxy: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let with_prefix = |key: &str, bits: u8| {
        let value = text(proxy, key);
        (!value.is_empty()).then(|| {
            if value.contains('/') {
                value
            } else {
                format!("{value}/{bits}")
            }
        })
    };
    let address: Vec<String> = [with_prefix("ip", 32), with_prefix("ipv6", 128)]
        .into_iter()
        .flatten()
        .collect();
    if address.is_empty() {
        return Err("wireguard 缺少 ip".into());
    }
    let private_key = raw(proxy, "private-key");
    if private_key.is_empty() {
        return Err("缺少 private-key".into());
    }
    let peer = |source: &Map<String, Value>| -> Result<Value, String> {
        let port: u16 = text(source, "port")
            .parse()
            .map_err(|_| "wireguard 的端口无效".to_owned())?;
        let mut peer = Map::new();
        peer.insert("address".into(), json!(text(source, "server")));
        peer.insert("port".into(), json!(port));
        peer.insert("public_key".into(), json!(text(source, "public-key")));
        let shared = raw(source, "pre-shared-key");
        if !shared.is_empty() {
            peer.insert("pre_shared_key".into(), json!(shared));
        }
        let allowed = strings(source, "allowed-ips");
        peer.insert(
            "allowed_ips".into(),
            json!(if allowed.is_empty() {
                vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()]
            } else {
                allowed
            }),
        );
        if let Some(reserved) = source.get("reserved") {
            peer.insert("reserved".into(), reserved.clone());
        }
        let keepalive: u64 = text(proxy, "persistent-keepalive").parse().unwrap_or(0);
        if keepalive != 0 {
            peer.insert("persistent_keepalive_interval".into(), json!(keepalive));
        }
        if peer["address"] == "" || peer["public_key"] == "" {
            return Err("wireguard 的 peer 缺少 server 或 public-key".into());
        }
        Ok(Value::Object(peer))
    };
    let peers = match proxy.get("peers") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| peer(&obj(item.clone())))
            .collect::<Result<Vec<_>, _>>()?,
        _ => vec![peer(proxy)?],
    };
    let mut outbound = Map::new();
    outbound.insert("type".into(), json!("wireguard"));
    outbound.insert("address".into(), json!(address));
    outbound.insert("private_key".into(), json!(private_key));
    let mtu: u64 = text(proxy, "mtu").parse().unwrap_or(0);
    if mtu != 0 {
        outbound.insert("mtu".into(), json!(mtu));
    }
    if let Some(workers) = proxy.get("workers") {
        let workers = workers.as_i64().or_else(|| workers.as_str()?.parse().ok())
            .ok_or("wireguard workers 必须是整数")?;
        outbound.insert("workers".into(), json!(workers));
    }
    outbound.insert("peers".into(), Value::Array(peers));
    Ok(outbound)
}

fn clash_proxy(proxy: &Map<String, Value>) -> Result<Imported, String> {
    let kind = text(proxy, "type");
    if kind == "wireguard" {
        clash_smux(proxy, &kind)?;
        let mut outbound = clash_wireguard(proxy)?;
        clash_dial_fields(proxy, &mut outbound, &kind)?;
        let name = text(proxy, "name");
        let name = if name.is_empty() {
            "wireguard".to_owned()
        } else {
            name
        };
        return Ok((name, outbound));
    }
    let realm = section(proxy, "realm-opts");
    let uses_realm = kind == "hysteria2" && truthy(&realm, "enable");
    let ports_only = kind == "hysteria2" && !text(proxy, "ports").is_empty()
        && matches!(text(proxy, "port").as_str(), "" | "0");
    let port: u16 = if ports_only || uses_realm {
        0
    } else {
        text(proxy, "port").parse::<u16>().ok().filter(|port| *port != 0)
            .ok_or_else(|| "端口无效".to_owned())?
    };
    let server = text(proxy, "server");
    let mut outbound = match kind.as_str() {
        "http" => {
            let mut outbound = base("http", &server, port)?;
            for key in ["username", "password", "headers"] {
                if let Some(value) = proxy.get(key) {
                    outbound.insert(key.into(), value.clone());
                }
            }
            put(&mut outbound, "tls", clash_tls_options(proxy, truthy(proxy, "tls")));
            outbound
        }
        "ss" => {
            if text(proxy, "cipher").is_empty() {
                return Err("缺少 cipher".into());
            }
            let mut outbound = base("shadowsocks", &server, port)?;
            outbound.insert("method".into(), json!(text(proxy, "cipher")));
            outbound.insert("password".into(), json!(raw(proxy, "password")));
            if proxy.contains_key("udp-over-tcp") {
                let enabled = truthy(proxy, "udp-over-tcp");
                let version = match text(proxy, "udp-over-tcp-version").as_str() {
                    "" | "0" | "1" => 1,
                    "2" => 2,
                    _ => return Err("udp-over-tcp-version 必须是 1 或 2".into()),
                };
                outbound.insert("udp_over_tcp".into(), if enabled && version == 1 {
                    json!({"enabled": true, "version": 1})
                } else {
                    json!(enabled)
                });
            }
            let plugin = text(proxy, "plugin");
            if !plugin.is_empty() {
                let opts = section(proxy, "plugin-opts");
                let (name, options) = match plugin.as_str() {
                    "obfs" => (
                        "obfs-local",
                        format!(
                            "obfs={};obfs-host={}",
                            text(&opts, "mode"),
                            text(&opts, "host")
                        ),
                    ),
                    "v2ray-plugin" => {
                        let mut options = format!("mode={}", text(&opts, "mode"));
                        if truthy(&opts, "tls") {
                            options.push_str(";tls");
                        }
                        for key in ["host", "path"] {
                            let value = text(&opts, key);
                            if !value.is_empty() {
                                options.push_str(&format!(";{key}={value}"));
                            }
                        }
                        if opts.contains_key("mux") {
                            options.push_str(if truthy(&opts, "mux") { ";mux=1" } else { ";mux=0" });
                        }
                        ("v2ray-plugin", options)
                    }
                    other => return Err(format!("不支持的 ss 插件 `{other}`")),
                };
                outbound.insert("plugin".into(), json!(name));
                outbound.insert("plugin_opts".into(), json!(options));
            }
            outbound
        }
        "vmess" => {
            let mut outbound = base("vmess", &server, port)?;
            outbound.insert("uuid".into(), json!(raw(proxy, "uuid")));
            let cipher = text(proxy, "cipher");
            outbound.insert(
                "security".into(),
                json!(if cipher.is_empty() {
                    "auto"
                } else {
                    cipher.as_str()
                }),
            );
            let alter: u64 = text(proxy, "alterId").parse().unwrap_or(0);
            if alter != 0 {
                outbound.insert("alter_id".into(), json!(alter));
            }
            for (source, target) in [("global-padding", "global_padding"), ("authenticated-length", "authenticated_length")] {
                if proxy.contains_key(source) {
                    outbound.insert(target.into(), json!(truthy(proxy, source)));
                }
            }
            put(
                &mut outbound,
                "tls",
                clash_tls_options(proxy, truthy(proxy, "tls")),
            );
            put(&mut outbound, "transport", clash_transport(proxy)?);
            let encoding = packet_encoding(proxy, &kind)?;
            if !encoding.is_empty() {
                outbound.insert("packet_encoding".into(), json!(encoding));
            }
            outbound
        }
        "vless" => {
            let mut outbound = base("vless", &server, port)?;
            outbound.insert("uuid".into(), json!(raw(proxy, "uuid")));
            let flow = text(proxy, "flow");
            if !flow.is_empty() {
                outbound.insert("flow".into(), json!(flow));
            }
            let reality = proxy.contains_key("reality-opts");
            put(
                &mut outbound,
                "tls",
                clash_tls_options(proxy, truthy(proxy, "tls") || reality),
            );
            put(&mut outbound, "transport", clash_transport(proxy)?);
            outbound.insert("packet_encoding".into(), json!(packet_encoding(proxy, &kind)?));
            outbound
        }
        "trojan" => {
            let mut outbound = base("trojan", &server, port)?;
            outbound.insert("password".into(), json!(raw(proxy, "password")));
            put(&mut outbound, "tls", clash_tls_options(proxy, true));
            put(&mut outbound, "transport", clash_transport(proxy)?);
            outbound
        }
        "hysteria2" => {
            let mut outbound = base("hysteria2", &server, port)?;
            let mut tls = clash_tls_options(proxy, true).unwrap_or_else(|| json!({"enabled":true}));
            if uses_realm {
                if !text(proxy, "ports").is_empty() {
                    return Err("Hysteria2 Realm 不能与跳端口同时使用".into());
                }
                let url = text(&realm, "server-url");
                let (realm_host, _) = crate::atom_mihomo::realm_address(&url)?;
                if outbound["server"] != realm_host && text(proxy, "sni").is_empty() {
                    tls["server_name"] = outbound["server"].clone();
                }
                let mut translated = json!({"server_url":url, "realm_id":text(&realm,"realm-id")});
                for (source, target) in [("token", "token"), ("stun-servers", "stun_servers")] {
                    if let Some(value) = realm.get(source) {
                        translated[target] = value.clone();
                    }
                }
                outbound.insert("realm".into(), translated);
                outbound.remove("server");
            } else {
                clash_hysteria2_ports(proxy, &mut outbound)?;
            }
            if let Some(profile) = proxy.get("bbr-profile") {
                outbound.insert("bbr_profile".into(), profile.clone());
            }
            let password = raw(proxy, "password");
            if !password.is_empty() {
                outbound.insert("password".into(), json!(password));
            }
            let obfs = text(proxy, "obfs");
            if !obfs.is_empty() {
                let mut config = json!({"type": obfs, "password": raw(proxy, "obfs-password")});
                if obfs == "gecko" {
                    for (source, target) in [("obfs-min-packet-size", "min_packet_size"), ("obfs-max-packet-size", "max_packet_size")] {
                        if let Some(value) = proxy.get(source) {
                            config[target] = value.clone();
                        }
                    }
                }
                outbound.insert("obfs".into(), config);
            }
            // Zero (mihomo's "no limit") and what is not a whole Mbps are left
            // out, as before these were read.
            for (source, target) in [("up", "up_mbps"), ("down", "down_mbps")] {
                if let Some(mbps) = clash_rate_mbps(&text(proxy, source)) {
                    outbound.insert(target.into(), json!(mbps));
                }
            }
            outbound.insert("tls".into(), tls);
            outbound
        }
        "tuic" => {
            let mut outbound = base("tuic", &server, port)?;
            if let Some(value) = proxy.get("heartbeat-interval") {
                let interval = value.as_str()
                    .and_then(|value| value.strip_prefix(crate::atom_mihomo::TUIC_HEARTBEAT_PREFIX))
                    .ok_or("TUIC 的数字 heartbeat-interval 是 QUIC 保活，sing-box 的 heartbeat 是协议心跳")?;
                outbound.insert("heartbeat".into(), json!(interval));
            }
            outbound.insert("uuid".into(), json!(raw(proxy, "uuid")));
            let password = raw(proxy, "password");
            if !password.is_empty() {
                outbound.insert("password".into(), json!(password));
            }
            let congestion = text(proxy, "congestion-controller");
            if !congestion.is_empty() {
                outbound.insert("congestion_control".into(), json!(congestion));
            }
            let relay = text(proxy, "udp-relay-mode");
            if !relay.is_empty() {
                outbound.insert("udp_relay_mode".into(), json!(relay));
            }
            for (source, target) in [
                ("disable-mtu-discovery", "disable_path_mtu_discovery"),
                ("reduce-rtt", "zero_rtt_handshake"),
                ("udp-over-stream", "udp_over_stream"),
            ] {
                if proxy.contains_key(source) {
                    outbound.insert(target.into(), json!(truthy(proxy, source)));
                }
            }
            if truthy(proxy, "udp-over-stream") && text(proxy, "udp-over-stream-version") != "2" {
                return Err("Mihomo 的 TUIC udp-over-stream 默认用 v1，sing-box 只支持 v2".into());
            }
            put(&mut outbound, "tls", clash_tls_options(proxy, true));
            outbound
        }
        "anytls" => {
            let mut outbound = base("anytls", &server, port)?;
            outbound.insert("password".into(), json!(raw(proxy, "password")));
            for (source, target) in [("idle-session-check-interval", "idle_session_check_interval"), ("idle-session-timeout", "idle_session_timeout")] {
                if proxy.contains_key(source) {
                    let seconds = text(proxy, source).parse::<u64>().map_err(|_| format!("{source} 必须是整数秒"))?;
                    outbound.insert(target.into(), json!(format!("{seconds}s")));
                }
            }
            if proxy.contains_key("min-idle-session") {
                let min = text(proxy, "min-idle-session").parse::<u64>().map_err(|_| "min-idle-session 必须是整数")?;
                outbound.insert("min_idle_session".into(), json!(min));
            }
            if proxy.contains_key("client-metadata") {
                outbound.insert("client_metadata".into(), json!(raw(proxy, "client-metadata")));
            }
            put(&mut outbound, "tls", clash_tls_options(proxy, true));
            outbound
        }
        "snell" => {
            let mut outbound = base("snell", &server, port)?;
            outbound.insert("psk".into(), json!(raw(proxy, "psk")));
            let version: u64 = text(proxy, "version").parse().unwrap_or(0);
            if version != 4 && version != 6 {
                return Err("sing-box 只支持 snell 4 和 6".into());
            }
            outbound.insert("version".into(), json!(version));
            if truthy(proxy, "reuse") {
                outbound.insert("reuse".into(), json!(true));
            }
            if version == 6 {
                let mode = text(proxy, "mode");
                if !mode.is_empty() {
                    outbound.insert("mode".into(), json!(mode));
                }
            } else {
                let opts = section(proxy, "obfs-opts");
                let mode = text(&opts, "mode");
                if !mode.is_empty() {
                    outbound.insert("obfs_mode".into(), json!(mode));
                }
                let host = text(&opts, "host");
                if !host.is_empty() {
                    outbound.insert("obfs_host".into(), json!(host));
                }
            }
            outbound
        }
        "ssh" => {
            let mut outbound = base("ssh", &server, port)?;
            outbound.insert("user".into(), json!(text(proxy, "username")));
            for (source, target) in [("password", "password"), ("private-key-passphrase", "private_key_passphrase")] {
                let value = raw(proxy, source);
                if !value.is_empty() {
                    outbound.insert(target.into(), json!(value));
                }
            }
            let key = raw(proxy, "private-key");
            if !key.is_empty() {
                if !key.contains("PRIVATE KEY") {
                    return Err("ssh 的 private-key 要写私钥内容，不能是文件路径".into());
                }
                outbound.insert("private_key".into(), json!([key]));
            }
            for (source, target) in [("host-key", "host_key"), ("host-key-algorithms", "host_key_algorithms")] {
                let values = strings(proxy, source);
                if !values.is_empty() {
                    outbound.insert(target.into(), json!(values));
                }
            }
            outbound
        }
        "hysteria" => {
            let protocol = text(proxy, "protocol");
            if !protocol.is_empty() && protocol != "udp" {
                return Err("hysteria 只支持 udp 协议".into());
            }
            let mut outbound = base("hysteria", &server, port)?;
            if proxy.contains_key("disable-mtu-discovery") {
                outbound.insert("disable_path_mtu_discovery".into(), json!(truthy(proxy, "disable-mtu-discovery")));
            }
            for key in ["up", "down"] {
                let value = text(proxy, key);
                if value.is_empty() {
                    return Err(format!("缺少 {key}"));
                }
                // A bare number in Clash is Mbps; sing-box wants a unit.
                let value = if value.bytes().all(|b| b.is_ascii_digit()) { format!("{value} Mbps") } else { value };
                outbound.insert(key.into(), json!(value));
            }
            // mihomo takes `auth` over `auth-str`, sing-box the other way round.
            let sources: &[(&str, &str)] = if raw(proxy, "auth").is_empty() {
                &[("auth-str", "auth_str"), ("obfs", "obfs")]
            } else {
                &[("auth", "auth"), ("obfs", "obfs")]
            };
            for (source, target) in sources {
                let value = raw(proxy, source);
                if !value.is_empty() {
                    outbound.insert((*target).into(), json!(value));
                }
            }
            clash_port_ranges(proxy, &mut outbound);
            let hop: u64 = text(proxy, "hop-interval").parse().unwrap_or(0);
            if hop != 0 {
                outbound.insert("hop_interval".into(), json!(format!("{hop}s")));
            }
            put(&mut outbound, "tls", clash_tls_options(proxy, true));
            outbound
        }
        "socks5" => {
            let mut outbound = base("socks", &server, port)?;
            outbound.insert("version".into(), json!("5"));
            for key in ["username", "password"] {
                let value = raw(proxy, key);
                if !value.is_empty() {
                    outbound.insert(key.into(), json!(value));
                }
            }
            if truthy(proxy, "tls") {
                return Err("不支持带 TLS 的 socks5".into());
            }
            outbound
        }
        "" => return Err("缺少 type".into()),
        other => return Err(format!("不支持的 Clash 节点类型 `{other}`")),
    };
    put(&mut outbound, "multiplex", clash_smux(proxy, &kind)?);
    clash_dial_fields(proxy, &mut outbound, &kind)?;
    // Mihomo's smux advertises UDP independently of the underlying proxy's flag.
    if matches!(kind.as_str(), "ss" | "socks5" | "vless" | "vmess" | "trojan" | "snell")
        && !truthy(proxy, "udp") && !smux_carries_udp(&section(proxy, "smux"))
    {
        outbound.insert("network".into(), json!("tcp"));
    }
    // sing-box rejects it on AnyTLS and it means nothing over QUIC.
    if truthy(proxy, "tfo") && !matches!(kind.as_str(), "anytls" | "hysteria" | "hysteria2" | "tuic") {
        outbound.insert("tcp_fast_open".into(), json!(true));
    }
    for key in ["uuid", "password", "method"] {
        if outbound.get(key).and_then(Value::as_str) == Some("") {
            return Err(format!("缺少 {key}"));
        }
    }
    let name = text(proxy, "name");
    Ok((clean_name(&name, &outbound), outbound))
}

fn clash_dial_fields(
    proxy: &Map<String, Value>, outbound: &mut Map<String, Value>, kind: &str,
) -> Result<(), String> {
    if let Some(value) = proxy.get("interface-name") {
        let interface = value.as_str().ok_or("interface-name 必须是网卡名称")?;
        outbound.insert("bind_interface".into(), json!(interface));
    }
    if proxy.contains_key("routing-mark") {
        let mark = text(proxy, "routing-mark").parse::<u32>().map_err(|_| "routing-mark 必须是无符号整数")?;
        outbound.insert("routing_mark".into(), json!(mark));
    }
    if let Some(value) = proxy.get("mptcp") {
        if !matches!(kind, "wireguard" | "hysteria" | "hysteria2" | "tuic") {
            outbound.insert("tcp_multi_path".into(), json!(value.as_bool().ok_or("mptcp 必须是布尔值")?));
        }
    }
    Ok(())
}

fn clash_port_ranges(proxy: &Map<String, Value>, outbound: &mut Map<String, Value>) {
    let ports = text(proxy, "ports");
    if !ports.is_empty() {
        let ranges: Vec<String> = ports.split(',').map(|port| {
            let port = port.trim();
            match port.split_once('-') {
                Some((start, end)) => format!("{}:{}", start.trim(), end.trim()),
                None => format!("{port}:{port}"),
            }
        }).collect();
        outbound.insert("server_ports".into(), json!(ranges));
    }
}

fn clash_hysteria2_ports(proxy: &Map<String, Value>, outbound: &mut Map<String, Value>) -> Result<(), String> {
    clash_port_ranges(proxy, outbound);
    let interval = text(proxy, "hop-interval");
    if !interval.is_empty() && interval != "0" {
        let seconds = |value: &str| value.trim().parse::<u64>().map_err(|_| "hop-interval 必须是秒数或秒数范围");
        let (start, end) = match interval.split_once('-') {
            Some((start, end)) => (seconds(start)?, Some(seconds(end)?)),
            None => (seconds(&interval)?, None),
        };
        if start < 5 || end.is_some_and(|end| end < start) {
            return Err("hop-interval 起点至少为 5 秒，且终点不能小于起点".into());
        }
        outbound.insert("hop_interval".into(), json!(format!("{start}s")));
        if let Some(end) = end.filter(|end| *end != start) {
            outbound.insert("hop_interval_max".into(), json!(format!("{end}s")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

fn numbered<T>(index: usize, result: Result<T, String>) -> Result<T, String> {
    result.map_err(|error| format!("第 {} 项: {error}", index + 1))
}

/// Nodes from share links, one per line (blank lines and `#` comments
/// skipped).
pub(crate) fn from_links(content: &str) -> Result<Vec<Imported>, String> {
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| numbered(index, parse_link(line)))
        .collect()
}

fn clash_maps(content: &str) -> Result<Vec<Map<String, Value>>, String> {
    let value: Value = match yaml_serde::from_str(content) {
        Ok(value) => value,
        Err(error) => inline_clash_list(content).ok_or_else(|| format!("YAML 无法解析: {error}"))?,
    };
    let proxies = match value {
        Value::Object(mut map) if map.contains_key("proxies") => match map.remove("proxies") {
            Some(Value::Array(items)) => items,
            _ => return Err("proxies 必须是列表".into()),
        },
        Value::Object(map) => vec![Value::Object(map)],
        Value::Array(items) => items,
        _ => return Err("YAML 里没有节点".into()),
    };
    proxies.into_iter()
        .enumerate()
        .map(|(index, proxy)| {
            numbered(index, match proxy {
                Value::Object(proxy) => Ok(proxy),
                _ => Err("节点必须是映射".to_owned()),
            })
        })
        .collect()
}

/// Pasted inline nodes can have misaligned list markers. Retry only when
/// every item is a complete flow mapping on its own line.
fn inline_clash_list(content: &str) -> Option<Value> {
    let entries = content.lines().map(str::trim_start)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let nodes = entries.map(|line| {
        let item = line.strip_prefix("- ")?.trim_start();
        if !item.starts_with('{') {
            return None;
        }
        let node: Value = yaml_serde::from_str(item).ok()?;
        node.is_object().then_some(node)
    }).collect::<Option<Vec<_>>>()?;
    (!nodes.is_empty()).then_some(Value::Array(nodes))
}

#[cfg(test)]
fn from_clash_yaml(content: &str) -> Result<Vec<Imported>, String> {
    clash_maps(content)?.iter().enumerate()
        .map(|(index, proxy)| numbered(index, clash_proxy(proxy)))
        .collect()
}

pub(crate) fn check_mihomo_proxy(proxy: &Map<String, Value>) -> Result<(), String> {
    match proxy.get("type").and_then(Value::as_str) {
        Some("ss" | "ssr" | "socks5" | "http" | "vmess" | "vless" | "snell" | "trojan"
            | "hysteria" | "hysteria2" | "wireguard" | "tuic" | "shadowquic" | "gost-relay"
            | "ssh" | "mieru" | "anytls" | "sudoku" | "masque" | "trusttunnel" | "openvpn"
            | "tailscale" | "zerotier" | "easytier") => {}
        _ => return Err("未知的 Mihomo 节点类型".into()),
    }
    for key in ["name", "dialer-proxy"] {
        if proxy.keys().any(|field| field.eq_ignore_ascii_case(key)) {
            return Err(format!("保存的 Mihomo 节点不能带 `{key}`"));
        }
    }
    if text(proxy, "type") == "ssh" {
        let key = raw(proxy, "private-key");
        if !key.is_empty() && !key.contains("PRIVATE KEY") {
            return Err("ssh 的 private-key 要写私钥内容，不能是文件路径".into());
        }
    }
    Ok(())
}

/// Node imports keep the original Mihomo settings when conversion would lose
/// information. Re-evaluate that conversion when switching kernels so new
/// mappings also work for nodes saved by earlier releases.
pub(crate) fn import_clash_yaml(content: &str) -> Result<Vec<Node>, String> {
    clash_maps(content)?.into_iter().enumerate().map(|(index, mut proxy)| {
        let name = text(&proxy, "name");
        proxy.remove("name");
        numbered(index, check_mihomo_proxy(&proxy))?;
        let name = clean_name(&name, &proxy);
        match singbox_from_clash(&proxy) {
            Ok(node) => Ok(Node { name, ..node }),
            Err(_) => Ok(Node { mihomo: Some(proxy), ..Node::new(name, Map::new()) }),
        }
    }).collect()
}

fn clash_shadowtls(proxy: &Map<String, Value>) -> Result<Node, String> {
    let mut ss = proxy.clone();
    ss.remove("plugin");
    ss.remove("plugin-opts");
    let (name, mut outbound) = clash_proxy(&ss)?;
    if truthy(proxy, "udp") && !truthy(proxy, "udp-over-tcp") && !outbound.contains_key("multiplex") {
        return Err("Mihomo 的 SS ShadowTLS 裸 UDP 无法通过 sing-box 的 ShadowTLS 出站".into());
    }
    let opts = section(proxy, "plugin-opts");
    let version = match text(&opts, "version").as_str() {
        "" | "2" => 2,
        "1" => 1,
        "3" => 3,
        _ => return Err("ShadowTLS 版本必须为 1、2 或 3".into()),
    };
    let host = text(&opts, "host");
    if host.is_empty() {
        return Err("ShadowTLS 插件缺少 host，无法保留 TLS 服务器名称".into());
    }
    let mut tls = json!({"enabled":true, "server_name":host});
    let fingerprint = text(proxy, "client-fingerprint");
    if !fingerprint.is_empty() {
        tls["utls"] = json!({"enabled":true,"fingerprint":fingerprint});
    }
    if let Some(alpn) = opts.get("alpn") {
        tls["alpn"] = alpn.clone();
    } else if fingerprint.is_empty() {
        tls["alpn"] = json!(["h2", "http/1.1"]);
    }
    if let Some(insecure) = opts.get("skip-cert-verify") {
        tls["insecure"] = insecure.clone();
    }
    let mut shadowtls = Map::from_iter([
        ("type".into(), json!("shadowtls")), ("version".into(), json!(version)), ("tls".into(), tls),
    ]);
    if let Some(password) = opts.get("password") {
        shadowtls.insert("password".into(), password.clone());
    }
    for key in ["server", "server_port", "bind_interface", "routing_mark", "tcp_fast_open", "tcp_multi_path"] {
        if let Some(value) = outbound.remove(key) {
            shadowtls.insert(key.into(), value);
        }
    }
    Ok(Node { shadowtls: Some(shadowtls), ..Node::new(name, outbound) })
}

pub(crate) fn singbox_from_clash(proxy: &Map<String, Value>) -> Result<Node, String> {
    let kind = text(proxy, "type");
    if matches!(kind.as_str(), "wireguard" | "anytls") && !truthy(proxy, "udp") {
        return Err(format!("Mihomo 的 {kind} 没有启用 UDP，sing-box 无法禁用此协议的 UDP"));
    }
    let node = if kind == "ss" && text(proxy, "plugin") == "shadow-tls" {
        clash_shadowtls(proxy)?
    } else {
        let (name, outbound) = clash_proxy(proxy)?;
        Node::new(name, outbound)
    };
    node.check_singbox().map_err(|error| error.message)?;
    let converted = crate::atom_mihomo::convert_proxy(&node)
        .map_err(|error| format!("无法保留 Mihomo 配置：{error}"))?;
    let mut comparable = proxy.clone();
    normalize_clash_defaults(&mut comparable, &kind);
    if kind == "hysteria2" && node.outbound.contains_key("realm") {
        comparable.remove("server");
        comparable.remove("port");
    }
    if matches!(kind.as_str(), "vmess" | "vless") {
        for alias in ["packet-addr", "xudp", "packet-encoding"] {
            comparable.remove(alias);
        }
        let encoding = packet_encoding(proxy, &kind)?;
        if !encoding.is_empty() {
            comparable.insert("packet-encoding".into(), json!(encoding));
        }
    }
    if kind == "wireguard" {
        // Mihomo accepts the peer fields either at the top level or in `peers`.
        if !comparable.contains_key("peers") {
            let mut peer = Map::new();
            for key in ["server", "port", "public-key", "pre-shared-key", "allowed-ips", "reserved"] {
                if let Some(value) = comparable.remove(key) {
                    peer.insert(key.into(), value);
                }
            }
            comparable.insert("peers".into(), json!([peer]));
        }
        for (key, subnet) in [("ip", 32), ("ipv6", 128)] {
            if let Some(Value::String(address)) = comparable.get_mut(key) {
                if !address.contains('/') {
                    *address = format!("{address}/{subnet}");
                }
            }
        }
    }
    if matches!(text(proxy, "type").as_str(), "vmess" | "vless" | "trojan")
        && comparable.get("network").is_some_and(|value| value == "tcp")
    {
        comparable.remove("network");
    }
    for key in ["tls", "tfo", "skip-cert-verify"] {
        if comparable.get(key).is_some_and(|value| value == false) && converted.get(key).is_none() {
            comparable.remove(key);
        }
    }
    let mut lost = Vec::new();
    unkept(&Value::Object(comparable), &converted, "", &mut lost);
    if !lost.is_empty() {
        return Err(format!("转换到 sing-box 无法保留字段：{}", lost.join("、")));
    }
    Ok(node)
}

/// Compare settings that take effect. This only touches the copy used for
/// comparison, so native YAML retained for a blocked node stays intact.
fn normalize_clash_defaults(proxy: &mut Map<String, Value>, kind: &str) {
    let disabled = |opts: &Map<String, Value>| opts.get("enabled").is_none_or(|value| value == false || value.is_null());
    if proxy.get("brutal-opts").and_then(Value::as_object).is_some_and(disabled) {
        proxy.remove("brutal-opts");
    }
    if proxy.get("smux").and_then(Value::as_object).is_some_and(disabled) {
        proxy.remove("smux");
    } else if let Some(Value::Object(smux)) = proxy.get_mut("smux") {
        let mux_udp = smux_carries_udp(smux);
        for key in ["only-tcp", "statistic", "padding"] {
            if smux.get(key).is_some_and(|value| value == false) {
                smux.remove(key);
            }
        }
        if smux.get("brutal-opts").and_then(Value::as_object).is_some_and(disabled) {
            smux.remove("brutal-opts");
        }
        if mux_udp && proxy.get("udp").is_some_and(Value::is_boolean) {
            proxy.remove("udp");
        }
    }
    if let Some(Value::Object(reality)) = proxy.get_mut("reality-opts") {
        // Both cores decode an absent or empty short ID to eight zero bytes.
        if reality.get("short-id").is_some_and(|value| value == "") {
            reality.remove("short-id");
        }
    }
    if kind == "tuic" && matches!(text(proxy, "request-timeout").as_str(), "0" | "8000") {
        proxy.remove("request-timeout");
    }
}

/// Also accept equivalent scalar spellings used by both YAML decoders.
fn unkept(written: &Value, saved: &Value, path: &str, lost: &mut Vec<String>) {
    if written == saved { return; }
    let scalar = |value: &Value| match value {
        Value::String(text) => Some(text.strip_suffix(" Mbps").filter(|n| n.bytes().all(|b| b.is_ascii_digit())).unwrap_or(text).to_owned()),
        Value::Number(_) | Value::Bool(_) => Some(value.to_string()),
        _ => None,
    };
    match (written, saved) {
        (Value::Object(written), Value::Object(saved)) => {
            for (key, value) in written {
                let at = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                match saved.get(key) {
                    Some(kept) => unkept(value, kept, &at, lost),
                    None if value.is_null() => {}
                    None => lost.push(at),
                }
            }
        }
        (Value::Array(written), Value::Array(saved)) if written.len() == saved.len() => {
            for (index, (value, kept)) in written.iter().zip(saved).enumerate() {
                unkept(value, kept, &format!("{path}[{index}]"), lost);
            }
        }
        _ if scalar(written).is_some() && scalar(written) == scalar(saved) => {}
        _ => lost.push(path.to_owned()),
    }
}

/// Parses JSON text as copied out of a sing-box configuration: `//` and
/// `/* */` comments and trailing commas are allowed (sing-box reads its own
/// configuration with comments too), and objects separated by commas without
/// an enclosing `[ ]` are read as a list.
pub(crate) fn lenient_json(text: &str) -> Result<Value, String> {
    let cleaned = strip_comments_and_trailing_commas(text);
    let trimmed = cleaned.trim();
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) => Ok(value),
        Err(error) => {
            if trimmed.starts_with('{') {
                if let Ok(value) = serde_json::from_str::<Value>(&format!("[{trimmed}]")) {
                    return Ok(value);
                }
            }
            Err(format!("JSON 无法解析: {error}"))
        }
    }
}

fn strip_comments_and_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            '/' if chars.get(i + 1) == Some(&'/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            ',' => {
                // Drop a comma followed only by whitespace or comments and then
                // `}`, `]` or the end of the text.
                let mut j = i + 1;
                loop {
                    while j < chars.len() && chars[j].is_whitespace() {
                        j += 1;
                    }
                    if chars.get(j) == Some(&'/') && chars.get(j + 1) == Some(&'/') {
                        while j < chars.len() && chars[j] != '\n' {
                            j += 1;
                        }
                    } else if chars.get(j) == Some(&'/') && chars.get(j + 1) == Some(&'*') {
                        j += 2;
                        while j < chars.len()
                            && !(chars[j] == '*' && chars.get(j + 1) == Some(&'/'))
                        {
                            j += 1;
                        }
                        j += 2;
                    } else {
                        break;
                    }
                }
                if !matches!(chars.get(j), None | Some('}') | Some(']')) {
                    out.push(c);
                }
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Nodes from sing-box JSON: one outbound, a list, or a configuration with
/// `outbounds` (only its proxy outbounds).
pub(crate) fn from_singbox_json(value: Value) -> Result<Vec<Node>, String> {
    let (items, whole) = match value {
        Value::Object(mut map)
            if (map.contains_key("outbounds") || map.contains_key("endpoints"))
                && !map.contains_key("type") =>
        {
            let mut items = match map.remove("outbounds") {
                Some(Value::Array(items)) => items,
                None => Vec::new(),
                _ => return Err("outbounds 必须是数组".into()),
            };
            // WireGuard is an endpoint since sing-box 1.13; the other
            // endpoint types are not nodes.
            if let Some(Value::Array(endpoints)) = map.remove("endpoints") {
                items.extend(
                    endpoints
                        .into_iter()
                        .filter(|item| item.get("type").and_then(Value::as_str) == Some("wireguard")),
                );
            }
            (items, true)
        }
        Value::Object(map) => (vec![Value::Object(map)], false),
        Value::Array(items) => (items, false),
        _ => return Err("JSON 里没有 outbound".into()),
    };
    let mut tags = std::collections::BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        if let Some(tag) = item.get("tag").and_then(Value::as_str).filter(|tag| !tag.is_empty()) {
            tags.entry(tag).and_modify(|entry| *entry = None).or_insert(Some(index));
        }
    }
    let mut transports = std::collections::BTreeSet::new();
    let mut nodes = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let mut outbound = item.as_object().cloned().unwrap_or_default();
        if outbound.is_empty() {
            return Err(format!("第 {} 项不是对象", index + 1));
        }
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        if whole
            && matches!(
                kind,
                "direct" | "block" | "dns" | "selector" | "urltest" | "fallback" | "load_balance"
            )
        {
            continue;
        }
        let shadowtls = if let Some(detour) = outbound.remove("detour") {
            if kind != "shadowsocks" {
                return numbered(index, Err("目前只支持 Shadowsocks 通过 detour 引用 ShadowTLS".into()));
            }
            let target = numbered(index, detour.as_str().filter(|tag| !tag.is_empty())
                .ok_or_else(|| "detour 需要非空的 ShadowTLS 标签".to_owned()))?;
            let target_index = match tags.get(target) {
                Some(Some(target_index)) => *target_index,
                Some(None) => return numbered(index, Err(format!("detour 引用的标签 `{target}` 重复"))),
                None => return numbered(index, Err(format!("找不到 detour 引用的 ShadowTLS `{target}`，请一起导入两个出站"))),
            };
            let mut transport = items[target_index].as_object().cloned().unwrap_or_default();
            transport.remove("tag");
            transports.insert(target_index);
            Some(transport)
        } else {
            None
        };
        let name = match outbound.remove("tag") {
            Some(Value::String(tag)) => tag,
            _ => String::new(),
        };
        let name = clean_name(&name, shadowtls.as_ref().unwrap_or(&outbound));
        let node = Node { shadowtls, ..Node::new(name, outbound) };
        numbered(index, node.check_singbox().map_err(|refusal| refusal.message))?;
        nodes.push((index, node));
    }
    let nodes: Vec<_> = nodes.into_iter().filter_map(|(index, node)| (!transports.contains(&index)).then_some(node)).collect();
    if nodes.is_empty() {
        return Err("没有可导入的节点".into());
    }
    Ok(nodes)
}

#[cfg(test)]
#[path = "atom_links_tests.rs"]
mod tests;
