//! What a dstack `app-compose.json` pins, read strictly.
//!
//! dstack's `compose_hash` is SHA-256 of `app-compose.json`, which embeds the
//! docker-compose YAML. Two things depend on reading that YAML exactly as
//! docker compose does:
//!
//! - the holders' `verify-compose`: `compose_hash` pins the images only if
//!   every service names its image by digest;
//! - the node in a TEE: the escrow recipients and the pinned fingerprint
//!   must be literal values in the measured compose.
//!
//! Only a deliberately small subset is accepted, so no YAML feature, and no
//! difference between this parser and docker compose's, can hide anything:
//!
//! - the compose text is `\n` plus printable ASCII only (YAML parsers
//!   disagree on Unicode line breaks such as U+2028);
//! - one document; no anchors, aliases, merge keys, tags or duplicate keys;
//! - a top-level `services` mapping, and no `include`;
//! - `runner` is `docker-compose`.

use std::collections::HashSet;

use yaml_rust2::parser::{Event, Parser};

use crate::EscrowError;

/// The compose environment variables that must be literal in a TEE.
pub const RECIPIENTS_ENV: &str = "TINYCLOUD_AT_REST__ESCROW__RECIPIENTS";
pub const VERIFIED_FP_ENV: &str = "TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP";
type Result<T, E = EscrowError> = std::result::Result<T, E>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(EscrowError::Compose(msg.into()))
}

macro_rules! ensure {
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return err(format!($($fmt)+));
        }
    };
}

/// Untrusted text, made safe to print: printable ASCII stays, everything
/// else (control characters, terminal escapes, any non-ASCII) becomes a
/// visible `\u{…}` escape.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' '..='~' if c != '\\' => out.push(c),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push_str(&format!("\\u{{{:x}}}", other as u32)),
        }
    }
    out
}

#[derive(Debug)]
enum Node {
    Scalar(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

struct Reader<'a> {
    parser: Parser<std::str::Chars<'a>>,
}

impl Reader<'_> {
    fn next(&mut self) -> Result<Event> {
        let (event, mark) = self.parser.next_token().map_err(|e| {
            EscrowError::Compose(format!("the compose file is not valid YAML: {e}"))
        })?;
        match &event {
            Event::Alias(_) => {
                return err(format!(
                    "YAML aliases are not allowed (line {})",
                    mark.line()
                ))
            }
            Event::Scalar(_, _, anchor, tag)
            | Event::SequenceStart(anchor, tag)
            | Event::MappingStart(anchor, tag) => {
                ensure!(
                    *anchor == 0,
                    "YAML anchors are not allowed (line {})",
                    mark.line()
                );
                ensure!(
                    tag.is_none(),
                    "YAML tags are not allowed (line {})",
                    mark.line()
                );
            }
            _ => {}
        }
        Ok(event)
    }

    fn node(&mut self, event: Event) -> Result<Node> {
        match event {
            Event::Scalar(value, ..) => Ok(Node::Scalar(value)),
            Event::SequenceStart(..) => {
                let mut items = Vec::new();
                loop {
                    match self.next()? {
                        Event::SequenceEnd => return Ok(Node::Seq(items)),
                        e => items.push(self.node(e)?),
                    }
                }
            }
            Event::MappingStart(..) => {
                let mut entries = Vec::new();
                let mut seen = HashSet::new();
                loop {
                    let key = match self.next()? {
                        Event::MappingEnd => return Ok(Node::Map(entries)),
                        Event::Scalar(key, ..) => key,
                        _ => return err("only plain string mapping keys are allowed"),
                    };
                    ensure!(key != "<<", "YAML merge keys are not allowed");
                    ensure!(seen.insert(key.clone()), "duplicate key {:?}", escape(&key));
                    let value = self.next()?;
                    entries.push((key, self.node(value)?));
                }
            }
            other => err(format!("unexpected YAML structure: {other:?}")),
        }
    }
}

/// Only `\n` and printable ASCII: no Unicode line breaks (U+0085, U+2028,
/// U+2029), no CR, tabs, BOM or control characters.
fn check_charset(yaml: &str) -> Result<()> {
    if let Some((i, b)) = yaml
        .bytes()
        .enumerate()
        .find(|(_, b)| *b != b'\n' && !(0x20..=0x7e).contains(b))
    {
        return err(format!(
            "the compose file may contain only newlines and printable ASCII; byte 0x{b:02x} at offset {i} is not allowed"
        ));
    }
    Ok(())
}

fn parse(yaml: &str) -> Result<Vec<(String, Node)>> {
    check_charset(yaml)?;
    let mut r = Reader {
        parser: Parser::new_from_str(yaml),
    };
    ensure!(matches!(r.next()?, Event::StreamStart), "not a YAML stream");
    ensure!(
        matches!(r.next()?, Event::DocumentStart),
        "the compose file is empty"
    );
    let first = r.next()?;
    let root = r.node(first)?;
    ensure!(
        matches!(r.next()?, Event::DocumentEnd),
        "trailing YAML content"
    );
    ensure!(
        matches!(r.next()?, Event::StreamEnd),
        "the compose file must be a single YAML document"
    );
    let Node::Map(top) = root else {
        return err("the compose file must be a mapping");
    };
    ensure!(
        get(&top, "include").is_none(),
        "`include` pulls in other compose files and is not allowed"
    );
    Ok(top)
}

fn get<'a>(entries: &'a [(String, Node)], key: &str) -> Option<&'a Node> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// A YAML mapping's entries, in document order.
type Entries = [(String, Node)];

fn services(top: &Entries) -> Result<Vec<(&str, &Entries)>> {
    let Some(Node::Map(services)) = get(top, "services") else {
        return err("the compose file has no `services` mapping");
    };
    ensure!(!services.is_empty(), "the compose file has no services");
    services
        .iter()
        .map(|(name, service)| match service {
            Node::Map(fields) => Ok((name.as_str(), fields.as_slice())),
            _ => err(format!("service {:?} is not a mapping", escape(name))),
        })
        .collect()
}

/// `<name>[:tag]@sha256:<64 lowercase hex>`, no whitespace or comments.
fn pinned_reference(image: &str) -> bool {
    let Some((name, digest)) = image.split_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
        && digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The parsed `app-compose.json` and its compose YAML.
pub struct AppCompose {
    doc: serde_json::Map<String, serde_json::Value>,
    top: Vec<(String, Node)>,
}

/// Walks any JSON value and fails on an object key that appears twice at
/// any depth. serde_json keeps the last duplicate; dstack's own struct
/// parse would refuse it, so every reader of the hashed bytes must too.
struct NoDuplicateKeys;

impl<'de> serde::Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> serde::de::Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate key {:?}",
                    escape(&key)
                )));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

impl AppCompose {
    /// Parse `app-compose.json` and its `docker_compose_file` strictly.
    pub fn parse(app_compose: &[u8]) -> Result<Self> {
        serde_json::from_slice::<NoDuplicateKeys>(app_compose)
            .map_err(|e| EscrowError::Compose(format!("app-compose.json is not JSON: {e}")))?;
        let doc: serde_json::Value = serde_json::from_slice(app_compose)
            .map_err(|e| EscrowError::Compose(format!("app-compose.json is not JSON: {e}")))?;
        let serde_json::Value::Object(doc) = doc else {
            return err("app-compose.json is not a JSON object");
        };
        match doc.get("runner").and_then(|v| v.as_str()) {
            Some("docker-compose") => {}
            other => {
                return err(format!(
                    "app-compose.json runner must be \"docker-compose\", not {:?}",
                    other.map(escape)
                ))
            }
        }
        let compose = doc
            .get("docker_compose_file")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                EscrowError::Compose("app-compose.json has no docker_compose_file".into())
            })?;
        let top = parse(compose)?;
        services(&top)?;
        Ok(Self { doc, top })
    }

    /// Every service's image, each pinned by digest; refuses anything else.
    pub fn pinned_images(&self) -> Result<Vec<(String, String)>> {
        let mut images = Vec::new();
        for (name, fields) in services(&self.top)? {
            let name = escape(name);
            for forbidden in ["build", "extends"] {
                ensure!(
                    get(fields, forbidden).is_none(),
                    "service {name:?} uses `{forbidden}`; only digest-pinned images are allowed"
                );
            }
            let image = match get(fields, "image") {
                Some(Node::Scalar(image)) => image,
                Some(_) => return err(format!("service {name:?} has a non-string image")),
                None => return err(format!("service {name:?} has no image")),
            };
            ensure!(
                pinned_reference(image),
                "service {name:?} image {:?} is not referenced as <name>@sha256:<64 hex>",
                escape(image)
            );
            images.push((name, image.clone()));
        }
        Ok(images)
    }

    /// The other `app-compose.json` fields the hash also covers, in full
    /// (scripts included), escaped, for the holder to review.
    pub fn other_settings(&self) -> Vec<(String, String)> {
        self.doc
            .iter()
            .filter(|(k, _)| k.as_str() != "docker_compose_file")
            .map(|(k, v)| {
                let shown = match v {
                    serde_json::Value::String(s) => escape(s),
                    other => escape(&other.to_string()),
                };
                (escape(k), shown)
            })
            .collect()
    }

    /// The literal value of `key` in the services' `environment`, if set.
    ///
    /// Refused: a value that docker compose would interpolate (`$`), a key
    /// passed through from the runtime environment (`- KEY` or `KEY:`
    /// with no value), and different values in different services.
    pub fn literal_env(&self, key: &str) -> Result<Option<String>> {
        let mut found: Option<String> = None;
        for (service, fields) in services(&self.top)? {
            let service = escape(service);
            let value = match get(fields, "environment") {
                None => None,
                Some(Node::Map(env)) => match get(env, key) {
                    None => None,
                    Some(Node::Scalar(v)) => Some(v.clone()),
                    Some(_) => {
                        return err(format!("service {service:?} sets {key} to a non-string"))
                    }
                },
                Some(Node::Seq(items)) => {
                    let mut value = None;
                    for item in items {
                        let Node::Scalar(item) = item else {
                            return err(format!(
                                "service {service:?} has a non-string environment entry"
                            ));
                        };
                        let (k, v) = match item.split_once('=') {
                            Some((k, v)) => (k, Some(v)),
                            None => (item.as_str(), None),
                        };
                        if k == key {
                            ensure!(value.is_none(), "service {service:?} sets {key} twice");
                            value = Some(v.map(str::to_owned).ok_or_else(|| {
                                EscrowError::Compose(format!(
                                    "service {service:?} passes {key} through from the runtime environment; it must be a literal value"
                                ))
                            })?);
                        }
                    }
                    value
                }
                Some(_) => {
                    return err(format!(
                        "service {service:?} environment is not a mapping or list"
                    ))
                }
            };
            let Some(value) = value else { continue };
            // Empty or a YAML 1.2 null (any spelling docker compose reads as
            // null) passes the variable through from the runtime.
            ensure!(
                !matches!(value.as_str(), "" | "~" | "null" | "Null" | "NULL"),
                "service {service:?} passes {key} through from the runtime environment; it must be a literal value"
            );
            ensure!(
                !value.contains('$'),
                "service {service:?} sets {key} by interpolation; it must be a literal value"
            );
            match &found {
                Some(prev) => ensure!(*prev == value, "services set different values for {key}"),
                None => found = Some(value),
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "a".repeat(64)
    }

    fn app(yaml: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "manifest_version": 2,
            "runner": "docker-compose",
            "docker_compose_file": yaml,
        }))
        .unwrap()
    }

    fn images(yaml: &str) -> Result<Vec<(String, String)>> {
        AppCompose::parse(&app(yaml))?.pinned_images()
    }

    #[test]
    fn digest_pinned_services_pass() {
        let d = digest();
        let yaml = format!(
            "services:\n  node:\n    image: ghcr.io/tinycloudlabs/tinycloud-node@sha256:{d}\n    environment:\n      - A=1\n  ingress:\n    image: \"caddy:2.8@sha256:{d}\"\nvolumes:\n  data: {{}}\n"
        );
        let images = images(&yaml).unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[1].1, format!("caddy:2.8@sha256:{d}"));
    }

    #[test]
    fn every_known_bypass_is_refused() {
        let d = digest();
        let cases = [
            // A comment is not part of the value: the image is nginx:latest.
            (format!("services:\n  web:\n    image: nginx:latest # @sha256:{d}\n"), "nginx:latest"),
            // Flow mapping.
            ("services:\n  web: {image: nginx:latest}\n".to_string(), "nginx:latest"),
            // Quoted key.
            ("services:\n  web:\n    \"image\": nginx:latest\n".to_string(), "nginx:latest"),
            // build instead of an image.
            ("services:\n  web:\n    build: .\n".to_string(), "build"),
            // Anchors, aliases and merges that hide the real image.
            (format!("x: &img\n  image: a@sha256:{d}\nservices:\n  web:\n    <<: *img\n    image: nginx\n"), "anchor"),
            (format!("services:\n  a:\n    image: &i a@sha256:{d}\n  b:\n    image: *i\n"), "anchor"),
            // Duplicate keys: last-wins parsers would run the second.
            (format!("services:\n  web:\n    image: a@sha256:{d}\n    image: nginx\n"), "duplicate"),
            // Tags, extends, include, tag-only, digest of the wrong length/case.
            (format!("services:\n  web:\n    image: !!str a@sha256:{d}\n"), "tags"),
            (format!("services:\n  web:\n    image: a@sha256:{d}\n    extends: base\n"), "extends"),
            (format!("include:\n  - other.yaml\nservices:\n  web:\n    image: a@sha256:{d}\n"), "include"),
            ("services:\n  web:\n    image: nginx:1.27\n".to_string(), "nginx:1.27"),
            (format!("services:\n  web:\n    image: a@sha256:{}\n", "A".repeat(64)), "is not referenced"),
            (format!("services:\n  web:\n    image: a@sha256:{d}0\n"), "is not referenced"),
            ("services:\n  web:\n    environment: [A=1]\n".to_string(), "no image"),
            // Several documents, or no services.
            (format!("services:\n  web:\n    image: a@sha256:{d}\n---\nservices: {{}}\n"), "single YAML document"),
            ("version: '3'\n".to_string(), "no `services`"),
            ("services: [\n".to_string(), "not valid YAML"),
            // Anything but newline and printable ASCII.
            (format!("services:\r\n  web:\r\n    image: a@sha256:{d}\r\n"), "0x0d"),
            (format!("\u{feff}services:\n  web:\n    image: a@sha256:{d}\n"), "0xef"),
            (format!("services:\n\tweb:\n    image: a@sha256:{d}\n"), "0x09"),
        ];
        for (yaml, needle) in cases {
            let err = images(&yaml).expect_err(&yaml).to_string();
            assert!(err.contains(needle), "{yaml:?}: {err}");
        }
    }

    /// The security review's proofs of concept: Unicode line breaks that Go
    /// yaml.v3 (docker compose) honours and yaml-rust2 doesn't, so each one
    /// runs `nginx:latest` while a lax reader sees only the pinned image.
    #[test]
    fn unicode_line_breaks_are_refused() {
        for (name, yaml) in [
            (
                "U+2028",
                include_str!("../tests/fixtures/compose/ls_comment_quote.yaml"),
            ),
            (
                "U+0085",
                include_str!("../tests/fixtures/compose/nel_comment_quote.yaml"),
            ),
            (
                "U+2029",
                include_str!("../tests/fixtures/compose/ps_comment_quote.yaml"),
            ),
            (
                "hidden service",
                include_str!("../tests/fixtures/compose/ls_extra_service.yaml"),
            ),
        ] {
            assert!(!yaml.is_ascii(), "{name}: fixture lost its line break");
            let err = images(yaml).expect_err(name).to_string();
            assert!(err.contains("printable ASCII"), "{name}: {err}");
        }
    }

    #[test]
    fn production_compose_passes() {
        let yaml = include_str!("../../docker-compose.dstack-postgres.yaml");
        assert_eq!(images(yaml).unwrap().len(), 4);
    }

    #[test]
    fn duplicate_json_keys_are_refused_at_any_depth() {
        let yaml = format!("services:\\n  w:\\n    image: a@sha256:{}\\n", digest());
        for doc in [
            format!(
                r#"{{"runner":"docker-compose","runner":"bash","docker_compose_file":"{yaml}"}}"#
            ),
            format!(
                r#"{{"runner":"docker-compose","docker_compose_file":"{yaml}","x":{{"a":1,"a":2}}}}"#
            ),
        ] {
            let err = AppCompose::parse(doc.as_bytes()).err().unwrap().to_string();
            assert!(err.contains("duplicate key"), "{doc}: {err}");
        }
        let ok = format!(
            r#"{{"runner":"docker-compose","docker_compose_file":"{yaml}","x":[{{"a":1}},{{"a":2}}]}}"#
        );
        AppCompose::parse(ok.as_bytes()).unwrap();
    }

    #[test]
    fn only_the_docker_compose_runner_is_accepted() {
        let d = digest();
        let yaml = format!("services:\n  web:\n    image: a@sha256:{d}\n");
        for runner in [serde_json::json!("bash"), serde_json::Value::Null] {
            let doc = serde_json::json!({"runner": runner, "docker_compose_file": yaml});
            let err = AppCompose::parse(&serde_json::to_vec(&doc).unwrap())
                .err()
                .unwrap()
                .to_string();
            assert!(err.contains("runner"), "{err}");
        }
    }

    #[test]
    fn other_settings_are_shown_in_full_and_escaped() {
        let script = format!("docker pull nginx:latest && {}", "x".repeat(200));
        let doc = serde_json::json!({
            "runner": "docker-compose",
            "docker_compose_file": format!("services:\n  w:\n    image: a@sha256:{}\n", digest()),
            "kms_enabled": true,
            "pre_launch_script": script,
            "zz\u{1b}[1A\u{1b}[2K": "x",
        });
        let parsed = AppCompose::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let settings = parsed.other_settings();
        assert!(settings.contains(&("kms_enabled".into(), "true".into())));
        assert!(settings.contains(&("pre_launch_script".into(), script.clone())));
        assert!(settings.contains(&("zz\\u{1b}[1A\\u{1b}[2K".into(), "x".into())));
        assert!(!settings.iter().any(|(k, _)| k == "docker_compose_file"));
        assert!(settings.iter().all(|(k, v)| k
            .bytes()
            .chain(v.bytes())
            .all(|b| (0x20..=0x7e).contains(&b))));
    }

    #[test]
    fn escrow_values_must_be_literal() {
        let d = digest();
        let with_env = |env: &str| {
            AppCompose::parse(&app(&format!(
                "services:\n  node:\n    image: a@sha256:{d}\n    environment:\n{env}"
            )))
            .unwrap()
        };
        let r = "'[{holder=\"sam\",recipient=\"age1yubikey1q\"}]'";
        // Map and list forms give the literal.
        let map = with_env(&format!(
            "      {RECIPIENTS_ENV}: {r}\n      {VERIFIED_FP_ENV}: {d}\n"
        ));
        assert_eq!(
            map.literal_env(RECIPIENTS_ENV).unwrap().as_deref(),
            Some("[{holder=\"sam\",recipient=\"age1yubikey1q\"}]")
        );
        assert_eq!(map.literal_env(VERIFIED_FP_ENV).unwrap(), Some(d.clone()));
        let list = with_env(&format!("      - {VERIFIED_FP_ENV}={d}\n"));
        assert_eq!(list.literal_env(VERIFIED_FP_ENV).unwrap(), Some(d.clone()));
        assert_eq!(list.literal_env(RECIPIENTS_ENV).unwrap(), None);
        // Interpolated or passed through from the runtime environment.
        for env in [
            format!("      {VERIFIED_FP_ENV}: ${{FP}}\n"),
            format!("      {VERIFIED_FP_ENV}: $FP\n"),
            format!("      {VERIFIED_FP_ENV}:\n"),
            format!("      {VERIFIED_FP_ENV}: Null\n"),
            format!("      {VERIFIED_FP_ENV}: NULL\n"),
            format!("      {VERIFIED_FP_ENV}: null\n"),
            format!("      {VERIFIED_FP_ENV}: ~\n"),
            format!("      - {VERIFIED_FP_ENV}\n"),
            format!("      - {VERIFIED_FP_ENV}=${{FP:-{d}}}\n"),
        ] {
            let err = with_env(&env)
                .literal_env(VERIFIED_FP_ENV)
                .expect_err(&env)
                .to_string();
            assert!(err.contains("literal"), "{env:?}: {err}");
        }
        // Two services that disagree.
        let two = AppCompose::parse(&app(&format!(
            "services:\n  a:\n    image: a@sha256:{d}\n    environment:\n      {VERIFIED_FP_ENV}: {d}\n  b:\n    image: a@sha256:{d}\n    environment:\n      {VERIFIED_FP_ENV}: {}\n",
            "b".repeat(64)
        )))
        .unwrap();
        assert!(two.literal_env(VERIFIED_FP_ENV).is_err());
    }

    #[test]
    fn escape_makes_untrusted_text_printable() {
        assert_eq!(escape("ok -_./:@"), "ok -_./:@");
        assert_eq!(
            escape("\u{1b}[2K\r\u{2028}\\"),
            "\\u{1b}[2K\\u{d}\\u{2028}\\\\"
        );
    }
}
