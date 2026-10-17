//! `verify-compose`: does `compose_hash` pin every container image?
//!
//! dstack's `compose_hash` is SHA-256 of `app-compose.json`, which embeds the
//! docker-compose YAML. That pins the images only if every service names its
//! image by digest. This parses the YAML with a real parser and accepts only
//! a deliberately small subset, so no YAML feature can hide an image:
//!
//! - one document, no anchors, aliases, merge keys or tags, no duplicate keys;
//! - a top-level `services` mapping (no `include`);
//! - every service has a string `image` of the form `<name>[:tag]@sha256:<64
//!   lowercase hex>`, and no `build` or `extends`.

use std::collections::HashSet;

use anyhow::{anyhow, bail, ensure, Result};
use sha2::Digest as _;
use yaml_rust2::parser::{Event, Parser};

#[derive(Debug)]
enum Node {
    Scalar(String),
    /// Items are validated (no aliases, anchors, tags) but not kept: no
    /// check needs a sequence's contents.
    Seq,
    Map(Vec<(String, Node)>),
}

struct Reader<'a> {
    parser: Parser<std::str::Chars<'a>>,
}

impl Reader<'_> {
    fn next(&mut self) -> Result<Event> {
        let (event, mark) = self
            .parser
            .next_token()
            .map_err(|e| anyhow!("the compose file is not valid YAML: {e}"))?;
        match &event {
            Event::Alias(_) => bail!("YAML aliases are not allowed (line {})", mark.line()),
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
            Event::SequenceStart(..) => loop {
                match self.next()? {
                    Event::SequenceEnd => return Ok(Node::Seq),
                    e => {
                        self.node(e)?;
                    }
                }
            },
            Event::MappingStart(..) => {
                let mut entries = Vec::new();
                let mut seen = HashSet::new();
                loop {
                    let key = match self.next()? {
                        Event::MappingEnd => return Ok(Node::Map(entries)),
                        Event::Scalar(key, ..) => key,
                        _ => bail!("only plain string mapping keys are allowed"),
                    };
                    ensure!(key != "<<", "YAML merge keys are not allowed");
                    ensure!(seen.insert(key.clone()), "duplicate key {key:?}");
                    let value = self.next()?;
                    entries.push((key, self.node(value)?));
                }
            }
            other => bail!("unexpected YAML structure: {other:?}"),
        }
    }
}

fn parse(yaml: &str) -> Result<Node> {
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
    Ok(root)
}

fn get<'a>(entries: &'a [(String, Node)], key: &str) -> Option<&'a Node> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
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

/// Every service's image, each pinned by digest; refuses anything else.
pub fn pinned_images(compose_yaml: &str) -> Result<Vec<(String, String)>> {
    let Node::Map(top) = parse(compose_yaml)? else {
        bail!("the compose file must be a mapping");
    };
    ensure!(
        get(&top, "include").is_none(),
        "`include` pulls in other compose files and is not allowed"
    );
    let Some(Node::Map(services)) = get(&top, "services") else {
        bail!("the compose file has no `services` mapping");
    };
    ensure!(!services.is_empty(), "the compose file has no services");
    let mut images = Vec::new();
    for (name, service) in services {
        let Node::Map(fields) = service else {
            bail!("service {name:?} is not a mapping");
        };
        for forbidden in ["build", "extends"] {
            ensure!(
                get(fields, forbidden).is_none(),
                "service {name:?} uses `{forbidden}`; only digest-pinned images are allowed"
            );
        }
        let image = match get(fields, "image") {
            Some(Node::Scalar(image)) => image,
            Some(_) => bail!("service {name:?} has a non-string image"),
            None => bail!("service {name:?} has no image"),
        };
        ensure!(
            pinned_reference(image),
            "service {name:?} image {image:?} is not referenced as <name>@sha256:<64 hex>"
        );
        images.push((name.clone(), image.clone()));
    }
    Ok(images)
}

/// The `app-compose.json` fields besides the compose file that the hash also
/// covers, for the holder to review.
pub fn other_settings(app_compose: &serde_json::Value) -> Vec<String> {
    let Some(map) = app_compose.as_object() else {
        return Vec::new();
    };
    map.iter()
        .filter(|(k, _)| k.as_str() != "docker_compose_file")
        .map(|(k, v)| {
            let shown = match v {
                serde_json::Value::String(s) if s.len() > 80 => {
                    format!(
                        "<{} chars, sha256 {}>",
                        s.len(),
                        hex::encode(sha2::Sha256::digest(s.as_bytes()))
                    )
                }
                other => other.to_string(),
            };
            format!("{k} = {shown}")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "a".repeat(64)
    }

    #[test]
    fn digest_pinned_services_pass() {
        let d = digest();
        let yaml = format!(
            "services:\n  node:\n    image: ghcr.io/tinycloudlabs/tinycloud-node@sha256:{d}\n    environment:\n      - A=1\n  ingress:\n    image: \"caddy:2.8@sha256:{d}\"\nvolumes:\n  data: {{}}\n"
        );
        let images = pinned_images(&yaml).unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[1].1, format!("caddy:2.8@sha256:{d}"));
    }

    #[test]
    fn every_known_bypass_is_refused() {
        let d = digest();
        let cases = [
            // 1. A comment is not part of the value: the image is nginx:latest.
            (format!("services:\n  web:\n    image: nginx:latest # @sha256:{d}\n"), "nginx:latest"),
            // 2. Flow mapping.
            ("services:\n  web: {image: nginx:latest}\n".to_string(), "nginx:latest"),
            // 3. Quoted key.
            ("services:\n  web:\n    \"image\": nginx:latest\n".to_string(), "nginx:latest"),
            // 4. build instead of an image.
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
        ];
        for (yaml, needle) in cases {
            let err = pinned_images(&yaml).expect_err(&yaml).to_string();
            assert!(err.contains(needle), "{yaml:?}: {err}");
        }
    }

    #[test]
    fn other_settings_are_listed_for_review() {
        let doc = serde_json::json!({
            "docker_compose_file": "services: {}",
            "kms_enabled": true,
            "pre_launch_script": "x".repeat(100),
        });
        let lines = other_settings(&doc);
        assert!(lines.iter().any(|l| l == "kms_enabled = true"));
        assert!(lines
            .iter()
            .any(|l| l.starts_with("pre_launch_script = <100 chars")));
        assert!(!lines.iter().any(|l| l.starts_with("docker_compose_file")));
    }
}
