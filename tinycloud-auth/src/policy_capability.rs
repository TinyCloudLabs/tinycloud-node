extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};

pub mod generated;

/// Resolve a deprecated-alias action URN to its canonical form.
pub fn resolve_alias(action: &str) -> &str {
    generated::resolve_alias(action)
}

/// Does holding `held` satisfy a requirement for `required`, accounting for
/// deprecated-alias equivalence and implication expansion exactly as the
/// registry declares.
pub fn ability_matches(held: &str, required: &str) -> bool {
    expand_actions(core::iter::once(held)).contains(generated::resolve_alias(required))
}

/// Path containment per service.
pub fn path_contains(service: &str, auth: &str, req: &str) -> bool {
    match service {
        "tinycloud.sql" => auth == req,
        _ => {
            if auth == req {
                return true;
            }
            if auth.ends_with('/') {
                if let Some(rest) = req.strip_prefix(auth) {
                    return !rest.is_empty();
                }
                false
            } else {
                false
            }
        }
    }
}

/// Every action URN accepted at the policy boundary for `service`.
pub fn accepted_actions(service: &str) -> Option<&'static [&'static str]> {
    generated::accepted_actions(service)
}

/// URNs directly implied by holding `action`.
pub fn implied_actions(action: &str) -> &'static [&'static str] {
    generated::implied_actions(action)
}

fn expand_actions<'a>(actions: impl IntoIterator<Item = &'a str>) -> BTreeSet<&'a str> {
    let mut out: BTreeSet<&'a str> = BTreeSet::new();
    let mut stack: Vec<&'a str> = actions.into_iter().collect();
    while let Some(action) = stack.pop() {
        let canonical = generated::resolve_alias(action);
        if out.insert(canonical) {
            for implied in generated::implied_actions(canonical) {
                stack.push(implied);
            }
        }
    }
    out
}
