use super::*;
use crate::hash::hash;

fn graph(edges: &[(Hash, Hash)], rows: &[(Hash, &str)]) -> AuthGraphSnapshot {
    let mut parents: HashMap<Hash, Vec<Hash>> = HashMap::new();
    for (child, parent) in edges {
        parents.entry(*child).or_default().push(*parent);
    }
    AuthGraphSnapshot {
        parents,
        delegations: rows
            .iter()
            .map(|(id, _)| {
                (
                    *id,
                    delegation::Model {
                        id: *id,
                        delegator: "owner".into(),
                        delegatee: "recipient".into(),
                        expiry: None,
                        issued_at: None,
                        not_before: None,
                        facts: None,
                        serialization: vec![],
                        serialization_format: 0,
                    },
                )
            })
            .collect(),
        abilities: rows
            .iter()
            .map(|(id, path)| {
                (
                    *id,
                    vec![abilities::Model {
                        delegation: *id,
                        resource: format!("tinycloud:key:test:files/kv/{path}")
                            .parse()
                            .unwrap(),
                        ability: "tinycloud.kv/get".to_owned().try_into().unwrap(),
                        caveats: Default::default(),
                    }],
                )
            })
            .collect(),
        revoked: HashSet::new(),
        renewal_effective_ends: HashMap::new(),
    }
}
fn covers(cap: &abilities::Model) -> bool {
    cap.resource.to_string().ends_with("/first")
}

#[test]
fn positive_endpoint_is_required_even_for_parentless_nodes() {
    let root = hash(b"root");
    let graph = graph(&[], &[(root, "first")]);
    assert!(!graph.has_covering_path_to([root], covers, |_| true, |_| false));
}
#[test]
fn outside_endpoint_on_noncovering_branch_is_refused() {
    let root = hash(b"root");
    let outside = hash(b"outside");
    let graph = graph(&[(root, outside)], &[(root, "first"), (outside, "other")]);
    assert!(!graph.has_covering_path_to([root], covers, |_| true, |row| row.id == outside));
}
#[test]
fn new_descendant_is_refused_and_snapshotted_path_is_accepted() {
    let child = hash(b"new child");
    let outside = hash(b"outside");
    let graph = graph(&[(child, outside)], &[(child, "first"), (outside, "first")]);
    assert!(!graph.has_covering_path_to(
        [child],
        covers,
        |row| row.id == outside,
        |row| row.id == outside
    ));
    assert!(graph.has_covering_path_to([child], covers, |_| true, |row| row.id == outside));
}
#[test]
fn cycles_do_not_create_positive_paths() {
    let a = hash(b"a");
    let b = hash(b"b");
    let graph = graph(&[(a, b), (b, a)], &[(a, "first"), (b, "first")]);
    assert!(!graph.has_covering_path_to([a], covers, |_| true, |_| false));
}
