//! Logical SQL/DuckDB database identities, separate from physical artifact names.
//!
//! N3 can resolve these logical names through explicit aliases to old physical
//! artifacts. Never interpret a logical name as an old selector during lookup.

/// A stable, fixed-length, file-safe digest of the complete resource path.
///
/// The `n`/`p` marker distinguishes a pathless resource from an explicitly
/// empty path. Hashing the raw UTF-8 bytes preserves the distinction between
/// slashes, percent escapes, repeated separators, and trailing slashes without
/// making long paths exceed filesystem component limits. The physical name is
/// opaque; callers needing the logical path must keep it separately. SQL and
/// DuckDB artifacts already have separate service keys.
pub fn logical_name(path: Option<&str>) -> String {
    match path {
        None => "v2n".to_string(),
        Some(path) => {
            use sha2::{Digest, Sha256};
            format!("v2d{}", hex::encode(Sha256::digest(path.as_bytes())))
        }
    }
}

/// The exact pre-N2 SQL selector. N3 uses this only to inventory old artifacts.
pub fn legacy_sql_name(path: Option<&str>) -> String {
    path.map(|p| p.split('/').next_back().unwrap_or("default").to_string())
        .unwrap_or_else(|| "default".to_string())
}

/// The exact pre-N2 DuckDB selector. N3 uses this only for old-artifact inventory.
pub fn legacy_duckdb_name(path: Option<&str>) -> String {
    let name = legacy_sql_name(path);
    if name.is_empty()
        || name.contains("..")
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        "default".to_string()
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn logical_names_preserve_every_path_distinction() {
        let paths = [
            None,
            Some(""),
            Some("default"),
            Some("connectors"),
            Some("appA/connectors"),
            Some("appB/connectors"),
            Some("appA/connectors/"),
            Some("appA//connectors"),
            Some("appA/"),
            Some("appB/"),
            Some("appA/.."),
            Some("appA/a\\b"),
            Some("a%2Fb"),
            Some("a/b"),
            Some("café"),
            Some("café"),
            Some("a\0b"),
        ];
        let names: HashSet<_> = paths.into_iter().map(logical_name).collect();
        assert_eq!(names.len(), paths.len());
        for name in names {
            assert!(name.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        }
        assert_eq!(logical_name(None), "v2n");
        assert_ne!(logical_name(Some("")), logical_name(None));
        assert_eq!(logical_name(Some("a/b")).len(), 67);
        assert!(logical_name(Some("a/b")).starts_with("v2d"));
    }

    #[test]
    fn long_path_identity_fits_a_filename_component() {
        let path = "a".repeat(1024);
        let name = logical_name(Some(&path));
        assert_eq!(name.len(), 67);
        assert_ne!(name, logical_name(Some(&format!("{path}b"))));
        assert!(name.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    }

    #[test]
    fn old_selectors_are_available_only_for_explicit_migration() {
        assert_eq!(legacy_sql_name(None), "default");
        assert_eq!(legacy_sql_name(Some("appA/")), "");
        assert_eq!(legacy_sql_name(Some("appA/..")), "..");
        assert_eq!(legacy_duckdb_name(None), "default");
        assert_eq!(legacy_duckdb_name(Some("appA/")), "default");
        assert_eq!(legacy_duckdb_name(Some("appA/..")), "default");
        assert_eq!(legacy_duckdb_name(Some("appA/connectors")), "connectors");
    }

    #[cfg(feature = "duckdb")]
    #[test]
    fn sql_and_duckdb_use_the_same_full_path_identity() {
        for path in [
            None,
            Some(""),
            Some("appA/connectors"),
            Some("appB/connectors"),
            Some("appA/"),
            Some("appA/.."),
            Some("appA/a\\b"),
            Some(&"a".repeat(1024)),
        ] {
            let sql = crate::sql::SqlService::db_name_from_path(path);
            let duckdb = crate::duckdb::DuckDbService::db_name_from_path(path);
            assert_eq!(sql, duckdb, "{path:?}");
            assert!(crate::duckdb::service::validate_db_name(&duckdb).is_ok());
        }
    }
}
