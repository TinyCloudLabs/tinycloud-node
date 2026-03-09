use duckdb::Connection;

use super::caveats::DuckDbCaveats;
use super::types::{ColumnInfo, DuckDbError, SchemaInfo, TableInfo, ViewInfo};

pub fn describe_schema(
    conn: &Connection,
    caveats: &Option<DuckDbCaveats>,
) -> Result<SchemaInfo, DuckDbError> {
    let mut tables = describe_tables(conn)?;
    let mut views = describe_views(conn)?;

    // Filter by caveats if present
    if let Some(c) = caveats {
        if let Some(ref allowed_tables) = c.tables {
            tables.retain(|t| allowed_tables.iter().any(|at| at == &t.name));
            views.retain(|v| allowed_tables.iter().any(|at| at == &v.name));
        }

        if let Some(ref allowed_columns) = c.columns {
            for table in &mut tables {
                table
                    .columns
                    .retain(|col| allowed_columns.iter().any(|ac| ac == &col.name));
            }
        }
    }

    Ok(SchemaInfo { tables, views })
}

fn describe_tables(conn: &Connection) -> Result<Vec<TableInfo>, DuckDbError> {
    let mut stmt = conn
        .prepare(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'main' AND table_type = 'BASE TABLE' \
             ORDER BY table_name",
        )
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    let table_names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e: duckdb::Error| DuckDbError::DuckDb(e.to_string()))?;

    let mut tables = Vec::new();
    for table_name in table_names {
        let columns = describe_columns(conn, &table_name)?;
        tables.push(TableInfo {
            name: table_name,
            columns,
        });
    }

    Ok(tables)
}

fn describe_columns(conn: &Connection, table_name: &str) -> Result<Vec<ColumnInfo>, DuckDbError> {
    let mut stmt = conn
        .prepare(
            "SELECT column_name, data_type, is_nullable \
             FROM information_schema.columns \
             WHERE table_schema = 'main' AND table_name = ? \
             ORDER BY ordinal_position",
        )
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    let columns: Vec<ColumnInfo> = stmt
        .query_map([&table_name], |row| {
            let name: String = row.get(0)?;
            let data_type: String = row.get(1)?;
            let is_nullable_str: String = row.get(2)?;
            Ok(ColumnInfo {
                name,
                data_type,
                is_nullable: is_nullable_str == "YES",
            })
        })
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e: duckdb::Error| DuckDbError::DuckDb(e.to_string()))?;

    Ok(columns)
}

fn describe_views(conn: &Connection) -> Result<Vec<ViewInfo>, DuckDbError> {
    let mut stmt = conn
        .prepare(
            "SELECT view_name, sql FROM duckdb_views() \
             WHERE schema_name = 'main' \
             ORDER BY view_name",
        )
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    let views: Vec<ViewInfo> = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let sql: String = row.get(1)?;
            Ok(ViewInfo { name, sql })
        })
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e: duckdb::Error| DuckDbError::DuckDb(e.to_string()))?;

    Ok(views)
}
