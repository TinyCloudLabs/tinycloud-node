//! Fixed conditional TinyChat publication protocol over its existing SQL catalog.
use super::types::SqlError;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const STATEMENT: &str = "tinycloud.meetingPublication.v3";
pub const DATABASE: &str = "connectors";
pub const SQL_PATH: &str = "xyz.tinycloud.tinychat/connectors";
pub const ENVELOPE_LIMIT: usize = 2_097_152;
fn err(code: &str) -> SqlError {
    SqlError::InvalidStatement(code.into())
}
fn sql(err: rusqlite::Error) -> SqlError {
    SqlError::Sqlite(err.to_string())
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, SqlError> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err("publication_invalid_command"))
}
pub fn digest(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}
fn source(command: &Value) -> Result<&str, SqlError> {
    let value = text(command, "source")?;
    if !["fireflies", "google-meet", "tinycloud-transcriber"].contains(&value) {
        return Err(err("publication_invalid_source"));
    }
    Ok(value)
}
fn source_id(command: &Value) -> Result<&str, SqlError> {
    let value = text(command, "sourceId")?;
    if value.len() > 512 || value.contains('/') || value.contains('\\') || value.contains("..") {
        return Err(err("publication_invalid_identity"));
    }
    Ok(value)
}
fn encoded(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub fn connector_owned_path(path: &str) -> bool {
    path.strip_prefix(&format!("{SQL_PATH}/"))
        .is_some_and(|tail| {
            matches!(
                tail.split('/').next(),
                Some("fireflies" | "google-meet" | "tinycloud-transcriber")
            )
        })
}
pub fn protected_snapshot_path(path: &str) -> bool {
    path.strip_prefix(&format!("{SQL_PATH}/"))
        .is_some_and(|tail| tail.split('/').nth(1) == Some("snapshot"))
}
pub fn active(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT active FROM connector_publication_control WHERE id=1",
        [],
        |row| row.get::<_, i64>(0),
    )
    .unwrap_or(0)
        == 1
}
pub fn protected_table(table: &str) -> bool {
    table.eq_ignore_ascii_case("connector_meeting")
        || table.eq_ignore_ascii_case("connector_meeting_alias")
        || table
            .to_ascii_lowercase()
            .starts_with("connector_publication_")
}
pub fn authorizer(
    conn: &Connection,
    caveats: Option<super::caveats::SqlCaveats>,
    ability: String,
    is_admin: bool,
) -> impl FnMut(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization {
    let fenced = active(conn);
    let mut ordinary = super::authorizer::create_authorizer(caveats, ability, is_admin);
    move |ctx| {
        use rusqlite::hooks::{AuthAction::*, Authorization};
        if fenced
            && matches!(ctx.action,Pragma{pragma_name,..} if pragma_name.eq_ignore_ascii_case("writable_schema"))
        {
            return Authorization::Deny;
        }
        let table = match ctx.action {
            CreateView { view_name }
            | CreateTempView { view_name }
            | DropView { view_name }
            | DropTempView { view_name } => Some(view_name),
            Insert { table_name }
            | Delete { table_name }
            | Update { table_name, .. }
            | DropTable { table_name }
            | AlterTable { table_name, .. }
            | CreateIndex { table_name, .. }
            | DropIndex { table_name, .. }
            | CreateTable { table_name }
            | CreateTempTable { table_name }
            | DropTempTable { table_name }
            | CreateTrigger { table_name, .. }
            | DropTrigger { table_name, .. }
            | CreateTempTrigger { table_name, .. }
            | DropTempTrigger { table_name, .. }
            | CreateTempIndex { table_name, .. }
            | DropTempIndex { table_name, .. }
            | CreateVtable { table_name, .. }
            | DropVtable { table_name, .. } => Some(table_name),
            _ => None,
        };
        if table.is_some_and(|table| {
            (fenced && protected_table(table))
                || table
                    .to_ascii_lowercase()
                    .starts_with("connector_publication_")
                || table.eq_ignore_ascii_case("connector_meeting_alias")
        }) {
            Authorization::Deny
        } else {
            ordinary(ctx)
        }
    }
}
fn schema(conn: &Connection) -> Result<(), SqlError> {
    conn.execute_batch("PRAGMA writable_schema=OFF;")
        .map_err(sql)?;
    let triggers:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND lower(sql) LIKE '%connector_%')",[],|r|r.get(0)).map_err(sql)?;
    if triggers {
        return Err(err("publication_legacy_trigger_requires_review"));
    }
    let shadow: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE lower(name) LIKE 'connector_%')",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if shadow {
        return Err(err("publication_temp_shadow"));
    }
    conn.execute_batch("CREATE TABLE IF NOT EXISTS connector_meeting(id TEXT PRIMARY KEY,source TEXT NOT NULL,source_id TEXT NOT NULL,title TEXT,started_at TEXT,duration_secs INTEGER,organizer_email TEXT,participants TEXT,summary_overview TEXT,summary_action_items TEXT,keywords TEXT,meeting_type TEXT,metadata TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS connector_publication_deletion(operation_id TEXT PRIMARY KEY,command TEXT NOT NULL,receipt TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS connector_publication_control(id INTEGER PRIMARY KEY,active INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS connector_meeting_alias(alias TEXT PRIMARY KEY,meeting_id TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS connector_publication_operation(operation_id TEXT PRIMARY KEY,source TEXT NOT NULL,source_id TEXT NOT NULL,meeting_id TEXT NOT NULL,generation INTEGER NOT NULL,expected_head TEXT,created_at TEXT NOT NULL,inserted INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS connector_publication_snapshot(revision TEXT PRIMARY KEY,snapshot_key TEXT NOT NULL UNIQUE,meeting_id TEXT NOT NULL,operation_id TEXT NOT NULL,generation INTEGER NOT NULL,snapshot_metadata TEXT NOT NULL,staged INTEGER NOT NULL DEFAULT 0,published INTEGER NOT NULL DEFAULT 0);").map_err(sql)?;
    let columns = conn
        .prepare("PRAGMA table_info(connector_meeting)")
        .map_err(sql)?
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    for (column, kind) in [
        ("head_revision", "TEXT"),
        ("head_snapshot_key", "TEXT"),
        ("publication_state", "TEXT"),
        ("publication_operation", "TEXT"),
        ("publication_head_operation", "TEXT"),
        ("publication_generation", "INTEGER NOT NULL DEFAULT 0"),
        ("publication_unavailable_reason", "TEXT"),
    ] {
        if !columns.iter().any(|existing| existing == column) {
            conn.execute(
                &format!("ALTER TABLE connector_meeting ADD COLUMN {column} {kind}"),
                [],
            )
            .map_err(sql)?;
        }
    }
    let collisions:i64=conn.query_row("SELECT COUNT(*) FROM (SELECT source,source_id FROM connector_meeting GROUP BY source,source_id HAVING COUNT(*)>1)",[],|row|row.get(0)).map_err(sql)?;
    if collisions == 0 {
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS connector_publication_identity ON connector_meeting(source,source_id)",[]).map_err(sql)?;
    }
    conn.execute("UPDATE connector_meeting SET publication_state='unavailable',publication_unavailable_reason='original_not_verified' WHERE head_revision IS NULL AND (publication_state IS NULL OR publication_state='unverified')",[]).map_err(sql)?;
    conn.execute("UPDATE connector_meeting SET publication_state='unavailable',publication_unavailable_reason='identity_collision' WHERE (source,source_id) IN (SELECT source,source_id FROM connector_meeting GROUP BY source,source_id HAVING COUNT(*)>1)",[]).map_err(sql)?;
    conn.execute("INSERT INTO connector_publication_control VALUES(1,1) ON CONFLICT(id) DO UPDATE SET active=1",[]).map_err(sql)?;
    Ok(())
}
#[derive(Debug)]
struct Head {
    id: String,
    revision: Option<String>,
    key: Option<String>,
    operation: Option<String>,
    head_operation: Option<String>,
    generation: i64,
    state: Option<String>,
    created_at: String,
}
fn head(conn: &Connection, source: &str, id: &str) -> Result<Option<Head>, SqlError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM connector_meeting WHERE source=? AND source_id=?",
            params![source, id],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if count > 1 {
        return Err(err("publication_identity_collision"));
    }
    conn.query_row("SELECT id,head_revision,head_snapshot_key,publication_operation,publication_head_operation,publication_generation,publication_state,created_at FROM connector_meeting WHERE source=? AND source_id=?",params![source,id],|r|Ok(Head{id:r.get(0)?,revision:r.get(1)?,key:r.get(2)?,operation:r.get(3)?,head_operation:r.get(4)?,generation:r.get(5)?,state:r.get(6)?,created_at:r.get(7)?})).optional().map_err(sql)
}
fn current(conn: &Connection, command: &Value) -> Result<Head, SqlError> {
    let row = head(conn, source(command)?, source_id(command)?)?
        .ok_or_else(|| err("publication_reservation_missing"))?;
    if row.operation.as_deref() != Some(text(command, "operationId")?)
        || Some(row.generation) != command["generation"].as_i64()
        || row.revision.as_deref() != command["expectedHead"].as_str()
        || row.state.as_deref() != Some("reserved")
        || Some(row.id.as_str()) != command["meetingRef"].as_str()
    {
        return Err(err("publication_superseded"));
    }
    Ok(row)
}
fn previous(conn: &Connection, head: &Head) -> Result<Value, SqlError> {
    let Some(revision) = &head.revision else {
        return conn.query_row("SELECT source,source_id,title,started_at,duration_secs,organizer_email,participants,summary_overview,summary_action_items,keywords,meeting_type,metadata FROM connector_meeting WHERE id=?",[&head.id],|r|{
   let json_cell=|i|{let raw:Option<String>=r.get(i)?;Ok::<Value,rusqlite::Error>(raw.and_then(|raw|serde_json::from_str(&raw).ok()).unwrap_or(Value::Null))};
   Ok(json!({"id":head.id,"source":r.get::<_,String>(0)?,"sourceId":r.get::<_,String>(1)?,"title":r.get::<_,Option<String>>(2)?,"startedAt":r.get::<_,Option<String>>(3)?,"durationSecs":r.get::<_,Option<i64>>(4)?,"organizerEmail":r.get::<_,Option<String>>(5)?,"participants":json_cell(6)?.as_array().cloned().unwrap_or_default(),"summaryOverview":r.get::<_,Option<String>>(7)?,"summaryActionItems":r.get::<_,Option<String>>(8)?,"keywords":json_cell(9)?,"meetingType":r.get::<_,Option<String>>(10)?,"metadata":json_cell(11)?.as_object().cloned().unwrap_or_default()}))
  }).map_err(sql);
    };
    let raw:Option<String>=conn.query_row("SELECT snapshot_metadata FROM connector_publication_snapshot WHERE revision=? AND staged=1 AND published=1",[revision],|r|r.get(0)).optional().map_err(sql)?;
    let Some(raw) = raw else {
        return Ok(Value::Null);
    };
    let snapshot: Value =
        serde_json::from_str(&raw).map_err(|_| err("publication_snapshot_invalid"))?;
    let m = &snapshot["metadata"];
    let fields = &m["metadata"]["connector_fields"];
    let participants = m["participants"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|p| json!({"name":p["name"],"email":p.get("email").cloned().unwrap_or(Value::Null)}))
        .collect::<Vec<_>>();
    Ok(
        json!({"id":head.id,"source":snapshot["source"],"sourceId":snapshot["sourceId"],"title":m["title"],"startedAt":m["startedAt"],"organizerEmail":m["organizerEmail"],"participants":participants,"metadata":m["metadata"],"durationSecs":fields["durationSecs"],"summaryOverview":snapshot["overview"]["text"],"summaryActionItems":fields["summaryActionItems"],"keywords":fields["keywords"],"meetingType":fields["meetingType"]}),
    )
}
fn reservation(
    conn: &Connection,
    row: &Head,
    operation: &str,
    inserted: bool,
) -> Result<Value, SqlError> {
    Ok(
        json!({"contractVersion":3,"status":"reserved","operationId":operation,"generation":row.generation,"expectedHead":row.revision,"meetingRef":row.id,"inserted":inserted,"createdAt":row.created_at,"previousMeeting":previous(conn,row)?}),
    )
}
pub fn validate_snapshot(command: &Value) -> Result<Value, SqlError> {
    let raw = text(command, "snapshotRaw")?;
    if raw.len() > ENVELOPE_LIMIT {
        return Err(err("publication_capacity"));
    }
    let revision = text(command, "revision")?;
    if revision.len() != 64 || digest(raw) != revision {
        return Err(err("publication_digest_mismatch"));
    }
    let snapshot: Value =
        serde_json::from_str(raw).map_err(|_| err("publication_snapshot_invalid"))?;
    for field in ["meetingRef", "source", "sourceId", "operationId"] {
        if snapshot.get(field) != command.get(field) {
            return Err(err("publication_identity_mismatch"));
        }
    }
    if snapshot["contractVersion"] != 3
        || !snapshot["metadata"].is_object()
        || !snapshot["metadata"]["participants"].is_array()
        || !snapshot["metadata"]["metadata"].is_object()
        || !snapshot["aliases"].is_array()
    {
        return Err(err("publication_snapshot_invalid"));
    }
    if !snapshot["body"].is_null() {
        let body = &snapshot["body"];
        let raw = body["raw"]
            .as_str()
            .ok_or_else(|| err("publication_snapshot_invalid"))?;
        if raw.len() > 1_048_576
            || body["encoding"] != "utf-8"
            || body["original"]["byteLength"].as_u64() != Some(raw.len() as u64)
            || body["original"]["digest"].as_str() != Some(digest(raw).as_str())
        {
            return Err(err("publication_original_mismatch"));
        }
    }
    let expected = format!(
        "{SQL_PATH}/{}/snapshot/{}/{revision}",
        source(command)?,
        encoded(source_id(command)?)
    );
    if command["snapshotKey"].as_str() != Some(expected.as_str()) {
        return Err(err("publication_snapshot_key_mismatch"));
    }
    Ok(snapshot)
}
pub fn execute(conn: &Connection, space: &str, command: &Value) -> Result<Value, SqlError> {
    if command["contractVersion"] != 3 {
        return Err(err("publication_upgrade_required"));
    }
    let operation = text(command, "operation")?;
    if operation == "capabilities" {
        return Ok(
            json!({"contractVersion":3,"writerFencing":true,"snapshotImmutability":true,"digestVerification":true}),
        );
    }
    let tx = conn.unchecked_transaction().map_err(sql)?;
    if operation == "activate" {
        schema(&tx)?;
        tx.commit().map_err(sql)?;
        return Ok(json!({"contractVersion":3,"status":"ready"}));
    }
    if !active(&tx) {
        return Err(err("publication_activation_required"));
    }
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| err("publication_time_invalid"))?;
    let result = match operation {
        "reserve" => {
            let source = source(command)?;
            let source_id = source_id(command)?;
            let op = text(command, "operationId")?;
            if op.len() > 128 {
                return Err(err("publication_invalid_operation"));
            }
            let old = head(&tx, source, source_id)?;
            let deleted:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM connector_publication_deletion WHERE operation_id=?)",[op],|r|r.get(0)).map_err(sql)?;
            if deleted {
                return Err(err("publication_operation_reused"));
            }
            let seen:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM connector_publication_operation WHERE operation_id=?)",[op],|r|r.get(0)).map_err(sql)?;
            if seen {
                let row = old.ok_or_else(|| err("publication_superseded"))?;
                if row.operation.as_deref() != Some(op) || row.state.as_deref() != Some("reserved")
                {
                    return Err(err("publication_superseded"));
                }
                reservation(&tx, &row, op, false)?
            } else {
                let inserted = old.is_none();
                let id = old
                    .as_ref()
                    .map(|h| h.id.clone())
                    .unwrap_or_else(|| digest(&json!([space, source, source_id]).to_string()));
                if inserted {
                    tx.execute("INSERT INTO connector_meeting(id,source,source_id,participants,metadata,created_at,updated_at,publication_generation,publication_state) VALUES(?,?,?,'[]','{}',?,?,0,'unverified')",params![id,source,source_id,now,now]).map_err(sql)?;
                }
                tx.execute("UPDATE connector_meeting SET publication_generation=publication_generation+1,publication_operation=?,publication_state='reserved' WHERE id=?",params![op,id]).map_err(sql)?;
                let row = head(&tx, source, source_id)?.unwrap();
                tx.execute(
                    "INSERT INTO connector_publication_operation VALUES(?,?,?,?,?,?,?,?)",
                    params![
                        op,
                        source,
                        source_id,
                        id,
                        row.generation,
                        row.revision,
                        now,
                        inserted
                    ],
                )
                .map_err(sql)?;
                reservation(&tx, &row, op, inserted)?
            }
        }
        "prepare_stage" => {
            let row = current(&tx, command)?;
            let mut snapshot = validate_snapshot(command)?;
            snapshot["body"]
                .as_object_mut()
                .map(|body| body.remove("raw"));
            tx.execute("INSERT INTO connector_publication_snapshot(revision,snapshot_key,meeting_id,operation_id,generation,snapshot_metadata) VALUES(?,?,?,?,?,?) ON CONFLICT(revision) DO NOTHING",params![text(command,"revision")?,text(command,"snapshotKey")?,row.id,text(command,"operationId")?,row.generation,snapshot.to_string()]).map_err(sql)?;
            json!({"contractVersion":3,"status":"prepared"})
        }
        "stage" => {
            let row = current(&tx, command)?;
            let changed=tx.execute("UPDATE connector_publication_snapshot SET staged=1 WHERE revision=? AND snapshot_key=? AND meeting_id=? AND operation_id=? AND generation=?",params![text(command,"revision")?,text(command,"snapshotKey")?,row.id,text(command,"operationId")?,row.generation]).map_err(sql)?;
            if changed != 1 {
                return Err(err("publication_stage_missing"));
            }
            json!({"contractVersion":3,"status":"staged","revision":command["revision"],"snapshotKey":command["snapshotKey"]})
        }
        "publish" => {
            let source = source(command)?;
            let source_id = source_id(command)?;
            let existing = head(&tx, source, source_id)?
                .ok_or_else(|| err("publication_reservation_missing"))?;
            if existing.state.as_deref() == Some("published")
                && existing.head_operation.as_deref() == command["operationId"].as_str()
                && existing.revision.as_deref() == command["revision"].as_str()
            {
                json!({"contractVersion":3,"status":"published","meetingRef":existing.id,"operationId":command["operationId"],"revision":existing.revision,"snapshotKey":existing.key})
            } else {
                let row = current(&tx, command)?;
                let raw:Option<String>=tx.query_row("SELECT snapshot_metadata FROM connector_publication_snapshot WHERE revision=? AND operation_id=? AND generation=? AND snapshot_key=? AND staged=1",params![text(command,"revision")?,text(command,"operationId")?,row.generation,text(command,"snapshotKey")?],|r|r.get(0)).optional().map_err(sql)?;
                let snapshot: Value =
                    serde_json::from_str(&raw.ok_or_else(|| err("publication_stage_missing"))?)
                        .map_err(|_| err("publication_snapshot_invalid"))?;
                let m = &snapshot["metadata"];
                let fields = &m["metadata"]["connector_fields"];
                for alias in snapshot["aliases"].as_array().unwrap() {
                    let alias = alias
                        .as_str()
                        .filter(|a| !a.is_empty() && a.len() <= 128)
                        .ok_or_else(|| err("publication_alias_invalid"))?;
                    let collision:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM connector_meeting WHERE id=? AND id!=? UNION ALL SELECT 1 FROM connector_meeting_alias WHERE alias=? AND meeting_id!=?)",params![alias,row.id,alias,row.id],|r|r.get(0)).map_err(sql)?;
                    if collision {
                        return Err(err("publication_alias_collision"));
                    }
                    tx.execute("INSERT INTO connector_meeting_alias VALUES(?,?) ON CONFLICT(alias) DO NOTHING",params![alias,row.id]).map_err(sql)?;
                }
                tx.execute("UPDATE connector_meeting SET title=?,started_at=?,duration_secs=?,organizer_email=?,participants=?,summary_overview=?,summary_action_items=?,keywords=?,meeting_type=?,metadata=?,updated_at=?,head_revision=?,head_snapshot_key=?,publication_head_operation=?,publication_state='published',publication_unavailable_reason=NULL WHERE id=?",params![m["title"].as_str(),m["startedAt"].as_str(),fields["durationSecs"].as_i64(),m["organizerEmail"].as_str(),m["participants"].to_string(),snapshot["overview"]["text"].as_str(),fields["summaryActionItems"].as_str(),if fields["keywords"].is_null(){None}else{Some(fields["keywords"].to_string())},fields["meetingType"].as_str(),m["metadata"].to_string(),now,text(command,"revision")?,text(command,"snapshotKey")?,text(command,"operationId")?,row.id]).map_err(sql)?;
                tx.execute(
                    "UPDATE connector_publication_snapshot SET published=1 WHERE revision=?",
                    [text(command, "revision")?],
                )
                .map_err(sql)?;
                json!({"contractVersion":3,"status":"published","meetingRef":row.id,"operationId":command["operationId"],"revision":command["revision"],"snapshotKey":command["snapshotKey"]})
            }
        }
        "inspect" => {
            let row = head(&tx, source(command)?, source_id(command)?)?
                .ok_or_else(|| err("publication_reservation_missing"))?;
            json!({"contractVersion":3,"status":if row.head_operation.as_deref()==command["operationId"].as_str()&&row.revision.is_some(){"published"}else{"superseded"},"meetingRef":row.id,"operationId":row.head_operation,"revision":row.revision,"snapshotKey":row.key})
        }
        "delete" | "purge" => {
            let source = source(command)?;
            let op = text(command, "operationId")?;
            let mut public_command = command.clone();
            public_command
                .as_object_mut()
                .unwrap()
                .remove("cleanupKeys");
            let seen:Option<(String,String)>=tx.query_row("SELECT command,receipt FROM connector_publication_deletion WHERE operation_id=?",[op],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(sql)?;
            if let Some((prior, receipt)) = seen {
                if prior != public_command.to_string() {
                    return Err(err("publication_operation_reused"));
                }
                return serde_json::from_str(&receipt)
                    .map_err(|_| err("publication_receipt_invalid"));
            }
            let reserved:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM connector_publication_operation WHERE operation_id=?)",[op],|r|r.get(0)).map_err(sql)?;
            if reserved {
                return Err(err("publication_operation_reused"));
            }
            let condition = if operation == "delete" {
                "source=?1 AND source_id=?2"
            } else {
                "source=?1"
            };
            let source_id = if operation == "delete" {
                source_id(command)?
            } else {
                ""
            };
            let query=format!("SELECT snapshot_key FROM connector_publication_snapshot WHERE meeting_id IN (SELECT id FROM connector_meeting WHERE {condition})");
            let mut keys = if operation == "delete" {
                tx.prepare(&query)
                    .map_err(sql)?
                    .query_map(params![source, source_id], |r| r.get::<_, String>(0))
                    .map_err(sql)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sql)?
            } else {
                tx.prepare(&query)
                    .map_err(sql)?
                    .query_map([source], |r| r.get::<_, String>(0))
                    .map_err(sql)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sql)?
            };
            if operation == "delete" {
                keys.push(format!("{SQL_PATH}/{source}/transcript/{source_id}"));
            }
            if let Some(cleanup) = command["cleanupKeys"].as_array() {
                for key in cleanup {
                    let key = key
                        .as_str()
                        .filter(|key| key.starts_with(&format!("{SQL_PATH}/{source}/")))
                        .ok_or_else(|| err("publication_cleanup_invalid"))?;
                    keys.push(key.to_owned());
                }
            }
            keys.sort();
            keys.dedup();
            let count_query=format!("SELECT COUNT(*) FROM connector_meeting WHERE {condition} AND (publication_state IS NULL OR publication_state!='deleted')");
            let deleted_count: i64 = if operation == "delete" {
                tx.query_row(&count_query, params![source, source_id], |r| r.get(0))
                    .map_err(sql)?
            } else {
                tx.query_row(&count_query, [source], |r| r.get(0))
                    .map_err(sql)?
            };
            let revoke=format!("UPDATE connector_publication_snapshot SET published=0,staged=0 WHERE meeting_id IN (SELECT id FROM connector_meeting WHERE {condition})");
            if operation == "delete" {
                tx.execute(&revoke, params![source, source_id])
                    .map_err(sql)?;
            } else {
                tx.execute(&revoke, [source]).map_err(sql)?;
            }
            let update=format!("UPDATE connector_meeting SET title=NULL,started_at=NULL,duration_secs=NULL,organizer_email=NULL,participants='[]',summary_overview=NULL,summary_action_items=NULL,keywords=NULL,meeting_type=NULL,metadata='{{}}',publication_generation=publication_generation+1,publication_operation=?3,publication_head_operation=NULL,head_revision=NULL,head_snapshot_key=NULL,publication_state='deleted' WHERE {condition}");
            // Numbered binds keep the source-wide command's unused second bind explicit.
            tx.execute(&update, params![source, source_id, op])
                .map_err(sql)?;
            let receipt = json!({"contractVersion":3,"status":if operation=="delete"{"deleted"}else{"purged"},"operationId":op,"snapshotKeys":keys,"deletedCount":deleted_count});
            tx.execute(
                "INSERT INTO connector_publication_deletion VALUES(?,?,?)",
                params![op, public_command.to_string(), receipt.to_string()],
            )
            .map_err(sql)?;
            receipt
        }
        _ => return Err(err("publication_invalid_operation")),
    };
    tx.commit().map_err(sql)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    fn call(conn: &Connection, mut command: Value) -> Result<Value, SqlError> {
        command["contractVersion"] = json!(3);
        execute(conn, "synthetic-space", &command)
    }
    fn ready() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        call(&conn, json!({"operation":"activate"})).unwrap();
        conn
    }
    fn reserve(conn: &Connection, op: &str) -> Value {
        call(conn,json!({"operation":"reserve","source":"fireflies","sourceId":"source","operationId":op})).unwrap()
    }
    fn stage(conn: &Connection, reservation: &Value, text: &str) -> Value {
        let raw=json!({"contractVersion":3,"source":"fireflies","sourceId":"source","meetingRef":reservation["meetingRef"],"operationId":reservation["operationId"],"createdAt":"2026-09-14T00:00:00Z","metadata":{"title":text,"startedAt":null,"organizerEmail":null,"participants":[],"metadata":{}},"body":{"basis":"transcript","encoding":"utf-8","schema":"text","raw":text,"original":{"digest":hex::encode(Sha256::digest(text.as_bytes())),"byteLength":text.len(),"recordCount":1,"extent":"unknown","captureComplete":null},"omissions":[]},"overview":null,"aliases":[]}).to_string();
        let revision = hex::encode(Sha256::digest(raw.as_bytes()));
        let mut command = reservation.clone();
        command["source"] = json!("fireflies");
        command["sourceId"] = json!("source");
        command["revision"] = json!(revision);
        command["snapshotKey"] = json!(format!("{SQL_PATH}/fireflies/snapshot/source/{revision}"));
        command["snapshotRaw"] = json!(raw);
        command["operation"] = json!("prepare_stage");
        call(conn, command.clone()).unwrap();
        command["operation"] = json!("stage");
        call(conn, command.clone()).unwrap();
        command.as_object_mut().unwrap().remove("snapshotRaw");
        command
    }
    #[test]
    fn publication_capabilities_and_first_insert_race() {
        let conn = ready();
        assert_eq!(
            call(&conn, json!({"operation":"capabilities"})).unwrap()["writerFencing"],
            true
        );
        let a = reserve(&conn, "a");
        let b = reserve(&conn, "b");
        assert_eq!(a["meetingRef"], b["meetingRef"]);
        assert_eq!(a["inserted"], true);
        assert_eq!(b["inserted"], false);
        assert!(b["generation"].as_i64() > a["generation"].as_i64());
        assert!(call(&conn,json!({"operation":"reserve","source":"fireflies","sourceId":"source","operationId":"a"})).is_err());
    }
    #[test]
    fn publication_preserves_head_and_fences_stale_workers() {
        let conn = ready();
        let a = reserve(&conn, "a");
        let mut a = stage(&conn, &a, "first");
        a["operation"] = json!("publish");
        call(&conn, a.clone()).unwrap();
        let b = reserve(&conn, "b");
        assert_eq!(b["expectedHead"], a["revision"]);
        assert_eq!(b["previousMeeting"]["title"], "first");
        let mut b = stage(&conn, &b, "new");
        let _c = reserve(&conn, "c");
        b["operation"] = json!("publish");
        assert!(call(&conn, b).is_err());
        assert_eq!(call(&conn,json!({"operation":"inspect","source":"fireflies","sourceId":"source","operationId":"a"})).unwrap()["revision"],a["revision"]);
    }
    #[test]
    fn publication_lost_ack_after_newer_head_is_superseded() {
        let conn = ready();
        let a = reserve(&conn, "a");
        let mut a = stage(&conn, &a, "first");
        a["operation"] = json!("publish");
        call(&conn, a.clone()).unwrap();
        let b = reserve(&conn, "b");
        let mut b = stage(&conn, &b, "second");
        b["operation"] = json!("publish");
        call(&conn, b).unwrap();
        assert_eq!(call(&conn,json!({"operation":"inspect","source":"fireflies","sourceId":"source","operationId":"a"})).unwrap()["status"],"superseded");
        assert!(call(&conn, a).is_err());
    }
    #[test]
    fn publication_delete_recreate_fences_old_stage() {
        let conn = ready();
        let a = reserve(&conn, "a");
        let mut a = stage(&conn, &a, "first");
        call(&conn,json!({"operation":"delete","source":"fireflies","sourceId":"source","operationId":"del"})).unwrap();
        let b = reserve(&conn, "b");
        assert!(b["generation"].as_i64() > a["generation"].as_i64());
        a["operation"] = json!("publish");
        assert!(call(&conn, a).is_err());
        assert!(b["expectedHead"].is_null());
    }
    #[test]
    fn publication_rejects_bad_digests_and_cannot_publish_unstaged_body() {
        let conn = ready();
        let a = reserve(&conn, "a");
        let mut bad = a.clone();
        bad["operation"] = json!("publish");
        bad["revision"] = json!("a".repeat(64));
        bad["source"] = json!("fireflies");
        bad["sourceId"] = json!("source");
        assert!(call(&conn, bad).is_err());
    }
    #[test]
    fn publication_delete_retry_does_not_delete_recreated_meeting() {
        let conn = ready();
        let a = reserve(&conn, "a");
        let _a = stage(&conn, &a, "first");
        let command = json!({"operation":"delete","source":"fireflies","sourceId":"source","operationId":"del"});
        let first = call(&conn, command.clone()).unwrap();
        let b = reserve(&conn, "b");
        let mut b = stage(&conn, &b, "second");
        b["operation"] = json!("publish");
        call(&conn, b.clone()).unwrap();
        assert_eq!(call(&conn, command).unwrap(), first);
        assert_eq!(call(&conn,json!({"operation":"inspect","source":"fireflies","sourceId":"source","operationId":"b"})).unwrap()["revision"],b["revision"]);
    }
    #[test]
    fn publication_rejects_changed_key_between_stage_and_publish() {
        let conn = ready();
        let a = reserve(&conn, "a");
        let mut a = stage(&conn, &a, "first");
        a["operation"] = json!("publish");
        a["snapshotKey"] = json!("arbitrary-key");
        assert!(call(&conn, a).is_err());
    }
    #[test]
    fn publication_activation_preserves_legacy_collisions_and_metadata() {
        let conn = Connection::open_in_memory().unwrap();
        schema(&conn).unwrap();
        conn.execute("DROP INDEX connector_publication_identity", [])
            .unwrap();
        conn.execute("INSERT INTO connector_meeting(id,source,source_id,title,started_at,summary_overview,participants,metadata,created_at,updated_at) VALUES('old','fireflies','source','Older title','2025-01-01T10:00:00Z','Old summary','[]','{}','2025-01-01','2025-01-01'),('dup1','fireflies','collision','one',NULL,NULL,'[]','{}','2025-01-01','2025-01-01'),('dup2','fireflies','collision','two',NULL,NULL,'[]','{}','2025-01-01','2025-01-01')",[]).unwrap();
        call(&conn, json!({"operation":"activate"})).unwrap();
        let old = reserve(&conn, "migrate");
        assert_eq!(old["meetingRef"], "old");
        assert_eq!(old["previousMeeting"]["startedAt"], "2025-01-01T10:00:00Z");
        assert_eq!(old["previousMeeting"]["summaryOverview"], "Old summary");
        assert!(call(&conn,json!({"operation":"reserve","source":"fireflies","sourceId":"collision","operationId":"dup"})).is_err());
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM connector_meeting WHERE publication_unavailable_reason='identity_collision'",[],|r|r.get::<_,i64>(0)).unwrap(),2);
    }
    #[test]
    fn publication_legacy_null_metadata_has_safe_previous_shape() {
        let conn = ready();
        conn.execute("INSERT INTO connector_meeting(id,source,source_id,created_at,updated_at) VALUES('legacy','fireflies','source','2025-01-01','2025-01-01')",[]).unwrap();
        let row = reserve(&conn, "migrate");
        assert_eq!(row["previousMeeting"]["participants"], json!([]));
        assert_eq!(row["previousMeeting"]["metadata"], json!({}));
    }

    #[test]
    fn publication_membership_excludes_staged_and_revoked_revisions() {
        let conn = ready();
        let a = reserve(&conn, "a");
        let mut a = stage(&conn, &a, "deleted content");
        assert_eq!(
            conn.query_row(
                "SELECT published FROM connector_publication_snapshot",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        a["operation"] = json!("publish");
        call(&conn, a).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT published FROM connector_publication_snapshot",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        let deleted=call(&conn,json!({"operation":"delete","source":"fireflies","sourceId":"source","operationId":"delete"})).unwrap();
        assert_eq!(deleted["deletedCount"], 1);
        let b = reserve(&conn, "b");
        assert!(b["previousMeeting"]["title"].is_null());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM connector_publication_snapshot WHERE staged=1 OR published=1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn publication_purge_retry_retains_original_cleanup_inventory() {
        let conn = ready();
        let _a = reserve(&conn, "a");
        let old = format!("{SQL_PATH}/fireflies/archive-copy/old");
        let new = format!("{SQL_PATH}/fireflies/archive-copy/new");
        let first=call(&conn,json!({"operation":"purge","source":"fireflies","operationId":"purge","cleanupKeys":[old]})).unwrap();
        let replay=call(&conn,json!({"operation":"purge","source":"fireflies","operationId":"purge","cleanupKeys":[new]})).unwrap();
        assert_eq!(first, replay);
        assert!(!replay["snapshotKeys"]
            .as_array()
            .unwrap()
            .contains(&json!(new)));
    }
}
