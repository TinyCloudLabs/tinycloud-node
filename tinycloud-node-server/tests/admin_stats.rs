//! TC-1482: `GET /admin/stats` over the real node, on SQLite and (when
//! `TINYCLOUD_TEST_POSTGRES_URL` is set, mandatory in CI) PostgreSQL.
//!
//! The response rules are pinned in `tinycloud-core`'s `data_owners` tests; the
//! tests here cover the HTTP surface: the authentication matrix, the disabled
//! route, the response shape and one end-to-end data scenario per backend.
//! `tests/admin_stats_logs.rs` covers the logs and
//! `tests/postgres_round_trip_budget.rs` the round trips.

use std::ffi::OsString;

use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use tinycloud_core::sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};

const STATS_TOKEN: &str = "tc1482-stats-token-3f9a1c7e5b2d4a60";
const ADMIN_SECRET: &str = "tc1482-admin-secret-9d8c7b6a5f4e3d2c";
const TOKEN_ENV: &str = "NODE_STATS_READ_TOKEN";
const ADMIN_ENV: &str = "TINYCLOUD_ADMIN_SECRET";

const ALICE: &str = "0x0abcdefabcdefabcdefabcdefabcdefabcdefabc";
const ALICE_MIXED: &str = "0x0ABCDEFabcdefABCDEFabcdefABCDEFabcdefABC";
const BOB: &str = "0x1111111111111111111111111111111111111111";
const CAROL: &str = "0x2222222222222222222222222222222222222222";
const DAVE: &str = "0x3333333333333333333333333333333333333333";

/// The two secrets live in the process environment, which the guards read on
/// every request, so tests that set them run one at a time.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Sets (or clears) the two secrets and restores the previous values on drop.
struct Env(Vec<(&'static str, Option<OsString>)>);

impl Env {
    fn set(stats: Option<&str>, admin: Option<&str>) -> Self {
        let saved = [TOKEN_ENV, ADMIN_ENV]
            .map(|name| (name, std::env::var_os(name)))
            .to_vec();
        Self::apply(TOKEN_ENV, stats);
        Self::apply(ADMIN_ENV, admin);
        Self(saved)
    }

    fn apply(name: &str, value: Option<&str>) {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    fn stats(&self, value: Option<&str>) {
        Self::apply(TOKEN_ENV, value);
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// A throwaway PostgreSQL schema, dropped with the fixture.
struct PgSchema {
    url: String,
    schema: String,
}

impl Drop for PgSchema {
    fn drop(&mut self) {
        let (url, schema) = (self.url.clone(), self.schema.clone());
        let _ = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let admin = Database::connect(url).await?;
                    admin
                        .execute(Statement::from_string(
                            DbBackend::Postgres,
                            format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                        ))
                        .await
                        .map(|_| ())
                })
        })
        .join();
    }
}

struct Node {
    client: Client,
    seed: DatabaseConnection,
    _dir: tempfile::TempDir,
    _schema: Option<PgSchema>,
}

#[derive(Clone, Copy, PartialEq)]
enum Backend {
    Sqlite,
    Postgres,
}

struct Reply {
    status: Status,
    body: String,
    content_type: Option<String>,
    cache_control: Option<String>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body))
    }
}

fn postgres_test_url(test: &str) -> Option<String> {
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            if std::env::var_os("CI").is_some() {
                panic!(
                    "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset (or empty) in CI \
                     (TC-381)."
                );
            }
            eprintln!("skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset");
            None
        }
    }
}

impl Node {
    /// `None` only when PostgreSQL is requested, not configured, and not CI.
    async fn start(backend: Backend, test: &str) -> Option<Node> {
        let dir = tempfile::tempdir().unwrap();
        let (database, schema) = match backend {
            Backend::Sqlite => (
                format!("sqlite:{}?mode=rwc", dir.path().join("node.db").display()),
                None,
            ),
            Backend::Postgres => {
                let url = postgres_test_url(test)?;
                let schema = format!(
                    "tc1482_{}_{}",
                    std::process::id(),
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos()
                );
                let admin = Database::connect(url.as_str()).await.unwrap();
                admin
                    .execute(Statement::from_string(
                        DbBackend::Postgres,
                        format!("CREATE SCHEMA {schema}"),
                    ))
                    .await
                    .unwrap();
                let mut scoped = reqwest::Url::parse(&url).unwrap();
                scoped
                    .query_pairs_mut()
                    .append_pair("options", &format!("-c search_path={schema}"));
                (scoped.to_string(), Some(PgSchema { url, schema }))
            }
        };
        let overlay = format!(
            r#"
log_level = "critical"
[storage]
datadir = "{}"
database = "{}"
[keys]
type = "Static"
secret = "{}"
[database]
max_connections = 4
[epoch_head_backfill]
enabled = false
"#,
            dir.path().join("data").display(),
            database,
            base64::encode_config([9u8; 32], base64::URL_SAFE_NO_PAD),
        );
        let figment = rocket::Config::figment()
            .merge(Serialized::defaults(tinycloud::config::Config::default()))
            .merge(Toml::string(&overlay));
        let config = figment.extract::<tinycloud::config::Config>().unwrap();
        let rocket = tinycloud::app_with_control(&figment, &config, None)
            .await
            .unwrap();
        let seed = Database::connect(ConnectOptions::new(database))
            .await
            .unwrap();
        Some(Node {
            client: Client::tracked(rocket).await.unwrap(),
            seed,
            _dir: dir,
            _schema: schema,
        })
    }

    fn placeholders(&self, n: usize) -> String {
        (1..=n)
            .map(|i| match self.seed.get_database_backend() {
                DbBackend::Postgres => format!("${i}"),
                _ => "?".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    async fn exec(&self, sql: String, values: Vec<tinycloud_core::sea_orm::Value>) {
        self.seed
            .execute(Statement::from_sql_and_values(
                self.seed.get_database_backend(),
                sql,
                values,
            ))
            .await
            .unwrap();
    }

    async fn add_space(&self, space: &str) {
        self.exec(
            format!("INSERT INTO space (id) VALUES ({})", self.placeholders(1)),
            vec![space.into()],
        )
        .await;
    }

    async fn add_kv(&self, space: &str, key: &str, deleted: bool) {
        use tinycloud_core::sea_orm::Value;
        let blob = |tag: &str| Value::Bytes(Some(Box::new(tag.as_bytes().to_vec())));
        self.exec(
            format!(
                "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, \
                 metadata, deleted) VALUES ({})",
                self.placeholders(9)
            ),
            vec![
                space.into(),
                key.into(),
                blob("invocation"),
                1i64.into(),
                blob("epoch"),
                1i64.into(),
                blob("value"),
                Value::Json(Some(Box::new(json!({})))),
                deleted.into(),
            ],
        )
        .await;
    }

    async fn add_artifact(&self, space: &str) {
        use tinycloud_core::sea_orm::Value;
        self.exec(
            format!(
                "INSERT INTO database_artifact (service, space, name, revision, content_hash, \
                 payload, size_bytes, backend, storage_mode, created_at, updated_at, \
                 checkpoint_size_bytes, checkpoint_content_hash, delta_size_bytes) VALUES ({})",
                self.placeholders(14)
            ),
            vec![
                "sql".into(),
                space.into(),
                "main".into(),
                1i64.into(),
                "hash".into(),
                Value::Bytes(Some(Box::new(vec![0u8; 8]))),
                8i64.into(),
                "sqlite".into(),
                "checkpoint".into(),
                "now".into(),
                "now".into(),
                8i64.into(),
                "hash".into(),
                0i64.into(),
            ],
        )
        .await;
    }

    async fn request(
        &self,
        method: rocket::http::Method,
        path: &str,
        authorization: Option<&str>,
        body: Option<&str>,
    ) -> Reply {
        let mut request = self.client.req(method, path);
        if let Some(value) = authorization {
            request = request.header(Header::new("Authorization", value.to_owned()));
        }
        if let Some(body) = body {
            request = request.header(rocket::http::ContentType::JSON).body(body);
        }
        let response = request.dispatch().await;
        let status = response.status();
        let content_type = response
            .headers()
            .get_one("Content-Type")
            .map(str::to_owned);
        let cache_control = response
            .headers()
            .get_one("Cache-Control")
            .map(str::to_owned);
        Reply {
            status,
            body: response.into_string().await.unwrap_or_default(),
            content_type,
            cache_control,
        }
    }

    async fn get(&self, path: &str, authorization: Option<&str>) -> Reply {
        self.request(rocket::http::Method::Get, path, authorization, None)
            .await
    }

    async fn stats(&self, authorization: Option<&str>) -> Reply {
        self.get("/admin/stats", authorization).await
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn space(chain: u64, owner: &str, name: &str) -> String {
    format!("tinycloud:pkh:eip155:{chain}:{owner}:{name}")
}

/// One end-to-end data scenario: every rule the scoreboard relies on, through
/// the route.
async fn assert_stats_scenario(backend: Backend, test: &str) {
    let _lock = ENV_LOCK.lock().await;
    let _env = Env::set(Some(STATS_TOKEN), Some(ADMIN_SECRET));
    let Some(node) = Node::start(backend, test).await else {
        return;
    };
    let auth = bearer(STATS_TOKEN);

    let empty = node.stats(Some(&auth)).await;
    assert_eq!(empty.status, Status::Ok);
    assert_eq!(empty.json()["owners"], json!([]));
    assert_eq!(empty.json()["count"], 0);

    // Alice: the automatic registry space only (KV and a database in it).
    let alice_account = space(1, ALICE, "account");
    node.add_space(&alice_account).await;
    node.add_kv(&alice_account, "bootstrap/complete", false)
        .await;
    node.add_artifact(&alice_account).await;
    // Bob: a data space whose only rows are deleted.
    let bob = space(1, BOB, "default");
    node.add_space(&bob).await;
    node.add_kv(&bob, "gone", true).await;
    assert_eq!(node.stats(Some(&auth)).await.json()["owners"], json!([]));

    // Alice stores data on two chains, once under a mixed-case spelling.
    for (chain, owner, name) in [
        (1, ALICE, "default"),
        (137, ALICE, "photos"),
        (1, ALICE_MIXED, "mixed"),
    ] {
        let id = space(chain, owner, name);
        node.add_space(&id).await;
        node.add_kv(&id, "k", false).await;
    }
    // Carol has only a SQL/DuckDB database; Dave has a live key beside a tombstone.
    node.add_artifact(&space(1, CAROL, "analytics")).await;
    let dave = space(1, DAVE, "default");
    node.add_space(&dave).await;
    node.add_kv(&dave, "old", true).await;
    node.add_kv(&dave, "new", false).await;

    let reply = node.stats(Some(&auth)).await;
    assert_eq!(reply.status, Status::Ok);
    assert_eq!(reply.content_type.as_deref(), Some("application/json"));
    assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
    let body = reply.json();
    assert_eq!(body["owners"], json!([ALICE, CAROL, DAVE]));
    assert_eq!(body["count"], 3);
    let mut keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["count", "generatedAt", "owners"]);
    time::OffsetDateTime::parse(
        body["generatedAt"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("generatedAt is RFC 3339");
    assert!(
        !reply.body.contains("tinycloud:pkh"),
        "no space id in the body"
    );
    assert!(
        !reply.body.contains(&ALICE_MIXED[2..]),
        "addresses are lowercased"
    );
}

#[tokio::test]
async fn sqlite_stats_scenario() {
    assert_stats_scenario(Backend::Sqlite, "sqlite_stats_scenario").await;
}

#[tokio::test]
async fn postgres_stats_scenario() {
    assert_stats_scenario(Backend::Postgres, "postgres_stats_scenario").await;
}

#[tokio::test]
async fn auth_matrix() {
    let _lock = ENV_LOCK.lock().await;
    let env = Env::set(Some(STATS_TOKEN), Some(ADMIN_SECRET));
    let node = Node::start(Backend::Sqlite, "auth_matrix").await.unwrap();
    let nothing = || None::<&str>;

    // Credentials that must all be refused with the same bare 401.
    let wrong = [
        nothing().map(str::to_owned),
        Some(String::new()),
        Some("Bearer ".to_owned()),
        Some(bearer("")),
        Some(bearer("wrong-token")),
        Some(bearer(&format!("{STATS_TOKEN}x"))),
        Some(bearer(&STATS_TOKEN[..STATS_TOKEN.len() - 1])),
        Some(bearer(&STATS_TOKEN.to_uppercase())),
        Some(bearer(ADMIN_SECRET)),
        Some(format!("Basic {STATS_TOKEN}")),
        Some(format!("bearer {STATS_TOKEN}")),
        Some(STATS_TOKEN.to_owned()),
    ];
    let mut bodies = Vec::new();
    for authorization in &wrong {
        let reply = node.stats(authorization.as_deref()).await;
        assert_eq!(
            reply.status,
            Status::Unauthorized,
            "{authorization:?} must be refused"
        );
        assert!(!reply.body.contains(STATS_TOKEN));
        assert!(!reply.body.contains(ADMIN_SECRET));
        bodies.push((reply.body, reply.content_type, reply.cache_control));
    }
    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "every refusal looks the same: {bodies:?}"
    );
    assert!(!bodies[0].0.contains("alid"), "no detail in the refusal");

    let ok = node.stats(Some(&bearer(STATS_TOKEN))).await;
    assert_eq!(ok.status, Status::Ok);
    assert_eq!(ok.json()["owners"], json!([]));

    // Read-only: no other method is routed.
    for method in [
        rocket::http::Method::Post,
        rocket::http::Method::Put,
        rocket::http::Method::Patch,
        rocket::http::Method::Delete,
    ] {
        let reply = node
            .request(
                method,
                "/admin/stats",
                Some(&bearer(STATS_TOKEN)),
                Some("{}"),
            )
            .await;
        assert_eq!(reply.status, Status::NotFound, "{method}");
    }

    // The stats token opens no admin route, with the admin secret configured...
    let victim = space(1, ALICE, "default");
    let quota = format!("/admin/quota/{victim}");
    let stats_auth = bearer(STATS_TOKEN);
    for (method, path, body) in [
        (
            rocket::http::Method::Put,
            quota.as_str(),
            Some(r#"{"limit_bytes":1}"#),
        ),
        (rocket::http::Method::Delete, quota.as_str(), None),
        (rocket::http::Method::Get, quota.as_str(), None),
        (rocket::http::Method::Get, "/admin/quota", None),
        (rocket::http::Method::Get, "/admin/usage", None),
    ] {
        let reply = node.request(method, path, Some(&stats_auth), body).await;
        assert_eq!(
            reply.status,
            Status::Unauthorized,
            "{method} {path} accepted the stats token"
        );
    }
    // ...and with it unset.
    env.stats(Some(STATS_TOKEN));
    std::env::remove_var(ADMIN_ENV);
    for (method, path, body) in [
        (
            rocket::http::Method::Put,
            quota.as_str(),
            Some(r#"{"limit_bytes":1}"#),
        ),
        (rocket::http::Method::Delete, quota.as_str(), None),
        (rocket::http::Method::Get, "/admin/usage", None),
    ] {
        let reply = node.request(method, path, Some(&stats_auth), body).await;
        assert!(
            reply.status.class().is_client_error() || reply.status.class().is_server_error(),
            "{method} {path} accepted the stats token with no admin secret"
        );
    }
    // The admin secret still opens the admin routes it always did.
    std::env::set_var(ADMIN_ENV, ADMIN_SECRET);
    let usage = node.get("/admin/usage", Some(&bearer(ADMIN_SECRET))).await;
    assert_eq!(usage.status, Status::Ok);
}

#[tokio::test]
async fn disabled_route_is_an_unknown_route() {
    let _lock = ENV_LOCK.lock().await;
    let env = Env::set(None, Some(ADMIN_SECRET));
    let node = Node::start(Backend::Sqlite, "disabled_route")
        .await
        .unwrap();

    let unknown = node.get("/admin/stats-does-not-exist", None).await;
    assert_eq!(unknown.status, Status::NotFound);
    let shape = |reply: &Reply| {
        (
            reply.status,
            reply.body.clone(),
            reply.content_type.clone(),
            reply.cache_control.clone(),
        )
    };

    // Unset, empty, whitespace-only and equal-to-the-admin-secret all disable
    // the route, whatever credential the request carries.
    let disabled: [Option<&str>; 4] = [None, Some(""), Some(" \t\n"), Some(ADMIN_SECRET)];
    for value in disabled {
        env.stats(value);
        for authorization in [
            None,
            Some(bearer(STATS_TOKEN)),
            Some(bearer(ADMIN_SECRET)),
            Some(bearer("")),
        ] {
            let reply = node.stats(authorization.as_deref()).await;
            assert_eq!(
                shape(&reply),
                shape(&unknown),
                "NODE_STATS_READ_TOKEN={value:?} with {authorization:?} must look like an unknown route"
            );
        }
    }

    // Enabling it takes effect for the next request; the admin secret is
    // still refused and the token accepted.
    env.stats(Some(STATS_TOKEN));
    assert_eq!(
        node.stats(Some(&bearer(ADMIN_SECRET))).await.status,
        Status::Unauthorized
    );
    assert_eq!(
        node.stats(Some(&bearer(STATS_TOKEN))).await.status,
        Status::Ok
    );
}

/// The consumer makes no partial use of a response, so past the 200,000-owner
/// bound the route fails; it never answers a shorter list with a `200`.
#[tokio::test]
async fn more_than_the_owner_bound_is_an_error_not_a_partial_list() {
    const BOUND: u64 = 200_000;
    let _lock = ENV_LOCK.lock().await;
    let _env = Env::set(Some(STATS_TOKEN), Some(ADMIN_SECRET));
    let node = Node::start(Backend::Sqlite, "owner_bound").await.unwrap();
    let auth = bearer(STATS_TOKEN);

    let owner = "'tinycloud:pkh:eip155:1:0x' || printf('%040x', x) || ':default'";
    let series = format!(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < {BOUND})"
    );
    node.exec(
        format!("{series} INSERT INTO space (id) SELECT {owner} FROM n"),
        vec![],
    )
    .await;
    node.exec(
        format!(
            "{series} INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, \
             value, metadata, deleted) SELECT {owner}, 'k', x'01', 1, x'02', 1, x'03', '{{}}', 0 \
             FROM n"
        ),
        vec![],
    )
    .await;

    let at_bound = node.stats(Some(&auth)).await;
    assert_eq!(at_bound.status, Status::Ok);
    let body = at_bound.json();
    assert_eq!(body["count"], BOUND);
    let owners = body["owners"].as_array().unwrap();
    assert_eq!(owners.len() as u64, BOUND);
    assert!(owners.iter().all(|owner| {
        let owner = owner.as_str().unwrap();
        owner.len() == 42
            && owner.starts_with("0x")
            && owner[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }));

    let extra = space(1, BOB, "default");
    node.add_space(&extra).await;
    node.add_kv(&extra, "k", false).await;
    let over = node.stats(Some(&auth)).await;
    assert_eq!(over.status, Status::InsufficientStorage);
    assert!(!over.body.contains("0x"), "no addresses in the failure");
    assert!(!over.body.contains("owners"));
}
