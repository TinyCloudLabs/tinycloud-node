//! Owner lifecycle resource inventory. Routes remain unmounted until reconciliation is wired.
use super::*;
use tinycloud_core::{
    models::{encryption_network, encryption_network_key, resource_purge_job},
    resource_purge_fence::ResourceTarget,
    sea_orm::sea_query::JoinType,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceListRequest {
    version: u8,
    owner_did: String,
    cursor: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceListResponse {
    pub version: u8,
    pub host_id: String,
    pub owner_did: String,
    pub resources: Vec<String>,
    pub next_cursor: Option<String>,
    pub last_page: bool,
}
fn exact_resource(raw: &str, owner: &str) -> Result<(), ApiError> {
    let parsed =
        ResourceTarget::parse(raw).map_err(|_| error(Status::BadRequest, "invalid_request"))?;
    if parsed.owner_did() != owner || parsed.as_str() != raw {
        return Err(error(Status::BadRequest, "invalid_request"));
    }
    Ok(())
}

#[rocket::post("/resource/list", format = "json", data = "<body>")]
pub async fn list_my_resources(
    runtime: &State<LifecycleRuntime>,
    auth: AuthHeaderGetter<InvocationInfo>,
    key: IdempotencyKey,
    body: Json<ResourceListRequest>,
) -> Result<Json<ResourceListResponse>, ApiError> {
    use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
    if body.version != 1 {
        return Err(error(Status::BadRequest, "invalid_request"));
    }
    let owner = canonicalize_did(&body.owner_did)
        .map_err(|_| error(Status::BadRequest, "invalid_request"))?;
    let proof = verify_owner(
        &auth.0 .0.invocation,
        "tinycloud.resource/list",
        &owner,
        &owner,
        &key.0,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
    .map_err(proof_error)?;
    let cursor = body
        .cursor
        .as_ref()
        .map(|encoded| {
            if encoded.len() > 4096 {
                return Err(error(Status::BadRequest, "invalid_cursor"));
            }
            let bytes = decode_config(encoded, URL_SAFE_NO_PAD)
                .map_err(|_| error(Status::BadRequest, "invalid_cursor"))?;
            let raw = String::from_utf8(bytes)
                .map_err(|_| error(Status::BadRequest, "invalid_cursor"))?;
            exact_resource(&raw, &owner)
                .map_err(|_| error(Status::BadRequest, "invalid_cursor"))?;
            Ok(raw)
        })
        .transpose()?;
    let _admission = runtime.fence.lifecycle_operation().await;
    let tx = runtime
        .management_transaction(&proof, "resource-list", "owner", &owner)
        .await?;
    let mut all = Query::select();
    all.expr_as(
        Expr::col(encryption_network::Column::NetworkId),
        Alias::new("resource"),
    )
    .from(encryption_network::Entity)
    .and_where(Expr::col(encryption_network::Column::OwnerDid).eq(&owner));
    let mut keys = Query::select();
    let concatenation = match tx.get_database_backend() {
        tinycloud_core::sea_orm::DbBackend::MySql => "CONCAT(k.network_id, '/', k.key_path)",
        _ => "k.network_id || '/' || k.key_path",
    };
    keys.expr(Expr::cust(concatenation))
        .from_as(encryption_network_key::Entity, Alias::new("k"))
        .join_as(
            JoinType::InnerJoin,
            encryption_network::Entity,
            Alias::new("n"),
            Expr::col((Alias::new("n"), encryption_network::Column::NetworkId))
                .equals((Alias::new("k"), encryption_network_key::Column::NetworkId)),
        )
        .and_where(Expr::col((Alias::new("n"), encryption_network::Column::OwnerDid)).eq(&owner));
    all.union(UnionType::Distinct, keys);
    let mut jobs = Query::select();
    jobs.column(resource_purge_job::Column::Resource)
        .from(resource_purge_job::Entity)
        .and_where(
            Expr::col(resource_purge_job::Column::OwnerHmac).is_in(runtime.owner_hmacs(&owner)?),
        )
        .and_where(Expr::col(resource_purge_job::Column::Phase).ne("complete"));
    all.union(UnionType::Distinct, jobs);
    let binary_resource = match tx.get_database_backend() {
        tinycloud_core::sea_orm::DbBackend::Postgres => "resource COLLATE \"C\"",
        tinycloud_core::sea_orm::DbBackend::Sqlite => "resource COLLATE BINARY",
        tinycloud_core::sea_orm::DbBackend::MySql => "BINARY resource",
    };
    let mut page = Query::select();
    page.column(Alias::new("resource"))
        .from_subquery(all, Alias::new("owned"))
        .order_by_expr(Expr::cust(binary_resource), Order::Asc)
        .limit(501);
    if let Some(cursor) = cursor {
        page.and_where(Expr::expr(Expr::cust(binary_resource)).gt(cursor));
    }
    let mut resources = tx
        .query_all(tx.get_database_backend().build(&page))
        .await
        .map_err(unavailable)?
        .into_iter()
        .map(|row| row.try_get::<String>("", "resource"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(unavailable)?;
    for raw in &resources {
        exact_resource(raw, &owner).map_err(unavailable)?;
    }
    let last_page = resources.len() <= 500;
    resources.truncate(500);
    let next_cursor = if last_page {
        None
    } else {
        resources
            .last()
            .map(|raw| encode_config(raw, URL_SAFE_NO_PAD))
    };
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(ResourceListResponse {
        version: 1,
        host_id: runtime.host_id.clone(),
        owner_did: owner,
        resources,
        next_cursor,
        last_page,
    }))
}
