use crate::{
    authorization::{AuthHeaderGetter, PeerReplicationSessionToken, ReplicationSessionToken},
    BlockStage, TinyCloud,
};
use futures::future::BoxFuture;
use rocket::{http::Status, serde::json::Json, State};
use std::collections::BTreeMap;
use tinycloud_auth::resource::{Path as ResourcePath, Service, SpaceId};
use tinycloud_core::{
    events::Delegation,
    replication::{
        AuthReplicationApplyResponse, AuthReplicationExportRequest, AuthReplicationExportResponse,
        AuthReplicationReconcileRequest, KvReconCompareRequest, KvReconCompareResponse,
        KvReconExportRequest, KvReconExportResponse, KvReconSplitChildComparison,
        KvReconSplitCompareRequest, KvReconSplitCompareResponse, KvReconSplitReconcileChildResult,
        KvReconSplitReconcileRequest, KvReconSplitReconcileResponse, KvReconSplitRequest,
        KvReconSplitResponse, KvReplicationError, KvStateCompareItem, KvStateCompareRequest,
        KvStateCompareResponse, KvStateRequest, KvStateResponse, ReplicationExportRequest,
        ReplicationExportResponse, ReplicationReconcileRequest, ReplicationRouteStatus,
        ReplicationScope, ReplicationService, ReplicationSessionError,
        ReplicationSessionOpenRequest, ReplicationSessionOpenResponse, ReplicationSessionRecord,
        ReplicationSessionSummary, SqlReplicationApplyResponse, SqlReplicationExportRequest,
        SqlReplicationExportResponse, SqlReplicationReconcileRequest,
    },
    sql::{SqlError, SqlService},
    types::Resource,
    util::{Capability, DelegationInfo},
    TxError,
};

#[derive(Debug, Clone)]
struct SplitReconcileTarget {
    replay_prefix: String,
    result_prefix: String,
}

#[get("/replication/info")]
pub async fn replication_info(
    replication: &State<ReplicationService>,
) -> Json<ReplicationRouteStatus> {
    Json(ReplicationRouteStatus {
        protocol_ready: true,
        requires_auth: true,
        endpoints: vec![
            "GET /replication/info",
            "POST /replication/session/open",
            "POST /replication/auth/export",
            "POST /replication/auth/reconcile",
            "POST /replication/export",
            "POST /replication/kv/state",
            "POST /replication/kv/state/compare",
            "POST /replication/recon/export",
            "POST /replication/recon/split",
            "POST /replication/recon/split/compare",
            "POST /replication/recon/compare",
            "POST /replication/reconcile",
            "POST /replication/reconcile/split",
            "POST /replication/sql/export",
            "POST /replication/sql/reconcile",
        ],
        capabilities: replication.status().clone().into(),
        ..ReplicationRouteStatus::default()
    })
}

#[post("/replication/session/open", format = "json", data = "<request>")]
pub async fn replication_session_open(
    request: Json<ReplicationSessionOpenRequest>,
    auth: Option<AuthHeaderGetter<DelegationInfo>>,
    tinycloud: &State<TinyCloud>,
    replication: &State<ReplicationService>,
) -> Result<Json<ReplicationSessionOpenResponse>, (Status, String)> {
    let auth = auth.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Authorization delegation for replication session".to_string(),
        )
    })?;
    let scope = request_scope(&request)?;
    let delegation = auth.0;
    let requested_resource = requested_resource(&request.space_id, &scope)?;
    ensure_sync_scope(&delegation.0.capabilities, &requested_resource, &scope)?;
    let requester_did = delegation.0.delegate.clone();
    let delegation_hash = delegation.hash();

    import_supporting_delegations(request.supporting_delegations.as_deref(), tinycloud).await?;
    verify_replication_delegation(delegation, tinycloud).await?;
    ensure_replication_delegation_active(delegation_hash, tinycloud).await?;
    let space_id: SpaceId = request.space_id.parse().map_err(|_| {
        (
            Status::BadRequest,
            format!("invalid space id: {}", request.space_id),
        )
    })?;
    let server_did = tinycloud
        .stage_key(&space_id)
        .await
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;

    let (session_token, record) = replication.open_session(
        requester_did,
        request.space_id.clone(),
        scope,
        Some(delegation_hash),
    );
    let summary = ReplicationSessionSummary::from_record(&record);
    let status = replication.status();

    Ok(Json(ReplicationSessionOpenResponse {
        session_token,
        space_id: summary.space_id,
        service: summary.service,
        server_did,
        roles_enabled: status
            .roles_enabled
            .iter()
            .map(|role| (*role).to_string())
            .collect(),
        peer_serving: status.peer_serving,
        can_export: peer_export_allowed(status),
        recon: status.recon,
        auth_sync: status.auth_sync,
        prefix: summary.prefix,
        db_name: summary.db_name,
        expires_at: summary.expires_at,
    }))
}

#[post("/replication/auth/export", format = "json", data = "<request>")]
pub async fn auth_replication_export(
    request: Json<AuthReplicationExportRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<AuthReplicationExportResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Auth;
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    tinycloud
        .export_auth_replication(&request)
        .await
        .map(Json)
        .map_err(map_replication_error)
}

#[post("/replication/auth/reconcile", format = "json", data = "<request>")]
pub async fn auth_reconcile(
    request: Json<AuthReplicationReconcileRequest>,
    token: Option<ReplicationSessionToken>,
    peer_token: Option<PeerReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<AuthReplicationApplyResponse>, (Status, String)> {
    let scope = ReplicationScope::Auth;
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Peer-Replication-Session for auth replication reconcile".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let export = reqwest::Client::new()
        .post(format!("{peer_url}/replication/auth/export"))
        .header("Replication-Session", peer_token.0)
        .json(&AuthReplicationExportRequest {
            space_id: request.space_id.clone(),
        })
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer auth export failed", export).await);
    }

    let export = export
        .json::<AuthReplicationExportResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    let mut applied = tinycloud
        .apply_auth_replication(&export)
        .await
        .map_err(map_auth_tx_error)?;
    applied.peer_url = Some(request.peer_url.clone());
    Ok(Json(applied))
}

#[post("/replication/export", format = "json", data = "<request>")]
pub async fn replication_export(
    request: Json<ReplicationExportRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<ReplicationExportResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    tinycloud
        .export_kv_replication(&request)
        .await
        .map(Json)
        .map_err(map_replication_error)
}

#[post("/replication/kv/state", format = "json", data = "<request>")]
pub async fn kv_state(
    request: Json<KvStateRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KvStateResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    tinycloud
        .export_kv_state(&request)
        .await
        .map(Json)
        .map_err(map_replication_error)
}

#[post("/replication/kv/state/compare", format = "json", data = "<request>")]
pub async fn kv_state_compare(
    request: Json<KvStateCompareRequest>,
    token: Option<ReplicationSessionToken>,
    peer_token: Option<PeerReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KvStateCompareResponse>, (Status, String)> {
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Peer-Replication-Session for kv state compare".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let local = tinycloud
        .export_kv_recon(&KvReconExportRequest {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            start_after: request.start_after.clone(),
            limit: request.limit,
        })
        .await
        .map_err(map_replication_error)?;

    let keys = local
        .items
        .iter()
        .map(|item| item.key.clone())
        .collect::<Vec<_>>();
    let peer_state = if keys.is_empty() {
        KvStateResponse {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            items: Vec::new(),
        }
    } else {
        fetch_peer_kv_state(
            peer_url,
            &peer_token.0,
            &KvStateRequest {
                space_id: request.space_id.clone(),
                prefix: request.prefix.clone(),
                keys,
            },
        )
        .await?
    };
    let peer_items = peer_state
        .items
        .into_iter()
        .map(|item| (item.key.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let items = local
        .items
        .into_iter()
        .map(|item| {
            let peer = peer_items.get(&item.key);
            KvStateCompareItem {
                key: item.key,
                kind: item.kind,
                local_invocation_id: Some(item.invocation_id),
                peer_status: peer
                    .map(|state| state.status.clone())
                    .unwrap_or_else(|| "absent".to_string()),
                peer_seq: peer.and_then(|state| state.seq),
                peer_invocation_id: peer.and_then(|state| state.invocation_id.clone()),
                peer_deleted_invocation_id: peer
                    .and_then(|state| state.deleted_invocation_id.clone()),
                peer_value_hash: peer.and_then(|state| state.value_hash.clone()),
            }
        })
        .collect::<Vec<_>>();

    Ok(Json(KvStateCompareResponse {
        space_id: request.space_id.clone(),
        prefix: request.prefix.clone(),
        peer_url: request.peer_url.clone(),
        start_after: request.start_after.clone(),
        limit: request.limit,
        has_more: local.has_more,
        next_start_after: local.next_start_after,
        items,
    }))
}

#[post("/replication/recon/export", format = "json", data = "<request>")]
pub async fn recon_export(
    request: Json<KvReconExportRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KvReconExportResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    tinycloud
        .export_kv_recon(&request)
        .await
        .map(Json)
        .map_err(map_replication_error)
}

#[post("/replication/recon/split", format = "json", data = "<request>")]
pub async fn recon_split(
    request: Json<KvReconSplitRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KvReconSplitResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    tinycloud
        .export_kv_recon_split(&request)
        .await
        .map(Json)
        .map_err(map_replication_error)
}

#[post(
    "/replication/recon/split/compare",
    format = "json",
    data = "<request>"
)]
pub async fn recon_split_compare(
    request: Json<KvReconSplitCompareRequest>,
    token: Option<ReplicationSessionToken>,
    peer_token: Option<PeerReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KvReconSplitCompareResponse>, (Status, String)> {
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Peer-Replication-Session for recon split compare".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let export = reqwest::Client::new()
        .post(format!("{peer_url}/replication/recon/split"))
        .header("Replication-Session", peer_token.0)
        .json(&KvReconSplitRequest {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            child_start_after: None,
            child_limit: None,
        })
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer recon split failed", export).await);
    }

    let peer = export
        .json::<KvReconSplitResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;
    let local = tinycloud
        .export_kv_recon_split(&KvReconSplitRequest {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            child_start_after: None,
            child_limit: None,
        })
        .await
        .map_err(map_replication_error)?;
    let all_children = tinycloud_core::replication::recon::compare_kv_recon_split_children(
        &local.children,
        &peer.children,
    );
    let (children, has_more, next_child_start_after) =
        tinycloud_core::replication::recon::window_kv_recon_split_comparisons(
            &all_children,
            request.child_start_after.as_deref(),
            request.child_limit,
        );
    let matches = local.fingerprint == peer.fingerprint
        && local.item_count == peer.item_count
        && all_children.iter().all(|child| child.status == "match");

    Ok(Json(KvReconSplitCompareResponse {
        space_id: request.space_id.clone(),
        prefix: request.prefix.clone(),
        peer_url: request.peer_url.clone(),
        child_start_after: request.child_start_after.clone(),
        child_limit: request.child_limit,
        matches,
        has_more,
        next_child_start_after,
        children,
    }))
}

#[post("/replication/recon/compare", format = "json", data = "<request>")]
pub async fn recon_compare(
    request: Json<KvReconCompareRequest>,
    token: Option<ReplicationSessionToken>,
    peer_token: Option<PeerReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KvReconCompareResponse>, (Status, String)> {
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Peer-Replication-Session for recon compare".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let export = reqwest::Client::new()
        .post(format!("{peer_url}/replication/recon/export"))
        .header("Replication-Session", peer_token.0)
        .json(&KvReconExportRequest {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            start_after: request.start_after.clone(),
            limit: request.limit,
        })
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer recon export failed", export).await);
    }

    let peer = export
        .json::<KvReconExportResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;
    let local = tinycloud
        .export_kv_recon(&KvReconExportRequest {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            start_after: request.start_after.clone(),
            limit: request.limit,
        })
        .await
        .map_err(map_replication_error)?;
    let first_mismatch_key =
        tinycloud_core::replication::recon::first_kv_recon_mismatch(&local.items, &peer.items);
    let matches = local.fingerprint == peer.fingerprint
        && local.item_count == peer.item_count
        && first_mismatch_key.is_none();

    Ok(Json(KvReconCompareResponse {
        space_id: request.space_id.clone(),
        prefix: request.prefix.clone(),
        peer_url: request.peer_url.clone(),
        start_after: request.start_after.clone(),
        limit: request.limit,
        matches,
        local_item_count: local.item_count,
        peer_item_count: peer.item_count,
        local_has_more: local.has_more,
        peer_has_more: peer.has_more,
        local_next_start_after: local.next_start_after,
        peer_next_start_after: peer.next_start_after,
        local_fingerprint: local.fingerprint,
        peer_fingerprint: peer.fingerprint,
        first_mismatch_key,
    }))
}

async fn fetch_peer_kv_export(
    peer_url: &str,
    peer_token: &str,
    request: &ReplicationExportRequest,
) -> Result<ReplicationExportResponse, (Status, String)> {
    let export = reqwest::Client::new()
        .post(format!("{peer_url}/replication/export"))
        .header("Replication-Session", peer_token)
        .json(request)
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer export failed", export).await);
    }

    export
        .json::<ReplicationExportResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))
}

async fn fetch_peer_kv_state(
    peer_url: &str,
    peer_token: &str,
    request: &KvStateRequest,
) -> Result<KvStateResponse, (Status, String)> {
    let export = reqwest::Client::new()
        .post(format!("{peer_url}/replication/kv/state"))
        .header("Replication-Session", peer_token)
        .json(request)
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer kv state failed", export).await);
    }

    export
        .json::<KvStateResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))
}

async fn apply_kv_reconcile_from_peer(
    peer_url: &str,
    peer_token: &str,
    request: &ReplicationExportRequest,
    staging: &BlockStage,
    tinycloud: &State<TinyCloud>,
) -> Result<tinycloud_core::replication::ReplicationApplyResponse, (Status, String)> {
    let export = fetch_peer_kv_export(peer_url, peer_token, request).await?;
    let mut applied = tinycloud
        .apply_kv_replication(&export, staging)
        .await
        .map_err(map_replication_error)?;
    applied.peer_url = Some(peer_url.to_string());
    Ok(applied)
}

async fn fetch_peer_kv_recon_split(
    peer_url: &str,
    peer_token: &str,
    request: &KvReconSplitRequest,
) -> Result<KvReconSplitResponse, (Status, String)> {
    let export = reqwest::Client::new()
        .post(format!("{peer_url}/replication/recon/split"))
        .header("Replication-Session", peer_token)
        .json(request)
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer recon split failed", export).await);
    }

    export
        .json::<KvReconSplitResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))
}

async fn compare_split_scope(
    peer_url: &str,
    peer_token: &str,
    request: &KvReconSplitRequest,
    tinycloud: &State<TinyCloud>,
) -> Result<
    (
        KvReconSplitResponse,
        KvReconSplitResponse,
        Vec<KvReconSplitChildComparison>,
    ),
    (Status, String),
> {
    let peer = fetch_peer_kv_recon_split(peer_url, peer_token, request).await?;
    let local = tinycloud
        .export_kv_recon_split(request)
        .await
        .map_err(map_replication_error)?;
    let children = tinycloud_core::replication::recon::compare_kv_recon_split_children(
        &local.children,
        &peer.children,
    );

    Ok((local, peer, children))
}

async fn collect_split_reconcile_targets(
    peer_url: &str,
    peer_token: &str,
    space_id: &str,
    root_children: &[KvReconSplitChildComparison],
    child_limit: Option<usize>,
    max_depth: Option<usize>,
    tinycloud: &State<TinyCloud>,
) -> Result<Vec<SplitReconcileTarget>, (Status, String)> {
    let child_limit = child_limit.unwrap_or(usize::MAX);
    if child_limit == 0 {
        return Ok(Vec::new());
    }

    let max_depth = max_depth.unwrap_or(1).max(1);
    let mut targets = Vec::new();

    for child in root_children {
        if targets.len() >= child_limit {
            break;
        }
        if child.status != "local-missing" && child.status != "mismatch" {
            continue;
        }

        if !child.leaf && max_depth > 1 {
            collect_split_reconcile_targets_for_scope(
                peer_url,
                peer_token,
                space_id,
                Some(child.prefix.clone()),
                child.prefix.clone(),
                2,
                max_depth,
                child_limit,
                tinycloud,
                &mut targets,
            )
            .await?;
            if targets.len() >= child_limit {
                break;
            }
            if targets
                .iter()
                .any(|target| target.result_prefix == child.prefix)
            {
                continue;
            }
        }

        targets.push(SplitReconcileTarget {
            replay_prefix: child.prefix.clone(),
            result_prefix: child.prefix.clone(),
        });
    }

    Ok(targets)
}

fn collect_split_reconcile_targets_for_scope<'a>(
    peer_url: &'a str,
    peer_token: &'a str,
    space_id: &'a str,
    prefix: Option<String>,
    root_prefix: String,
    child_depth: usize,
    max_depth: usize,
    child_limit: usize,
    tinycloud: &'a State<TinyCloud>,
    targets: &'a mut Vec<SplitReconcileTarget>,
) -> BoxFuture<'a, Result<(), (Status, String)>> {
    Box::pin(async move {
        if targets.len() >= child_limit {
            return Ok(());
        }

        let (_, _, children) = compare_split_scope(
            peer_url,
            peer_token,
            &KvReconSplitRequest {
                space_id: space_id.to_string(),
                prefix: prefix.clone(),
                child_start_after: None,
                child_limit: None,
            },
            tinycloud,
        )
        .await?;

        for child in children {
            if targets.len() >= child_limit {
                break;
            }
            if child.status != "local-missing" && child.status != "mismatch" {
                continue;
            }

            if !child.leaf && child_depth < max_depth {
                collect_split_reconcile_targets_for_scope(
                    peer_url,
                    peer_token,
                    space_id,
                    Some(child.prefix.clone()),
                    root_prefix.clone(),
                    child_depth + 1,
                    max_depth,
                    child_limit,
                    tinycloud,
                    targets,
                )
                .await?;
                if targets.len() >= child_limit {
                    break;
                }
                if targets
                    .iter()
                    .any(|target| target.result_prefix == root_prefix)
                {
                    continue;
                }
            }

            targets.push(SplitReconcileTarget {
                replay_prefix: child.prefix,
                result_prefix: root_prefix.clone(),
            });
        }

        Ok(())
    })
}

#[post("/replication/reconcile", format = "json", data = "<request>")]
pub async fn reconcile(
    request: Json<ReplicationReconcileRequest>,
    token: Option<ReplicationSessionToken>,
    peer_token: Option<PeerReplicationSessionToken>,
    replication: &State<ReplicationService>,
    staging: &State<BlockStage>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<tinycloud_core::replication::ReplicationApplyResponse>, (Status, String)> {
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Peer-Replication-Session for replication reconcile".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let applied = apply_kv_reconcile_from_peer(
        peer_url,
        &peer_token.0,
        &ReplicationExportRequest {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            since_seq: request.since_seq,
            limit: request.limit,
        },
        staging.inner(),
        tinycloud,
    )
    .await?;
    Ok(Json(applied))
}

#[post("/replication/reconcile/split", format = "json", data = "<request>")]
pub async fn reconcile_split(
    request: Json<KvReconSplitReconcileRequest>,
    token: Option<ReplicationSessionToken>,
    peer_token: Option<PeerReplicationSessionToken>,
    replication: &State<ReplicationService>,
    staging: &State<BlockStage>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KvReconSplitReconcileResponse>, (Status, String)> {
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Peer-Replication-Session for split-driven replication reconcile".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let split_request = KvReconSplitRequest {
        space_id: request.space_id.clone(),
        prefix: request.prefix.clone(),
        child_start_after: None,
        child_limit: None,
    };
    let (_, _, before_all_children) =
        compare_split_scope(peer_url, &peer_token.0, &split_request, tinycloud).await?;
    let (before_children, _, _) =
        tinycloud_core::replication::recon::window_kv_recon_split_comparisons(
            &before_all_children,
            request.child_start_after.as_deref(),
            request.child_limit,
        );
    let mut results = before_children
        .iter()
        .map(|child| {
            (
                child.prefix.clone(),
                KvReconSplitReconcileChildResult {
                    prefix: child.prefix.clone(),
                    before_status: child.status.clone(),
                    after_status: child.status.clone(),
                    applied_sequences: 0,
                    applied_events: 0,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let reconcile_targets = collect_split_reconcile_targets(
        peer_url,
        &peer_token.0,
        &request.space_id,
        &before_children,
        request.child_limit,
        request.max_depth,
        tinycloud,
    )
    .await?;

    for target in &reconcile_targets {
        let applied = apply_kv_reconcile_from_peer(
            peer_url,
            &peer_token.0,
            &ReplicationExportRequest {
                space_id: request.space_id.clone(),
                prefix: Some(target.replay_prefix.clone()),
                since_seq: None,
                limit: None,
            },
            staging.inner(),
            tinycloud,
        )
        .await?;
        results
            .entry(target.result_prefix.clone())
            .and_modify(|result| {
                result.applied_sequences += applied.applied_sequences;
                result.applied_events += applied.applied_events;
            })
            .or_insert_with(|| KvReconSplitReconcileChildResult {
                prefix: target.result_prefix.clone(),
                before_status: "local-missing".to_string(),
                after_status: "local-missing".to_string(),
                applied_sequences: applied.applied_sequences,
                applied_events: applied.applied_events,
            });
    }

    let (local_after, peer_after, after_all_children) =
        compare_split_scope(peer_url, &peer_token.0, &split_request, tinycloud).await?;
    let (after_children, has_more, next_child_start_after) =
        tinycloud_core::replication::recon::window_kv_recon_split_comparisons(
            &after_all_children,
            request.child_start_after.as_deref(),
            request.child_limit,
        );
    for child in &after_children {
        results
            .entry(child.prefix.clone())
            .and_modify(|result| result.after_status = child.status.clone())
            .or_insert_with(|| KvReconSplitReconcileChildResult {
                prefix: child.prefix.clone(),
                before_status: child.status.clone(),
                after_status: child.status.clone(),
                applied_sequences: 0,
                applied_events: 0,
            });
    }

    let reconciled_children = reconcile_targets
        .iter()
        .map(|target| target.result_prefix.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|prefix| {
            results
                .get(*prefix)
                .map(|child| child.after_status == "match")
                .unwrap_or(false)
        })
        .count();

    Ok(Json(KvReconSplitReconcileResponse {
        space_id: request.space_id.clone(),
        prefix: request.prefix.clone(),
        peer_url: request.peer_url.clone(),
        child_start_after: request.child_start_after.clone(),
        child_limit: request.child_limit,
        matches: local_after.fingerprint == peer_after.fingerprint
            && local_after.item_count == peer_after.item_count,
        has_more,
        next_child_start_after,
        attempted_children: reconcile_targets.len(),
        reconciled_children,
        children: results.into_values().collect(),
    }))
}

#[post("/replication/sql/export", format = "json", data = "<request>")]
pub async fn sql_replication_export(
    request: Json<SqlReplicationExportRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    sql_service: &State<SqlService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<SqlReplicationExportResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Sql {
        db_name: request.db_name.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    let space_id: SpaceId = request.space_id.parse().map_err(|_| {
        (
            Status::BadRequest,
            format!("invalid space id: {}", request.space_id),
        )
    })?;
    let snapshot = sql_service
        .export(&space_id, &request.db_name)
        .await
        .map_err(map_sql_error)?;

    Ok(Json(SqlReplicationExportResponse {
        space_id: request.space_id.clone(),
        db_name: request.db_name.clone(),
        snapshot,
    }))
}

#[post("/replication/sql/reconcile", format = "json", data = "<request>")]
pub async fn sql_reconcile(
    request: Json<SqlReplicationReconcileRequest>,
    token: Option<ReplicationSessionToken>,
    peer_token: Option<PeerReplicationSessionToken>,
    replication: &State<ReplicationService>,
    sql_service: &State<SqlService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<SqlReplicationApplyResponse>, (Status, String)> {
    let space_id: SpaceId = request.space_id.parse().map_err(|_| {
        (
            Status::BadRequest,
            format!("invalid space id: {}", request.space_id),
        )
    })?;
    let scope = ReplicationScope::Sql {
        db_name: request.db_name.clone(),
    };
    let session = authorize_session_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Peer-Replication-Session for replication reconcile".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let mut export_request = reqwest::Client::new()
        .post(format!("{peer_url}/replication/sql/export"))
        .json(&SqlReplicationExportRequest {
            space_id: request.space_id.clone(),
            db_name: request.db_name.clone(),
        });

    export_request = export_request.header("Replication-Session", peer_token.0);

    let export = export_request
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer sql export failed", export).await);
    }

    let export = export
        .json::<SqlReplicationExportResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    sql_service
        .import(&space_id, &export.db_name, &export.snapshot)
        .await
        .map_err(map_sql_error)?;

    Ok(Json(SqlReplicationApplyResponse {
        space_id: export.space_id,
        db_name: export.db_name,
        peer_url: Some(request.peer_url.clone()),
        snapshot_bytes: export.snapshot.len(),
    }))
}

async fn verify_replication_delegation(
    delegation: Delegation,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    tinycloud
        .delegate(delegation)
        .await
        .map_err(|error| match error {
            TxError::SpaceNotFound => (Status::NotFound, error.to_string()),
            TxError::Db(tinycloud_core::sea_orm::DbErr::ConnectionAcquire(_)) => {
                (Status::InternalServerError, error.to_string())
            }
            _ => (Status::Unauthorized, error.to_string()),
        })?;
    Ok(())
}

async fn import_supporting_delegations(
    supporting_delegations: Option<&[String]>,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    let Some(supporting_delegations) = supporting_delegations else {
        return Ok(());
    };

    for delegation_header in supporting_delegations {
        let delegation = Delegation::from_header_ser::<
            tinycloud_auth::authorization::TinyCloudDelegation,
        >(delegation_header)
        .map_err(|error| (Status::BadRequest, error.to_string()))?;
        verify_replication_delegation(delegation, tinycloud).await?;
    }

    Ok(())
}

fn authorize_session_scope(
    space_id: &str,
    scope: &ReplicationScope,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
) -> Result<ReplicationSessionRecord, (Status, String)> {
    let session = replication
        .require_session(
            token.as_ref().map(|value| value.0.as_str()),
            space_id,
            scope,
        )
        .map_err(map_replication_session_error)?;

    Ok(session)
}

async fn ensure_replication_session_active(
    session: &ReplicationSessionRecord,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    let active = tinycloud
        .replication_session_delegation_active(session.delegation_hash)
        .await
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;

    if active {
        Ok(())
    } else {
        Err((
            Status::Unauthorized,
            "replication session delegation is no longer active".to_string(),
        ))
    }
}

async fn ensure_replication_delegation_active(
    delegation_hash: tinycloud_core::hash::Hash,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    let active = tinycloud
        .replication_session_delegation_active(Some(delegation_hash))
        .await
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;

    if active {
        Ok(())
    } else {
        Err((
            Status::Unauthorized,
            "replication delegation is no longer active".to_string(),
        ))
    }
}

fn request_scope(
    request: &ReplicationSessionOpenRequest,
) -> Result<ReplicationScope, (Status, String)> {
    match request.service.as_str() {
        "auth" => Ok(ReplicationScope::Auth),
        "kv" => Ok(ReplicationScope::Kv {
            prefix: request.prefix.clone(),
        }),
        "sql" => Ok(ReplicationScope::Sql {
            db_name: request.db_name.clone().ok_or_else(|| {
                (
                    Status::BadRequest,
                    "dbName is required for sql replication sessions".to_string(),
                )
            })?,
        }),
        other => Err((
            Status::BadRequest,
            format!("unsupported replication service: {other}"),
        )),
    }
}

fn ensure_sync_scope(
    capabilities: &[Capability],
    requested_resource: &Resource,
    requested_scope: &ReplicationScope,
) -> Result<(), (Status, String)> {
    let allowed = capabilities.iter().any(|capability| {
        capability.ability.as_ref().as_ref() == "tinycloud.space/sync"
            && (requested_resource.extends(&capability.resource)
                || capability_matches_scope(
                    &capability.resource,
                    requested_resource,
                    requested_scope,
                ))
    });

    if allowed {
        Ok(())
    } else {
        Err((
            Status::Forbidden,
            "authorization does not grant tinycloud.space/sync for requested scope".to_string(),
        ))
    }
}

fn capability_matches_scope(
    capability_resource: &Resource,
    requested_resource: &Resource,
    requested_scope: &ReplicationScope,
) -> bool {
    let Some(requested) = requested_resource.tinycloud_resource() else {
        return false;
    };
    let Some(capability) = capability_resource.tinycloud_resource() else {
        return false;
    };

    if requested.space() != capability.space() {
        return false;
    }

    if capability.service().as_str() != "space" {
        return false;
    }

    scope_matches_space_resource(capability.path().map(|path| path.as_str()), requested_scope)
}

fn scope_matches_space_resource(
    delegated_path: Option<&str>,
    requested_scope: &ReplicationScope,
) -> bool {
    let Some(delegated_path) = delegated_path.map(normalize_scope_value) else {
        return true;
    };

    if delegated_path.is_empty() {
        return true;
    }

    match requested_scope {
        ReplicationScope::Auth => delegated_path == "auth",
        ReplicationScope::Kv { prefix } => match delegated_path {
            "kv" => true,
            _ => delegated_path
                .strip_prefix("kv/")
                .map(|delegated_prefix| {
                    scope_path_is_subset(prefix.as_deref(), Some(delegated_prefix))
                })
                .unwrap_or(false),
        },
        ReplicationScope::Sql { db_name } => match delegated_path {
            "sql" => true,
            _ => delegated_path
                .strip_prefix("sql/")
                .map(|delegated_db| {
                    normalize_scope_value(delegated_db) == normalize_scope_value(db_name)
                })
                .unwrap_or(false),
        },
    }
}

fn scope_path_is_subset(requested: Option<&str>, delegated: Option<&str>) -> bool {
    match (
        requested
            .map(normalize_scope_value)
            .filter(|value| !value.is_empty()),
        delegated
            .map(normalize_scope_value)
            .filter(|value| !value.is_empty()),
    ) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(requested), Some(delegated)) => {
            requested == delegated || requested.starts_with(&format!("{delegated}/"))
        }
    }
}

fn normalize_scope_value(value: &str) -> &str {
    value.trim_matches('/')
}

fn requested_resource(
    space_id: &str,
    scope: &ReplicationScope,
) -> Result<Resource, (Status, String)> {
    let space_id: SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, format!("invalid space id: {space_id}")))?;
    let service: Service = match scope {
        ReplicationScope::Auth => "space".parse(),
        _ => scope.service().parse(),
    }
    .map_err(|error| (Status::BadRequest, format!("invalid service: {error}")))?;
    let path = match scope {
        ReplicationScope::Auth => Some(
            "auth"
                .parse::<ResourcePath>()
                .map_err(|error| (Status::BadRequest, format!("invalid auth scope: {error}")))?,
        ),
        ReplicationScope::Kv { prefix } => normalized_path(prefix.as_deref())?,
        ReplicationScope::Sql { db_name } => Some(
            normalize_required_db_name(db_name)?
                .parse::<ResourcePath>()
                .map_err(|error| (Status::BadRequest, format!("invalid sql db scope: {error}")))?,
        ),
    };

    Ok(Resource::from(
        space_id.to_resource(service, path, None, None),
    ))
}

fn normalized_path(value: Option<&str>) -> Result<Option<ResourcePath>, (Status, String)> {
    match value
        .map(|value| value.trim_matches('/'))
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.parse::<ResourcePath>().map(Some).map_err(|error| {
            (
                Status::BadRequest,
                format!("invalid replication scope: {error}"),
            )
        }),
        None => Ok(None),
    }
}

fn normalize_required_db_name(value: &str) -> Result<String, (Status, String)> {
    let value = value.trim_matches('/');
    if value.is_empty() {
        return Err((
            Status::BadRequest,
            "dbName is required for sql replication sessions".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn ensure_peer_serving_enabled(
    replication: &State<ReplicationService>,
) -> Result<(), (Status, String)> {
    let status = replication.status();
    if !status.enabled {
        return Err((
            Status::ServiceUnavailable,
            "replication export is disabled on this node".to_string(),
        ));
    }

    if peer_export_allowed(status) {
        return Ok(());
    }

    if status.roles_enabled.contains(&"replica") {
        return Err((
            Status::Forbidden,
            "replication export requires peerServing on replica nodes".to_string(),
        ));
    }

    Err((
        Status::Forbidden,
        "replication export is not enabled for this node role".to_string(),
    ))
}

fn peer_export_allowed(status: &tinycloud_core::replication::ReplicationStatus) -> bool {
    status.enabled
        && (status.roles_enabled.contains(&"host")
            || (status.roles_enabled.contains(&"replica") && status.peer_serving))
}

fn map_replication_error(error: KvReplicationError) -> (Status, String) {
    let status = match error {
        KvReplicationError::InvalidHashEncoding { .. }
        | KvReplicationError::InvalidInvocation { .. }
        | KvReplicationError::InvalidInvocationUtf8 { .. }
        | KvReplicationError::InvalidPath(_)
        | KvReplicationError::InvalidSpaceId(_)
        | KvReplicationError::UnsupportedInvocation { .. } => Status::BadRequest,
        KvReplicationError::MissingBlock { .. }
        | KvReplicationError::MissingDeletedWrite { .. } => Status::FailedDependency,
        KvReplicationError::Db(_)
        | KvReplicationError::Encryption(_)
        | KvReplicationError::Encoding(_)
        | KvReplicationError::Io(_)
        | KvReplicationError::StoreRead(_)
        | KvReplicationError::StoreWrite(_)
        | KvReplicationError::Stage(_)
        | KvReplicationError::Tx(_) => Status::InternalServerError,
    };
    (status, error.to_string())
}

fn map_replication_session_error(error: ReplicationSessionError) -> (Status, String) {
    let status = match error {
        ReplicationSessionError::MissingToken | ReplicationSessionError::InvalidToken => {
            Status::Unauthorized
        }
        ReplicationSessionError::ScopeMismatch => Status::Forbidden,
    };
    (status, error.to_string())
}

fn map_auth_tx_error<B, K>(error: TxError<B, K>) -> (Status, String)
where
    B: tinycloud_core::storage::StorageSetup,
    K: tinycloud_core::keys::Secrets,
{
    match error {
        TxError::SpaceNotFound => (Status::NotFound, error.to_string()),
        TxError::Db(tinycloud_core::sea_orm::DbErr::ConnectionAcquire(_)) => {
            (Status::InternalServerError, error.to_string())
        }
        TxError::Db(_) => (Status::InternalServerError, error.to_string()),
        _ => (Status::Unauthorized, error.to_string()),
    }
}

fn map_sql_error(error: SqlError) -> (Status, String) {
    let status = match error {
        SqlError::DatabaseNotFound => Status::NotFound,
        SqlError::PermissionDenied(_) | SqlError::ReadOnlyViolation => Status::Forbidden,
        SqlError::ResponseTooLarge(_) => Status::PayloadTooLarge,
        SqlError::QuotaExceeded => Status::TooManyRequests,
        SqlError::InvalidStatement(_)
        | SqlError::SchemaError(_)
        | SqlError::ParseError(_)
        | SqlError::Sqlite(_) => Status::BadRequest,
        SqlError::Internal(_) => Status::InternalServerError,
    };
    (status, error.to_string())
}

async fn map_peer_error(prefix: &str, response: reqwest::Response) -> (Status, String) {
    let peer_status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<no response body>".to_string());
    (
        Status::BadGateway,
        format!("{prefix} with status {peer_status}: {body}"),
    )
}
