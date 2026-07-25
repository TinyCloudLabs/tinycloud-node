use axum::{
    extract::Path,
    routing::{get, post},
    Extension, Json, Router,
};
use ethers::{
    core::utils::to_checksum,
    prelude::rand::{prelude::StdRng, SeedableRng},
    signers::{LocalWallet, Signer},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc};
use tinycloud_auth::{
    cacaos::siwe::TimeStamp,
    resource::SpaceId,
    ssi::{dids::DIDBuf, jwk::JWK},
};
use tinycloud_sdk_rs::{
    authorization::{DelegationHeaders, InvocationHeaders},
};
use tinycloud_sdk_wasm::session::{
    complete_session_setup, prepare_session, Session, SessionConfig, SignedSession,
};
use tinycloud_sdk_wasm::host::{
    generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage,
};
use tokio::sync::RwLock;

#[derive(Clone)]
struct User {
    wallet: LocalWallet,
    root_session: Session,
    session_config: SessionConfig,
}

async fn sign_session(wallet: &LocalWallet, session_config: SessionConfig) -> Session {
    let prepared_session = prepare_session(session_config.clone()).unwrap();
    let signature = wallet
        .sign_message(prepared_session.siwe.to_string())
        .await
        .unwrap();
    complete_session_setup(SignedSession {
        session: prepared_session,
        signature: signature.to_vec().try_into().unwrap(),
    })
    .unwrap()
}

async fn new_user(wallet: LocalWallet, jwk: JWK) -> User {
    let address = to_checksum(&wallet.address(), None);
    let did = format!("did:pkh:eip155:1:{address}");
    let space_id = SpaceId::new(
        DIDBuf::from_str(&did).unwrap(),
        "default".to_string().try_into().unwrap(),
    );

    let session_config = SessionConfig {
        abilities: HashMap::from([(
            "kv".parse().unwrap(),
            HashMap::from([(
                "".parse().unwrap(),
                vec![
                    "tinycloud.kv/put".parse().unwrap(),
                    "tinycloud.kv/get".parse().unwrap(),
                    "tinycloud.kv/del".parse().unwrap(),
                    "tinycloud.kv/metadata".parse().unwrap(),
                    "tinycloud.kv/list".parse().unwrap(),
                ],
            )]),
        )]),
        space_abilities: None,
        raw_abilities: HashMap::new(),
        address: wallet.address().into(),
        chain_id: 1,
        domain: "localhost".try_into().unwrap(),
        space_id,
        additional_spaces: None,
        not_before: None,
        parents: None,
        jwk: Some(jwk),
        delegate_uri: None,
        nonce: None,
        issued_at: TimeStamp::from_str("1985-04-12T23:20:50.52Z").unwrap(),
        expiration_time: TimeStamp::from_str("2985-04-12T23:20:50.52Z").unwrap(),
    };
    let root_session = sign_session(&wallet, session_config.clone()).await;

    User {
        wallet,
        root_session: root_session.clone(),
        session_config,
    }
}

impl User {
    async fn session_chain(&self, depth: u32) -> Vec<Session> {
        let mut chain = vec![self.root_session.clone()];
        if depth == 0 {
            return chain;
        }

        let mut previous = self.root_session.clone();
        for _ in 0..depth {
            let mut config = self.session_config.clone();
            config.parents = Some(vec![previous.delegation_cid]);
            let next = sign_session(&self.wallet, config).await;
            previous = next.clone();
            chain.push(next);
        }

        chain
    }

    async fn leaf_session(&self, depth: u32) -> Session {
        self.session_chain(depth).await.into_iter().last().unwrap()
    }
}

#[derive(Serialize, Deserialize)]
struct InvokeParams {
    name: String,
    action: String,
    #[serde(default)]
    depth: u32,
}

#[derive(Serialize, Deserialize)]
struct SessionParams {
    #[serde(default)]
    depth: u32,
}

#[derive(Serialize, Deserialize)]
struct SpaceParams {
    peer_id: String,
}

async fn create_space(
    Path(id): Path<u128>,
    Json(params): Json<SpaceParams>,
    Extension(_jwk): Extension<Arc<JWK>>,
    Extension(users): Extension<Arc<RwLock<HashMap<u128, User>>>>,
) -> Json<DelegationHeaders> {
    let reader = users.read().await;
    let user = reader.get(&id).unwrap();

    let message = generate_host_siwe_message(HostConfig {
        address: user.session_config.address,
        chain_id: user.session_config.chain_id,
        domain: user.session_config.domain.clone(),
        issued_at: user.session_config.issued_at.clone(),
        space_id: user.session_config.space_id.clone(),
        peer_id: params.peer_id,
    })
    .unwrap();
    let signature = user.wallet.sign_message(message.to_string()).await.unwrap();
    let delegation = siwe_to_delegation_headers(SignedMessage {
        siwe: message,
        signature: signature.to_vec().try_into().unwrap(),
    });
    Json(delegation)
}

async fn get_space_id(
    Path(id): Path<u128>,
    Extension(jwk): Extension<Arc<JWK>>,
    Extension(users): Extension<Arc<RwLock<HashMap<u128, User>>>>,
) -> String {
    let id_bytes = id.to_ne_bytes();
    let mut seed = id_bytes.to_vec();
    seed.extend_from_slice(&id_bytes);
    let mut rng = StdRng::from_seed(seed.try_into().unwrap());
    let wallet = LocalWallet::new(&mut rng);
    let user = new_user(wallet, (*jwk).clone()).await;
    users.write().await.insert(id, user.clone());

    user.session_config.space_id.to_string()
}

async fn create_session(
    Path(id): Path<u128>,
    Json(params): Json<SessionParams>,
    Extension(users): Extension<Arc<RwLock<HashMap<u128, User>>>>,
) -> Json<Vec<DelegationHeaders>> {
    let user = {
        let reader = users.read().await;
        reader.get(&id).cloned().unwrap()
    };
    let chain = user.session_chain(params.depth).await;
    Json(
        chain
            .into_iter()
            .map(|session| session.delegation_header)
            .collect(),
    )
}
async fn invoke_session(
    Path(id): Path<u128>,
    Json(params): Json<InvokeParams>,
    Extension(users): Extension<Arc<RwLock<HashMap<u128, User>>>>,
) -> Json<InvocationHeaders> {
    let user = {
        let reader = users.read().await;
        reader.get(&id).cloned().unwrap()
    };
    let invocation = user
        .leaf_session(params.depth)
        .await
        .invoke(
            [(
                "kv".parse().unwrap(),
                params.name.parse().unwrap(),
                None,
                None,
                [format!("tinycloud.kv/{}", params.action).parse().unwrap()],
            )],
            None,
        )
        .unwrap();
    let headers = InvocationHeaders::new(invocation);
    Json(headers)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let jwk = JWK::generate_ed25519().unwrap();
    let users: HashMap<u128, User> = HashMap::new();
    let app = Router::new()
        .route("/space_id/:id", get(get_space_id))
        .route("/namespace_id/:id", get(get_space_id))
        .route("/spaces/:id", post(create_space))
        .route("/sessions/:id/create", post(create_session))
        .route("/sessions/:id/invoke", post(invoke_session))
        .layer(Extension(Arc::new(RwLock::new(users))))
        .layer(Extension(Arc::new(jwk)));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::prelude::rand::{prelude::StdRng, SeedableRng};
    use std::collections::HashSet;

    async fn test_user() -> User {
        let mut rng = StdRng::seed_from_u64(7);
        let wallet = LocalWallet::new(&mut rng);
        let jwk = JWK::generate_ed25519().unwrap();
        new_user(wallet, jwk).await
    }

    #[tokio::test]
    async fn session_chain_depth_changes_the_signed_delegation_chain() {
        let user = test_user().await;
        let depth0 = user.session_chain(0).await;
        let depth1 = user.session_chain(1).await;
        let depth4 = user.session_chain(4).await;

        assert_eq!(depth0.len(), 1);
        assert_eq!(depth1.len(), 2);
        assert_eq!(depth4.len(), 5);

        let depth4_cids: HashSet<_> = depth4
            .iter()
            .map(|session| session.delegation_cid)
            .collect();
        assert_eq!(depth4_cids.len(), 5);
        assert_ne!(depth0.last().unwrap().delegation_cid, depth1.last().unwrap().delegation_cid);
        assert_ne!(depth1.last().unwrap().delegation_cid, depth4.last().unwrap().delegation_cid);

        let depth1_json = serde_json::to_string(&depth1.last().unwrap().delegation_header).unwrap();
        let depth4_json = serde_json::to_string(&depth4.last().unwrap().delegation_header).unwrap();
        assert_ne!(depth1_json, depth4_json);
    }

    #[tokio::test]
    async fn leaf_session_depth_tracks_the_requested_authorization_chain() {
        let user = test_user().await;
        let leaf = user.leaf_session(4).await;
        let root = user.leaf_session(0).await;

        assert_ne!(leaf.delegation_cid, root.delegation_cid);
        assert!(serde_json::to_value(&leaf.delegation_header).unwrap().is_object());
    }

    #[tokio::test]
    async fn invocations_cite_the_leaf_session_cid_for_each_requested_depth() {
        let user = test_user().await;
        let root = user.leaf_session(0).await;
        let depth1 = user.leaf_session(1).await;
        let depth4 = user.leaf_session(4).await;

        let root_invocation = root
            .invoke(
                [(
                    "kv".parse().unwrap(),
                    "depth-0".parse().unwrap(),
                    None,
                    None,
                    ["tinycloud.kv/get".parse().unwrap()],
                )],
                None,
            )
            .expect("depth-0 invocation");
        let depth1_invocation = depth1
            .invoke(
                [(
                    "kv".parse().unwrap(),
                    "depth-1".parse().unwrap(),
                    None,
                    None,
                    ["tinycloud.kv/get".parse().unwrap()],
                )],
                None,
            )
            .expect("depth-1 invocation");
        let depth4_invocation = depth4
            .invoke(
                [(
                    "kv".parse().unwrap(),
                    "depth-4".parse().unwrap(),
                    None,
                    None,
                    ["tinycloud.kv/get".parse().unwrap()],
                )],
                None,
            )
            .expect("depth-4 invocation");

        assert_eq!(root_invocation.payload().proof, vec![root.delegation_cid]);
        assert_eq!(depth1_invocation.payload().proof, vec![depth1.delegation_cid]);
        assert_eq!(depth4_invocation.payload().proof, vec![depth4.delegation_cid]);
        assert_ne!(root_invocation.payload().proof, depth1_invocation.payload().proof);
        assert_ne!(depth1_invocation.payload().proof, depth4_invocation.payload().proof);
    }
}
