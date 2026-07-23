use libp2p::identity::{
    ed25519::{Keypair as EdKP, SecretKey},
    DecodingError,
};
use multihash_derive::Hasher;
use sea_orm_migration::async_trait::async_trait;
use std::error::Error as StdError;
use tinycloud_auth::{multihash_codetable::Blake3_256, resource::SpaceId};

pub use libp2p::{
    identity::{Keypair, PublicKey},
    PeerId,
};

pub(crate) fn get_did_key(key: PublicKey) -> String {
    public_key_to_did_key(key)
}

pub fn public_key_to_did_key(key: PublicKey) -> String {
    use tinycloud_auth::ipld_core::cid::multibase;
    // only ed25519 feature is enabled, so this unwrap should never fail
    let ed25519_pk_bytes = key.try_into_ed25519().unwrap().to_bytes();
    let multicodec_pk = [[0xed, 0x01].as_slice(), ed25519_pk_bytes.as_slice()].concat();
    format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, multicodec_pk)
    )
}

#[async_trait]
pub trait Secrets {
    type Error: StdError;
    async fn get_keypair(&self, space: &SpaceId) -> Result<Keypair, Self::Error>;
    async fn get_pubkey(&self, space: &SpaceId) -> Result<PublicKey, Self::Error> {
        Ok(self.get_keypair(space).await?.public())
    }
    async fn stage_keypair(&self, space: &SpaceId) -> Result<PublicKey, Self::Error>;
    async fn save_keypair(&self, space: &SpaceId) -> Result<(), Self::Error>;
    async fn get_peer_id(&self, space: &SpaceId) -> Result<PeerId, Self::Error> {
        Ok(self.get_pubkey(space).await?.to_peer_id())
    }
}

#[async_trait]
pub trait SecretsSetup {
    type Error: StdError;
    type Input;
    type Output: Secrets;
    async fn setup(&self, input: Self::Input) -> Result<Self::Output, Self::Error>;
}

#[derive(Clone)]
pub struct StaticSecret {
    secret: Vec<u8>,
}

impl StaticSecret {
    pub fn new(secret: Vec<u8>) -> Result<Self, Vec<u8>> {
        if secret.len() < 32 {
            Err(secret)
        } else {
            Ok(Self { secret })
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    pub fn derive_key(&self, context: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3_256::default();
        hasher.update(&self.secret);
        hasher.update(context);
        let derived = hasher.finalize().to_vec();
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived[..32]);
        key
    }

    /// Derive a stable node-level did:key. The keypair is deterministic for a
    /// given static secret. Used by node-wide identity contexts (encryption
    /// module audience, signed responses).
    pub fn node_did(&self) -> String {
        public_key_to_did_key(self.node_keypair().public())
    }

    pub fn node_keypair(&self) -> Keypair {
        let derived = self.derive_key(b"tinycloud/node/identity");
        let secret = SecretKey::try_from_bytes(derived).expect("32 bytes");
        EdKP::from(secret).into()
    }

    /// Derive the public half of the node's Share invitation signing key.
    pub fn share_invitation_public_key(&self) -> [u8; 32] {
        let derived = self.derive_key(b"tinycloud/share-email/invitation-signing");
        let secret = SecretKey::try_from_bytes(derived).expect("32 bytes");
        EdKP::from(secret).public().to_bytes()
    }
}

#[async_trait]
impl Secrets for StaticSecret {
    type Error = DecodingError;
    async fn get_keypair(&self, space: &SpaceId) -> Result<Keypair, Self::Error> {
        let mut hasher = Blake3_256::default();
        hasher.update(&self.secret);
        hasher.update(space.to_string().as_bytes());
        let derived = hasher.finalize().to_vec();
        Ok(EdKP::from(SecretKey::try_from_bytes(derived)?).into())
    }
    async fn stage_keypair(&self, space: &SpaceId) -> Result<PublicKey, Self::Error> {
        self.get_pubkey(space).await
    }
    async fn save_keypair(&self, _space: &SpaceId) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[async_trait]
impl SecretsSetup for StaticSecret {
    type Error = std::convert::Infallible;
    type Input = ();
    type Output = Self;
    async fn setup(&self, _input: Self::Input) -> Result<Self::Output, Self::Error> {
        Ok(self.clone())
    }
}
