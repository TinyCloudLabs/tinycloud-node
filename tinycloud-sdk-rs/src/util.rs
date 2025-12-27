use std::str::FromStr;
pub use tinycloud_lib::cacaos::siwe::{decode_eip55, encode_eip55};
use tinycloud_lib::resource::{KRIParseError, NamespaceId};

pub fn make_namespace_id_pkh_eip155(
    address: &[u8; 20],
    chain_id: u32,
    name: String,
) -> Result<NamespaceId, KRIParseError> {
    let addr = encode_eip55(address);
    NamespaceId::from_str(&format!("tinycloud:pkh:eip155:{chain_id}:0x{addr}:{name}"))
}
