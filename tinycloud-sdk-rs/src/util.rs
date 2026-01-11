use std::str::FromStr;
pub use tinycloud_lib::cacaos::siwe::{decode_eip55, encode_eip55};
use tinycloud_lib::resource::{KRIParseError, SpaceId};

pub fn make_space_id_pkh_eip155(
    address: &[u8; 20],
    chain_id: u32,
    name: String,
) -> Result<SpaceId, KRIParseError> {
    let addr = encode_eip55(address);
    SpaceId::from_str(&format!("tinycloud:pkh:eip155:{chain_id}:0x{addr}:{name}"))
}
