mod definitions;
pub mod host;
pub mod session;

use hex::FromHex;
use tinycloud_lib::{
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
};
use tinycloud_sdk_rs::{authorization::InvocationHeaders, util};
use wasm_bindgen::prelude::*;

fn map_jserr<E: std::error::Error>(e: E) -> JsValue {
    e.to_string().into()
}

// removing since we have duplicate usage elsewhere
// #[wasm_bindgen]
// #[allow(non_snake_case)]
// /// Initialise console-error-panic-hook to improve debug output for panics.
// ///
// /// Run once on initialisation.
// pub fn initPanicHook() {
//     console_error_panic_hook::set_once();
// }

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn ensureEip55(address: String) -> Result<String, JsValue> {
    Ok(format!(
        "0x{}",
        util::encode_eip55(
            &<[u8; 20] as FromHex>::from_hex(address.strip_prefix("0x").unwrap_or(&address))
                .map_err(map_jserr)?,
        )
    ))
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn makeSpaceId(address: String, chainId: u32, name: String) -> Result<String, JsValue> {
    Ok(tinycloud_sdk_rs::util::make_space_id_pkh_eip155(
        &util::decode_eip55(address.strip_prefix("0x").unwrap_or(&address)).map_err(map_jserr)?,
        chainId,
        name,
    )
    .map_err(map_jserr)?
    .to_string())
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn prepareSession(config: JsValue) -> Result<JsValue, JsValue> {
    Ok(serde_wasm_bindgen::to_value(
        &session::prepare_session(serde_wasm_bindgen::from_value(config)?).map_err(map_jserr)?,
    )?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn completeSessionSetup(config: JsValue) -> Result<JsValue, JsValue> {
    Ok(serde_wasm_bindgen::to_value(
        &session::complete_session_setup(serde_wasm_bindgen::from_value(config)?)
            .map_err(map_jserr)?,
    )?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn invoke(
    session: JsValue,
    service: String,
    path: String,
    action: String,
    facts: JsValue,
) -> Result<JsValue, JsValue> {
    let session: session::Session = serde_wasm_bindgen::from_value(session)?;
    // Convert JsValue facts to Option<Vec<serde_json::Value>>
    let facts_opt: Option<Vec<serde_json::Value>> = if facts.is_undefined() || facts.is_null() {
        None
    } else {
        Some(serde_wasm_bindgen::from_value(facts)?)
    };
    let authz = session
        .invoke(
            std::iter::once((
                service.parse().map_err(map_jserr)?,
                path.parse().map_err(map_jserr)?,
                None,
                None,
                std::iter::once(action.parse().map_err(map_jserr)?),
            )),
            facts_opt,
        )
        .map_err(map_jserr)?;
    Ok(serde_wasm_bindgen::to_value(&InvocationHeaders::new(
        authz,
    ))?)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn generateHostSIWEMessage(config: JsValue) -> Result<String, JsValue> {
    Ok(
        host::generate_host_siwe_message(serde_wasm_bindgen::from_value(config)?)
            .map_err(map_jserr)?
            .to_string(),
    )
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn siweToDelegationHeaders(signedSIWEMessage: JsValue) -> Result<JsValue, JsValue> {
    Ok(serde_wasm_bindgen::to_value(
        &host::siwe_to_delegation_headers(serde_wasm_bindgen::from_value(signedSIWEMessage)?),
    )?)
}

/// Create a delegation UCAN from a session to another DID.
/// This allows session keys to delegate capabilities to other users client-side.
///
/// # Arguments
/// * `session` - The current session (with JWK and delegation info)
/// * `delegateDID` - The recipient's DID (audience of the delegation)
/// * `spaceId` - The space being delegated (e.g., "tinycloud:pkh:eip155:1:0x....:default")
/// * `path` - Path scope for the delegation
/// * `actions` - Actions to delegate (e.g., ["tinycloud.kv/get", "tinycloud.kv/put"])
/// * `expirationSecs` - Expiration timestamp in seconds since epoch
/// * `notBeforeSecs` - Optional not-before timestamp in seconds since epoch
///
/// # Returns
/// A `DelegationResult` containing:
/// * `delegation` - Base64url-encoded UCAN JWT string
/// * `cid` - CID of the delegation (for referencing in proof chains)
/// * `delegateDID` - The delegate's DID
/// * `path` - Path scope
/// * `actions` - Delegated actions
/// * `expiry` - Expiration timestamp
#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn createDelegation(
    session: JsValue,
    delegateDID: String,
    spaceId: String,
    path: String,
    actions: Vec<String>,
    expirationSecs: f64,
    notBeforeSecs: JsValue,
) -> Result<JsValue, JsValue> {
    let session: session::Session = serde_wasm_bindgen::from_value(session)?;

    // Parse space_id
    let space_id: tinycloud_lib::resource::SpaceId = spaceId.parse().map_err(map_jserr)?;

    // Parse path
    let path: tinycloud_lib::resource::Path = path.parse().map_err(map_jserr)?;

    // Parse actions
    let abilities: Vec<tinycloud_lib::siwe_recap::Ability> = actions
        .into_iter()
        .map(|a| a.parse())
        .collect::<Result<_, _>>()
        .map_err(map_jserr)?;

    // Parse optional not_before
    let not_before: Option<f64> = if notBeforeSecs.is_undefined() || notBeforeSecs.is_null() {
        None
    } else {
        Some(serde_wasm_bindgen::from_value(notBeforeSecs)?)
    };

    // Create the delegation
    let result = session
        .create_delegation(
            &delegateDID,
            &space_id,
            &path,
            abilities,
            expirationSecs,
            not_before,
        )
        .map_err(map_jserr)?;

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Compute a CID from data bytes using Blake3_256 hash.
///
/// This uses the same hashing algorithm as the TinyCloud server,
/// ensuring CID consistency between client and server.
///
/// # Arguments
/// * `data` - The bytes to hash
/// * `codec` - The multicodec code (e.g., 0x55 for raw)
///
/// # Returns
/// The CID as a string (base32 multibase encoded)
#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn computeCid(data: &[u8], codec: u64) -> String {
    let hash = Code::Blake3_256.digest(data);
    let cid = Cid::new_v1(codec, hash);
    cid.to_string()
}
