mod definitions;
pub mod host;
pub mod session;
pub mod vault;

use hex::FromHex;
use tinycloud_auth::{
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
};
use tinycloud_sdk_rs::{authorization::InvocationHeaders, util};
use wasm_bindgen::prelude::*;

fn map_jserr<E: std::error::Error>(e: E) -> JsValue {
    e.to_string().into()
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn protocolVersion() -> u32 {
    tinycloud_auth::protocol::PROTOCOL_VERSION
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

/// Create a multi-resource delegation UCAN from a session to another DID.
///
/// Produces a **single** UCAN JWT that encodes every `(service, path, actions)`
/// entry in `abilities`, scoped to `spaceId`. This lets a session key
/// re-delegate exactly the capabilities it holds (or a strict subset) in one
/// signed blob, regardless of how many services or paths the delegation
/// covers.
///
/// # Arguments
/// * `session` - The current session (with JWK and delegation info).
/// * `delegateDID` - The recipient DID (audience of the UCAN).
/// * `spaceId` - The TinyCloud user space the delegation targets
///   (e.g., `"tinycloud:pkh:eip155:1:0x....:default"`).
/// * `abilities` - JS object shape `{ [service]: { [path]: [action, ...] } }`
///   matching the shape `prepareSession` already accepts. Actions are
///   full-URN strings (e.g., `"tinycloud.kv/get"`). An empty map is an error.
/// * `expirationSecs` - UCAN expiration timestamp (seconds since epoch).
/// * `notBeforeSecs` - Optional UCAN not-before timestamp.
///
/// # Returns
/// A [`session::DelegationResult`] containing:
/// * `delegation` - Base64url-encoded UCAN JWT.
/// * `cid` - CID of the delegation (for proof chains).
/// * `delegateDid` - The delegate's DID.
/// * `expiry` - Expiration timestamp.
/// * `resources` - Deterministic list of `{ service, space, path, actions }`
///   entries describing what the UCAN grants. Sorted by `(service, path)`.
#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn createDelegation(
    session: JsValue,
    delegateDID: String,
    spaceId: String,
    abilities: JsValue,
    expirationSecs: f64,
    notBeforeSecs: JsValue,
) -> Result<JsValue, JsValue> {
    let session: session::Session = serde_wasm_bindgen::from_value(session)?;

    // Parse space_id
    let space_id: tinycloud_auth::resource::SpaceId = spaceId.parse().map_err(map_jserr)?;

    // Parse the multi-resource abilities map. This is the same shape that
    // `prepareSession` accepts: `{ [service]: { [path]: [action] } }`.
    // serde_wasm_bindgen handles the nested HashMap deserialization directly
    // because `Service`, `Path`, and `Ability` all implement `FromStr`/`Deserialize`.
    let abilities_map: std::collections::HashMap<
        tinycloud_auth::resource::Service,
        std::collections::HashMap<
            tinycloud_auth::resource::Path,
            Vec<tinycloud_auth::siwe_recap::Ability>,
        >,
    > = serde_wasm_bindgen::from_value(abilities)?;

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
            abilities_map,
            expirationSecs,
            not_before,
        )
        .map_err(map_jserr)?;

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Parse a signed SIWE message and extract its recap capabilities.
///
/// This is the inverse of what `prepareSession` + `completeSessionSetup`
/// produce: given the SIWE string that a session was signed over, return the
/// list of `{ service, space, path, actions }` entries that were granted.
///
/// Used by the SDK layer to decide whether a requested delegation is derivable
/// from the current session (capability subset check). When the caps are a
/// subset, the SDK can issue the delegation via `createDelegation` without any
/// wallet prompt.
///
/// # Arguments
/// * `siweString` - The signed SIWE message as a string (exactly as returned
///   by `PreparedSession.siwe.toString()`, before or after signing).
///
/// # Returns
/// An array of `{ service, space, path, actions }` objects. Returns an empty
/// array (not an error) when the SIWE has no recap resource.
#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn parseRecapFromSiwe(siweString: &str) -> Result<JsValue, JsValue> {
    let entries = session::parse_recap_from_siwe(siweString).map_err(map_jserr)?;
    Ok(serde_wasm_bindgen::to_value(&entries)?)
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
