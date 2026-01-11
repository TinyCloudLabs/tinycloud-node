mod definitions;
pub mod host;
pub mod session;

use hex::FromHex;
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
) -> Result<JsValue, JsValue> {
    let session: session::Session = serde_wasm_bindgen::from_value(session)?;
    let authz = session
        .invoke(std::iter::once((
            service.parse().map_err(map_jserr)?,
            path.parse().map_err(map_jserr)?,
            None,
            None,
            std::iter::once(action.parse().map_err(map_jserr)?),
        )))
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
