mod definitions;

use tinycloud_sdk_rs::*;
use wasm_bindgen::prelude::*;

fn map_jsvalue<E: std::error::Error>(result: Result<String, E>) -> Result<String, JsValue> {
    match result {
        Ok(string) => Ok(string),
        Err(err) => Err(err.to_string().into()),
    }
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
pub fn makeOrbitId(address: String, chainId: u32, name: Option<String>) -> String {
    util::make_orbit_id_pkh_eip155(address, chainId, name)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn prepareSession(config: String) -> Result<String, JsValue> {
    map_jsvalue(
        serde_json::from_str(&config)
            .map_err(session::Error::JSONDeserializing)
            .and_then(session::prepare_session)
            .and_then(|preparation| {
                serde_json::to_string(&preparation).map_err(session::Error::JSONSerializing)
            }),
    )
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn completeSessionSetup(config: String) -> Result<String, JsValue> {
    map_jsvalue(
        serde_json::from_str(&config)
            .map_err(session::Error::JSONDeserializing)
            .and_then(session::complete_session_setup)
            .and_then(|session| {
                serde_json::to_string(&session).map_err(session::Error::JSONSerializing)
            }),
    )
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn invoke(
    session: String,
    service: String,
    path: String,
    action: String,
) -> Result<String, JsValue> {
    map_jsvalue(
        serde_json::from_str(&session)
            .map_err(authorization::Error::JSONDeserializing)
            .and_then(|s| authorization::InvocationHeaders::from(s, vec![(service, path, action)]))
            .and_then(|headers| {
                serde_json::to_string(&headers).map_err(authorization::Error::JSONSerializing)
            }),
    )
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn generateHostSIWEMessage(config: String) -> Result<String, JsValue> {
    map_jsvalue(
        serde_json::from_str(&config)
            .map_err(siwe_utils::Error::JSONDeserializing)
            .and_then(siwe_utils::generate_host_siwe_message)
            .map(|message| message.to_string()),
    )
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn siweToDelegationHeaders(signedSIWEMessage: String) -> Result<String, JsValue> {
    map_jsvalue(
        serde_json::from_str(&signedSIWEMessage)
            .map_err(siwe_utils::Error::JSONDeserializing)
            .map(siwe_utils::siwe_to_delegation_headers)
            .and_then(|headers| {
                serde_json::to_string(&headers).map_err(siwe_utils::Error::JSONSerializing)
            }),
    )
}
