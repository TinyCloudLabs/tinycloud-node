use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TS_DEF: &'static str = r#"
/**
 * Configuration object for starting a TinyCloud session.
 */
export type SessionConfig = {
  /** Actions that the session key will be permitted to perform, organized by service and path */
  actions: { [service: string]: { [key: string]: string[] }},
  /** Non-space resources to include directly in the ReCap, keyed by raw resource URI */
  rawAbilities?: { [resource: string]: string[] },
  /** Ethereum address. */
  address: string,
  /** Chain ID. */
  chainId: number,
  /** Domain of the webpage. */
  domain: string,
  /** Current time for SIWE message. */
  issuedAt: string,
  /** The space that is the target resource of the delegation. */
  spaceId: string,
  /** The earliest time that the session will be valid from. */
  notBefore?: string,
  /** The latest time that the session will be valid until. */
  expirationTime: string,
  /** Optional parent delegations to inherit and attenuate */
  parents?: string[]
  /** Optional jwk to delegate to */
  jwk?: object
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const RECIPIENT_DID_DELEGATION_V2: &'static str = r#"
export type RecipientDidDelegationBundleV2 = {
  format: "tinycloud-recipient-delegation-v2",
  routing: { origin: string, nodeAudience: string },
  grant: { kind: "ucan", cid: string, encoding: "jwt", value: string },
  issuerProofs: Array<
    | { kind: "cacao", cid: string, encoding: "dag-cbor-base64url-pad", value: string }
    | { kind: "ucan", cid: string, encoding: "jwt", value: string }
  >,
};

export type NativeVerifiedRecipientDidDelegationBundleV2 = {
  verification: "tinycloud-native-authority-v1",
  ownerDid: string,
  sessionPrincipalDid: string,
  sessionVerificationMethod: string,
  recipientDid: string,
  grantCid: string,
  proofCids: string[],
  scope: {
    spaceId: string,
    resource: { kind: "exact", path: string },
    actions: string[],
  },
  notBefore?: string,
  expiry: string,
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "RecipientDidDelegationBundleV2")]
    pub type JsRecipientDidDelegationBundleV2;

    #[wasm_bindgen(typescript_type = "NativeVerifiedRecipientDidDelegationBundleV2")]
    pub type JsNativeVerifiedRecipientDidDelegationBundleV2;
}

#[wasm_bindgen(typescript_custom_section)]
const TS_DEF: &'static str = r#"
/**
 * A TinyCloud session.
 */
export type Session = {
  /** The delegation from the user to the session key. */
  delegationHeader: { Authorization: string },
  /** The delegation reference from the user to the session key. */
  delegationCid: string,
  /** The session key. */
  jwk: object,
  /** The space that the session key is permitted to perform actions against. */
  spaceId: string,
  /** The verification method of the session key. */
  verificationMethod: string,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const TS_DEF: &'static str = r#"
/**
 * Configuration object for generating a TinyCloud Space Host Delegation SIWE message.
 */
export type HostConfig = {
  /** Ethereum address. */
  address: string,
  /** Chain ID. */
  chainId: number,
  /** Domain of the webpage. */
  domain: string,
  /** Current time for SIWE message. */
  issuedAt: string,
  /** The space that is the target resource of the delegation. */
  spaceId: string,
  /** The peer that is the target/invoker in the delegation. */
  peerId: string,
}
"#;
