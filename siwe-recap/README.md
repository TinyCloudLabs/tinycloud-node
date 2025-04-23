# EIP-5573: SIWE ReCap

This crate implements [EIP-5573](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-5573.md). Use this crate to build wallet-signable messages with capability delegations. The generated message contains two representations of the capabilities: an unambiguous machine-readable representation, and a human-readable description. Of the two representations, the latter is deterministically generated from the former.

## Message formats

We currently support the following message formats:
* [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361): Sign-In With Ethereum (SIWE)

## SIWE Examples

An example with:
- the capability to `present` any credential, without restrictions
- the capability to `present` credentials of type `type1` (technically redundant)
- the capability to `list`, `get` and retrieve `metadata` from the kepler location `kepler:ens:example.eth://default/kv`, without restrictions
- the capability to `list`, `get`, retrieve `metadata`, `put` and `delete` from the kepler locations `kepler:ens:example.eth://default/kv/public` and `kepler:ens:example.eth://default/kv/dapp-space`, without restrictions
```rust
let msg: siwe::Message = Builder::new()
    .with_actions_convert("urn:credential:type:type1", [("credential/present", [])])?
    .with_actions_convert(
        "kepler:ens:example.eth://default/kv",
        [("kv/list", []), ("kv/get", []), ("kv/metadata", [])],
    )?
    .with_actions_convert(
        "kepler:ens:example.eth://default/kv/public",
        [
            ("kv/list", []),
            ("kv/get", []),
            ("kv/metadata", []),
            ("kv/put", []),
            ("kv/delete", []),
        ],
    )?
    .with_actions_convert(
        "kepler:ens:example.eth://default/kv/dapp-space",
        [
            ("kv/list", []),
            ("kv/get", []),
            ("kv/metadata", []),
            ("kv/put", []),
            ("kv/delete", []),
        ],
    )?
    .build(siwe::Message {
        domain: "example.com".parse().unwrap(),
        address: Default::default(),
        statement: None,
        uri: "did:key:example".parse().unwrap(),
        version: siwe::Version::V1,
        chain_id: 1,
        nonce: "mynonce1".into(),
        issued_at: "2022-06-21T12:00:00.000Z".parse().unwrap(),
        expiration_time: None,
        not_before: None,
        request_id: None,
        resources: vec![],
    })?;
```

Which produces this SIWE message:
```
example.com wants you to sign in with your Ethereum account:
0x0000000000000000000000000000000000000000

I further authorize the state URI to perform the following actions on my behalf: (1) "kv": "get", "list", "metadata" for "kepler:ens:example.eth://default/kv". (2) "kv": "delete", "get", "list", "metadata", "put" for "kepler:ens:example.eth://default/kv/dapp-space". (3) "kv": "delete", "get", "list", "metadata", "put" for "kepler:ens:example.eth://default/kv/public". (4) "credential": "present" for "urn:credential:type:type1".

URI: did:key:example
Version: 1
Chain ID: 1
Nonce: mynonce1
Issued At: 2022-06-21T12:00:00.000Z
Resources:
- urn:recap:eyJhdHQiOnsia2VwbGVyOmVuczpleGFtcGxlLmV0aDovL2RlZmF1bHQva3YiOnsia3YvZ2V0IjpbXSwia3YvbGlzdCI6W10sImt2L21ldGFkYXRhIjpbXX0sImtlcGxlcjplbnM6ZXhhbXBsZS5ldGg6Ly9kZWZhdWx0L2t2L2RhcHAtc3BhY2UiOnsia3YvZGVsZXRlIjpbXSwia3YvZ2V0IjpbXSwia3YvbGlzdCI6W10sImt2L21ldGFkYXRhIjpbXSwia3YvcHV0IjpbXX0sImtlcGxlcjplbnM6ZXhhbXBsZS5ldGg6Ly9kZWZhdWx0L2t2L3B1YmxpYyI6eyJrdi9kZWxldGUiOltdLCJrdi9nZXQiOltdLCJrdi9saXN0IjpbXSwia3YvbWV0YWRhdGEiOltdLCJrdi9wdXQiOltdfSwidXJuOmNyZWRlbnRpYWw6dHlwZTp0eXBlMSI6eyJjcmVkZW50aWFsL3ByZXNlbnQiOltdfX0sInByZiI6W119
```

### Sign-in only

A Message can be built without any capabilities, in which case a statement with only the "sign-in" message is generated:
```rust
let msg: siwe::Message = DelegationBuilder::new()
    .build(siwe::Message {
        domain: "example.com".parse().unwrap(),
        address: Default::default(),
        statement: None,
        uri: "did:key:example".parse().unwrap(),
        version: siwe::Version::V1,
        chain_id: 1,
        nonce: "mynonce1".into(),
        issued_at: "2022-06-21T12:00:00.000Z".parse().unwrap(),
        expiration_time: None,
        not_before: None,
        request_id: None,
        resources: vec![],
    }))?;
```

Which produces this SIWE message:
```
'example.com wants you to sign in with your Ethereum account:
0x0000000000000000000000000000000000000000


URI: did:key:example
Version: 1
Chain ID: 1
Nonce: mynonce1
Issued At: 2022-06-21T12:00:00.000Z
```
