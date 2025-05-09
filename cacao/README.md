# CACAOs

CACAOs is a Rust library implementing the [CAIP-74 Chain-Agnostic Object Capability Specification](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md), with built in support for Sign In With Ethereum.

## Example

A simple example using SIWE-type CACAOs:

``` rust
use async_trait::async_trait;
use cacaos::{
    siwe_cacao::{Eip191, Eip4361, Payload, SiweCacao},
    SignatureScheme,
};
use futures::executor::block_on;
use hex::FromHex;
use libipld::{cbor::DagCborCodec, codec::Encode, multihash::Code, store::DefaultParams, Block};
use siwe::Message;
use std::str::FromStr;

async fn run_example() {
    let message: Payload = Message::from_str(
        r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
    )
    .unwrap()
    .into();

    let sig = <Vec<u8>>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap().try_into().unwrap();

    // verify a siwe signature
    let v = Eip191::verify(&message, &sig).await.unwrap();

    // sign the message to create a cacao
    let cacao: SiweCacao = SiweCacao::new(message, sig, None);

    // ipld-encode the cacao
    let block = Block::<DefaultParams>::encode(DagCborCodec, Code::Blake3_256, &cacao).unwrap();
}

fn main() {
    block_on(run_example());
}

```

`
