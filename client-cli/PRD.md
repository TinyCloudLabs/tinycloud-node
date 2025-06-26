# Tinycloud Client CLI

A cli tool for acting as a client for tinycloud-node. implemented using tinycloud-lib and tinycloud-sdk-rs. additional dependancies should include:
- clap for cli (https://docs.rs/clap/latest/clap/)
- ssi.workspace for cryto operations, formats and DID support (https://github.com/chunningham/ssi)
- reqwest async for http (https://docs.rs/reqwest/0.12.20/reqwest/)
- anyhow for error handling
- tokio for async runtime
other dependancies may be used if they are needed. If possible, try and use the workspace dependancies instead of external ones, however external is fine if it's necessary.

for now, assume that any issuing DIDs are of the form did:pkh:eip155:1:0x..., based on the eth address of the given `--ethkey` used for the command.

## example usage

global required arguments are:
- --ethkey: hex-encoded ethereum private key

global optional arguments are:
- --url: URL of the tinycloud orbit host (defaults to "https://demo.tinycloud.xyz"). this is where the http requests are sent
- --parent: Vec<CID> of parent capabilities proving authority (defaults to Vec::new())
- --orbit: orbit ID containing the resources. (defaults to `tinycloud:pkh:eip155:1:0x...://default/` orbit for the given issuer)

### delegate capabilities

#### Orbit Hosting
- with siwe to $RECIPIENT DID using hex-encoded ethereum private key $PRIVATEKEY
```
tinycloud-client host \
    --ethkey=${PRIVATEKEY} \
    --url=${URL} \
    --name=${ORBIT_NAME}
```

${ORBIT_NAME} defaults to `default`

1. gets a host DID from `/peer/generate/${ORBIT}` where $ORBIT is created from the issuer's DID and the $ORBIT_NAME
2. use the host DID to create a siwe CACAO delegation creating the orbit with the host (e.g. delegate `${ORBIT}` resource with `orbit/host` capability)
3. POSTs an empty request to `/delegate` with `Authorization` header set to be the encoded siwe CACAO
4. returns ${ORBIT} in plaintext

#### General Resource Access Delegation
```
tinycloud-client delegate ${RECIPIENT} \
    --ethkey=${PRIVATEKEY} \
    --url=${URL} \
    --orbit=${ORBIT} \
    --
    --kv/some/path=get,put,delete
    --kv/another/path=metadata
```


1. POSTs an empty request to `/delegate` with `Authorization` header set to be the encoded siwe CACAO
2. returns a CID of the delegation to be used in further delegations or invocations made by $RECIPIENT in plaintext

delegates the `get,put,delete` abilities of `${ORBIT}/kv/some/path` and the `metadata` ability to `${ORBIT}/kv/another/path` to `${RECIPIENT}`.

### invoke capabilities

invoke a delegation to access a resource in a given orbit.

#### KV Get
- invoke the `kv/get` capability on $PATH using hex-encoded eth private key $PRIVATEKEY, referencing parent delegation $CID in orbit ${ORBIT}
```
tinycloud-client invoke kv get ${PATH} \
    --ethkey=${PRIVATEKEY} \
    --url=${URL} \
    --orbit=${ORBIT} \
    --parent=${CID} > file.txt
```
returns the content of $PATH from the orbit's kv store, streamed into file.txt

#### KV Metadata
- invoke the `kv/metadata` capability on $PATH using hex-encoded eth private key $PRIVATEKEY, referencing parent delegation $CID in orbit ${ORBIT}
```
tinycloud-client invoke kv head ${PATH} \
    --ethkey=${PRIVATEKEY} \
    --url=${URL} \
    --orbit=${ORBIT} \
    --parent=${CID}
```
returns the metadata for the $PATH

#### KV Put
- invoke the `kv/put` capability on $PATH using hex-encoded eth private key $PRIVATEKEY, referencing parent delegation $CID in orbit ${ORBIT}
```
cat file.txt | tinycloud-client invoke kv put ${PATH} \
    --ethkey=${PRIVATEKEY} \
    --url=${URL} \
    --orbit=${ORBIT} \
    --parent=${CID}
```
uploads file.txt into $PATH in $ORBIT (e.g. `${Orbit}/kv/${PATH}`)

#### KV Delete
- invoke the `kv/delete` capability on $PATH using hex-encoded eth private key $PRIVATEKEY, referencing parent delegation $CID in orbit ${ORBIT}
```
tinycloud-client invoke kv delete ${PATH} \
    --ethkey=${PRIVATEKEY} \
    --url=${URL} \
    --orbit=${ORBIT} \
    --parent=${CID}
```

deletes the kv entry at $PATH
