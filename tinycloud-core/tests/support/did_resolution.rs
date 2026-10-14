use std::{net::TcpListener, time::Duration};
use tinycloud_auth::{
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::{Payload, Ucan},
    },
    ucan_capabilities_object::Capabilities,
};

pub fn bound_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

pub async fn assert_no_connections(listeners: &[&TcpListener]) {
    let until = tokio::time::Instant::now() + Duration::from_millis(200);
    while tokio::time::Instant::now() < until {
        for listener in listeners {
            match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                result => panic!("expected zero accepted connections, got {result:?}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub fn signed_ucan(issuer: &str, jwk: &JWK, algorithm: Algorithm) -> Ucan {
    signed_ucan_with_proof(issuer, jwk, algorithm, true)
}

pub fn signed_ucan_with_proof(
    issuer: &str,
    jwk: &JWK,
    algorithm: Algorithm,
    has_proof: bool,
) -> Ucan {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Payload {
        issuer: issuer.parse().unwrap(),
        audience: "did:key:audience".parse().unwrap(),
        expiration: NumericDate::try_from_seconds((now + 300) as f64).unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 10) as f64).unwrap()),
        nonce: Some("tc1080-local-refusal".into()),
        facts: None,
        proof: if has_proof {
            vec![
                "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"
                    .parse()
                    .unwrap(),
            ]
        } else {
            vec![]
        },
        attenuation: Capabilities::new(),
    }
    .sign(algorithm, jwk)
    .unwrap()
}
