use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
};
use std::convert::TryFrom;
use std::time::Instant;
use tinycloud_auth::authorization::{
    TinyCloudDelegation, TinyCloudInvocation, TinyCloudRevocation,
};
use tinycloud_core::{
    events::{FromReqErr, SerializedEvent},
    util::{DelegationInfo, InvocationInfo, RevocationInfo},
};

pub struct AuthHeaderGetter<T>(pub SerializedEvent<T>);

macro_rules! impl_fromreq {
    ($type:ident, $inter:ident, $name:tt, $try_from_status:expr) => {
        #[rocket::async_trait]
        impl<'r> FromRequest<'r> for AuthHeaderGetter<$type> {
            type Error = FromReqErr<<$type as TryFrom<$inter>>::Error>;
            async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
                let start = Instant::now();
                let result = match request
                    .headers()
                    .get_one($name)
                    .map(SerializedEvent::<$type>::from_header_ser::<$inter>)
                {
                    Some(Ok(e)) => Outcome::Success(AuthHeaderGetter(e)),
                    Some(Err(e)) => Outcome::Error((
                        if matches!(e, FromReqErr::TryFrom(_)) {
                            $try_from_status
                        } else {
                            Status::Unauthorized
                        },
                        e,
                    )),
                    None => Outcome::Forward(Status::Unauthorized),
                };
                // TC-326: this guard decodes the base64url auth header into a
                // typed event (`from_header_ser`); it does NOT perform
                // signature verification. It was previously mislabeled under
                // `InvocationSignatureVerify`; emit the accurate
                // `AuthorizationHeaderDecode` stage instead. The old stage is
                // retained (unused) in the enum for metric continuity.
                crate::prometheus::observe_stage(
                    crate::prometheus::InvocationStage::AuthorizationHeaderDecode,
                    crate::prometheus::StageOutcome::from(matches!(result, Outcome::Success(_))),
                    start.elapsed(),
                );
                result
            }
        }
    };
}

impl_fromreq!(
    DelegationInfo,
    TinyCloudDelegation,
    "Authorization",
    Status::Unauthorized
);
impl_fromreq!(
    InvocationInfo,
    TinyCloudInvocation,
    "Authorization",
    Status::Unauthorized
);
impl_fromreq!(
    RevocationInfo,
    TinyCloudRevocation,
    "Authorization",
    Status::Forbidden
);
