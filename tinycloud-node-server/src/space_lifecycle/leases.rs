//! Transfer operation lifetimes to response bodies, including cancelled streams.
use rocket::{
    fairing::{Fairing, Info, Kind},
    request::{FromRequest, Outcome},
    Request, Response,
};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tinycloud_core::{resource_purge_fence::ResourceOperation, space_purge_fence::SpaceOperation};
use tokio::io::{AsyncRead, ReadBuf};

enum Lease {
    Space { _operation: SpaceOperation },
    Resource { _operation: ResourceOperation },
}
#[derive(Default)]
struct RequestLeases(Mutex<Vec<Lease>>);
#[derive(Clone)]
pub struct PurgeLeases(Arc<RequestLeases>);
impl PurgeLeases {
    pub fn hold_space(&self, operation: SpaceOperation) {
        self.0
             .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Lease::Space {
                _operation: operation,
            });
    }
    pub fn hold_resource(&self, operation: ResourceOperation) {
        self.0
             .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Lease::Resource {
                _operation: operation,
            });
    }
}
#[rocket::async_trait]
impl<'r> FromRequest<'r> for PurgeLeases {
    type Error = Infallible;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(
            request
                .local_cache(|| Arc::new(RequestLeases::default()))
                .clone(),
        ))
    }
}
pub struct PurgeLeaseFairing;
#[rocket::async_trait]
impl Fairing for PurgeLeaseFairing {
    fn info(&self) -> Info {
        Info {
            name: "space-operation-response-lifetimes",
            kind: Kind::Response,
        }
    }
    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let request_leases = request.local_cache(|| Arc::new(RequestLeases::default()));
        let leases = std::mem::take(
            &mut *request_leases
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if leases.is_empty() {
            return;
        }
        let size = response.body_mut().size().await;
        let chunk_size = response.body().max_chunk_size();
        let body = response.body_mut().take();
        response.set_streamed_body(LeasedBody { body, leases });
        response.set_max_chunk_size(chunk_size);
        // Rocket cannot seek through its erased Body. Preserve the original
        // known length explicitly while the wrapper forwards bytes unchanged.
        if let Some(size) = size {
            response.set_raw_header("Content-Length", size.to_string());
        }
    }
}
struct LeasedBody<'r> {
    body: rocket::response::Body<'r>,
    leases: Vec<Lease>,
}
impl AsyncRead for LeasedBody<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.body).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && buf.remaining() > 0
        {
            self.leases.clear();
        }
        result
    }
}
