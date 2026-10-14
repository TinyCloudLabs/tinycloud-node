use super::{EgressError, LookupHost};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;

#[derive(Default)]
pub(crate) struct TestLookup {
    answers: Mutex<HashMap<String, VecDeque<Vec<IpAddr>>>>,
    pub calls: AtomicUsize,
}

impl TestLookup {
    pub async fn set(&self, host: &str, addresses: &[&str]) {
        self.sequence(host, &[addresses]).await;
    }

    pub async fn sequence(&self, host: &str, answers: &[&[&str]]) {
        self.answers.lock().await.insert(
            host.to_owned(),
            answers
                .iter()
                .map(|addresses| addresses.iter().map(|ip| ip.parse().unwrap()).collect())
                .collect(),
        );
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl LookupHost for TestLookup {
    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, EgressError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().await;
        let sequence = answers.get_mut(host).ok_or(EgressError::Dns)?;
        if sequence.len() > 1 {
            Ok(sequence.pop_front().unwrap())
        } else {
            sequence.front().cloned().ok_or(EgressError::Dns)
        }
    }
}

pub(crate) struct CallbackServer {
    pub url: String,
    pub certificate: reqwest::Certificate,
    pub requests: tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, hyper::HeaderMap)>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CallbackServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) async fn callback_server(
    status: u16,
    location: Option<String>,
) -> anyhow::Result<CallbackServer> {
    use hyper::{service::service_fn, Body, Request, Response};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let generated = rcgen::generate_simple_self_signed(vec!["callback.test".to_owned()])?;
    let certificate = reqwest::Certificate::from_pem(generated.cert.pem().as_bytes())?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key.into())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls));
    let (sender, requests) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let sender = sender.clone();
            let location = location.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Body>| {
                    let sender = sender.clone();
                    let location = location.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let bytes = hyper::body::to_bytes(body).await.unwrap();
                        let _ = sender.send((bytes.to_vec(), parts.headers));
                        let mut response = Response::builder().status(status);
                        if let Some(location) = location {
                            response = response.header("Location", location);
                        }
                        Ok::<_, std::convert::Infallible>(response.body(Body::empty()).unwrap())
                    }
                });
                let _ = hyper::server::conn::Http::new()
                    .serve_connection(stream, service)
                    .await;
            });
        }
    });
    Ok(CallbackServer {
        url: format!("https://callback.test:{}/hooks", address.port()),
        certificate,
        requests,
        task,
    })
}
