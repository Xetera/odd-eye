use axum::{
    http::{HeaderValue, StatusCode},
    prelude::*,
    response::IntoResponse,
    AddExtensionLayer,
};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Nonce,
};
use rand::{thread_rng, RngCore};
use serde;
use serde::{Serialize, Serializer};
use std::{iter::FromIterator, net::SocketAddr, sync::Arc, time::SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

struct State {
    aead: ChaCha20Poly1305,
}

const ENCRYPTION_KEY_NAME: &'static str = "ODD_EYE_ENCRYPTION_KEY";

#[tokio::main]
async fn main() {
    let key = std::env::var(ENCRYPTION_KEY_NAME).expect(&format!(
        "Could not find the encryption key variable '{}'",
        &ENCRYPTION_KEY_NAME
    ));
    let key_bytes = key.as_bytes();
    let key_length = key_bytes.len();
    assert!(
        key_length == 32,
        "Encryption key is not exactly 32 bytes. Key size = {}",
        key_length
    );
    tracing_subscriber::fmt::init();

    let state = Arc::new(State {
        aead: ChaCha20Poly1305::new_from_slice(key_bytes).unwrap(),
    });
    let mut app = route("/", get(root))
        .route("/b64", get(base64_route))
        .boxed();

    if cfg!(debug_assertions) {
        app = app.route("/test", get(test_route)).boxed();
    }

    let default_port = 4000u16;
    let addr = SocketAddr::from((
        [127, 0, 0, 1],
        std::env::var("ODD_EYE_PORT").map_or(default_port, |str| {
            str.parse::<u16>().unwrap_or(default_port)
        }),
    ));

    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.layer(AddExtensionLayer::new(state)).into_make_service())
        .await
        .unwrap();
}

fn unwrap_header(header: HeaderValue) -> String {
    header.to_str().unwrap_or("").to_owned()
}

type FingerprintResponse = Result<Vec<u8>, chacha20poly1305::aead::Error>;

fn encrypt_fingerprint(fp: Fingerprint, aead: &ChaCha20Poly1305) -> FingerprintResponse {
    let mut rng = thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    println!("{:?}", &fp);
    let payload = serde_json::to_string(&fp).unwrap();

    let mut out: Vec<u8> = Vec::from_iter(nonce.as_slice().to_owned());
    out.extend(aead.encrypt(nonce, payload.as_bytes())?);
    Ok(out)
}

fn build_fingerprint(req: Request<Body>) -> Fingerprint {
    let mut headers = req.headers().clone();
    let http = headers.remove("x-http-fingerprint").map(unwrap_header);
    let ja3 = headers.remove("x-tls-fingerprint").map(unwrap_header);
    let ja3_hash = headers.remove("x-tls-fingerprint-hash").map(unwrap_header);
    // TODO: collect this data in NGINX to ensure the order is preserved.
    // Currently not working
    let user_agent = headers
        .get("user-agent")
        .map_or(None, |e| Some(e.to_str().unwrap_or("").to_owned()));

    let pfp = PassiveFingerprint {
        http,
        ja3,
        ja3_hash,
        user_agent,
        headers: headers
            .into_iter()
            .filter_map(|v| v.0.map(|name| name.to_string()))
            .collect::<Vec<String>>(),
    };
    Fingerprint {
        fingerprint: pfp,
        timestamp: SystemTime::now(),
    }
}

#[cfg(debug_assertions)]
async fn test_route(req: Request<Body>) -> impl IntoResponse {
    let fp = build_fingerprint(req);
    return (StatusCode::OK, response::Json(fp));
}

fn get_response(state: extract::Extension<Arc<State>>, req: Request<Body>) -> FingerprintResponse {
    let fp = build_fingerprint(req);
    encrypt_fingerprint(fp, &state.aead)
}

async fn base64_route(
    state: extract::Extension<Arc<State>>,
    req: Request<Body>,
) -> impl IntoResponse {
    match get_response(state, req) {
        Ok(data) => (StatusCode::OK, base64::encode(data).into_response()),
        Err(err) => {
            println!("{:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                // TODO: better error handling here
                "Internal Server Error".into_response(),
            )
        }
    }
}

async fn root(state: extract::Extension<Arc<State>>, req: Request<Body>) -> impl IntoResponse {
    match get_response(state, req) {
        Ok(data) => (StatusCode::OK, data.into_response()),
        Err(err) => {
            println!("{:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                // TODO: better error handling here
                "Internal Server Error".into_response(),
            )
        }
    }
}

#[derive(Debug, Serialize)]
struct PassiveFingerprint {
    http: Option<String>,
    ja3: Option<String>,
    ja3_hash: Option<String>,
    user_agent: Option<String>,
    headers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Fingerprint {
    fingerprint: PassiveFingerprint,
    #[serde(serialize_with = "to_rfc3339")]
    timestamp: SystemTime,
}

fn to_rfc3339<S>(dt: &SystemTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let x: OffsetDateTime = dt.to_owned().into();
    s.serialize_str(&x.format(&Rfc3339).unwrap())
}
