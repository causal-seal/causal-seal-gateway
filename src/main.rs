//! Causal Seal Gateway — a drop-in, OpenAI-compatible reverse proxy that attaches
//! a Causal Seal (https://causalseal.org) to every AI response, without the calling
//! application changing a single line of code.
//!
//! Point your app at the gateway instead of the provider:
//!     OPENAI_BASE_URL=http://127.0.0.1:8080
//! Every /v1/chat/completions response comes back with an `X-Causal-Seal` header
//! and is appended to an NDJSON audit log.
//!
//! HONEST SCOPE: a proxy can only seal what it observes from the outside — the model,
//! the timing, the request/response. That yields a *thin* but genuine, verifiable seal
//! (a "gateway-basic" domain profile). The *rich* causal state (the full governance
//! parameters) exists only when a governance engine produces it upstream. This binary
//! is the open, model-agnostic on-ramp; it is not the engine.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SPEC: &str = "causal-seal/1.0";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Fingerprint per SPEC §4: SHA-256 over the JCS-canonical serialization of the seal
/// minus `fingerprint` and `signature`. serde_json's default Map is a BTreeMap, so
/// `to_string` emits members in sorted order with no insignificant whitespace — which
/// matches the reference Python and JavaScript implementations exactly.
fn fingerprint(seal: &Value) -> String {
    let mut body = seal.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("fingerprint");
        obj.remove("signature");
    }
    let canon = serde_json::to_string(&body).expect("serialize seal");
    sha256_hex(canon.as_bytes())
}

fn now_iso() -> String {
    // Millisecond UTC timestamp without pulling a date crate.
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = d.as_secs() as i64;
    let ms = d.subsec_millis();
    // days since epoch -> civil date (Howard Hinnant's algorithm)
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    let sod = secs.rem_euclid(86400);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hh, mm, ss, ms
    )
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Build a gateway-basic seal for one observed response.
fn build_seal(emitter: &str, model: &str, upstream_host: &str, output_text: &str, dict: &str) -> Value {
    let mut seal = json!({
        "spec": SPEC,
        "emitter": emitter,
        "timestamp": now_iso(),
        "output_hash": sha256_hex(output_text.as_bytes()),
        "causal_state": {
            "identity.route": "gateway-passthrough",
            "engine.model": model,
            "engine.upstream": upstream_host,
            "context.memory_state": "stateless",
            "shaping.guard": "none"
        },
        "dictionary": dict
    });
    let fp = fingerprint(&seal);
    seal.as_object_mut().unwrap().insert("fingerprint".into(), json!(fp));
    seal
}

fn selftest() {
    // Reproduce the published test vector valid-001 and confirm interoperability
    // with the reference verifier (verify.html / causal_seal.py).
    let vector = json!({
        "spec": "causal-seal/1.0",
        "emitter": "example-engine/1.0",
        "timestamp": "2026-07-17T14:00:00.000Z",
        "output_hash": "63b6530c4afbe3545db2e0173e91cda673ee93001f0c597e73e9820507096bc3",
        "causal_state": {
            "identity.expert": "TECH",
            "identity.confidence": "0.87",
            "engine.model": "example-model-7b",
            "field.regime": "stable",
            "shaping.depth": "3",
            "shaping.guard": "nominal",
            "context.memory_state": "awake"
        },
        "dictionary": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    });
    let expected = "81d931140be9a128df3091479b61aa7b496c7fc023104e57d4a5ebd4cae3740a";
    let got = fingerprint(&vector);
    println!("expected : {expected}");
    println!("computed : {got}");
    if got == expected {
        println!("SELFTEST OK — fingerprint interoperable with the reference verifier.");
        std::process::exit(0);
    } else {
        eprintln!("SELFTEST FAILED — canonicalization diverges from the spec.");
        std::process::exit(1);
    }
}

fn header_val<'a>(headers: &'a [tiny_http::Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("selftest") {
        selftest();
        return;
    }

    let listen = env("CAUSAL_LISTEN", "127.0.0.1:8080");
    let upstream = env("CAUSAL_UPSTREAM", "https://api.openai.com");
    let emitter = env("CAUSAL_EMITTER", "causal-seal-gateway/0.1");
    let dict = env(
        "CAUSAL_DICTIONARY",
        "https://causalseal.org/profiles/gateway-basic.json",
    );
    let logpath = env("CAUSAL_LOG", "causal-seal-log.ndjson");
    let upstream_host = upstream
        .split("://")
        .nth(1)
        .unwrap_or(&upstream)
        .trim_end_matches('/')
        .to_string();

    let server = tiny_http::Server::http(&listen)
        .unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));
    eprintln!("causal-seal-gateway → listening on http://{listen}  ·  upstream {upstream}");
    eprintln!("point your app at:  OPENAI_BASE_URL=http://{listen}");

    for mut req in server.incoming_requests() {
        let method = req.method().as_str().to_string();
        let path = req.url().to_string();
        let headers: Vec<tiny_http::Header> = req.headers().to_vec();
        let mut body = Vec::new();
        let _ = req.as_reader().read_to_end(&mut body);

        // Forward to upstream, preserving auth and content-type.
        let url = format!("{}{}", upstream.trim_end_matches('/'), path);
        let mut rq = ureq::request(&method, &url);
        for name in ["authorization", "content-type", "accept", "openai-organization"] {
            if let Some(v) = header_val(&headers, name) {
                rq = rq.set(name, v);
            }
        }
        let resp = if body.is_empty() {
            rq.call()
        } else {
            rq.send_bytes(&body)
        };

        let (status, resp_body) = match resp {
            Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
            Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
            Err(e) => {
                let msg = format!("{{\"error\":\"gateway upstream error: {e}\"}}");
                let response = tiny_http::Response::from_string(msg)
                    .with_status_code(502)
                    .with_header(
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap(),
                    );
                let _ = req.respond(response);
                continue;
            }
        };

        // Seal chat/completions JSON responses; pass everything else through untouched.
        let mut seal_header: Option<String> = None;
        if path.contains("/chat/completions") || path.contains("/v1/completions") {
            if let Ok(v) = serde_json::from_str::<Value>(&resp_body) {
                let model = v.get("model").and_then(|m| m.as_str()).unwrap_or("unknown");
                let output_text = v
                    .pointer("/choices/0/message/content")
                    .and_then(|c| c.as_str())
                    .or_else(|| v.pointer("/choices/0/text").and_then(|c| c.as_str()))
                    .unwrap_or("");
                if !output_text.is_empty() {
                    let seal = build_seal(&emitter, model, &upstream_host, output_text, &dict);
                    let line = serde_json::to_string(&seal).unwrap();
                    // Append to the NDJSON audit log.
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&logpath)
                    {
                        use std::io::Write;
                        let _ = writeln!(f, "{line}");
                    }
                    seal_header = Some(line);
                }
            }
        }

        let mut response = tiny_http::Response::from_string(resp_body).with_status_code(status);
        response.add_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        if let Some(seal) = seal_header {
            if let Ok(h) = tiny_http::Header::from_bytes(&b"X-Causal-Seal"[..], seal.as_bytes()) {
                response.add_header(h);
            }
        }
        let _ = req.respond(response);
    }
}
