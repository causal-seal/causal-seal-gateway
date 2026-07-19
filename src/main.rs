//! Causal Seal Gateway — a drop-in, OpenAI-compatible reverse proxy that attaches
//! a Causal Seal (https://causalseal.org) to every AI response, without the calling
//! application changing a single line of code.
//!
//! Point your app at the gateway instead of the provider:
//!     OPENAI_BASE_URL=http://127.0.0.1:8080
//!
//! - Non-streaming responses  → `X-Causal-Seal` header + NDJSON audit log.
//! - Streaming (SSE) responses → the stream is passed through untouched, and a final
//!   `event: causal-seal` SSE event carrying the seal is injected just before [DONE].
//!
//! HONEST SCOPE: a proxy can only seal what it observes from the outside — the model,
//! the timing, the output. That is a *thin* but genuine, verifiable seal. The rich
//! causal state exists only when a governance engine produces it upstream.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::Read;

const SPEC: &str = "causal-seal/1.0";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// SPEC §4 fingerprint: SHA-256 over JCS-canonical serialization (serde_json's default
/// Map is a BTreeMap → sorted keys, no whitespace — matches the reference verifiers).
fn fingerprint(seal: &Value) -> String {
    let mut body = seal.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("fingerprint");
        obj.remove("signature");
    }
    sha256_hex(serde_json::to_string(&body).expect("serialize").as_bytes())
}

fn now_iso() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = d.as_secs() as i64;
    let ms = d.subsec_millis();
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
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, sod / 3600, (sod % 3600) / 60, sod % 60, ms
    )
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[derive(Clone)]
struct SealCtx {
    emitter: String,
    dict: String,
    upstream_host: String,
    logpath: String,
}

impl SealCtx {
    fn build(&self, model: &str, output_text: &str) -> Value {
        let mut seal = json!({
            "spec": SPEC,
            "emitter": self.emitter,
            "timestamp": now_iso(),
            "output_hash": sha256_hex(output_text.as_bytes()),
            "causal_state": {
                "identity.route": "gateway-passthrough",
                "engine.model": model,
                "engine.upstream": self.upstream_host,
                "context.memory_state": "stateless",
                "shaping.guard": "none"
            },
            "dictionary": self.dict
        });
        let fp = fingerprint(&seal);
        seal.as_object_mut().unwrap().insert("fingerprint".into(), json!(fp));
        seal
    }
    fn log(&self, seal: &Value) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.logpath) {
            use std::io::Write;
            let _ = writeln!(f, "{}", serde_json::to_string(seal).unwrap());
        }
    }
}

/// A Read that passes an upstream SSE stream through unchanged, accumulates the
/// assistant content, and injects a `causal-seal` event just before `data: [DONE]`
/// (or at end-of-stream if no [DONE] is sent).
struct SealingStream {
    upstream: Box<dyn Read + Send + Sync>,
    out: VecDeque<u8>,
    line: Vec<u8>,
    content: String,
    model: String,
    ctx: SealCtx,
    upstream_eof: bool,
    seal_flushed: bool,
}

impl SealingStream {
    fn new(upstream: Box<dyn Read + Send + Sync>, ctx: SealCtx) -> Self {
        SealingStream {
            upstream, out: VecDeque::new(), line: Vec::new(),
            content: String::new(), model: "unknown".into(), ctx,
            upstream_eof: false, seal_flushed: false,
        }
    }

    fn seal_event(&mut self) {
        if self.seal_flushed { return; }
        let seal = self.ctx.build(&self.model, &self.content);
        self.ctx.log(&seal);
        let ev = format!("event: causal-seal\ndata: {}\n\n", serde_json::to_string(&seal).unwrap());
        self.out.extend(ev.as_bytes());
        self.seal_flushed = true;
    }

    /// Parse one complete SSE line for content/model, then decide passthrough vs. seal injection.
    fn handle_line(&mut self, raw: &[u8]) {
        let text = String::from_utf8_lossy(raw);
        let trimmed = text.trim_end_matches('\r');
        if let Some(payload) = trimmed.strip_prefix("data: ") {
            if payload.trim() == "[DONE]" {
                // Inject the seal BEFORE [DONE] so clients that stop at [DONE] still receive it.
                self.seal_event();
                self.out.extend(raw);
                self.out.push_back(b'\n');
                return;
            }
            if let Ok(v) = serde_json::from_str::<Value>(payload) {
                if self.model == "unknown" {
                    if let Some(m) = v.get("model").and_then(|m| m.as_str()) {
                        self.model = m.to_string();
                    }
                }
                if let Some(c) = v.pointer("/choices/0/delta/content").and_then(|c| c.as_str()) {
                    self.content.push_str(c);
                } else if let Some(c) = v.pointer("/choices/0/text").and_then(|c| c.as_str()) {
                    self.content.push_str(c);
                }
            }
        }
        // passthrough (unchanged bytes)
        self.out.extend(raw);
        self.out.push_back(b'\n');
    }

    fn ingest(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line);
                self.handle_line(&line);
            } else {
                self.line.push(b);
            }
        }
    }
}

impl Read for SealingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.out.is_empty() {
                let n = self.out.len().min(buf.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = self.out.pop_front().unwrap();
                }
                return Ok(n);
            }
            if self.upstream_eof {
                if !self.seal_flushed {
                    // stream ended without [DONE]: flush any partial line, then the seal
                    if !self.line.is_empty() {
                        let line = std::mem::take(&mut self.line);
                        self.handle_line(&line);
                    }
                    self.seal_event();
                    continue;
                }
                return Ok(0);
            }
            let mut tmp = [0u8; 8192];
            let k = self.upstream.read(&mut tmp)?;
            if k == 0 {
                self.upstream_eof = true;
                continue;
            }
            self.ingest(&tmp[..k]);
        }
    }
}

fn selftest() {
    let vector = json!({
        "spec": "causal-seal/1.0",
        "emitter": "example-engine/1.0",
        "timestamp": "2026-07-17T14:00:00.000Z",
        "output_hash": "63b6530c4afbe3545db2e0173e91cda673ee93001f0c597e73e9820507096bc3",
        "causal_state": {
            "identity.expert": "TECH", "identity.confidence": "0.87",
            "engine.model": "example-model-7b", "field.regime": "stable",
            "shaping.depth": "3", "shaping.guard": "nominal", "context.memory_state": "awake"
        },
        "dictionary": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    });
    let expected = "81d931140be9a128df3091479b61aa7b496c7fc023104e57d4a5ebd4cae3740a";
    let got = fingerprint(&vector);
    println!("expected : {expected}\ncomputed : {got}");
    if got == expected {
        println!("SELFTEST OK — fingerprint interoperable with the reference verifier.");
    } else {
        eprintln!("SELFTEST FAILED");
        std::process::exit(1);
    }
}

fn header_val<'a>(headers: &'a [tiny_http::Header], name: &str) -> Option<&'a str> {
    headers.iter()
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
    let ctx = SealCtx {
        emitter: env("CAUSAL_EMITTER", "causal-seal-gateway/0.1"),
        dict: env("CAUSAL_DICTIONARY", "https://causalseal.org/profiles/gateway-basic.json"),
        upstream_host: upstream.split("://").nth(1).unwrap_or(&upstream).trim_end_matches('/').to_string(),
        logpath: env("CAUSAL_LOG", "causal-seal-log.ndjson"),
    };

    let server = tiny_http::Server::http(&listen).unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));
    eprintln!("causal-seal-gateway → http://{listen}  ·  upstream {upstream}");
    eprintln!("point your app at:  OPENAI_BASE_URL=http://{listen}");

    for mut req in server.incoming_requests() {
        let method = req.method().as_str().to_string();
        let path = req.url().to_string();
        let headers: Vec<tiny_http::Header> = req.headers().to_vec();
        let mut body = Vec::new();
        let _ = req.as_reader().read_to_end(&mut body);

        let wants_stream = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("stream").and_then(|s| s.as_bool()))
            .unwrap_or(false);
        let sealable = path.contains("/chat/completions") || path.contains("/v1/completions");

        let url = format!("{}{}", upstream.trim_end_matches('/'), path);
        let mut rq = ureq::request(&method, &url);
        for name in ["authorization", "content-type", "accept", "openai-organization"] {
            if let Some(v) = header_val(&headers, name) {
                rq = rq.set(name, v);
            }
        }
        let resp = if body.is_empty() { rq.call() } else { rq.send_bytes(&body) };

        // ─── Streaming path: pass through + inject a final causal-seal event ───
        if wants_stream && sealable {
            match resp {
                Ok(r) => {
                    let reader = SealingStream::new(r.into_reader(), ctx.clone());
                    let response = tiny_http::Response::new(
                        tiny_http::StatusCode(200),
                        vec![
                            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap(),
                            tiny_http::Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).unwrap(),
                        ],
                        reader, None, None,
                    );
                    let _ = req.respond(response);
                    continue;
                }
                Err(e) => {
                    let msg = format!("{{\"error\":\"gateway upstream error: {e}\"}}");
                    let _ = req.respond(tiny_http::Response::from_string(msg).with_status_code(502));
                    continue;
                }
            }
        }

        // ─── Non-streaming path: buffer, seal into a header ───
        let (status, resp_body) = match resp {
            Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
            Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
            Err(e) => {
                let msg = format!("{{\"error\":\"gateway upstream error: {e}\"}}");
                let _ = req.respond(
                    tiny_http::Response::from_string(msg).with_status_code(502).with_header(
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                    ),
                );
                continue;
            }
        };

        let mut seal_header: Option<String> = None;
        if sealable {
            if let Ok(v) = serde_json::from_str::<Value>(&resp_body) {
                let model = v.get("model").and_then(|m| m.as_str()).unwrap_or("unknown");
                let output_text = v.pointer("/choices/0/message/content").and_then(|c| c.as_str())
                    .or_else(|| v.pointer("/choices/0/text").and_then(|c| c.as_str()))
                    .unwrap_or("");
                if !output_text.is_empty() {
                    let seal = ctx.build(model, output_text);
                    ctx.log(&seal);
                    seal_header = Some(serde_json::to_string(&seal).unwrap());
                }
            }
        }

        let mut response = tiny_http::Response::from_string(resp_body).with_status_code(status);
        response.add_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
        if let Some(seal) = seal_header {
            if let Ok(h) = tiny_http::Header::from_bytes(&b"X-Causal-Seal"[..], seal.as_bytes()) {
                response.add_header(h);
            }
        }
        let _ = req.respond(response);
    }
}
