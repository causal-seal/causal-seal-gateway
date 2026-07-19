# Causal Seal Gateway

> A drop-in, OpenAI-compatible proxy that attaches a **[Causal Seal](https://causalseal.org)** to every AI response — **without the calling application changing a single line of code.**

Point your app at the gateway instead of the provider:

```
OPENAI_BASE_URL=http://127.0.0.1:8080
```

…and every `/v1/chat/completions` response comes back with an `X-Causal-Seal` header and is appended to a tamper-evident NDJSON audit log. The seal is verifiable by anyone — including the free verifier at [causalseal.org/verify.html](https://causalseal.org/verify.html).

## Quickstart

```bash
cargo build --release
CAUSAL_UPSTREAM=https://api.openai.com ./target/release/causal-seal-gateway
```

Then send a normal OpenAI request to the gateway:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}' -D -
```

The response is unchanged; look for the `X-Causal-Seal:` header. Verify it:

```bash
# paste the header value into seal.json, then:
python causal_seal.py verify seal.json --output-text "…the response content…"
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `CAUSAL_LISTEN` | `127.0.0.1:8080` | address the gateway listens on |
| `CAUSAL_UPSTREAM` | `https://api.openai.com` | the real provider requests are forwarded to |
| `CAUSAL_EMITTER` | `causal-seal-gateway/0.1` | emitter id written into each seal |
| `CAUSAL_DICTIONARY` | `…/profiles/gateway-basic.json` | URL of the parameter dictionary |
| `CAUSAL_LOG` | `causal-seal-log.ndjson` | append-only audit log path |

Auth (`Authorization`) and content headers are forwarded to the upstream untouched. Streaming and non-JSON responses pass through unsealed.

## Honest scope

A proxy can only seal **what it observes from the outside** — the model, the timing, the request and response. That produces a *thin but genuine, verifiable* seal (the `gateway-basic` domain profile): who the upstream was, which model answered, when, and a hash binding the exact output.

The **rich** causal state — the full governance parameters (routing, regime, guard, context state) — exists only when a governance **engine** produces it upstream. This binary is the open, model-agnostic **on-ramp**; it is not the engine. Two tiers, by design:

- **Gateway alone** → basic, model-agnostic seal. The adoption on-ramp. *(MIT)*
- **Gateway + a governance engine** → complete causal seal.

## Verification of interoperability

`causal-seal-gateway selftest` recomputes the fingerprint of the published test vector and asserts it matches the reference implementation — proving seals from this gateway verify with the standard tools.

## License

MIT. Part of the open [Causal Seal](https://causalseal.org) standard (specification CC BY 4.0). See the [neutrality charter](https://causalseal.org/charter.html).
