# continuity-auth docs

continuity-auth is one service. The documentation is a hub-and-spoke. The repo
[`README`](../README.md) is the pitch. The spokes below carry the substance:

| Doc | When to read |
|---|---|
| [`ontology.md`](ontology.md) | The data model. Identity, tuple, pubkey, host-link, score, tier. Read first if you want to reason about the system. |
| [`threat-model.md`](threat-model.md) | What we defend against (T1–T19), what we don't. PII minimisation. Operating boundaries. |
| [`architecture.md`](architecture.md) | Module structure, decisions, trade-offs, per-request data flow. Why each piece is where it is. |
| [`crypto-protocol.md`](crypto-protocol.md) | Envelope format, canonical bytes, signature algorithms. |
| [`api.md`](api.md) | Wire format for every endpoint. |
| [`integration-guide.md`](integration-guide.md) | How to wire continuity-auth into a host application. |
| [`non-browser-clients.md`](non-browser-clients.md) | CLI / daemon / mobile substrates. The `continuity` CLI. Keys-on-disk threat model. |
| [`deployment.md`](deployment.md) | Environment variables, secrets, Datalevin server mode, Prometheus scrape, OTel. |
| [`runbook.md`](runbook.md) | On-call. IP-HMAC keystore. Manual interventions. Common alerts. |
