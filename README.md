# tethro-credential-proxy

HTTP proxy that keeps model API keys off the agent process. Agents get a per-session scoped key (`tethro-session-…`); this service swaps in the real Anthropic/OpenAI key from the host environment, with basic rate limiting and revocation.

```bash
export ANTHROPIC_API_KEY=...
bun src/index.js
```

## Open source vs commercial

This proxy is **Apache 2.0** (local / self-hosted). Hosted credential isolation, org-wide key governance, and enterprise audit export ship with the commercial console — not this repo.

## License

Apache 2.0
