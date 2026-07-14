# tethro-credential-proxy

Credential isolation proxy for AI agents. Agents never see your real API keys — a per-session scoped proxy key is injected into outbound requests, rate-limited and revocable. Supports Anthropic + OpenAI.

```bash
bun src/index.js
```

## License

Apache 2.0
