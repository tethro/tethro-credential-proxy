# Contributing to Tethro (public packages)

**Do not open PRs against the private console.** External contributions are accepted only in the public Apache-2.0 repositories described in [`REPO-SPLIT.md`](./REPO-SPLIT.md).

## Before your first PR

1. Read [`CLA.md`](./CLA.md).
2. Add yourself to [`CLA-SIGNATORIES.md`](./CLA-SIGNATORIES.md).
3. Open the PR against the **public** repo (`tethro-cli` / shared libs), not this console monorepo once the split lands.

## While we are still a monorepo

Until the split is complete, treat these paths as the future public surface:

- `mini-services/tethro-cli/`
- `src/lib/scanners/`
- `src/lib/isolation/` + `src/lib/isolation.ts`
- `mini-services/mcp-proxy/` (policy engine)
- `mini-services/credential-proxy/`
- `mini-services/audit-ws/`

Console UI (`src/app`, `src/components`), runbooks catalog, marketplace, and SIEM UI stay private.

## Standards

- No secrets in commits.
- Prefer small, reviewable PRs.
- Security-sensitive changes (proxy, isolation, kill relay) require pair review.
