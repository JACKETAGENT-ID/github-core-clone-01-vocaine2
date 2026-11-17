[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/JACKETAGENT-ID/github-core-clone-01-vocaine2/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/JACKETAGENT-ID/github-core-clone-01-vocaine2/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

# forge2 — GitHub-compatible git forge (make.fun `github-core-clone-01`)

A from-scratch Node 22 (stdlib only) implementation of the forge spec: git smart
HTTP (upload-pack v2 + v0, receive-pack v0), REST v3, GraphQL, and MCP — in a
single process with an in-memory store. No git binary, no network, no wall clock
in any response (timestamps are a fixed epoch plus a monotonic counter, so live
and replay runs produce identical bytes).

## Run

```sh
node --experimental-strip-types main.ts   # needs MAKEFUN_ENV_URL
```

## Optimisation (perf focus)

- **Cached read path:** every GET-one-issue response is pre-serialised to a Buffer
  at creation time; the read workload does zero `JSON.stringify` and zero object
  lookups beyond two `Map.get` calls. Same for GET-repo.
- **O(1) git lookups:** objects and refs live in `Map`s keyed by oid / ref name;
  commit headers and tree entries are parsed lazily and cached on the object.
- **Minimal parsing:** pkt-line / pack codecs work on Buffers; packs are plain
  (no deltas) and chunked into sideband frames once.
- **No per-request allocation churn** on the hot paths: pre-built buffers,
  shared label/user shapes, no re-serialisation.

## Layout

- `app.ts` — the whole forge (store, git codecs, REST, GraphQL, MCP, HTTP server)
- `main.ts` — lifecycle: listen on an ephemeral port, register with the
  environment, long-poll `/done`, exit 0
