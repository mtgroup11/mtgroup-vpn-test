# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

XDP-Spectre (MTGroup VPN Ultimate) — a self-hosted VPN panel built to evade DPI-based censorship (GFW-class firewalls). FastAPI backend + Next.js "Zero-UI" frontend (disguises itself as a 404 Nginx page unless a secret header is present) + optional eBPF/XDP kernel-level packet filtering + a Telegram bot for remote C2. Runs as a multi-service Docker Swarm stack (see `docker-compose.yml`, `Dockerfile`).

## Commands

Run everything from the repo root; the backend is imported as `backend.app.*`, so always invoke pytest/uvicorn from here, not from inside `backend/`.

```bash
# Install deps
pip install -r requirements.txt

# Run the full backend test suite
pytest backend/tests/ -v --asyncio-mode=auto

# Run a single test file / test
pytest backend/tests/test_api_users.py -v --asyncio-mode=auto
pytest backend/tests/test_api_users.py::test_create_user -v --asyncio-mode=auto

# Coverage (CI gate is --cov-fail-under=82; see .coveragerc for exclusions)
pytest backend/tests/ --asyncio-mode=auto --cov=backend --cov-report=term-missing --cov-fail-under=82

# eBPF-specific tests / Telegram bot tests (run separately in CI)
pytest backend/tests/test_ebpf.py -v --asyncio-mode=auto
pytest telegram_bot/tests_bot.py -v --asyncio-mode=auto

# Lint / type-check (mirrors CI; mypy is non-blocking there)
ruff check backend/ telegram_bot/ --ignore E501
mypy backend/app/ --ignore-missing-imports --no-strict-optional

# Security scans (bandit is a BLOCKING CI gate at 0 findings; safety is non-blocking)
bandit -r backend/ telegram_bot/ -ll --skip B101
safety check --full-report

# Run the backend locally (single process, settings.PORT, TLS if TLS_CERT_PATH/TLS_KEY_PATH set)
python -m backend.app.serve

# Frontend
cd frontend && npm install && npm run dev

# Full stack via Docker — install.sh generates .env (all secrets incl. STEALTH_TOKEN)
sudo bash install.sh
docker compose up -d --build   # state (DB, logs) lives in ./data; secrets via env_file: .env

# Node agent on each remote VPN node (command with the key: GET /api/nodes/{id}/agent-setup)
sudo MTGROUP_NODE_API_KEY=... bash agent/install_agent.sh

# Compile the eBPF XDP program (needs clang/llvm/libbpf-dev, Linux only)
make
```

CI (`.github/workflows/ci.yml`) runs on Python 3.11 and 3.12: ruff → mypy (non-blocking) → `backend/tests/` → `test_ebpf.py` → `telegram_bot/tests_bot.py` → coverage gate (**blocking**, currently 82%) → bandit (**blocking**, currently 0 findings) / safety (non-blocking, separate job).

All five gates are green as of 2026-08-10 — if one goes red, it's something you changed. Note bandit and the coverage gate are both blocking now, so **re-run `bandit` and the coverage gate after adding test files too**, not just production code: test fixtures with `/tmp` paths or `"0.0.0.0"` literals will trip bandit's heuristics (annotate with `# nosec BXXX - reason` or avoid the literal).

`telegram_bot/` is a proper Python package (it has `__init__.py` files and uses package-relative imports throughout). Run it with `python -m telegram_bot.bot` from the repo root, **not** `python bot.py` from inside the directory — the latter was the old script-style layout and no longer works. Note this standalone bot tree is not referenced by `Dockerfile`/`docker-compose.yml`/`install.sh` at all; the bot that actually ships is `backend/app/telegram_bot.py`, which is a separate implementation.

## Architecture

### Request path and the stealth gate
Every request to `backend/app/main.py`'s FastAPI app passes through `stealth_middleware` before hitting any router: it checks `orchestrator.is_app_banned(ip)` first, then requires the exact `X-Stealth-Token` header via `hmac.compare_digest` — anything else gets a generic `404 Not Found` (not 401/403), so the API is indistinguishable from "nothing here" to scanners and censors. Test clients must always send this header (see `backend/tests/conftest.py`'s `client` fixture).

Global middleware order: `SecurityHeadersMiddleware` → `RateLimitMiddleware` → `stealth_middleware`. `BannedIPMiddleware` (in `api/rate_limiter.py`) exists but is **intentionally not registered** — it needs a `db_session_factory` that isn't available until after `lifespan` runs; `orchestrator.is_app_banned()` covers the same app-level ban set without that ordering hazard.

### Dependency injection quirk
`get_db` in `backend/app/api/auth.py` is a placeholder that raises `NotImplementedError` by design. The real DB session is wired in via `app.dependency_overrides[get_db]` inside `main.py`'s `lifespan()` (production) or inside the `client` fixture in `conftest.py` (tests). If you add a new DB-backed router/endpoint and see `NotImplementedError`, this override wiring — not the endpoint — is where to look.

### Routers and their prefixes (not all use `/api`)
- `auth` → `/api/auth`, `users` → `/api/users`, `nodes` → `/api/nodes`, `system` → `/api/system`, `metrics` → `/api/metrics`, `resellers` → `/api/resellers`
- `subscriptions` has **no prefix** — its routes are `/sub/{token}`, `/sub/{token}/singbox`, `/clash`, `/v2ray`, `/amnezia`, `/qr`, `/links` (these are the client-facing subscription URLs handed to end users, deliberately not under `/api`).
- Historically `resellers`/`metrics` were mounted *without* `/api` which silently 404'd the dashboard and made the frontend fall back to fake `Math.random()` data — if dashboard numbers look suspiciously random again, check router prefixes first.

### Privilege separation
The FastAPI process should never need `NET_ADMIN`/`SYS_ADMIN` for routine operations. `backend/app/core/privileged_helper.py` is the client-side stub that talks over a Unix socket (`PRIVILEGED_HELPER_SOCKET`, default `/run/mtgroup/helper.sock`) to `backend/app/privileged_helper_daemon.py`, a separate root-owned daemon that actually runs `iptables`/`nft`/`systemctl`. eBPF XDP load/attach is the one exception still done in-process in `main.py`'s `lifespan()` (deferred follow-up, not yet moved behind the helper).

### Node orchestration (master ↔ node agents)
`backend/app/orchestrator.py` (`NodeOrchestrator`) runs on the master panel and pushes config to remote VPN nodes. The node-side agent lives in `agent/node_daemon.py` + `agent/mesh_router.py` and exposes `POST /api/v1/sync` and `GET /api/v1/health`; it is installed on a node with `agent/install_agent.sh` (systemd unit `mtgroup-node-agent`), and `GET /api/nodes/{id}/agent-setup` gives the admin the node's API key plus that exact command.

Wire contract (both sides implement it independently — `backend/tests/test_agent_wire_e2e.py` runs the real orchestrator against the real agent over TLS to keep them in agreement):
- **Endpoint:** `https://{node.address}:{node.agent_port}` — `agent_port` (default 8443), *not* `node.port`, which is the VPN port clients use. These used to be the same field, so every health check hit Xray/AmneziaWG and failed.
- **TLS, pinned:** the agent generates a self-signed CA:TRUE cert on first start (`python -m agent.node_daemon --print-cert`). The orchestrator trusts exactly `node.agent_cert_pem` for that node (pasted by the admin, or recorded on first contact — TOFU) and never connects unverified. Full Xray syncs carry the Reality private key, so this matters against an on-path ISP.
- **Signature:** `HMAC-SHA256(api_key, METHOD\nPATH\nTS\nNONCE\nBODY)` in `X-MTGroup-Signature`, with `X-MTGroup-Timestamp` (±30s) and a single-use `X-MTGroup-Nonce` the agent remembers. Method/path are signed so a request can't be re-aimed; the nonce stops replays inside the window.

Health vs. enable: **`Node.is_active` is the admin's switch and nothing automatic changes it.** Failed health checks only move `health_status` (`degraded` → `offline` after 3 consecutive failures, but only for a node that has been healthy at least once; a never-reached node is `unreachable`). Subscriptions skip `offline` nodes and pick them back up on the next successful check. Previously one failed poll set `is_active = False` and the node was never polled or listed again.

`sync_node_config()` queues failures for retry; `send_command()` doesn't (for callers that recompute and retry themselves).

**The two ends are separate deployables that share no code** — nothing type-checks the wire contract between them, so a change on one side silently breaks the other. This already happened once, expensively: the master multiplexes several command types through `/api/v1/sync` by putting an `action` key inside `payload`, and the daemon used to ignore `action` entirely and write whatever arrived straight over `config.json` before restarting the service. A two-key `{"action": "drop_user", ...}` command therefore replaced a node's *entire* configuration and took every user on it offline. `port_hopper`'s 6-hourly `update_port` did the same thing on any `EBPF_ENABLED` deployment.

The daemon now dispatches on `action` (`sync` / `drop_user` / `update_port`; absent means `sync`), applies `drop_user` and `update_port` surgically against the existing config, rejects unknown actions with 400, and refuses any `sync` whose payload doesn't structurally look like a proxy config. Writes are atomic (temp file + `os.replace`). **If you add a new master→node command, add a matching branch in `sync_handler` and a test in `agent/tests/test_node_daemon.py` in the same change** — the daemon deliberately fails closed, so an unhandled action is rejected rather than silently misapplied, but the feature simply won't work until both sides exist.

### Node user provisioning (`core/node_user_sync.py`, gated on `NODE_USER_SYNC_ENABLED`)
Renders each active VLESS-Reality node's full Xray server config (via `ProxyManager.build_vless_reality_config`) with one client per subscription that may connect right now — active sub, active user, not expired, not over lifetime/periodic quota — and pushes it as a full `sync` when it differs from what the node last accepted. Runs every `NODE_USER_SYNC_INTERVAL_SEC` and is woken (debounced) by `request_user_sync()`, which the users API calls after every create/update/delete/reset/regenerate. Client id == email == `derive_proxy_uuid(subscription.token, node.id)` — the same credential subscriptions hand out and accounting maps Xray stats back through. It *owns* the node's Xray config, hence opt-in (default `false`; `.env.example` sets `true` for new installs). Nodes without `reality_private_key` are skipped with a warning. AmneziaWG nodes are reconciled *surgically* in the same pass (`_sync_amnezia`): an ineligible subscription's peer gets `remove_peer` and `is_synced_to_node=False` but keeps its DB row and key, and is re-added with `add_peer` once eligible again — so renewing doesn't force the user to re-import. Hysteria2/TUIC nodes aren't provisioned yet — their server side needs a real TLS certificate/domain per node, which the model doesn't have.

`agent/` is covered by CI (lint, bandit, and `agent/tests/`) — note that until this fix it was excluded from all three, so `test_mesh_router.py` had never actually run.

### Defense-in-depth engines started in `lifespan()`
- `honeypot` (`core/honeypot.py`) — always starts regardless of `EBPF_ENABLED`; simulates a vulnerable Nginx serving decoy paths (`/.env`, etc.) and permanently bans IPs that probe them (app-level ban if eBPF is off, kernel eBPF map ban if on).
- `hopper_engine` (`generators/port_hopper.py`, `AsyncPortHoppingEngine`) and `ai_engine` (`core/ai_detector.py`, `AnomalyPredictor`, a dependency-free RNN) — only start when `settings.EBPF_ENABLED` is true; fully bypassed otherwise to save resources.
- `killswitch` (`core/killswitch.py`) — drops all non-VPN traffic at the XDP layer on trigger, exposed via `/api/v1/system/killswitch/trigger|release`.
All three of eBPF-off, BCC-not-installed, and BCC-import-failure are handled as graceful degradation paths, not hard failures — check `HAS_BCC` and `settings.EBPF_ENABLED` together when touching this code.

### Database migrations (Alembic) — required for ANY model change
`init_db()` runs `alembic upgrade head` at startup; it no longer calls `Base.metadata.create_all()`. That matters because `create_all` only ever *creates missing tables* — it silently ignores a new column on a table that already exists, so a model change would work perfectly on your fresh local DB and then crash an existing deployment with `no such column`.

**After editing anything in `models.py`, generate a migration in the same change:**
```bash
alembic revision --autogenerate -m "what changed"   # review the generated file before committing
alembic upgrade head                                 # apply locally
```
`backend/tests/test_migrations.py` fails the build if models and migrations diverge, so forgetting this is caught by CI rather than in production.

Details worth knowing:
- **`alembic.ini`'s `sqlalchemy.url` is deliberately blank.** `migrations/env.py` takes the URL from `settings.DATABASE_URL`, so there's one source of truth. An explicitly-passed URL still wins (tests target a temp DB that way).
- **Databases created before migrations existed are adopted automatically** — if the tables are there but `alembic_version` isn't, startup stamps the initial revision and then upgrades. No manual `alembic stamp` step when deploying.
- **`EncryptedType` columns render as `sa.Text()` in migrations** (`render_item` in `env.py`). At the database level they genuinely are TEXT; the encryption is applied in Python. This keeps migration history from importing application code.
- **`render_as_batch=True`** is on because SQLite can't `ALTER` most column properties in place.
- Six columns had both a column-level `unique=True` *and* a named `UniqueConstraint` in `__table_args__`, which emitted duplicate DDL and made `alembic check` permanently dirty. The redundant `unique=True` was removed; the named constraints still enforce uniqueness (there's a test).

### Data integrity / auth conventions
- **SQLite runs with `PRAGMA foreign_keys` OFF, deliberately.** Alembic's SQLite batch mode rebuilds tables (create-copy-drop); with FKs on, dropping the old table fires `ON DELETE CASCADE` into child tables, i.e. a migration could delete live rows. Consequence: every `ondelete=` in `models.py` is documentation only. Anything that must disappear with its parent needs an ORM `cascade=` or an explicit delete in the endpoint (see `delete_user` → Agent/AbuseReputation, `delete_node` → WireGuardPeer). SQLite also reuses the highest rowid, so an orphan row gets silently "inherited" by the next row created with that id.
- **Agent hierarchy:** `Agent.sub_agents` is one-to-many, `Agent.parent_agent` many-to-one. They were mapped inverted with `cascade="all"`, so deleting a sub-agent deleted its parent chain.
- **JWT revocation:** every token carries `tv` = `User.token_version`; `auth.user_from_payload` rejects a mismatch. Bump it on password/role change and deactivation (users API does) and via `POST /api/auth/logout-all`.
- **IP bans** are enforced in memory (app-level set or XDP map) and persisted in `banned_ips`; `orchestrator.restore_bans()` re-applies unexpired ones at startup and `record_ban()` upserts (the hash is `hash_for_lookup`, same as the admin API).

### Deployment notes
- **One process only.** App-level bans, the rate limiter and every background loop (orchestrator retry/health poll, node user sync, …) live in memory, so `serve.py` always runs a single uvicorn worker regardless of `WORKERS`.
- **Docker:** `.dockerignore` keeps `.env`, `.git`, the DB and logs out of the image; secrets arrive through `env_file`. Runtime state is the `./data` volume (`DATABASE_URL`/`LOG_FILE`/`AUDIT_LOG_FILE` point into it). The backend runs as `0:10001` so the privileged helper's `SO_PEERCRED` check (group `mtgroup`, gid 10001, created in the Dockerfile) accepts it. The frontend port is bound to `127.0.0.1` — the dashboard has no login of its own.
- **install.sh** never touches the host's system Python any more (Reality keys via `openssl`; schema created by the container's Alembic run). It renders `watchdog.service` with the checkout's real path. AmneziaWG obfuscation params are randomized per server and printed — the panel's node entry must use the same values. Regenerating the AmneziaWG server (which invalidates every issued config) needs `MTGROUP_AWG_REPROVISION=1`; `--force` only regenerates `.env`.

### Config and required production secrets
`backend/app/core/config.py`'s `Settings` (pydantic-settings, loads from `.env`) has safe defaults for local dev, but `lifespan()` (`main._enforce_production_secrets`) **hard-fails at startup** when `DEBUG=False` and any of `DB_ENCRYPTION_KEY`, `ADMIN_PASSWORD`, `STEALTH_TOKEN` or `JWT_SECRET_KEY` is empty, too short, a shipped default, or any `CHANGE_ME*` placeholder from `.env.example` (those are long enough to pass the length checks and are public — a test parses `.env.example` itself so the two can't drift). `JWT_SECRET_KEY` must be set explicitly: its random per-process default would log everyone out on restart. When writing tests or local scripts, either set `DEBUG=True` or set real values.

### Coverage / test conventions

**Never remove `concurrency = greenlet, thread` from `.coveragerc`.** SQLAlchemy's async ORM bridges every awaited DB call through an internal greenlet switch, and `coverage.py` silently stops attributing lines once execution crosses that boundary unless told to follow it. Without that line, nearly every route handler line after its first `await db.execute(...)` reports as uncovered *while actually executing fine* — it made well-tested files look 29-50% covered. Adding it moved total coverage 67% → 73% with zero new tests. If a file suddenly looks badly covered despite obvious tests, suspect measurement before writing more tests: put a temporary `print()` in a "missed" line and confirm whether it actually runs.

`.coveragerc` also excludes `backend/app/cli.py` (interactive tool, human-operated, not test-worthy) and all test files from the denominator. Don't add tests purely to move the number for excluded files, and don't lower `--cov-fail-under` without raising it back as coverage genuinely improves (see the comment above the gate in `ci.yml` for the running history and rationale).

`backend/tests/conftest.py` holds shared fixtures (`client`, `db_session`, `db_engine`, `seed_admin`, `seed_node`) used across most `test_api_*.py` files — extend those rather than duplicating DB/client setup. Note the `rate_limiter._buckets.clear()` reset in the `client` fixture: the rate limiter is a module-level singleton shared across the whole test session, and the ASGI test transport has no real peer IP, so every test collapses onto the same bucket key without this reset.

Established patterns worth reusing when adding tests:
- **Async engines with background loops** (`accounting`, `auto_cdn`, `port_hopper`, `metrics`): drive the private `_loop`/`_stream` coroutine directly and patch `asyncio.sleep` with a one-shot that flips `_is_running = False`, rather than starting the real task and racing it with `asyncio.sleep(0)`. Timing-based versions flake.
- **Socket/stream code** (`routing_engine`, `honeypot`): use small in-process `_FakeReader`/`_FakeWriter` classes; no real sockets are opened anywhere in this suite.
- **Fire-and-forget `asyncio.create_task`**: capture `asyncio.all_tasks()` before and after, then `await asyncio.gather(*spawned)` — don't guess at tick counts.

### The bandit `# nosec` convention
The bandit gate is blocking at zero findings. Anything intentional carries an inline `# nosec BXXX - one-line reason` (public-facing `0.0.0.0` binds, `verify=False` on self-signed node certs where HMAC signing provides integrity instead, the helper socket's restrictive `chmod 0o660`, the literal `cls`/`clear` shell call). When you hit a new finding, either fix it or add the same annotated form — do not flip the CI step back to `continue-on-error`.

### Engines gated behind opt-in settings flags (not "deferred" anymore — wired, just off by default)

Both engines below are now fully wired into `lifespan()`, each behind its own settings flag defaulting to `False`, so a routine upgrade with an unchanged `.env` changes nothing. Turning either on is still an operator decision made via `.env` — not "ask first" anymore (that reservation was explicitly lifted by the repo owner on 2026-08-13), but still something to flag to the operator since both affect live traffic/user state once enabled.

(`SingularityAutoCDN` used to be in this list too and **is wired up and starting** — see the note further down.)

**`SNIMultiplexer` (`core/routing_engine.py`)**, gated on `settings.SNI_MULTIPLEXER_ENABLED` (default `False`) — full SNI-routing / active-probe-deflection TCP server, started via `main.py`'s `lifespan()`. This codebase's own `install.sh` already reserves `:443` for the backend process when `EBPF_ENABLED=false` (`docker-compose.override.yml` maps `443:443` alongside `8443:8443`), and the panel API listens on `settings.SNI_MULTIPLEXER_API_PORT` (`8443` by default), never on `:443` directly — so there is no port conflict to resolve.
- **Backend routes are now populated for real.** `lifespan()`'s `_sni_mux_sync_loop()` queries active nodes and calls `add_backend(node.sni, node.address, node.port, ...)` for every node that has an `sni` set, once at startup and every `SNI_MUX_SYNC_INTERVAL_SEC` (default 60s) thereafter — added/removed/renamed nodes get picked up without a restart. A ClientHello SNI matching a node forwards straight to that node; anything else still falls through to `DECOY_REVERSE_PROXY_TARGET`.
- Still worth checking on a given host before enabling: confirm nothing else (nginx, another process) already holds `:443` outside this project's own deployment model (`ss -lntp`); verify `reuse_port=True` in `start()` behaves as intended on the deployment kernel.

**`TrafficAccountingEngine` (`core/accounting.py`)**, gated on `settings.ACCOUNTING_ENABLED` (default `False`) — quota enforcement, constructed with **`dry_run=False`** (live) when the flag is on, and wired via `orchestrator.set_accounting_engine(engine)`. There is no separate settings flag for dry-run vs. live: `ACCOUNTING_ENABLED=true` means real suspensions, immediately. `TrafficAccountingEngine.__init__` still supports `dry_run: bool = True` as a constructor default for anyone instantiating it directly (e.g. in a script) to observe behaviour before trusting it, but the `lifespan()` wiring always passes `dry_run=False`.
- *Before enabling in production:* audit current usage counters against real limits first (`SELECT username, data_used_bytes, data_limit_bytes FROM users WHERE data_limit_bytes > 0 AND data_used_bytes >= data_limit_bytes`) to see exactly who would be suspended on the first cycle; same for `agents`. Note the Xray traffic side is speculative until something actually pushes a real multi-user Xray config through `proxy_manager.build_vless_reality_config()` — right now nothing in production calls that function, so `xray_user_traffic` will be empty on any live deployment; only AmneziaWG traffic (`agent/node_daemon.py`'s `amnezia_peer_traffic` via `awg show transfer`) is real today.

Related, found while wiring the above: **`orchestrator.start()`/`.stop()` were never called anywhere** — `main.py`'s `lifespan()` injected `orchestrator._db_session_factory` but never started the orchestrator itself, so its retry-queue (failed `sync_node_config` pushes never retried) and node health polling (`check_node_health()` was previously only ever called by tests) had never run in production. This one **was** an oversight, not a deferred decision, and is now fixed — `orchestrator.start()`/`.stop()` are unconditional in `lifespan()`, same as `honeypot`.

**`SingularityAutoCDN` (`core/auto_cdn.py`) — hooks now implemented, engine gated on `settings.CDN_ENABLED`.** `_check_sni_health()` does a real TLS handshake against every active node's `address:port` using its `sni` as the ClientHello SNI (a clean handshake vs. a reset/timeout is the literal DPI-interference signature), caching per-SNI health in `self._sni_healthy`. `_manage_auto_cdn()`, only when `CDN_ENABLED` is true and something is unhealthy, probes `FALLBACK_CDN_CANDIDATES` (a small built-in pool of Cloudflare edge addresses — there is no Cloudflare account API token anywhere in this project's config, so this is reachability probing, not real Cloudflare API management despite the class's original docstring claiming that) and records the first reachable one in `self.current_cdn_target`.
- **Deliberately does not rewrite any `Node.sni`/routing config automatically** — even with `CDN_ENABLED` on, this only detects and exposes a candidate; actually rerouting live traffic based on an automated probe is bigger scope than "implement the two stubs," and there's no real Cloudflare management API to provision a new target through anyway. Wiring `current_cdn_target` into an actual routing decision (e.g. `routing_engine.py`'s `DECOY_REVERSE_PROXY_TARGET`) is separate follow-up work.
- Since the hooks now do real outbound network I/O (TLS probes to nodes and to Cloudflare addresses), the engine's `start()`/`stop()` in `main.py`'s `lifespan()` are gated on `settings.CDN_ENABLED` (default `False`) rather than starting unconditionally — operators who haven't opted into CDN fronting get none of this on a routine upgrade.

**`XDPStatsExporter` (`core/xdp_stats_exporter.py`) — NOW WIRED UP, gated on `settings.EBPF_ENABLED`.** The XDP stats file `cli.py` and the Telegram bot read (`/run/mtgroup/xdp_stats.json`) had no writer anywhere — both readers always degraded to zeroed stats, on every deployment, regardless of whether eBPF was actually protecting anything. This engine wraps `XDPLoader.get_stats()` and writes the file every 5s (atomic temp-file + `os.replace`, matching this codebase's other atomic writers).
- **Deliberately never writes `XDPLoader`'s `"simulated": True` numbers.** `XDPLoader.simulation_mode` is `not HAS_BCC` — i.e. it fabricates random drop/ban counts whenever BCC isn't importable, *independent* of `EBPF_ENABLED`. An operator reading the stats file has no way to tell fake numbers from real ones, so a simulated snapshot is simply not written; the file staying absent is the honest outcome, since both readers already degrade gracefully to zero.
- `active_v6` is hardcoded to `0` in the written schema — `XDPLoader`'s blacklist map is IPv4-only (`_int_to_ip` uses `socket.inet_ntoa`), so there's no real v6 count to report yet. Kept in the schema because both readers already index it unconditionally.

### Licensing boundary (established, durable)
Architectural ideas have been adapted from two reference VPN panels: Spiritus (MIT) and 3x-ui (GPL-3.0). MIT-licensed code may be copied directly with attribution. GPL-licensed code must never be copied — only the underlying idea may be reimplemented from scratch in this project's own code/naming. Do not obscure or rename copied GPL code to hide provenance; that boundary has been explicitly refused before.
