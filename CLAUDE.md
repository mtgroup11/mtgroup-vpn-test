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
pytest telegram_bot/tests_bot.py -v --asyncio-mode=auto   # currently has a pre-existing relative-import failure

# Lint / type-check (mirrors CI; mypy is non-blocking there)
ruff check backend/ telegram_bot/ --ignore E501
mypy backend/app/ --ignore-missing-imports --no-strict-optional

# Security scans (bandit is a BLOCKING CI gate at 0 findings; safety is non-blocking)
bandit -r backend/ telegram_bot/ -ll --skip B101
safety check --full-report

# Run the backend locally
uvicorn backend.app.main:app --host 0.0.0.0 --port 8443

# Frontend
cd frontend && npm install && npm run dev

# Full stack via Docker
cp .env.example .env   # then set TELEGRAM_BOT_TOKEN, ADMIN_ID, STEALTH_TOKEN, DB_ENCRYPTION_KEY, etc.
docker compose up -d --build

# Compile the eBPF XDP program (needs clang/llvm/libbpf-dev, Linux only)
make
```

CI (`.github/workflows/ci.yml`) runs on Python 3.11 and 3.12: ruff → mypy (non-blocking) → `backend/tests/` → `test_ebpf.py` → `telegram_bot/tests_bot.py` → coverage gate (**blocking**, currently 82%) → bandit (**blocking**, currently 0 findings) / safety (non-blocking, separate job).

Two known pre-existing CI failures unrelated to any current work: `telegram_bot/tests_bot.py` has a relative-import error, and `ruff check` reports ~35 errors (mostly unused imports in `telegram_bot/handlers/*.py`). Both are in `telegram_bot/`, both predate the backend hardening work — don't assume your change caused them; verify with `git stash` first.

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
`backend/app/orchestrator.py` (`NodeOrchestrator`) runs on the master panel and pushes config to remote VPN nodes over HTTP, every request HMAC-SHA256-signed (`X-MTGroup-Signature`) and retried via an in-memory `asyncio.Queue` on failure. The corresponding node-side agent lives in `agent/node_daemon.py` + `agent/mesh_router.py` and exposes `POST /api/v1/sync` and `GET /api/v1/health` (see the docstring at the top of `orchestrator.py` for the expected wire format) — the two ends are separate deployables, not imported from each other.

### Defense-in-depth engines started in `lifespan()`
- `honeypot` (`core/honeypot.py`) — always starts regardless of `EBPF_ENABLED`; simulates a vulnerable Nginx serving decoy paths (`/.env`, etc.) and permanently bans IPs that probe them (app-level ban if eBPF is off, kernel eBPF map ban if on).
- `hopper_engine` (`generators/port_hopper.py`, `AsyncPortHoppingEngine`) and `ai_engine` (`core/ai_detector.py`, `AnomalyPredictor`, a dependency-free RNN) — only start when `settings.EBPF_ENABLED` is true; fully bypassed otherwise to save resources.
- `killswitch` (`core/killswitch.py`) — drops all non-VPN traffic at the XDP layer on trigger, exposed via `/api/v1/system/killswitch/trigger|release`.
All three of eBPF-off, BCC-not-installed, and BCC-import-failure are handled as graceful degradation paths, not hard failures — check `HAS_BCC` and `settings.EBPF_ENABLED` together when touching this code.

### Config and required production secrets
`backend/app/core/config.py`'s `Settings` (pydantic-settings, loads from `.env`) has safe defaults for local dev, but `lifespan()` **hard-fails at startup** when `DEBUG=False` and any of `DB_ENCRYPTION_KEY`, `ADMIN_PASSWORD`, or `STEALTH_TOKEN` are empty or still the shipped default — this is intentional so the app can't accidentally go to production insecure. When writing tests or local scripts, either set `DEBUG=True` or set real values for these three.

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

### Real code that isn't wired up yet
Several modules are implemented and tested but nothing starts them at boot — don't mistake these for dead code, and don't assume they're running either:
- `SNIMultiplexer` (`core/routing_engine.py`) — full SNI-routing/decoy-deflection TCP server, never instantiated in `lifespan()`.
- `SingularityAutoCDN` (`core/auto_cdn.py`) — lifecycle works, but its two health-check hooks are deliberate `pass` stubs and nothing instantiates it.
- `TrafficAccountingEngine` (`core/accounting.py`) — its docstring says "instantiated in main.py lifespan"; it currently isn't.
- The XDP stats file that `cli.py` and the Telegram bot read (`/run/mtgroup/xdp_stats.json`) has no writer yet; both readers degrade to zeroed stats.

### Licensing boundary (established, durable)
Architectural ideas have been adapted from two reference VPN panels: Spiritus (MIT) and 3x-ui (GPL-3.0). MIT-licensed code may be copied directly with attribution. GPL-licensed code must never be copied — only the underlying idea may be reimplemented from scratch in this project's own code/naming. Do not obscure or rename copied GPL code to hide provenance; that boundary has been explicitly refused before.
