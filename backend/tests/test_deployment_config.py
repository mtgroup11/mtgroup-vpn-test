"""
Deployment wiring: the production entry point, Docker build context, and
compose file. Each test pins a way the shipped stack used to break.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from backend.app import serve

REPO = Path(__file__).resolve().parents[2]


def _run_args(monkeypatch, **settings_overrides):
    captured = {}
    monkeypatch.setattr(serve.uvicorn, "run", lambda app, **kw: captured.update(app=app, **kw))
    for key, value in settings_overrides.items():
        monkeypatch.setattr(serve.settings, key, value)
    serve.main()
    return captured


def test_serves_on_the_configured_port_single_worker(monkeypatch):
    kw = _run_args(monkeypatch, PORT=8443, WORKERS=4, TLS_CERT_PATH=None, TLS_KEY_PATH=None)
    assert kw["app"] == "backend.app.main:app"
    assert kw["port"] == 8443
    # In-memory bans / rate limits / node-sync loops: N workers = N copies.
    assert kw["workers"] == 1
    assert kw["server_header"] is False
    assert "ssl_certfile" not in kw


def test_enables_tls_when_both_paths_are_set(monkeypatch):
    kw = _run_args(monkeypatch, TLS_CERT_PATH="/c.pem", TLS_KEY_PATH="/k.pem")
    assert kw["ssl_certfile"] == "/c.pem" and kw["ssl_keyfile"] == "/k.pem"


def test_dockerfile_runs_the_entry_point_and_exposes_8443():
    dockerfile = (REPO / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["python", "-m", "backend.app.serve"]' in dockerfile
    assert "EXPOSE 8443" in dockerfile
    assert "--gid 10001 mtgroup" in dockerfile


def test_secrets_and_state_are_kept_out_of_the_image():
    ignored = (REPO / ".dockerignore").read_text(encoding="utf-8").split()
    for entry in (".env", ".git", "data/", "*.db", "*.log"):
        assert entry in ignored


def test_compose_reads_secrets_at_runtime_and_keeps_state_in_data():
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
    backend = compose["services"]["vpn-backend"]
    assert backend["env_file"] == ".env"
    assert "./data:/app/data" in backend["volumes"]
    # no single-file bind mounts (Docker turns missing ones into directories)
    assert not any(v.startswith("./") and v.split(":")[0].endswith((".db", ".log")) for v in backend["volumes"])
    env = dict(e.split("=", 1) for e in backend["environment"])
    assert env["DATABASE_URL"].endswith("/app/data/mtgroup.db")
    assert env["AUDIT_LOG_FILE"].startswith("/app/data/")
    # backend's primary gid must be the helper's `mtgroup` group
    assert backend["user"] == "0:10001"
    frontend = compose["services"]["vpn-frontend"]
    assert frontend["ports"] == ["127.0.0.1:3000:3000"]
    assert any(e.startswith("BACKEND_INTERNAL_URL=") and e.endswith(":8443") for e in frontend["environment"])


def test_frontend_public_dir_exists_for_the_standalone_build():
    # frontend/Dockerfile copies /app/public; without the directory the
    # image build fails.
    assert (REPO / "frontend" / "public").is_dir()


def test_audit_log_directory_is_created(tmp_path):
    from backend.app.core.logging_config import SecurityAuditLogger
    target = tmp_path / "nested" / "dir" / "audit.log"
    import logging
    logger = logging.getLogger("mtgroup.audit")
    saved = list(logger.handlers)
    for h in saved:
        logger.removeHandler(h)
    try:
        SecurityAuditLogger(log_file=str(target))
        assert target.parent.is_dir()
    finally:
        for h in list(logger.handlers):
            h.close()
            logger.removeHandler(h)
        for h in saved:
            logger.addHandler(h)
