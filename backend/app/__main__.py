"""
MTGroup VPN Ultimate v2.0 — CLI Entry Point

Allows running the Terminal Control Center via:
    python -m backend.app.cli
    python -m backend.app.cli --cron reset-quotas
"""
from backend.app.cli import main

if __name__ == "__main__":
    main()
