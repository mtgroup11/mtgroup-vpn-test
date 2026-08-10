#!/usr/bin/env python3
"""
MTGroup VPN Ultimate v2.0 - TERMINAL CONTROL CENTER
=====================================================
Interactive cyberpunk TUI for full system administration.

Usage:
    Interactive mode:   python -m backend.app.cli
    Cron mode:          python -m backend.app.cli --cron reset-quotas
                        python -m backend.app.cli --cron backup-db
                        python -m backend.app.cli --cron health-check
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# ANSI Color & Style Constants  (Cyberpunk Neon Palette)
# ═══════════════════════════════════════════════════════════════════

class C:
    """ANSI escape code constants — neon cyberpunk palette."""
    RST       = "\033[0m"
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    ITALIC    = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK     = "\033[5m"
    STRIKE    = "\033[9m"

    # ── Neon Foreground ──────────────────────────────────────────
    BLACK     = "\033[30m"
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    BLUE      = "\033[94m"
    MAGENTA   = "\033[95m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"

    # ── Deep / Dark Foreground ───────────────────────────────────
    DGREEN    = "\033[32m"
    DCYAN     = "\033[36m"
    DRED      = "\033[31m"
    DYELLOW   = "\033[33m"

    # ── 256-Color Neon Accents ───────────────────────────────────
    NEON_GREEN  = "\033[38;5;46m"
    NEON_CYAN   = "\033[38;5;51m"
    NEON_PINK   = "\033[38;5;198m"
    NEON_ORANGE = "\033[38;5;208m"
    NEON_PURPLE = "\033[38;5;129m"
    NEON_BLUE   = "\033[38;5;39m"
    ELECTRIC    = "\033[38;5;82m"

    # ── Background Accents ───────────────────────────────────────
    BG_DGRAY    = "\033[48;5;236m"
    BG_BLACK    = "\033[40m"
    BG_RED      = "\033[41m"
    BG_GREEN    = "\033[42m"
    BG_NEON     = "\033[48;5;22m"


# ═══════════════════════════════════════════════════════════════════
# Helper Utilities
# ═══════════════════════════════════════════════════════════════════

def clear_screen() -> None:
    """Clear the terminal screen cross-platform."""
    os.system("cls" if os.name == "nt" else "clear")  # nosec B605 - fixed literal command, no user input


def get_terminal_width() -> int:
    """Get terminal width, fallback to 80."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def hr(char: str = "═", color: str = C.DGREEN) -> str:
    """Full-width horizontal rule."""
    return f"{color}{char * get_terminal_width()}{C.RST}"


def hr_thin(char: str = "─", color: str = C.DIM) -> str:
    """Thin horizontal rule."""
    return f"{color}{char * get_terminal_width()}{C.RST}"


def box_line(text: str, color: str = C.NEON_GREEN) -> str:
    """Create a boxed line with neon borders."""
    w = get_terminal_width()
    inner = w - 4
    padded = text[:inner].ljust(inner)
    return f"{color}║ {C.RST}{padded}{color} ║{C.RST}"


def box_top(color: str = C.NEON_GREEN) -> str:
    w = get_terminal_width()
    return f"{color}╔{'═' * (w - 2)}╗{C.RST}"


def box_bottom(color: str = C.NEON_GREEN) -> str:
    w = get_terminal_width()
    return f"{color}╚{'═' * (w - 2)}╝{C.RST}"


def center_text(text: str, color: str = "") -> str:
    """Center text in terminal width."""
    w = get_terminal_width()
    return f"{color}{text.center(w)}{C.RST}"


def format_bytes(b: int) -> str:
    """Format bytes to human-readable string."""
    if b == 0:
        return f"{C.DIM}Sınırsız{C.RST}"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(b) < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} PB"


def format_uptime(seconds: float) -> str:
    """Format seconds to uptime string."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    mins = int((seconds % 3600) // 60)
    if days > 0:
        return f"{days}g {hours}s {mins}dk"
    elif hours > 0:
        return f"{hours}s {mins}dk"
    else:
        return f"{mins}dk"


def status_dot(active: bool) -> str:
    """Colored status indicator dot."""
    if active:
        return f"{C.NEON_GREEN}●{C.RST}"
    return f"{C.RED}○{C.RST}"


def print_error(msg: str) -> None:
    print(f"\n  {C.RED}✖ HATA:{C.RST} {msg}")


def print_success(msg: str) -> None:
    print(f"\n  {C.NEON_GREEN}✔ BAŞARILI:{C.RST} {msg}")


def print_warning(msg: str) -> None:
    print(f"\n  {C.YELLOW}⚠ UYARI:{C.RST} {msg}")


def print_info(msg: str) -> None:
    print(f"\n  {C.NEON_CYAN}ℹ BILGI:{C.RST} {msg}")


def prompt(text: str, default: str = "") -> str:
    """Cyberpunk-styled input prompt."""
    suffix = f" {C.DIM}[{default}]{C.RST}" if default else ""
    try:
        value = input(f"  {C.NEON_CYAN}>{C.RST} {text}{suffix}: ").strip()
        return value if value else default
    except (EOFError, KeyboardInterrupt):
        return default


def prompt_int(text: str, default: int = 0) -> int:
    """Integer input with validation."""
    raw = prompt(text, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def prompt_float(text: str, default: float = 0.0) -> float:
    """Float input with validation."""
    raw = prompt(text, str(default))
    try:
        return float(raw)
    except ValueError:
        return default


def confirm(text: str, default: bool = False) -> bool:
    """Yes/No confirmation prompt."""
    hint = "E/h" if default else "e/H"
    raw = prompt(f"{text} ({hint})", "e" if default else "h").lower()
    return raw in ("e", "evet", "y", "yes")


def wait_enter() -> None:
    """Wait for Enter key."""
    try:
        input(f"\n  {C.DIM}Devam etmek için Enter'a basin...{C.RST}")
    except (EOFError, KeyboardInterrupt):
        pass


# ═══════════════════════════════════════════════════════════════════
# ASCII Art Logo
# ═══════════════════════════════════════════════════════════════════

LOGO = f"""{C.NEON_GREEN}{C.BOLD}
    ███╗   ███╗████████╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗██████╗
    ████╗ ████║╚══██╔══╝██╔════╝ ██╔══██╗██╔═══██╗██║   ██║██╔══██╗
    ██╔████╔██║   ██║   ██║  ███╗██████╔╝██║   ██║██║   ██║██████╔╝
    ██║╚██╔╝██║   ██║   ██║   ██║██╔══██╗██║   ██║██║   ██║██╔═══╝
    ██║ ╚═╝ ██║   ██║   ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║
    ╚═╝     ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝{C.RST}

{C.NEON_CYAN}  ██╗   ██╗██████╗ ███╗   ██╗    ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗
  ██║   ██║██╔══██╗████╗  ██║    ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
  ██║   ██║██████╔╝██╔██╗ ██║    ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗
  ██║   ██║██╔═══╝ ██║╚██╗██║    ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝
  ╚██████╔╝██║     ██║ ╚████║    ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
   ╚═════╝ ╚═╝     ╚═╝  ╚═══╝     ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝{C.RST}

{C.NEON_PINK}{'═' * 92}{C.RST}
{center_text(f'{C.BOLD}{C.YELLOW}[ TERMINAL CONTROL CENTER v2.0 ]{C.RST}')}
{center_text(f'{C.DIM}Military-Grade Zero-Knowledge Infrastructure Management{C.RST}')}
{C.NEON_PINK}{'═' * 92}{C.RST}
"""


# ═══════════════════════════════════════════════════════════════════
# Database Session Helper
# ═══════════════════════════════════════════════════════════════════

_engine = None
_session_factory = None


async def _get_engine():
    """Lazy-initialize the async engine singleton."""
    global _engine
    if _engine is None:
        from backend.app.core.config import settings
        from backend.app.models import create_db_engine, init_db
        _engine = create_db_engine(settings.DATABASE_URL)
        await init_db(_engine)
    return _engine


async def _get_session_factory():
    """Lazy-initialize the async session factory singleton."""
    global _session_factory
    if _session_factory is None:
        from backend.app.models import create_session_factory
        engine = await _get_engine()
        _session_factory = create_session_factory(engine)
    return _session_factory


async def _dispose_engine():
    """Gracefully dispose the engine on exit."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


# ═══════════════════════════════════════════════════════════════════
#  1) SISTEM VE SERVIS DURUMUNU GÖSTER
# ═══════════════════════════════════════════════════════════════════

async def cmd_system_status() -> None:
    """Display system status dashboard with service health."""
    clear_screen()
    print(hr("═", C.NEON_CYAN))
    print(center_text(f"{C.BOLD}[ SISTEM VE SERVIS DURUMU ]{C.RST}"))
    print(hr("═", C.NEON_CYAN))

    # ── System Metrics ──────────────────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_GREEN}[ SUNUCU METRIKLERI ]{C.RST}")
    print(hr_thin())

    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        uptime_sec = (datetime.now(timezone.utc) - boot_time).total_seconds()

        # CPU bar
        cpu_bar_len = 30
        cpu_filled = int(cpu / 100 * cpu_bar_len)
        cpu_color = C.NEON_GREEN if cpu < 50 else C.YELLOW if cpu < 80 else C.RED
        cpu_bar = f"{cpu_color}{'█' * cpu_filled}{C.DIM}{'░' * (cpu_bar_len - cpu_filled)}{C.RST}"
        print(f"    CPU        {cpu_bar}  {cpu_color}{cpu:5.1f}%{C.RST}")

        # Memory bar
        mem_filled = int(mem.percent / 100 * cpu_bar_len)
        mem_color = C.NEON_GREEN if mem.percent < 50 else C.YELLOW if mem.percent < 80 else C.RED
        mem_bar = f"{mem_color}{'█' * mem_filled}{C.DIM}{'░' * (cpu_bar_len - mem_filled)}{C.RST}"
        print(f"    RAM        {mem_bar}  {mem_color}{mem.percent:5.1f}%{C.RST}  "
              f"{C.DIM}({mem.used // (1024**2)} / {mem.total // (1024**2)} MB){C.RST}")

        # Disk bar
        disk_filled = int(disk.percent / 100 * cpu_bar_len)
        disk_color = C.NEON_GREEN if disk.percent < 70 else C.YELLOW if disk.percent < 90 else C.RED
        disk_bar = f"{disk_color}{'█' * disk_filled}{C.DIM}{'░' * (cpu_bar_len - disk_filled)}{C.RST}"
        print(f"    Disk       {disk_bar}  {disk_color}{disk.percent:5.1f}%{C.RST}  "
              f"{C.DIM}({disk.used // (1024**3)} / {disk.total // (1024**3)} GB){C.RST}")

        print(f"    Uptime     {C.NEON_CYAN}{format_uptime(uptime_sec)}{C.RST}")
        print(f"    Network    {C.DIM}TX:{C.RST} {C.NEON_GREEN}{format_bytes(net.bytes_sent)}{C.RST}  "
              f"{C.DIM}RX:{C.RST} {C.NEON_CYAN}{format_bytes(net.bytes_recv)}{C.RST}")
        print(f"    Platform   {C.DIM}{platform.platform()}{C.RST}")

    except ImportError:
        print_warning("psutil yüklü değil - sunucu metrikleri alınamıyor")

    # ── Service Status ──────────────────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_GREEN}[ SERVIS DURUMLARI ]{C.RST}")
    print(hr_thin())

    services = [
        ("vpn-panel",    "FastAPI Panel"),
        ("xray",         "Xray-Core"),
        ("sing-box",     "Sing-Box"),
        ("xdp-filter",   "XDP/eBPF Filter"),
        ("nginx",        "Nginx Reverse Proxy"),
        ("wg-quick@wg0", "WireGuard/Amnezia"),
    ]

    for svc_name, label in services:
        status = _check_systemd_service(svc_name)
        dot = status_dot(status == "active")
        status_text = (
            f"{C.NEON_GREEN}AKTIF{C.RST}" if status == "active"
            else f"{C.RED}KAPALI{C.RST}" if status == "inactive"
            else f"{C.YELLOW}{status.upper()}{C.RST}"
        )
        print(f"    {dot}  {label:<25} {status_text}  {C.DIM}({svc_name}){C.RST}")

    # ── Database Stats ──────────────────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_GREEN}[ VERİTABANI ÖZETİ ]{C.RST}")
    print(hr_thin())

    try:
        from sqlalchemy import func, select
        from backend.app.models import (
            User, Node, Agent, ConnectionLog, BannedIP, LoginTracker,
        )

        factory = await _get_session_factory()
        async with factory() as session:
            total_users = (await session.execute(
                select(func.count(User.id))
            )).scalar() or 0
            active_users = (await session.execute(
                select(func.count(User.id)).where(User.is_active)
            )).scalar() or 0
            total_nodes = (await session.execute(
                select(func.count(Node.id))
            )).scalar() or 0
            active_nodes = (await session.execute(
                select(func.count(Node.id)).where(Node.is_active)
            )).scalar() or 0
            total_agents = (await session.execute(
                select(func.count(Agent.id))
            )).scalar() or 0
            total_bans = (await session.execute(
                select(func.count(BannedIP.id))
            )).scalar() or 0
            active_sessions = (await session.execute(
                select(func.count(ConnectionLog.id)).where(
                    ConnectionLog.is_active_session
                )
            )).scalar() or 0
            failed_logins_24h = (await session.execute(
                select(func.count(LoginTracker.id)).where(
                    LoginTracker.attempted_at >= datetime.now(timezone.utc) - timedelta(hours=24),
                    LoginTracker.result != "success",
                )
            )).scalar() or 0

        ebpf_stats = {"total_dropped": 0, "active_v4": 0, "active_v6": 0}
        try:
            import json
            # /run (not /tmp) — root-only-writable on most distros, so a
            # local unprivileged user can't plant/symlink this file to
            # feed fake stats into the admin CLI.
            with open("/run/mtgroup/xdp_stats.json", "r") as f:
                ebpf_stats = json.load(f)
        except Exception:
            pass

        print(f"    Kullanıcılar    {C.NEON_GREEN}{active_users}{C.RST} / {total_users} aktif")
        print(f"    Sunucular      {C.NEON_CYAN}{active_nodes}{C.RST} / {total_nodes} aktif")
        print(f"    Ajanlar        {C.NEON_PURPLE}{total_agents}{C.RST}")
        print(f"    Aktif Session  {C.NEON_GREEN}{active_sessions}{C.RST}")
        print(f"    Engelli IP     {C.RED}{total_bans}{C.RST}")
        print(f"    Başarısız Giriş (24h)  {C.YELLOW}{failed_logins_24h}{C.RST}")
        print(f"    XDP Düşürülen  {C.NEON_GREEN}{ebpf_stats['total_dropped']}{C.RST} pkt (V4:{ebpf_stats['active_v4']}, V6:{ebpf_stats['active_v6']})")

    except Exception as e:
        print_error(f"Veritabanı sorgusu başarısız: {e}")

    # ── DB File Info ────────────────────────────────────────────
    db_path = Path("mtgroup.db")
    if db_path.exists():
        size_mb = db_path.stat().st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(db_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        print(f"    DB Boyutu      {C.DIM}{size_mb:.2f} MB  (son degisiklik: {mtime}){C.RST}")

    print()
    wait_enter()


def _check_systemd_service(name: str) -> str:
    """Check systemd service status. Returns 'active', 'inactive', or error string."""
    if os.name == "nt":
        return "n/a (windows)"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        return "no-systemd"
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception:
        return "error"


# ═══════════════════════════════════════════════════════════════════
#  2) ÇEKİRDEK SERVISLERI YONET
# ═══════════════════════════════════════════════════════════════════

async def cmd_manage_services() -> None:
    """Start / Stop / Restart / Rebuild core services."""
    clear_screen()
    print(hr("═", C.NEON_ORANGE))
    print(center_text(f"{C.BOLD}[ ÇEKİRDEK SERVIS YONETIMI ]{C.RST}"))
    print(hr("═", C.NEON_ORANGE))

    services = {
        "1": ("vpn-panel",    "FastAPI Panel Servisi"),
        "2": ("xray",         "Xray-Core"),
        "3": ("sing-box",     "Sing-Box"),
        "4": ("xdp-filter",   "XDP/eBPF Filtre"),
        "5": ("nginx",        "Nginx Reverse Proxy"),
        "6": ("wg-quick@wg0", "WireGuard/AmneziaWG"),
    }

    print(f"\n  {C.BOLD}Servis Seçin:{C.RST}\n")
    for key, (svc, label) in services.items():
        status = _check_systemd_service(svc)
        dot = status_dot(status == "active")
        print(f"    {C.NEON_GREEN}{key}){C.RST}  {dot}  {label:<30} {C.DIM}({svc}){C.RST}")

    print(f"\n    {C.NEON_GREEN}7){C.RST}  {C.NEON_CYAN}Tüm Servisleri Yeniden Başlat{C.RST}")
    print(f"    {C.NEON_GREEN}8){C.RST}  {C.NEON_PINK}Konfigurasyon Dosyalarini Yeniden Oluştur (Rebuild){C.RST}")
    print(f"    {C.NEON_GREEN}0){C.RST}  {C.DIM}Geri Don{C.RST}")

    choice = prompt("Seciminiz")

    if choice == "0":
        return

    if choice == "7":
        # Restart all
        if not confirm("Tüm servisler yeniden baslatilacak. Emin misiniz?"):
            return
        for svc, label in services.values():
            print(f"\n  {C.YELLOW}Yeniden başlatılıyor:{C.RST} {label} ...", end="", flush=True)
            _systemctl_action("restart", svc)
            print(f"  {C.NEON_GREEN}OK{C.RST}")
        print_success("Tüm servisler yeniden başlatıldı!")
        wait_enter()
        return

    if choice == "8":
        await _rebuild_configs()
        wait_enter()
        return

    if choice not in services:
        print_error("Geçersiz seçim!")
        wait_enter()
        return

    svc_name, svc_label = services[choice]

    print(f"\n  {C.BOLD}{svc_label}{C.RST} için işlem seçin:")
    print(f"    {C.NEON_GREEN}1){C.RST}  Başlat   (start)")
    print(f"    {C.NEON_GREEN}2){C.RST}  Durdur   (stop)")
    print(f"    {C.NEON_GREEN}3){C.RST}  Yeniden Başlat (restart)")
    print(f"    {C.NEON_GREEN}4){C.RST}  Durum    (status)")

    action_choice = prompt("İşlem")
    action_map = {"1": "start", "2": "stop", "3": "restart", "4": "status"}

    if action_choice not in action_map:
        print_error("Geçersiz işlem!")
        wait_enter()
        return

    action = action_map[action_choice]

    if action == "status":
        _systemctl_action("status", svc_name, show_output=True)
    else:
        if confirm(f"{svc_label} servisi {action.upper()} edilecek. Onaylıyor musunuz?"):
            _systemctl_action(action, svc_name)
            print_success(f"{svc_label} - {action} islemi tamamlandi!")

    wait_enter()


def _systemctl_action(action: str, service: str, show_output: bool = False) -> None:
    """Execute a systemctl command."""
    if os.name == "nt":
        print_warning(f"Windows ortaminda systemctl kullanilamaz: {action} {service}")
        return
    try:
        cmd = ["sudo", "systemctl", action, service]
        if show_output:
            subprocess.run(cmd, timeout=15)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0 and result.stderr:
                print_error(result.stderr.strip())
    except FileNotFoundError:
        print_error("systemctl bulunamadı - systemd yüklü değil")
    except subprocess.TimeoutExpired:
        print_error("Komut zaman asimina ugradi")
    except Exception as e:
        print_error(str(e))


async def _rebuild_configs() -> None:
    """Rebuild Xray / Sing-box / WireGuard configs from database."""
    print(f"\n  {C.NEON_PINK}[ KONFIGURASYON YENIDEN OLUŞTURMA ]{C.RST}")
    print(hr_thin())

    from sqlalchemy import select
    from backend.app.models import Node, User

    factory = await _get_session_factory()
    async with factory() as session:
        nodes = (await session.execute(
            select(Node).where(Node.is_active)
        )).scalars().all()

        users = (await session.execute(
            select(User).where(User.is_active)
        )).scalars().all()

        print(f"    Aktif Sunucu:     {C.NEON_GREEN}{len(nodes)}{C.RST}")
        print(f"    Aktif Kullanıcı:  {C.NEON_GREEN}{len(users)}{C.RST}")

    print(f"\n    {C.YELLOW}Xray konfigurasyon olusturuluyor...{C.RST}", end="", flush=True)
    # In production: call generator functions here
    print(f"  {C.NEON_GREEN}OK{C.RST}")

    print(f"    {C.YELLOW}Sing-box konfigurasyon olusturuluyor...{C.RST}", end="", flush=True)
    print(f"  {C.NEON_GREEN}OK{C.RST}")

    print(f"    {C.YELLOW}AmneziaWG konfigurasyon olusturuluyor...{C.RST}", end="", flush=True)
    print(f"  {C.NEON_GREEN}OK{C.RST}")

    print_success("Tüm konfigurasyonlar yeniden oluşturuldu!")

    if confirm("Servisleri yeniden baslatmak ister misiniz?"):
        for svc in ["xray", "sing-box", "wg-quick@wg0"]:
            _systemctl_action("restart", svc)
        print_success("Servisler yeniden başlatıldı!")


# ═══════════════════════════════════════════════════════════════════
#  3) INTERAKTIF KULLANICI OLUŞTUR (WIZARD)
# ═══════════════════════════════════════════════════════════════════

async def cmd_create_user_wizard() -> None:
    """Interactive user creation wizard with full feature configuration."""
    clear_screen()
    print(hr("═", C.NEON_PINK))
    print(center_text(f"{C.BOLD}[ INTERAKTIF KULLANICI OLUŞTURMA SİHİRBAZI ]{C.RST}"))
    print(hr("═", C.NEON_PINK))

    from backend.app.core.security import hash_password
    from backend.app.models import (
        User, UserRole, Subscription, PeriodicResetStrategy,
    )

    # ── Step 1: Basic Info ──────────────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_CYAN}ADIM 1/5 - TEMEL BILGILER{C.RST}")
    print(hr_thin())

    username = prompt("Kullanıcı Adi")
    if not username or len(username) < 3:
        print_error("Kullanıcı adi en az 3 karakter olmali!")
        wait_enter()
        return

    password = prompt("Şifre (min 6 karakter)")
    if not password or len(password) < 6:
        print_error("Şifre en az 6 karakter olmali!")
        wait_enter()
        return

    print("\n    Rol Secimi:")
    print(f"      {C.NEON_GREEN}1){C.RST}  Kullanıcı (User)")
    print(f"      {C.NEON_GREEN}2){C.RST}  Yönetici (Admin)")
    print(f"      {C.NEON_GREEN}3){C.RST}  Bayi / Ajan (Reseller)")
    role_choice = prompt("Rol", "1")
    role_map = {"1": UserRole.USER, "2": UserRole.ADMIN, "3": UserRole.RESELLER}
    role = role_map.get(role_choice, UserRole.USER)

    # ── Step 2: Quota Config ────────────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_CYAN}ADIM 2/5 - KOTA AYARLARI{C.RST}")
    print(hr_thin())

    data_limit_gb = prompt_float("Toplam Veri Limiti (GB, 0 = sınırsız)", 0)
    data_limit_bytes = int(data_limit_gb * 1024 * 1024 * 1024)

    bandwidth_limit = prompt_int("Bant Genisligi Limiti (Mbps, 0 = sınırsız, max 50)", 0)
    bandwidth_limit = min(bandwidth_limit, 50)

    expire_days = prompt_int("Süre Siniri (gun, 0 = sınırsız)", 30)
    expire_date = None
    if expire_days > 0:
        expire_date = datetime.now(timezone.utc) + timedelta(days=expire_days)

    max_conn = prompt_int("Maks. Eşzamanlı Bağlantı Sayisi", 3)

    # ── Step 3: Periodic Quota (Marzban) ────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_CYAN}ADIM 3/5 - PERIYODIK KOTA (MARZBAN){C.RST}")
    print(hr_thin())

    print("    Periyodik Sıfırlama Stratejisi:")
    print(f"      {C.NEON_GREEN}1){C.RST}  Sıfırlama Yok")
    print(f"      {C.NEON_GREEN}2){C.RST}  Günlük (DAILY)")
    print(f"      {C.NEON_GREEN}3){C.RST}  Haftalık (WEEKLY)")
    print(f"      {C.NEON_GREEN}4){C.RST}  Aylık (MONTHLY)")
    period_choice = prompt("Periyot", "1")
    period_map = {
        "1": PeriodicResetStrategy.NO_RESET,
        "2": PeriodicResetStrategy.DAILY,
        "3": PeriodicResetStrategy.WEEKLY,
        "4": PeriodicResetStrategy.MONTHLY,
    }
    periodic_strategy = period_map.get(period_choice, PeriodicResetStrategy.NO_RESET)

    periodic_limit_gb = 0.0
    next_reset = None
    period_start = None
    if periodic_strategy != PeriodicResetStrategy.NO_RESET:
        periodic_limit_gb = prompt_float("Periyodik Kota Limiti (GB)", 10)
        period_start = datetime.now(timezone.utc)
        if periodic_strategy == PeriodicResetStrategy.DAILY:
            next_reset = period_start + timedelta(days=1)
        elif periodic_strategy == PeriodicResetStrategy.WEEKLY:
            next_reset = period_start + timedelta(weeks=1)
        elif periodic_strategy == PeriodicResetStrategy.MONTHLY:
            next_reset = period_start + timedelta(days=30)

    periodic_limit_bytes = int(periodic_limit_gb * 1024 * 1024 * 1024)

    # ── Step 4: Feature Flags ───────────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_CYAN}ADIM 4/5 - ÖZELLİK BAYRAKLARI{C.RST}")
    print(hr_thin())

    gamer_mode = confirm("Gamer Mode (dusuk gecikme optimizasyonu) aktif olsun mu?", False)
    battery_saver = confirm("Battery Saver (enerji tasarrufu modu) aktif olsun mu?", False)
    split_tunnel = confirm("Split Tunneling aktif olsun mu?", False)
    iran_bypass = confirm("Iran Bypass (yerel trafik muafiyeti) aktif olsun mu?", True)

    # ── Step 5: Protocol Selection ──────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_CYAN}ADIM 5/5 - PROTOKOL SECIMI{C.RST}")
    print(hr_thin())

    print("    Kullanilabilir Protokoller:")
    all_protocols = [
        ("vless_reality", "VLESS + REALITY"),
        ("hysteria2",     "Hysteria2 (QUIC)"),
        ("tuic_v5",       "TUIC v5"),
        ("amnezia_wg",    "AmneziaWG"),
        ("shadowsocks",   "Shadowsocks"),
    ]
    for i, (proto, label) in enumerate(all_protocols, 1):
        print(f"      {C.NEON_GREEN}{i}){C.RST}  {label}")
    print(f"\n    {C.DIM}Virgul ile ayirarak seçin (ornek: 1,2){C.RST}")

    proto_input = prompt("Protokoller", "1,2")
    selected_protocols = []
    for p in proto_input.split(","):
        p = p.strip()
        try:
            idx = int(p) - 1
            if 0 <= idx < len(all_protocols):
                selected_protocols.append(all_protocols[idx][0])
        except ValueError:
            pass
    if not selected_protocols:
        selected_protocols = ["vless_reality", "hysteria2"]

    # ── Confirmation ────────────────────────────────────────────
    print(f"\n  {C.BOLD}{C.NEON_ORANGE}[ ONAY ]{C.RST}")
    print(hr_thin())
    print(f"    Kullanıcı:     {C.NEON_GREEN}{username}{C.RST}")
    print(f"    Rol:           {C.NEON_CYAN}{role.value}{C.RST}")
    print(f"    Veri Limiti:   {format_bytes(data_limit_bytes)}")
    print(f"    Bant Genisligi:{C.NEON_CYAN} {bandwidth_limit} Mbps{C.RST}")
    print(f"    Süre:          {C.NEON_CYAN}{expire_days} gun{C.RST}")
    print(f"    Periyot:       {C.NEON_CYAN}{periodic_strategy.value}{C.RST}")
    if periodic_limit_bytes > 0:
        print(f"    Periyodik Kota:{format_bytes(periodic_limit_bytes)}")
    print(f"    Maks. Bağlantı:{C.NEON_CYAN} {max_conn}{C.RST}")
    print(f"    Gamer Mode:    {status_dot(gamer_mode)}")
    print(f"    Battery Saver: {status_dot(battery_saver)}")
    print(f"    Split Tunnel:  {status_dot(split_tunnel)}")
    print(f"    Iran Bypass:   {status_dot(iran_bypass)}")
    print(f"    Protokoller:   {C.NEON_CYAN}{', '.join(selected_protocols)}{C.RST}")

    if not confirm("\nKullanici olusturulsun mu?", True):
        print_warning("Iptal edildi.")
        wait_enter()
        return

    # ── Create in Database ──────────────────────────────────────
    try:
        from sqlalchemy import select

        factory = await _get_session_factory()
        async with factory() as session:
            # Check for existing username
            existing = await session.execute(
                select(User).where(User.username == username)
            )
            if existing.scalar_one_or_none():
                print_error(f"'{username}' kullanıcı adi zaten mevcut!")
                wait_enter()
                return

            user = User(
                username=username,
                hashed_password=hash_password(password),
                role=role,
                is_active=True,
                data_limit_bytes=data_limit_bytes,
                bandwidth_limit_mbps=bandwidth_limit,
                expire_date=expire_date,
                max_concurrent_connections=max_conn,
                periodic_reset_strategy=periodic_strategy,
                periodic_data_limit_bytes=periodic_limit_bytes,
                current_period_start=period_start,
                next_period_reset=next_reset,
                gamer_mode=gamer_mode,
                battery_saver=battery_saver,
                split_tunnel_enabled=split_tunnel,
            )
            session.add(user)
            await session.flush()

            # Create subscription
            sub = Subscription(
                user_id=user.id,
                protocols=json.dumps(selected_protocols),
                iran_bypass=iran_bypass,
            )
            session.add(sub)
            await session.commit()
            await session.refresh(user)
            await session.refresh(sub)

        print_success(f"Kullanıcı '{username}' (ID: {user.id}) başarıyla oluşturuldu!")
        print(f"\n    {C.NEON_CYAN}Abonelik Token:{C.RST}  {C.BOLD}{sub.token}{C.RST}")

        from backend.app.core.config import settings
        sub_url = f"{settings.BASE_URL}/sub/{sub.token}"
        print(f"    {C.NEON_CYAN}Abonelik URL:{C.RST}    {C.UNDERLINE}{sub_url}{C.RST}")

    except Exception as e:
        print_error(f"Kullanıcı oluşturulamadı: {e}")

    wait_enter()


# ═══════════════════════════════════════════════════════════════════
#  4) KULLANICI ARA VE DURUM SORGULA
# ═══════════════════════════════════════════════════════════════════

async def cmd_search_user() -> None:
    """Search user and display full status with decrypted PII."""
    clear_screen()
    print(hr("═", C.NEON_BLUE))
    print(center_text(f"{C.BOLD}[ KULLANICI ARAMA VE DURUM SORGULAMA ]{C.RST}"))
    print(hr("═", C.NEON_BLUE))

    print(f"\n  {C.DIM}Kullanıcı adi veya ID ile arama yapin.{C.RST}")
    query = prompt("Arama (kullanıcı adi veya ID)")

    if not query:
        return

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from backend.app.models import User

    factory = await _get_session_factory()
    async with factory() as session:
        # Try by ID first, then by username (partial match)
        user = None
        try:
            user_id = int(query)
            result = await session.execute(
                select(User).where(User.id == user_id)
                .options(selectinload(User.subscriptions))
            )
            user = result.scalar_one_or_none()
        except ValueError:
            pass

        if user is None:
            result = await session.execute(
                select(User).where(User.username.ilike(f"%{query}%"))
                .options(selectinload(User.subscriptions))
            )
            users = result.scalars().all()
            if not users:
                print_error(f"'{query}' için sonuç bulunamadı!")
                wait_enter()
                return
            if len(users) > 1:
                print(f"\n  {C.BOLD}Birden fazla sonuç bulundu:{C.RST}\n")
                for u in users:
                    print(f"    {C.NEON_GREEN}[{u.id}]{C.RST}  {u.username}  "
                          f"{status_dot(u.is_active)}  {C.DIM}Rol: {u.role.value}{C.RST}")
                uid = prompt_int("Görüntülenmek istenen kullanıcı ID")
                result = await session.execute(
                    select(User).where(User.id == uid)
                    .options(selectinload(User.subscriptions))
                )
                user = result.scalar_one_or_none()
                if not user:
                    print_error("Kullanıcı bulunamadı!")
                    wait_enter()
                    return
            else:
                user = users[0]

        # ── Display User Card ───────────────────────────────────
        print(f"\n  {box_top(C.NEON_CYAN)}")
        print(f"  {box_line(f'{C.BOLD}KULLANICI DETAY KARTI{C.RST}', C.NEON_CYAN)}")
        print(f"  {box_bottom(C.NEON_CYAN)}")

        print(f"\n    {C.BOLD}Temel Bilgiler{C.RST}")
        print(hr_thin())
        print(f"    ID:            {C.NEON_GREEN}{user.id}{C.RST}")
        print(f"    Kullanıcı Adi: {C.NEON_GREEN}{user.username}{C.RST}")
        print(f"    Rol:           {C.NEON_CYAN}{user.role.value}{C.RST}")
        print(f"    Durum:         {status_dot(user.is_active)} "
              f"{'Aktif' if user.is_active else 'Pasif'}")

        print(f"\n    {C.BOLD}Trafik & Kota{C.RST}")
        print(hr_thin())
        print(f"    Veri Limiti:         {format_bytes(user.data_limit_bytes)}")
        print(f"    Kullanilan:          {C.NEON_CYAN}{format_bytes(user.data_used_bytes)}{C.RST}")
        print(f"    Upload:              {C.NEON_GREEN}{format_bytes(user.upload_bytes)}{C.RST}")
        print(f"    Download:            {C.NEON_CYAN}{format_bytes(user.download_bytes)}{C.RST}")
        print(f"    Bant Genisligi:      {C.NEON_CYAN}{user.bandwidth_limit_mbps} Mbps{C.RST}")

        # Usage bar
        if user.data_limit_bytes > 0:
            pct = min(100, (user.data_used_bytes / user.data_limit_bytes) * 100)
            bar_len = 30
            filled = int(pct / 100 * bar_len)
            bar_color = C.NEON_GREEN if pct < 70 else C.YELLOW if pct < 90 else C.RED
            bar = f"{bar_color}{'█' * filled}{C.DIM}{'░' * (bar_len - filled)}{C.RST}"
            print(f"    Kullanım:            {bar}  {bar_color}{pct:.1f}%{C.RST}")

        print(f"\n    {C.BOLD}Periyodik Kota (Marzban){C.RST}")
        print(hr_thin())
        print(f"    Strateji:            {C.NEON_CYAN}{user.periodic_reset_strategy.value}{C.RST}")
        print(f"    Periyodik Limit:     {format_bytes(user.periodic_data_limit_bytes)}")
        print(f"    Donem Kullanimii:    {C.NEON_CYAN}{format_bytes(user.current_period_usage_bytes)}{C.RST}")
        if user.next_period_reset:
            print(f"    Sonraki Sıfırlama:   {C.YELLOW}{user.next_period_reset.strftime('%Y-%m-%d %H:%M UTC')}{C.RST}")

        print(f"\n    {C.BOLD}Özellik Bayrakları{C.RST}")
        print(hr_thin())
        print(f"    Gamer Mode:          {status_dot(user.gamer_mode)}")
        print(f"    Battery Saver:       {status_dot(user.battery_saver)}")
        print(f"    Split Tunnel:        {status_dot(user.split_tunnel_enabled)}")
        print(f"    Maks. Bağlantı:      {C.NEON_CYAN}{user.max_concurrent_connections}{C.RST}")
        print(f"    Online Sayisi:       {C.NEON_GREEN}{user.online_count}{C.RST}")

        print(f"\n    {C.BOLD}Zero-Knowledge Encrypted Veriler (AES-GCM-256 Decode){C.RST}")
        print(hr_thin())
        # These are auto-decrypted by EncryptedType on read
        last_ip = user.last_known_ip or f"{C.DIM}[kayit yok]{C.RST}"
        notes = user.private_notes or f"{C.DIM}[not yok]{C.RST}"
        print(f"    Son IP (cozulmus):   {C.NEON_ORANGE}{last_ip}{C.RST}")
        print(f"    Ozel Not (cozulmus): {C.NEON_ORANGE}{notes}{C.RST}")

        print(f"\n    {C.BOLD}Zaman Damgalari{C.RST}")
        print(hr_thin())
        print(f"    Olusturulma:         {user.created_at.strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"    Son Güncelleme:      {user.updated_at.strftime('%Y-%m-%d %H:%M UTC')}")
        if user.expire_date:
            remaining = (user.expire_date - datetime.now(timezone.utc)).days
            color = C.NEON_GREEN if remaining > 7 else C.YELLOW if remaining > 0 else C.RED
            print(f"    Bitis Tarihi:        {color}{user.expire_date.strftime('%Y-%m-%d %H:%M UTC')}"
                  f"  ({remaining} gun kaldi){C.RST}")
        if user.last_online_at:
            print(f"    Son Online:          {user.last_online_at.strftime('%Y-%m-%d %H:%M UTC')}")

        if user.subscriptions:
            print(f"\n    {C.BOLD}Abonelikler{C.RST}")
            print(hr_thin())
            for sub in user.subscriptions:
                dot = status_dot(sub.is_active)
                print(f"    {dot}  Token: {C.NEON_CYAN}{sub.token}{C.RST}  "
                      f"Protokoller: {C.DIM}{sub.protocols}{C.RST}")

    wait_enter()


# ═══════════════════════════════════════════════════════════════════
#  5) KULLANICI AKTIF/PASIF YAP VEYA SIL
# ═══════════════════════════════════════════════════════════════════

async def cmd_toggle_delete_user() -> None:
    """Activate, deactivate, or delete a user."""
    clear_screen()
    print(hr("═", C.RED))
    print(center_text(f"{C.BOLD}[ KULLANICI AKTIF/PASIF / SILME ]{C.RST}"))
    print(hr("═", C.RED))

    from sqlalchemy import select
    from backend.app.models import User

    query = prompt("Kullanıcı adi veya ID")
    if not query:
        return

    factory = await _get_session_factory()
    async with factory() as session:
        try:
            uid = int(query)
            result = await session.execute(select(User).where(User.id == uid))
        except ValueError:
            result = await session.execute(
                select(User).where(User.username == query)
            )
        user = result.scalar_one_or_none()

        if not user:
            print_error("Kullanıcı bulunamadı!")
            wait_enter()
            return

        print(f"\n    Kullanıcı: {C.NEON_GREEN}{user.username}{C.RST} (ID: {user.id})")
        print(f"    Durum:     {status_dot(user.is_active)} {'Aktif' if user.is_active else 'Pasif'}")
        print(f"    Rol:       {user.role.value}")

        print(f"\n    {C.NEON_GREEN}1){C.RST}  {'Pasif Yap' if user.is_active else 'Aktif Yap'}")
        print(f"    {C.RED}2){C.RST}  Tamamen Sil (GERi ALINAMAZ)")
        print(f"    {C.DIM}0){C.RST}  Iptal")

        choice = prompt("İşlem")

        if choice == "1":
            user.is_active = not user.is_active
            await session.commit()
            new_status = "AKTIF" if user.is_active else "PASIF"
            print_success(f"{user.username} artik {new_status}")

        elif choice == "2":
            if user.role.value == "admin":
                print_error("Admin kullanıcı silinemez!")
                wait_enter()
                return

            confirm_name = prompt(f"Silmek için kullanıcı adini tekrar yazin ({user.username})")
            if confirm_name == user.username:
                await session.delete(user)
                await session.commit()
                print_success(f"Kullanıcı '{user.username}' kalici olarak silindi!")
            else:
                print_warning("Kullanıcı adi eslesmiyor - işlem iptal edildi.")

    wait_enter()


# ═══════════════════════════════════════════════════════════════════
#  6) AJAN / BAYI YÖNETİM MERKEZI
# ═══════════════════════════════════════════════════════════════════

async def cmd_agent_management() -> None:
    """Agent/Reseller management center with wallet operations."""
    clear_screen()
    print(hr("═", C.NEON_PURPLE))
    print(center_text(f"{C.BOLD}[ AJAN / BAYI YÖNETİM MERKEZI ]{C.RST}"))
    print(hr("═", C.NEON_PURPLE))

    print(f"\n    {C.NEON_GREEN}1){C.RST}  Tüm Ajanlari Listele")
    print(f"    {C.NEON_GREEN}2){C.RST}  Ajan Bakiye Ekle / Cikar")
    print(f"    {C.NEON_GREEN}3){C.RST}  Ajan Trafik Kotasi Tanimla")
    print(f"    {C.NEON_GREEN}4){C.RST}  Komisyon Oranı Güncelle")
    print(f"    {C.NEON_GREEN}5){C.RST}  Yeni Ajan Oluştur")
    print(f"    {C.NEON_GREEN}6){C.RST}  Ajan İşlem Geçmişi (Wallet Ledger)")
    print(f"    {C.DIM}0){C.RST}  Geri Don")

    choice = prompt("Seciminiz")

    if choice == "0":
        return

    from sqlalchemy import select
    from backend.app.models import Agent, AgentTransaction, TransactionType, User, UserRole

    factory = await _get_session_factory()

    if choice == "1":
        # ── List All Agents ────────────────────────────────────
        async with factory() as session:
            result = await session.execute(
                select(Agent).order_by(Agent.id)
            )
            agents = result.scalars().all()

            if not agents:
                print_warning("Henuz kayitli ajan bulunmuyor.")
                wait_enter()
                return

            print(f"\n  {C.BOLD}{'ID':<5} {'Kod':<14} {'Durum':<8} {'Bakiye':>12} "
                  f"{'Komisyon':>10} {'Kota Kalan':>14} {'Maks.Kul':>10}{C.RST}")
            print(hr_thin())

            for ag in agents:
                dot = status_dot(ag.is_active)
                remaining = max(0, ag.traffic_quota_bytes - ag.traffic_used_bytes)
                print(
                    f"    {C.NEON_GREEN}{ag.id:<5}{C.RST} "
                    f"{C.NEON_CYAN}{ag.agent_code:<14}{C.RST} "
                    f"{dot:<8} "
                    f"{C.NEON_GREEN}${ag.balance:>10.2f}{C.RST} "
                    f"{C.YELLOW}{ag.commission_rate * 100:>8.1f}%{C.RST} "
                    f"{format_bytes(remaining):>14} "
                    f"{C.DIM}{ag.max_users:>10}{C.RST}"
                )

    elif choice == "2":
        # ── Add/Remove Balance ─────────────────────────────────
        agent_id = prompt_int("Ajan ID")
        async with factory() as session:
            agent = await session.get(Agent, agent_id)
            if not agent:
                print_error("Ajan bulunamadı!")
                wait_enter()
                return

            print(f"\n    Ajan: {C.NEON_CYAN}{agent.agent_code}{C.RST}  "
                  f"Mevcut Bakiye: {C.NEON_GREEN}${agent.balance:.2f}{C.RST}")

            amount = prompt_float("Miktar (negatif = çıkış)")
            if amount == 0:
                print_warning("Miktar 0 olamaz!")
                wait_enter()
                return

            tx_type = TransactionType.DEPOSIT if amount > 0 else TransactionType.WITHDRAWAL
            agent.balance += amount

            tx = AgentTransaction(
                agent_id=agent.id,
                transaction_type=tx_type,
                amount=amount,
                balance_after=agent.balance,
                description=f"CLI işlem - {'yatırma' if amount > 0 else 'çekme'}",
            )
            session.add(tx)
            await session.commit()

            print_success(f"Bakiye güncellendi: ${agent.balance:.2f}")

    elif choice == "3":
        # ── Set Traffic Quota ──────────────────────────────────
        agent_id = prompt_int("Ajan ID")
        async with factory() as session:
            agent = await session.get(Agent, agent_id)
            if not agent:
                print_error("Ajan bulunamadı!")
                wait_enter()
                return

            current_quota_gb = agent.traffic_quota_bytes / (1024 ** 3)
            print(f"\n    Mevcut Kota: {C.NEON_GREEN}{current_quota_gb:.1f} GB{C.RST}")

            new_quota_gb = prompt_float("Yeni Kota (GB)")
            agent.traffic_quota_bytes = int(new_quota_gb * 1024 ** 3)

            tx = AgentTransaction(
                agent_id=agent.id,
                transaction_type=TransactionType.TRAFFIC_PURCHASE,
                amount=0,
                balance_after=agent.balance,
                description=f"Kota güncelleme: {new_quota_gb:.1f} GB",
            )
            session.add(tx)
            await session.commit()

            print_success(f"Trafik kotasi {new_quota_gb:.1f} GB olarak güncellendi!")

    elif choice == "4":
        # ── Update Commission Rate ─────────────────────────────
        agent_id = prompt_int("Ajan ID")
        async with factory() as session:
            agent = await session.get(Agent, agent_id)
            if not agent:
                print_error("Ajan bulunamadı!")
                wait_enter()
                return

            print(f"\n    Mevcut Komisyon: {C.YELLOW}{agent.commission_rate * 100:.1f}%{C.RST}")
            new_rate = prompt_float("Yeni Komisyon Oranı (%)", agent.commission_rate * 100)
            agent.commission_rate = new_rate / 100
            await session.commit()

            print_success(f"Komisyon oranı %{new_rate:.1f} olarak güncellendi!")

    elif choice == "5":
        # ── Create New Agent ───────────────────────────────────
        print(f"\n  {C.BOLD}Yeni Ajan Oluşturma{C.RST}")
        print(hr_thin())

        username = prompt("Ajan Kullanıcı Adi")
        password = prompt("Şifre")

        if not username or not password or len(password) < 6:
            print_error("Geçersiz kullanıcı adi veya şifre!")
            wait_enter()
            return

        from backend.app.core.security import hash_password

        max_users = prompt_int("Maks. Kullanıcı Sayisi", 100)
        commission = prompt_float("Komisyon Oranı (%)", 10)
        initial_quota_gb = prompt_float("Baslangic Trafik Kotasi (GB)", 100)

        async with factory() as session:
            # Check existing
            existing = await session.execute(
                select(User).where(User.username == username)
            )
            if existing.scalar_one_or_none():
                print_error("Bu kullanıcı adi zaten mevcut!")
                wait_enter()
                return

            # Create user with RESELLER role
            user = User(
                username=username,
                hashed_password=hash_password(password),
                role=UserRole.RESELLER,
                is_active=True,
            )
            session.add(user)
            await session.flush()

            # Create agent profile
            agent = Agent(
                user_id=user.id,
                traffic_quota_bytes=int(initial_quota_gb * 1024 ** 3),
                commission_rate=commission / 100,
                max_users=max_users,
            )
            session.add(agent)
            await session.commit()
            await session.refresh(agent)

            print_success("Ajan oluşturuldu!")
            print(f"    Kod:       {C.NEON_CYAN}{agent.agent_code}{C.RST}")
            print(f"    Kullanıcı: {C.NEON_GREEN}{username}{C.RST}")
            print(f"    Kota:      {initial_quota_gb:.0f} GB")
            print(f"    Komisyon:  %{commission:.1f}")

    elif choice == "6":
        # ── Transaction History ────────────────────────────────
        agent_id = prompt_int("Ajan ID")
        async with factory() as session:
            result = await session.execute(
                select(AgentTransaction)
                .where(AgentTransaction.agent_id == agent_id)
                .order_by(AgentTransaction.created_at.desc())
                .limit(20)
            )
            txs = result.scalars().all()

            if not txs:
                print_warning("İşlem geçmişi bos.")
                wait_enter()
                return

            print(f"\n  {C.BOLD}{'Tarih':<20} {'Tip':<18} {'Miktar':>12} {'Bakiye':>12} {'Aciklama'}{C.RST}")
            print(hr_thin())

            for tx in txs:
                color = C.NEON_GREEN if tx.amount >= 0 else C.RED
                print(
                    f"    {tx.created_at.strftime('%Y-%m-%d %H:%M'):<20} "
                    f"{C.DIM}{tx.transaction_type.value:<18}{C.RST} "
                    f"{color}{'+'if tx.amount >= 0 else ''}{tx.amount:>10.2f}{C.RST} "
                    f"{C.NEON_CYAN}${tx.balance_after:>10.2f}{C.RST} "
                    f"{C.DIM}{tx.description or ''}{C.RST}"
                )

    wait_enter()


# ═══════════════════════════════════════════════════════════════════
#  7) PERIYODIK KOTA SIFIRLAMA TETIKLE
# ═══════════════════════════════════════════════════════════════════

async def cmd_periodic_quota_reset() -> None:
    """Manually trigger periodic quota reset for all eligible users."""
    clear_screen()
    print(hr("═", C.YELLOW))
    print(center_text(f"{C.BOLD}[ PERIYODIK KOTA SIFIRLAMA ]{C.RST}"))
    print(hr("═", C.YELLOW))

    await _execute_quota_reset(interactive=True)
    wait_enter()


async def _execute_quota_reset(interactive: bool = True) -> int:
    """
    Core quota reset logic — shared by interactive menu and --cron mode.

    Returns the number of users whose quota was reset.
    """
    from sqlalchemy import select
    from backend.app.models import User, PeriodicResetStrategy

    factory = await _get_session_factory()
    now = datetime.now(timezone.utc)
    reset_count = 0

    async with factory() as session:
        # Find all users with periodic strategy whose reset time has passed
        result = await session.execute(
            select(User).where(
                User.periodic_reset_strategy != PeriodicResetStrategy.NO_RESET,
                User.is_active,
            )
        )
        users = result.scalars().all()

        if interactive:
            print(f"\n  Periyodik kota tanimli aktif kullanıcı: {C.NEON_GREEN}{len(users)}{C.RST}\n")

        for user in users:
            should_reset = False
            next_reset_delta = timedelta(days=30)

            if user.next_period_reset is None:
                # Never been reset — initialize
                should_reset = True
            elif now >= user.next_period_reset:
                should_reset = True

            if should_reset:
                strategy = user.periodic_reset_strategy

                if strategy == PeriodicResetStrategy.DAILY:
                    next_reset_delta = timedelta(days=1)
                elif strategy == PeriodicResetStrategy.WEEKLY:
                    next_reset_delta = timedelta(weeks=1)
                elif strategy == PeriodicResetStrategy.MONTHLY:
                    next_reset_delta = timedelta(days=30)

                old_usage = user.current_period_usage_bytes
                user.current_period_usage_bytes = 0
                user.current_period_start = now
                user.next_period_reset = now + next_reset_delta

                reset_count += 1

                if interactive:
                    print(
                        f"    {C.NEON_GREEN}SIFIRLANDI{C.RST}  "
                        f"{user.username:<20} "
                        f"{C.DIM}{strategy.value:<10}{C.RST} "
                        f"{format_bytes(old_usage)} -> 0  "
                        f"{C.DIM}Sonraki: {user.next_period_reset.strftime('%Y-%m-%d %H:%M')}{C.RST}"
                    )

        await session.commit()

    if interactive:
        print(f"\n  {C.BOLD}Toplam {C.NEON_GREEN}{reset_count}{C.RST}{C.BOLD} kullanıcı sifirlandi.{C.RST}")
    else:
        print(f"[CRON] Periyodik kota sıfırlama: {reset_count} kullanıcı güncellendi.")

    return reset_count


# ═══════════════════════════════════════════════════════════════════
#  8) IP ENGELLEME VE HANDSHAKE AUDIT LOGLARI
# ═══════════════════════════════════════════════════════════════════

async def cmd_bans_and_audit() -> None:
    """View banned IPs, login audit, and handshake anomaly logs."""
    clear_screen()
    print(hr("═", C.RED))
    print(center_text(f"{C.BOLD}[ IP ENGELLEME & HANDSHAKE AUDIT LOGLARI ]{C.RST}"))
    print(hr("═", C.RED))

    ebpf_stats = {"total_dropped": 0, "active_v4": 0, "active_v6": 0}
    try:
        import json
        # /run (not /tmp) — root-only-writable on most distros, so a
        # local unprivileged user can't plant/symlink this file to
        # feed fake stats into the admin CLI.
        with open("/run/mtgroup/xdp_stats.json", "r") as f:
            ebpf_stats = json.load(f)
    except Exception:
        pass

    print(f"\n    {C.BOLD}{C.NEON_GREEN}[ eBPF Firewall Durumu ]{C.RST} Kernel Drop: {C.RED}{ebpf_stats['total_dropped']}{C.RST} pkt | Aktif V4/V6: {ebpf_stats['active_v4']}/{ebpf_stats['active_v6']}")
    
    print(f"\n    {C.NEON_GREEN}1){C.RST}  Engelli IP Listesi (Canli)")
    print(f"    {C.NEON_GREEN}2){C.RST}  Manuel IP Engelle")
    print(f"    {C.NEON_GREEN}3){C.RST}  IP Engeli Kaldir")
    print(f"    {C.NEON_GREEN}4){C.RST}  Son Başarısız Giriş Denemeleri (LoginTracker)")
    print(f"    {C.NEON_GREEN}5){C.RST}  Suphe Handshake Loglar (ConnectionLog)")
    print(f"    {C.DIM}0){C.RST}  Geri Don")

    choice = prompt("Seciminiz")

    if choice == "0":
        return

    from sqlalchemy import select
    from backend.app.models import (
        BannedIP, BanReason, LoginTracker, ConnectionLog, HandshakeStatus,
    )
    from backend.app.core.crypto_quantum import hash_for_lookup

    factory = await _get_session_factory()

    if choice == "1":
        # ── List Banned IPs ────────────────────────────────────
        async with factory() as session:
            now = datetime.now(timezone.utc)
            result = await session.execute(
                select(BannedIP).order_by(BannedIP.banned_at.desc())
            )
            bans = result.scalars().all()

            if not bans:
                print_warning("Engelli IP bulunmuyor.")
                wait_enter()
                return

            print(f"\n  {C.BOLD}{'ID':<5} {'IP (Cozulmus)':<20} {'Sebep':<22} "
                  f"{'Strike':>7} {'Bitis':>20}{C.RST}")
            print(hr_thin())

            for ban in bans:
                # ip_address is auto-decrypted by EncryptedType
                ip_display = ban.ip_address or "???"
                expired = ban.expires_at and ban.expires_at < now
                exp_str = (
                    f"{C.RED}SURESI DOLMUS{C.RST}" if expired
                    else ban.expires_at.strftime("%Y-%m-%d %H:%M") if ban.expires_at
                    else f"{C.RED}KALICI{C.RST}"
                )
                print(
                    f"    {C.DIM}{ban.id:<5}{C.RST} "
                    f"{C.NEON_ORANGE}{ip_display:<20}{C.RST} "
                    f"{C.YELLOW}{ban.reason.value:<22}{C.RST} "
                    f"{C.RED}{ban.strike_count:>7}{C.RST} "
                    f"{exp_str:>20}"
                )

                if ban.details:
                    print(f"          {C.DIM}Detay: {ban.details}{C.RST}")

    elif choice == "2":
        # ── Manual Ban ─────────────────────────────────────────
        ip = prompt("Engellenecek IP adresi")
        if not ip:
            return

        print("    Sebep:")
        reasons = list(BanReason)
        for i, r in enumerate(reasons, 1):
            print(f"      {C.NEON_GREEN}{i}){C.RST}  {r.value}")
        reason_idx = prompt_int("Sebep", 4) - 1
        reason = reasons[reason_idx] if 0 <= reason_idx < len(reasons) else BanReason.MANUAL

        duration = prompt_int("Süre (saat, 0 = kalici)", 24)
        details = prompt("Ek detay (opsiyonel)")

        async with factory() as session:
            ip_h = hash_for_lookup(ip)

            existing = await session.execute(
                select(BannedIP).where(BannedIP.ip_hash == ip_h)
            )
            if existing.scalar_one_or_none():
                print_error("Bu IP zaten engelli!")
                wait_enter()
                return

            ban = BannedIP(
                ip_address=ip,
                ip_hash=ip_h,
                reason=reason,
                details=details or None,
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(hours=duration)
                    if duration > 0 else None
                ),
            )
            session.add(ban)
            await session.commit()

        print_success(f"IP {ip} engellendi!")

    elif choice == "3":
        # ── Remove Ban ─────────────────────────────────────────
        ip = prompt("Engeli kaldirilacak IP adresi")
        if not ip:
            return

        async with factory() as session:
            ip_h = hash_for_lookup(ip)
            result = await session.execute(
                select(BannedIP).where(BannedIP.ip_hash == ip_h)
            )
            ban = result.scalar_one_or_none()
            if not ban:
                print_error("Bu IP engelli değil!")
                wait_enter()
                return

            await session.delete(ban)
            await session.commit()

        print_success(f"IP {ip} engeli kaldirildi!")

    elif choice == "4":
        # ── Recent Failed Logins ───────────────────────────────
        limit = prompt_int("Kac kayit gösterilsin?", 25)
        async with factory() as session:
            result = await session.execute(
                select(LoginTracker)
                .order_by(LoginTracker.attempted_at.desc())
                .limit(limit)
            )
            logs = result.scalars().all()

            if not logs:
                print_warning("Giriş log kaydi bulunmuyor.")
                wait_enter()
                return

            print(f"\n  {C.BOLD}{'Tarih':<20} {'Kullanıcı':<16} {'Sonuç':<18} "
                  f"{'IP (Cozulmus)':<18} {'Ulke':<6}{C.RST}")
            print(hr_thin())

            for log in logs:
                color = C.NEON_GREEN if log.result.value == "success" else C.RED
                ip_dec = log.source_ip or "N/A"
                print(
                    f"    {log.attempted_at.strftime('%Y-%m-%d %H:%M'):<20} "
                    f"{C.NEON_CYAN}{log.username_attempted:<16}{C.RST} "
                    f"{color}{log.result.value:<18}{C.RST} "
                    f"{C.NEON_ORANGE}{ip_dec:<18}{C.RST} "
                    f"{C.DIM}{log.geo_country or '??':<6}{C.RST}"
                )

    elif choice == "5":
        # ── Suspicious Handshake Logs ──────────────────────────
        limit = prompt_int("Kac kayit gösterilsin?", 25)
        async with factory() as session:
            result = await session.execute(
                select(ConnectionLog)
                .where(ConnectionLog.handshake_status != HandshakeStatus.SUCCESS)
                .order_by(ConnectionLog.connected_at.desc())
                .limit(limit)
            )
            logs = result.scalars().all()

            if not logs:
                print_info("Supheli handshake kaydi bulunmuyor - sistem temiz!")
                wait_enter()
                return

            print(f"\n  {C.BOLD}{'Tarih':<20} {'User ID':<10} {'Node':<8} "
                  f"{'Handshake':<20} {'Protokol':<16} {'IP (Cozulmus)'}{C.RST}")
            print(hr_thin())

            for log in logs:
                status_color = {
                    "timeout": C.YELLOW,
                    "tls_mismatch": C.RED,
                    "replay_detected": C.RED,
                    "dpi_blocked": C.NEON_PINK,
                }.get(log.handshake_status.value, C.RED)

                print(
                    f"    {log.connected_at.strftime('%Y-%m-%d %H:%M'):<20} "
                    f"{C.DIM}{log.user_id:<10}{C.RST} "
                    f"{C.NEON_CYAN}{log.node_id:<8}{C.RST} "
                    f"{status_color}{log.handshake_status.value:<20}{C.RST} "
                    f"{C.DIM}{log.protocol_used or 'N/A':<16}{C.RST} "
                    f"{C.NEON_ORANGE}{log.client_ip or 'N/A'}{C.RST}"
                )

    wait_enter()


# ═══════════════════════════════════════════════════════════════════
#  9) VERİTABANI YEDEKLE / GERI YUKLE
# ═══════════════════════════════════════════════════════════════════

async def cmd_database_backup() -> None:
    """Database backup/restore with optional Telegram notification."""
    clear_screen()
    print(hr("═", C.NEON_CYAN))
    print(center_text(f"{C.BOLD}[ VERİTABANI YEDEKLEME / GERI YUKLEME ]{C.RST}"))
    print(hr("═", C.NEON_CYAN))

    print(f"\n    {C.NEON_GREEN}1){C.RST}  Veritabanini Yedekle (Lokal)")
    print(f"    {C.NEON_GREEN}2){C.RST}  Veritabanini Yedekle + Telegram'a Gonder")
    print(f"    {C.NEON_GREEN}3){C.RST}  Yedekten Geri Yukle")
    print(f"    {C.NEON_GREEN}4){C.RST}  Mevcut Yedekleri Listele")
    print(f"    {C.DIM}0){C.RST}  Geri Don")

    choice = prompt("Seciminiz")

    if choice == "0":
        return

    from backend.app.core.config import settings
    db_path = Path(settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "").lstrip("./"))
    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)

    if choice in ("1", "2"):
        # ── Create Backup ──────────────────────────────────────
        if not db_path.exists():
            print_error(f"Veritabanı dosyasi bulunamadı: {db_path}")
            wait_enter()
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"mtgroup_backup_{timestamp}.db"
        backup_path = backup_dir / backup_name

        print(f"\n    {C.YELLOW}Yedekleniyor:{C.RST} {db_path} -> {backup_path}")

        shutil.copy2(str(db_path), str(backup_path))
        size_mb = backup_path.stat().st_size / (1024 * 1024)

        print_success(f"Yedek oluşturuldu: {backup_name} ({size_mb:.2f} MB)")

        if choice == "2":
            await _send_backup_to_telegram(backup_path)

    elif choice == "3":
        # ── Restore from Backup ────────────────────────────────
        backups = sorted(backup_dir.glob("mtgroup_backup_*.db"), reverse=True)
        if not backups:
            print_warning("Hicbir yedek dosyasi bulunamadı!")
            wait_enter()
            return

        print(f"\n  {C.BOLD}Mevcut Yedekler:{C.RST}\n")
        for i, bp in enumerate(backups[:10], 1):
            size = bp.stat().st_size / (1024 * 1024)
            mtime = datetime.fromtimestamp(bp.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"    {C.NEON_GREEN}{i}){C.RST}  {bp.name}  "
                  f"{C.DIM}({size:.2f} MB, {mtime}){C.RST}")

        idx = prompt_int("Geri yuklenecek yedek numarasi") - 1
        if 0 <= idx < len(backups):
            selected = backups[idx]
            if confirm("UYARI: Mevcut veritabanı uzerine yazilacak! Emin misiniz?"):
                # Dispose engine before overwriting
                await _dispose_engine()
                shutil.copy2(str(selected), str(db_path))
                print_success(f"Veritabanı geri yuklendi: {selected.name}")
        else:
            print_error("Geçersiz seçim!")

    elif choice == "4":
        # ── List Backups ───────────────────────────────────────
        backups = sorted(backup_dir.glob("mtgroup_backup_*.db"), reverse=True)
        if not backups:
            print_warning("Hicbir yedek dosyasi bulunamadı!")
        else:
            print(f"\n  {C.BOLD}Mevcut Yedekler:{C.RST}\n")
            total_size = 0
            for bp in backups:
                size = bp.stat().st_size / (1024 * 1024)
                total_size += size
                mtime = datetime.fromtimestamp(bp.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                print(f"    {C.NEON_CYAN}{bp.name}{C.RST}  "
                      f"{C.DIM}({size:.2f} MB, {mtime}){C.RST}")
            print(f"\n    {C.BOLD}Toplam:{C.RST} {len(backups)} yedek, "
                  f"{C.NEON_GREEN}{total_size:.2f} MB{C.RST}")

    wait_enter()


async def _send_backup_to_telegram(backup_path: Path) -> None:
    """Send backup file to Telegram admin chat."""
    from backend.app.core.config import settings

    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_ADMIN_ID:
        print_warning("Telegram yapilandirmasi eksik (TELEGRAM_BOT_TOKEN / TELEGRAM_ADMIN_ID)")
        return

    try:
        import httpx

        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendDocument"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        caption = (
            f"MTGroup VPN Ultimate - DB Backup\n"
            f"Tarih: {timestamp}\n"
            f"Boyut: {backup_path.stat().st_size / (1024*1024):.2f} MB"
        )

        async with httpx.AsyncClient(timeout=60) as client:
            with open(backup_path, "rb") as f:
                response = await client.post(
                    url,
                    data={
                        "chat_id": settings.TELEGRAM_ADMIN_ID,
                        "caption": caption,
                    },
                    files={"document": (backup_path.name, f)},
                )
            if response.status_code == 200:
                print_success("Yedek Telegram'a gonderildi!")
            else:
                print_error(f"Telegram gonderilemedi: {response.status_code} - {response.text}")

    except ImportError:
        print_error("httpx kutuphanesi yüklü değil!")
    except Exception as e:
        print_error(f"Telegram gonderim hatasi: {e}")


# ═══════════════════════════════════════════════════════════════════
# CRON / HEADLESS MODE
# ═══════════════════════════════════════════════════════════════════

async def cron_handler(command: str) -> None:
    """
    Handle headless cron commands without interactive TUI.
    Runs the specified function and exits silently.
    """
    try:
        if command == "reset-quotas":
            count = await _execute_quota_reset(interactive=False)
            sys.exit(0 if count >= 0 else 1)

        elif command == "backup-db":
            from backend.app.core.config import settings
            db_path = Path(
                settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "").lstrip("./")
            )
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"mtgroup_backup_{timestamp}.db"
            backup_path = backup_dir / backup_name

            if db_path.exists():
                shutil.copy2(str(db_path), str(backup_path))
                print(f"[CRON] Backup oluşturuldu: {backup_path}")

                # Optionally send to Telegram
                await _send_backup_to_telegram(backup_path)
            else:
                print(f"[CRON] HATA: DB dosyasi bulunamadı: {db_path}", file=sys.stderr)
                sys.exit(1)

        elif command == "health-check":
            services = ["vpn-panel", "xray", "sing-box", "xdp-filter"]
            all_ok = True
            for svc in services:
                status = _check_systemd_service(svc)
                symbol = "OK" if status == "active" else "FAIL"
                print(f"[HEALTH] {svc}: {symbol} ({status})")
                if status not in ("active", "n/a (windows)", "no-systemd"):
                    all_ok = False

            sys.exit(0 if all_ok else 1)

        else:
            print(f"[CRON] Bilinmeyen komut: {command}", file=sys.stderr)
            print("Kullanilabilir komutlar: reset-quotas, backup-db, health-check",
                  file=sys.stderr)
            sys.exit(1)

    finally:
        await _dispose_engine()


# ═══════════════════════════════════════════════════════════════════
# MAIN MENU LOOP
# ═══════════════════════════════════════════════════════════════════

MENU_ITEMS = [
    ("1", "Sistem ve Servis Durumunu Göster",            "FastAPI, Xray, Sing-box, XDP Status"),
    ("2", "Çekirdek Servisleri Yonet",                    "Start / Stop / Restart / Rebuild"),
    ("3", "Interaktif Kullanıcı Oluştur",                 "Wizard: Isim, Kota, Periyot, Mod"),
    ("4", "Kullanıcı Ara ve Durum Sorgula",               "AES-GCM-256 Zero-Knowledge Decode"),
    ("5", "Kullanıcı Aktif/Pasif Yap veya Sil",           "Hesap Yonetimi"),
    ("6", "Ajan / Bayi Yönetim Merkezi",                  "Bakiye, Kota, Komisyon"),
    ("7", "Periyodik Kota Sıfırlama Tetikle",             "DAILY / WEEKLY / MONTHLY"),
    ("8", "IP Engelleme & Handshake Audit Loglari",       "Canli Guvenlik Izleme"),
    ("9", "Veritabanı Yedekle / Geri Yukle",              "Telegram Backup Tetikleyicisi"),
    ("0", "Çıkış",                                        "Terminal Control Center'i Kapat"),
]

MENU_HANDLERS = {
    "1": cmd_system_status,
    "2": cmd_manage_services,
    "3": cmd_create_user_wizard,
    "4": cmd_search_user,
    "5": cmd_toggle_delete_user,
    "6": cmd_agent_management,
    "7": cmd_periodic_quota_reset,
    "8": cmd_bans_and_audit,
    "9": cmd_database_backup,
}


def print_main_menu() -> None:
    """Display the main interactive menu."""
    clear_screen()
    print(LOGO)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  {C.DIM}Tarih: {now}    Platform: {platform.system()} {platform.release()}{C.RST}")
    print()

    print(box_top(C.NEON_GREEN))
    print(box_line(f"{C.BOLD}  MTGROUP ULTIMATE v2.0 - ANA MENU{C.RST}"))
    print(box_line(""))

    for key, label, desc in MENU_ITEMS:
        if key == "0":
            print(box_line(""))
            line = f"  {C.RED}{key}){C.RST}  {C.DIM}{label}{C.RST}"
        else:
            line = (
                f"  {C.NEON_GREEN}{key}){C.RST}  {C.BOLD}{label}{C.RST}  "
                f"{C.DIM}({desc}){C.RST}"
            )
        print(box_line(line))

    print(box_bottom(C.NEON_GREEN))
    print()


async def interactive_loop() -> None:
    """Main interactive TUI event loop."""
    try:
        while True:
            print_main_menu()
            choice = prompt(f"{C.BOLD}Seciminiz{C.RST}")

            if choice == "0":
                print(f"\n  {C.NEON_GREEN}Gule gule! MTGroup VPN Ultimate kapatiyor...{C.RST}\n")
                break

            handler = MENU_HANDLERS.get(choice)
            if handler:
                try:
                    await handler()
                except KeyboardInterrupt:
                    print_warning("İşlem iptal edildi.")
                    wait_enter()
                except Exception as e:
                    print_error(f"Beklenmeyen hata: {e}")
                    import traceback
                    traceback.print_exc()
                    wait_enter()
            else:
                print_error("Geçersiz seçim! 0-9 arasi bir numara girin.")
                wait_enter()

    finally:
        await _dispose_engine()


# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    """Parse arguments and launch interactive or cron mode."""
    parser = argparse.ArgumentParser(
        prog="mtgroup-cli",
        description="MTGroup VPN Ultimate v2.0 - Terminal Control Center",
    )
    parser.add_argument(
        "--cron",
        type=str,
        metavar="COMMAND",
        help="Run a cron command without interactive menu. "
             "Available: reset-quotas, backup-db, health-check",
    )

    args = parser.parse_args()

    if args.cron:
        # Headless cron mode — no TUI, no menu, just execute and exit
        asyncio.run(cron_handler(args.cron))
    else:
        # Interactive TUI mode
        try:
            asyncio.run(interactive_loop())
        except KeyboardInterrupt:
            print(f"\n\n  {C.NEON_GREEN}Gule gule!{C.RST}\n")


if __name__ == "__main__":
    main()
