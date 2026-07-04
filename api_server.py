"""
BASTION IDS — PRODUCTION API SERVER v2.0
==========================================
FastAPI backend for the Bastion IDS desktop application.

Key changes from v1:
  - Real signature matching (48k+ ET-Open rules)
  - Universal feature bridge (any CSV/PCAP format)
  - Interface hot-swap (sniffer restarts on interface change)
  - Thread-safe alerts.json writes (file lock)
  - Real packet count and model stats in health endpoint
  - /api/v1/startup-log endpoint for dashboard
  - /api/v1/settings/* endpoints (config, update, actions)
  - /api/v1/reports/* endpoints (generate, list, download)
  - Sweep progress tracking endpoint
  - Layer 4 anomaly detection integrated
"""

import os, sys, json, shutil, time, datetime, warnings, threading, asyncio, logging, ipaddress
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd
import psutil
import uvicorn

# ── Silence Scapy's "No route found" per-packet warnings ──────────────────────
# These spam the console during the ARP topology scan (one warning per target IP
# when the OS routing table has no route for that /24).  They are not errors —
# Scapy falls back to the correct interface — so we suppress them entirely.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*No route found.*")
warnings.filterwarnings("ignore", message=".*more No route.*")
# Scapy 2.6 renamed the DNS qd/an/ns/ar fields to PacketListField and emits a
# DeprecationWarning every time we read pkt[DNS].qd (which we do for every DNS
# packet, incl. the DNS-tunnelling anomaly check). Accessing .qd still works;
# this just keeps the console clean during live capture / the defense demo.
warnings.filterwarnings("ignore", message=".*PacketListField.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy.*")

# ── Silence Scapy's _sndrcv_snd "Bad file descriptor" thread noise ─────────────
# On Windows/Npcap, Scapy's internal sender thread (_sndrcv_snd) tries to write
# to a close-pipe after srp()/sr1() already closed it — OSError errno 9.
# The scan completed successfully; this is pure cleanup noise. Filter it via
# threading.excepthook (Python ≥ 3.8) so it never reaches the console.
def _scapy_thread_exc_filter(args):
    import traceback as _tb
    # errno 9 = Bad file descriptor, errno 22 = Invalid argument
    # Both are raised by Scapy's sendrecv pipe-close race on Windows/Npcap.
    if (isinstance(args.exc_value, OSError)
            and args.exc_value.errno in (9, 22)
            and any("sendrecv" in (f.filename or "")
                    for f in _tb.extract_tb(args.exc_traceback))):
        return  # swallow silently — harmless Npcap pipe-close race
    # All other unhandled thread exceptions → default handler
    threading.__excepthook__(args)

threading.excepthook = _scapy_thread_exc_filter

# ── Admin check (Windows) — packet capture requires elevation ──
def _check_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True   # non-Windows or check failed — assume OK

if sys.platform == "win32" and not _check_admin():
    print("=" * 60)
    print("  WARNING: Not running as Administrator!")
    print("  Live packet capture (Scapy/Npcap) requires admin rights.")
    print("  Use START_BASTION.bat to launch with auto-elevation.")
    print("  API and sweep analysis will still work; capture may fail.")
    print("=" * 60)

from fastapi import (FastAPI, File, UploadFile, HTTPException,
                     Header, BackgroundTasks, WebSocket, WebSocketDisconnect,
                     Request, Response, Body)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

warnings.filterwarnings("ignore")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────────────────────
# ENGINE INIT
# ─────────────────────────────────────────────────────────────
try:
    from core.engine import BastionEngine
    engine = BastionEngine()
    ENGINE_STARTUP_LOG = engine.get_startup_log()
    ENGINE_STATUS      = engine.get_model_status()
except Exception as ex:
    print(f"[WARN] Engine init failed: {ex}")
    class _FallbackEngine:
        def analyze_flow(self, df, raw_payload=None):
            return "NORMAL", 0.0, "FALLBACK"
        def get_startup_log(self):
            return [f"[WARN] Engine load failed: {ex}"]
        def get_model_status(self):
            return {"signatures_active": 0, "layers_active": 0,
                    "ml_rf":False,"ml_xgb":False,"ml_cat":False,
                    "dl":False,"anomaly":False}
    engine = _FallbackEngine()
    ENGINE_STARTUP_LOG = engine.get_startup_log()
    ENGINE_STATUS      = engine.get_model_status()

# ─────────────────────────────────────────────────────────────
# APP CONFIG
# ─────────────────────────────────────────────────────────────
CONFIG = {
    "UPLOAD_DIR":    os.path.join(BASE_DIR, "uploaded_datasets"),
    "ALERTS_FILE":   os.path.join(BASE_DIR, "alerts.json"),
    "ARCHIVE_FILE":  os.path.join(BASE_DIR, "alerts_archive.json"),
    "REPORTS_DIR":   os.path.join(BASE_DIR, "reports"),
    "SETTINGS_FILE": os.path.join(BASE_DIR, "config", "settings.json"),
    "AUTH_KEY":      "BASTION-KADIAN-SEC-0x42",
    "PREVIEW_LIMIT": 20,
}

# ── Session-scoped alerts: clear alerts.json on every server start ──────────
# alerts.json is EPHEMERAL — it holds the current session only.
# Permanent storage lives in alerts_archive.json and is written only when the
# admin explicitly presses "Save to Archive".  This keeps alerts.json small
# (fast I/O) and avoids cross-session pollution of the live feed.
try:
    _session_alerts_file = CONFIG["ALERTS_FILE"]
    with open(_session_alerts_file, "w", encoding="utf-8") as _sf:
        json.dump([], _sf)
    print("SESSION: alerts.json cleared for new session", flush=True)
except Exception as _se:
    print(f"SESSION: could not clear alerts.json: {_se}", flush=True)
for d in [CONFIG["UPLOAD_DIR"], CONFIG["REPORTS_DIR"],
          os.path.join(BASE_DIR,"config")]:
    os.makedirs(d, exist_ok=True)

app = FastAPI(title="BASTION_AUTHORITY_CORE", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"],
                   allow_headers=["*"], expose_headers=["*"])

# ─────────────────────────────────────────────────────────────
# AUTH HELPER — used by HTTP endpoints and the WS endpoint
# ─────────────────────────────────────────────────────────────
# Live-traffic WebSocket path is excluded from middleware auth — the WS endpoint
# performs its own key check via query param (?key=) on connection accept.
_PUBLIC_PATHS = {"/api/v1/health", "/api/v1/startup-log", "/api/v1/live-traffic"}
# Path prefixes that bypass auth — report downloads must be accessible via browser
# navigation (<a href> and window.open) which cannot send custom headers.
# The filenames are opaque timestamp-based IDs so there is no meaningful
# information-disclosure risk in allowing unauthenticated GET downloads.
_PUBLIC_PREFIXES = ("/api/v1/reports/download/",)

def _check_auth(key: str) -> bool:
    """Return True if the provided key is valid."""
    if not key:
        return False
    if key == CONFIG["AUTH_KEY"]:
        return True
    # Also accept the rotated apiKey stored in settings.json
    try:
        stored = _load_settings().get("apiKey", "")
        if stored and key == stored:
            return True
    except Exception:
        pass
    return False

from starlette.requests import Request as _SR
from starlette.responses import Response as _SRp
from starlette.types import ASGIApp, Receive, Scope, Send

class _AuthMiddleware:
    """
    Pure ASGI middleware — does NOT subclass BaseHTTPMiddleware so it never
    interferes with WebSocket (scope['type'] == 'websocket') connections.
    WebSocket auth is handled inside the WebSocket endpoint itself.
    """
    def __init__(self, app: ASGIApp):
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        # Pass WebSocket scopes straight through — the WS endpoint does its own auth
        if scope["type"] == "websocket":
            await self._app(scope, receive, send)
            return

        if scope["type"] == "http":
            # CORS preflight (OPTIONS) must pass through so CORSMiddleware can respond.
            # Browsers do NOT send custom headers (x-authority) in preflight requests,
            # so blocking OPTIONS here would cause "Failed to fetch" on all POST/DELETE calls.
            if scope.get("method", "").upper() == "OPTIONS":
                await self._app(scope, receive, send)
                return

            path = scope.get("path", "")
            if (path.startswith("/api/") and
                    path not in _PUBLIC_PATHS and
                    not any(path.startswith(p) for p in _PUBLIC_PREFIXES)):
                headers = dict(scope.get("headers", []))
                # Headers are bytes in ASGI scope
                key = (
                    headers.get(b"x-authority", b"").decode() or
                    headers.get(b"X-Authority", b"").decode() or
                    ""
                )
                # Also check query string for ?key= (used by dashboard fetch calls)
                if not key:
                    qs = scope.get("query_string", b"").decode()
                    for part in qs.split("&"):
                        if part.startswith("key="):
                            key = part[4:]
                            break
                if not _check_auth(key):
                    body = b'{"detail":"UNAUTHORIZED \xe2\x80\x94 invalid or missing x-authority header"}'
                    await send({
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"content-length", str(len(body)).encode()],
                        ],
                    })
                    await send({"type": "http.response.body", "body": body})
                    return

        await self._app(scope, receive, send)

app.add_middleware(_AuthMiddleware)

# ─────────────────────────────────────────────────────────────
# SUPPRESS WINDOWS ASYNCIO ConnectionResetError NOISE
# ─────────────────────────────────────────────────────────────
def _asyncio_exception_handler(loop, context):
    exc = context.get("exception")
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, OSError)):
        return  # silently ignore client disconnect noise
    loop.default_exception_handler(context)

@app.on_event("startup")
async def _set_asyncio_handler():
    asyncio.get_event_loop().set_exception_handler(_asyncio_exception_handler)
    # Load persisted policy state from settings.json
    _load_policies_from_settings()
    # Apply Ghost Protocol / Stealth on boot if they were left enabled
    with _policy_lock:
        if _active_policies.get("ghostProtocol"):
            threading.Thread(target=_apply_ghost_protocol, args=(True,), daemon=True).start()
        if _active_policies.get("stealthMode"):
            threading.Thread(target=_apply_stealth_mode, args=(True,), daemon=True).start()
    # Start background topology refresh immediately on boot
    threading.Thread(target=_topology_refresh_loop, daemon=True).start()

# ─────────────────────────────────────────────────────────────
# BACKGROUND TOPOLOGY CACHE
# ARP scan runs on boot and every 30 s. /api/v1/topology returns
# the cache immediately — no blocking on the HTTP request path.
# ─────────────────────────────────────────────────────────────
_topology_cache: dict = {"nodes": [], "connections": [], "interface": "all", "total_devices": 0}
_topology_cache_lock  = threading.Lock()
_topology_cache_age   = 0.0   # unix timestamp of last successful scan

def _run_arp_scan(iface=None):
    """Run ARP broadcast on the given interface (or default route).
    Returns (nodes, connections, target_subnet, host_ip) — always a 4-tuple."""
    import math
    _fallback_nodes = [
        {"id":"CORE-IDS","type":"server","label":"Bastion Host",
         "status":"optimal","x":500,"y":280,"ip":"127.0.0.1",
         "mac":"local","os":"Bastion IDS v2.0","ttl":0},
        {"id":"ETH-GW-01","type":"gateway","label":"Network Gateway",
         "status":"optimal","x":650,"y":180,"ip":"192.168.1.1",
         "mac":"00:1A:2B:3C:4D:5E","os":"Cisco / Network Device","ttl":255},
    ]
    _fallback_conns = [{"from":"CORE-IDS","to":"ETH-GW-01","speed":"1ms"}]
    try:
        import logging as _logging
        _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
        _logging.getLogger("scapy").setLevel(_logging.ERROR)
        from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf as scapy_conf
        scapy_conf.verb = 0          # suppress all Scapy-level output
        scapy_conf.warning_threshold = 0  # suppress "No route found" per-packet warnings
    except Exception:
        return _fallback_nodes, _fallback_conns, "192.168.1.0/24", "127.0.0.1"

    target_ip = "192.168.1.0/24"
    host_ip   = "127.0.0.1"
    effective_iface = iface

    try:
        if effective_iface:
            addrs = psutil.net_if_addrs().get(effective_iface, [])
            iface_ip = next((a.address for a in addrs if a.family == 2), None)
            if iface_ip:
                p = iface_ip.split(".")
                target_ip = f"{p[0]}.{p[1]}.{p[2]}.0/24"
                host_ip   = iface_ip
        else:
            gw = scapy_conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                p = gw.split(".")
                target_ip = f"{p[0]}.{p[1]}.{p[2]}.0/24"
                host_ip   = gw
    except Exception:
        pass

    nodes = [{"id":"CORE-IDS","type":"server","label":"Bastion Host",
              "status":"optimal","x":500,"y":280,"ip":host_ip,
              "mac":"local","os":"Bastion IDS v2.0","ttl":0}]
    connections = []

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
            iface=effective_iface, timeout=2, verbose=0
        )

        # ── PROXY ARP DETECTION ──────────────────────────────────────────────
        # A router using proxy ARP answers on behalf of every IP in the /24.
        # This creates hundreds of fake "hosts" all sharing the router's MAC.
        # Detection: count how many IPs each MAC answered for.
        # Any MAC that answered for > 2 IPs is a proxy ARP MAC.
        mac_ip_count: dict = {}
        for _, rcv in ans:
            m = rcv.sprintf(r"%Ether.src%").lower()
            i = rcv.sprintf(r"%ARP.psrc%")
            mac_ip_count.setdefault(m, set()).add(i)

        # Proxy MACs = those responding for more than 2 distinct IPs
        proxy_macs = {m for m, ips in mac_ip_count.items() if len(ips) > 2}

        # Filter to REAL hosts only:
        #   keep if (a) MAC is not a proxy MAC, OR
        #           (b) IP is the actual gateway (.1 or .254)
        real_entries = []
        seen_ips = set()
        for _, rcv in ans:
            ip  = rcv.sprintf(r"%ARP.psrc%")
            mac = rcv.sprintf(r"%Ether.src%")
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            is_gateway_ip = ip.endswith(".1") or ip.endswith(".254")
            if mac.lower() in proxy_macs and not is_gateway_ip:
                continue   # Ghost entry — skip proxy ARP noise
            real_entries.append((ip, mac))

        step   = 360 / max(len(real_entries), 1)
        cx, cy = 500, 280
        radius = min(220, max(120, 40 * math.sqrt(len(real_entries))))
        for i, (ip, mac) in enumerate(real_entries):
            node_id = f"NODE-{ip.replace('.','_')}"
            angle   = math.radians(i * step - 90)
            ox      = cx + radius * math.cos(angle)
            oy      = cy + radius * math.sin(angle)
            ttl, os_name = 0, "Unknown"
            tcp_window, tcp_opts = 0, []
            open_ports, services, banner_hints = [], [], {}
            try:
                # ICMP ping for TTL
                pkt = sr1(IP(dst=ip)/ICMP(), timeout=0.8, verbose=0)
                if pkt and pkt.haslayer(IP):
                    ttl = pkt[IP].ttl
                # TCP SYN probe — test common ports, collect window/options
                from scapy.layers.inet import TCP
                for probe_port in (80, 443, 22, 3389, 445, 8080, 8443, 5985):
                    try:
                        syn    = IP(dst=ip)/TCP(dport=probe_port, flags="S")
                        synack = sr1(syn, timeout=0.4, verbose=0)
                        if synack and synack.haslayer(TCP):
                            tf = synack[TCP].flags
                            # SA = SYN+ACK → port open
                            if tf == 0x12 or (hasattr(tf, '__contains__') and 'SA' in str(tf)):
                                open_ports.append(probe_port)
                                if not tcp_window:
                                    tcp_window = synack[TCP].window
                                    tcp_opts   = synack[TCP].options or []
                                # Quick banner grab on SSH/HTTP (send RST first to be clean)
                                if probe_port == 22:
                                    services.append("SSH")
                                    banner_hints["ssh"] = True
                                elif probe_port in (80, 8080):
                                    services.append("HTTP")
                                elif probe_port in (443, 8443):
                                    services.append("HTTPS")
                                elif probe_port == 3389:
                                    services.append("RDP")
                                    banner_hints["rdp"] = True
                                elif probe_port == 445:
                                    services.append("SMB")
                                    banner_hints["smb"] = True
                                elif probe_port == 5985:
                                    services.append("WinRM")
                                    banner_hints["winrm"] = True
                    except Exception:
                        pass
                # Resolve hostname (quick, non-blocking)
                import socket
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ""
                os_name = _fingerprint_os(
                    ttl=ttl, mac=mac,
                    tcp_window=tcp_window, tcp_options=tcp_opts,
                    ports=set(open_ports),
                    hostname=hostname,
                    banner_hints=banner_hints,
                )
            except Exception:
                os_name = _fingerprint_os(ttl=ttl, mac=mac)
                hostname = ""
            is_gw  = ip.endswith(".1") or ip.endswith(".254")
            vendor = _vendor_from_mac(mac)
            label  = hostname or (f"Gateway ({vendor})" if is_gw and vendor else
                                  f"Gateway"            if is_gw else
                                  f"{vendor} Device"    if vendor else
                                  f"Host {ip}")
            nodes.append({
                "id":         node_id,
                "type":       "gateway" if is_gw else "workstation",
                "label":      label,
                "status":     "optimal",
                "x":          round(ox, 1),
                "y":          round(oy, 1),
                "ip":         ip, "mac": mac, "os": os_name, "ttl": ttl,
                "hostname":   hostname or "",
                "vendor":     vendor,
                "open_ports": open_ports,
                "services":   services,
            })
            connections.append({"from": "CORE-IDS", "to": node_id, "speed": "<1ms"})
    except Exception:
        nodes.append({"id":"ETH-GW-01","type":"gateway","label":"Network Gateway",
                      "status":"optimal","x":650,"y":180,"ip":"192.168.1.1",
                      "mac":"00:1A:2B:3C:4D:5E","os":"Cisco / Network Device","ttl":255})
        connections.append({"from":"CORE-IDS","to":"ETH-GW-01","speed":"1ms"})

    return nodes, connections, target_ip, host_ip

def _topology_refresh_loop():
    """Background daemon: refresh ARP topology cache every 30 seconds.
    Always uses last_topology_interface so the background refresh matches what
    the user selected — never drifts back to the default-route subnet."""
    global _topology_cache_age
    import math, time as _time
    while True:
        try:
            # ── Use the interface the user last selected (or None for auto) ──────
            iface = last_topology_interface
            nodes, connections, target_subnet, host_ip = _run_arp_scan(iface)

            # Derive subnet prefix for strict filtering (e.g. "192.168.100.")
            # This prevents devices from other subnets leaking into the map when
            # the user has selected a specific interface.
            subnet_prefix = ".".join(target_subnet.split(".")[:3]) + "." if target_subnet else None

            # Merge live-capture discovered devices
            # Only include devices seen recently (last 5 minutes) — stops stale
            # hosts from cluttering the topology view.
            cutoff = datetime.datetime.now() - datetime.timedelta(minutes=5)
            with _device_lock:
                live_devs = dict(_discovered_devices)
            existing_ips = {n["ip"] for n in nodes}
            for ip, info in live_devs.items():
                # Skip public internet IPs
                if not _is_lan_ip(ip):
                    continue
                # Skip IPs not in the scanned interface's subnet
                if subnet_prefix and not ip.startswith(subnet_prefix):
                    continue
                if ip in existing_ips or ip in ("0.0.0.0", "255.255.255.255"):
                    continue
                # Active-host filter: only include devices seen in last 5 min
                try:
                    ls = datetime.datetime.fromisoformat(info.get("last_seen", ""))
                    if ls < cutoff:
                        continue
                except Exception:
                    continue
                i = len(nodes)
                angle = math.radians(i * 30 - 90)
                r = 250
                nodes.append({
                    "id": f"LIVE-{ip.replace('.','_')}",
                    "type": "workstation",
                    "label": info.get("hostname") or f"Host {ip}",
                    "status": "active",
                    "x": round(500 + r * math.cos(angle), 1),
                    "y": round(280 + r * math.sin(angle), 1),
                    "ip": ip, "mac": info.get("mac","?"),
                    "os": info.get("os","Unknown"), "ttl": info.get("ttl",0),
                    "hostname": info.get("hostname",""),
                    "pkt_count": info.get("pkt_count",0),
                    "first_seen": info.get("first_seen",""),
                    "last_seen":  info.get("last_seen",""),
                    "source": "live_capture",
                })
                existing_ips.add(ip)
                connections.append({"from":"CORE-IDS","to":f"LIVE-{ip.replace('.','_')}","speed":"live"})

            with _topology_cache_lock:
                _topology_cache.update({
                    "nodes":         nodes,
                    "connections":   connections,
                    "interface":     iface or "auto",
                    "total_devices": len(nodes) - 1,
                    "target_subnet": target_subnet,
                })
                _topology_cache_age = _time.time()
        except Exception:
            pass
        _time.sleep(30)   # refresh every 30 seconds

# ─────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────
_alerts_lock    = threading.Lock()
_packet_lock    = threading.Lock()
active_websockets: list = []
is_sniffing     = False
sniff_thread    = None
current_interface = None
_lockdown_active = False          # set True by hard_lockdown, False by release
_sniffer_error  = None            # last capture error string, None = healthy

# ── OUI MAC vendor lookup (IEEE Organizationally Unique Identifier) ───────────
# First 3 bytes (6 hex chars) of MAC → vendor name.
# Covers the most common manufacturers seen on enterprise/home networks.
_OUI_DB = {
    "000C29":"VMware","000569":"VMware","001C14":"VMware","005056":"VMware",
    "000D3A":"Microsoft","0015E9":"Dell","18A99B":"Dell","B083FE":"Dell",
    "3C977D":"Dell","F0761C":"Dell","1098A0":"Cisco","68EFBD":"Cisco",
    "70B317":"Cisco","A493A9":"Cisco","E8BA70":"Cisco","000A8A":"Cisco",
    "001B0D":"Cisco","001E4A":"Cisco","002268":"Cisco","00234F":"Cisco",
    "BC1648":"Cisco","C02DE0":"Cisco","F4CFE2":"Cisco","485B39":"Cisco",
    "3C0E23":"Cisco","4C4E35":"Cisco","001F6C":"Hewlett Packard",
    "9CB6D0":"Hewlett Packard","889600":"HP","A0D3C1":"HP","705A0F":"HP",
    "001A2B":"Intel","001D25":"Intel","00236F":"Intel","0024D7":"Intel",
    "3417EB":"Intel","5404A6":"Intel","8086F2":"Intel","AC9E17":"Intel",
    "F45C89":"Intel","00802D":"Xircom","ACDE48":"Apple","F0B429":"Apple",
    "F4F15A":"Apple","3C8709":"Apple","70ECE4":"Apple","A4B197":"Apple",
    "D8BB2C":"Apple","F0DCE2":"Apple","0C4DE9":"Apple","10DEE7":"Apple",
    "18AF61":"Apple","2CF0A2":"Apple","3CC313":"Apple","40A6D9":"Apple",
    "6C4008":"Apple","70CD60":"Apple","788C54":"Apple","7CAACF":"Apple",
    "84B153":"Apple","9CE335":"Apple","A88195":"Apple","C86F1D":"Apple",
    "D4619D":"Apple","DC2B2A":"Apple","E4B318":"Apple","FCFC48":"Apple",
    "041E64":"Google","1C3ADE":"Google","44E3E0":"Google","204E7F":"Google",
    "E4F0AB":"Google","F4F5E8":"Google","00145A":"Netgear","20E52A":"Netgear",
    "28C68E":"Netgear","4CBEED":"Netgear","6CB0CE":"Netgear","9003B7":"Netgear",
    "A040A0":"Netgear","C03F0E":"Netgear","E091F5":"Netgear","001018":"Broadcom",
    "00904C":"Epigram","1C87F4":"ASUS","2C4D54":"ASUS","485D36":"ASUS",
    "60A44C":"ASUS","788332":"ASUS","AC220B":"ASUS","BC9490":"ASUS",
    "E03F49":"ASUS","EC086B":"ASUS","F832E4":"ASUS","F8AB05":"TP-Link",
    "1027F5":"TP-Link","34BA9A":"TP-Link","50C7BF":"TP-Link","54A751":"TP-Link",
    "601374":"TP-Link","6894AF":"TP-Link","98DED0":"TP-Link","C46E1F":"TP-Link",
    "D86C63":"TP-Link","001CF0":"D-Link","1C7EE5":"D-Link","28107B":"D-Link",
    "340804":"D-Link","5CD998":"D-Link","7C8BCA":"D-Link","90FDB1":"D-Link",
    "B891A4":"D-Link","D8FEE3":"D-Link","F07D68":"D-Link","00175A":"Linksys",
    "001CBD":"Linksys","002722":"Linksys","003048":"Linksys","00A0CC":"Xircom",
    "1CE87B":"Linksys","58EF68":"Belkin","EC1A59":"Belkin","9C1E95":"Samsung",
    "A4EBAF":"Samsung","B47443":"Samsung","DC7144":"Samsung","E43EA7":"Samsung",
    "001A8C":"Qualcomm","0A005E":"Qualcomm","00095B":"NETGEAR",
    "001977":"Synology","C0C1C0":"Synology","BCCEC5":"Amazon","68ECC8":"Amazon",
    "FC65DE":"Amazon","78E103":"Amazon","A4025B":"Amazon","BC5426":"Anker",
    "00E04C":"Realtek","00E0B1":"Realtek","001B21":"Realtek","001CA8":"Raspberry Pi",
    "B827EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "080027":"VirtualBox","0A0027":"VirtualBox",
}

def _oui_lookup(mac: str) -> str:
    """Return vendor name for a MAC address, or empty string if unknown."""
    if not mac:
        return ""
    key = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_DB.get(key, "")
last_topology_interface = None   # last interface used for ARP topology scan

# ── JSON-safe coercion ─────────────────────────────────────────────────────────
# Scapy field types (FlagsField, IntField) and numpy scalars are NOT JSON-serializable.
# This helper converts any value in pkt_info to a native Python type so that
# ws.send_json() never raises TypeError and silently drops the packet.
def _json_safe(v):
    """Recursively coerce v to a JSON-serialisable Python native type."""
    t = type(v).__name__
    # numpy scalar → python scalar
    if hasattr(v, 'item'):
        try: return v.item()
        except Exception: pass
    # bytes → hex string
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    # dict / list recursion
    if isinstance(v, dict):
        return {kk: _json_safe(vv) for kk, vv in v.items()}
    if isinstance(v, (list, tuple)):
        return [_json_safe(x) for x in v]
    # bool must come before int (bool IS int in Python)
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return int(v)
    if isinstance(v, float):
        return float(v)
    if isinstance(v, str):
        return v
    # Scapy special types: FlagsField, Packet, etc. → stringify
    return str(v)

packet_counter  = 0
sweep_progress  = {}   # filename → {status, processed, total, hits}
# ── Cheap alert counter — updated on every write, read by health endpoint ──────
# Never re-read the entire alerts.json just to get a count; that blocks the loop.
_alerts_disk_count: int = 0
# ── In-memory recent-alerts ring — last 500 alerts for display endpoints ──────
# The UI display feed (/api/v1/alerts) reads this ring, never the disk file.
# Only full exports / session-filtered searches need to touch alerts.json.
from collections import deque as _deque, defaultdict as _defaultdict
_recent_alerts: _deque = _deque(maxlen=500)
boot_time            = time.time()
# Detection thresholds — live-updated from settings sliders (sigWeight/mlThreshold/anomalyWeight)
_alert_threshold = 0.70   # sigWeight / 100
_ml_threshold    = 0.60   # mlThreshold / 100
_anomaly_gate    = 0.85   # 1.0 - anomalyWeight * 0.003 (higher weight = more sensitive = lower gate)
_dpi_target      = ""     # IP under active DPI ("" = disabled)
session_threat_count = 0   # threats flagged since this server process started
session_flow_count   = 0   # flows analyzed (sweep rows) since boot
session_layer_counts = {"SIGNATURE_DB": 0, "ML_ENSEMBLE": 0, "DL_LAYER": 0, "ANOMALY": 0}  # per-layer live-capture hits

# ─────────────────────────────────────────────────────────────
# HTTP POST BRUTE-FORCE TRACKER
# Dedicated tracker for HTTP form-auth attacks (Hydra http-post-form,
# Burp Intruder, etc.).  Port 80 is excluded from the general BRUTE_PORTS
# heuristic to avoid false-positives on normal web traffic; this tracker
# fires only on repeated POST requests to the EXACT SAME URL path from
# the same source — a pattern that doesn't occur in legitimate browsing.
# ─────────────────────────────────────────────────────────────
_http_post_events: dict = {}   # hk → deque of timestamps
_http_post_fired:  dict = {}   # hk → last-fire timestamp
_http_post_lock         = threading.Lock()
_HTTP_POST_WINDOW       = 30   # sliding window (seconds)
_HTTP_POST_THRESHOLD    = 8    # POSTs to same endpoint in window → alert
_HTTP_POST_COOLDOWN     = 300  # seconds before re-alerting same key

# ─────────────────────────────────────────────────────────────
# BEHAVIOURAL ANOMALY ENGINE (live zero-day detection)
# ─────────────────────────────────────────────────────────────
# Signatures match KNOWN attacks. These detectors instead flag attack
# *behaviour* that no signature describes — covert channels and tunnels used
# for C2 / exfiltration. They are distribution-independent (unlike the UNSW
# autoencoder, they don't break on live traffic) and threshold-gated so normal
# pings and DNS lookups never trip them. This is what lets Bastion catch a
# brand-new, signatureless attack live and label it ANOMALY / zero-day.
_anom_events: dict = {}    # key → deque of timestamps
_anom_fired:  dict = {}    # key → last-fire timestamp
_anom_lock         = threading.Lock()
_ANOM_WINDOW       = 60    # sliding window (seconds)
_ANOM_COOLDOWN     = 120   # seconds before re-alerting same key
# ICMP covert channel (T1095): normal ping data is 32-56 bytes. A stream of
# echo packets carrying large payloads is data smuggled inside ICMP.
_ICMP_DATA_MIN     = 100   # bytes of ICMP payload to count as suspicious
_ICMP_DATA_THRESH  = 3     # such packets from one src in window → fire
# DNS tunnelling / exfiltration (T1071.004): encoded data ride in oversized,
# high-entropy subdomain labels. Normal lookups are short, dictionary-like.
_DNS_LABEL_MIN     = 40    # a single label this long is encoded data, not a name
_DNS_QNAME_MIN     = 60    # or a very long full query name
_DNS_TUNNEL_THRESH = 5     # such queries from one src in window → fire

# Each time the user starts/restarts capture, a new session ID is minted.
# Every alert saved to alerts.json carries this ID so the report generator
# can filter to ONLY the current session's alerts.
_current_session_id: str = datetime.datetime.now().strftime("session_%Y%m%d_%H%M%S")

# ─────────────────────────────────────────────────────────────────────────────
# LIVE FLOW TRACKER
# Aggregates per-packet events into UNSW-NB15-style flow records, then submits
# completed flows through the full 4-layer detection pipeline (ML Ensemble,
# Deep Learning, Anomaly Sentinel) in background threads.
#
# Architecture: signature engine runs synchronously per-packet (microseconds).
# ML/DL/Anomaly run on completed flows in a thread pool (milliseconds, non-blocking).
# This gives the system true real-time multi-layer detection on live traffic.
# ─────────────────────────────────────────────────────────────────────────────
import statistics as _stats_mod
import concurrent.futures as _futures

_ml_executor = _futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="bastion_ml")

# ── LIVE-WIRE ML/DL/ANOMALY ALERTING TOGGLE ──────────────────────────────────
# The supervised ensemble + DNN + autoencoder were trained on the UNSW-NB15
# feature distribution. Live-captured flows have a different statistical
# fingerprint (train/serve domain gap), so on the wire these models mislabel
# normal traffic en masse. With this False, LIVE alerts come ONLY from the
# precise, distribution-independent layers (signature engine + scan/brute/flood
# heuristics). The ML/DL/Anomaly engines still SCORE every flow (forensic
# value) and are demonstrated at full, calibrated strength on the Analysis /
# batch-ingest path, where input features match their training domain.
# Re-arm by setting True ONLY after implementing live-baseline calibration.
LIVE_ML_ALERTS = False

class _LiveFlowTracker:
    """
    Accumulates packets into BIDIRECTIONAL flow records and runs the full
    4-layer pipeline (signature -> ML ensemble -> DL -> anomaly) when a flow
    completes (FIN/RST) or goes idle. Builds COMPLETE UNSW-NB15 features for
    BOTH directions plus connection-based ct_* counts, so the trained models
    score live traffic at their calibrated accuracy. Per-source correlation
    keeps normal traffic quiet while catching sustained / strong attacks.
    """
    TIMEOUT   = 8.0     # seconds idle -> flush
    MIN_PKTS  = 4       # minimum total packets before ML analysis
    MAX_FLOWS = 8000
    CT_WINDOW = 100     # UNSW connection-feature window (last N flows)

    def __init__(self):
        self._flows        = {}
        self._lock         = threading.Lock()
        self._loop         = None
        self._recent       = _deque(maxlen=self.CT_WINDOW)  # finalized flows for ct_*
        self._recent_lock  = threading.Lock()
        self._evidence     = _defaultdict(_deque)           # src_ip -> deque[ts]
        self._ev_lock      = threading.Lock()
        self._timer        = None

    def start(self, loop):
        self._loop = loop
        self._schedule()

    def stop(self):
        if self._timer:
            self._timer.cancel()

    def _schedule(self):
        self._timer = threading.Timer(5.0, self._flush_stale)
        self._timer.daemon = True
        self._timer.start()

    def _flush_stale(self):
        now = time.time()
        to_flush = []
        with self._lock:
            for key, f in list(self._flows.items()):
                if now - f["last_ts"] >= self.TIMEOUT:
                    to_flush.append(dict(f))
                    del self._flows[key]
        for f in to_flush:
            if (f["spkts"] + f["dpkts"]) >= self.MIN_PKTS:
                _ml_executor.submit(self._analyze, f)
        if self._loop and not self._loop.is_closed():
            self._schedule()

    def record(self, src_ip, dst_ip, proto, sport, dport, pkt_len, ttl,
               flags_str, tcp_win):
        now = time.time()
        # Canonical key: identical for both directions of one conversation.
        a, b = (src_ip, sport), (dst_ip, dport)
        if a <= b:
            key, fwd = (a, b, proto), True
        else:
            key, fwd = (b, a, proto), False
        is_syn    = bool(flags_str and "S" in flags_str and "A" not in flags_str)
        is_synack = bool(flags_str and "S" in flags_str and "A" in flags_str)
        is_close  = bool(flags_str and ("F" in flags_str or "R" in flags_str))

        with self._lock:
            if len(self._flows) >= self.MAX_FLOWS:
                oldest = min(self._flows, key=lambda k: self._flows[k]["start_ts"])
                del self._flows[oldest]
            f = self._flows.get(key)
            if f is None:
                # The first packet defines the initiator (the "source" side).
                f = {
                    "src_ip": src_ip, "dst_ip": dst_ip, "proto": proto,
                    "sport": sport, "dport": dport, "init_fwd": fwd,
                    "spkts": 0, "dpkts": 0, "sbytes": 0, "dbytes": 0,
                    "sttl": 0, "dttl": 0, "swin": 0, "dwin": 0,
                    "has_syn": 0, "has_synack": 0, "has_ack": 0,
                    "syn_ts": 0.0, "synack_ts": 0.0, "ack_ts": 0.0,
                    "start_ts": now, "last_ts": now,
                    "fwd_ts": [], "bwd_ts": [],
                }
                self._flows[key] = f
            from_src = (fwd == f["init_fwd"])   # packet from the initiator side?
            f["last_ts"] = now
            if from_src:
                f["spkts"] += 1; f["sbytes"] += pkt_len
                if not f["sttl"]: f["sttl"] = ttl
                if tcp_win and not f["swin"]: f["swin"] = tcp_win
                f["fwd_ts"].append(now)
            else:
                f["dpkts"] += 1; f["dbytes"] += pkt_len
                if not f["dttl"]: f["dttl"] = ttl
                if tcp_win and not f["dwin"]: f["dwin"] = tcp_win
                f["bwd_ts"].append(now)
            if is_syn and not f["syn_ts"]:
                f["syn_ts"] = now; f["has_syn"] = 1
            if is_synack and not f["synack_ts"]:
                f["synack_ts"] = now; f["has_synack"] = 1
            if flags_str and "A" in flags_str:
                f["has_ack"] = 1
                if f["has_synack"] and not f["ack_ts"]:
                    f["ack_ts"] = now
            fdata = None
            if is_close and (f["spkts"] + f["dpkts"]) >= self.MIN_PKTS:
                fdata = dict(f); del self._flows[key]

        if fdata:
            _ml_executor.submit(self._analyze, fdata)

    def _service_for(self, dport, proto):
        if   dport in (80, 8080, 8000): return "http"
        elif dport in (443, 8443):      return "ssl"
        elif dport == 53:               return "dns"
        elif dport in (21, 20):         return "ftp"
        elif dport == 22:               return "ssh"
        elif dport in (25, 587, 465):   return "smtp"
        return "-"

    def _ct_features(self, src, dst, dport, service, state):
        """UNSW connection-based counts over the last CT_WINDOW finalized flows."""
        with self._recent_lock:
            r = list(self._recent)
        return {
            "ct_srv_src":        sum(1 for x in r if x[0] == src and x[3] == service),
            "ct_srv_dst":        sum(1 for x in r if x[1] == dst and x[3] == service),
            "ct_dst_ltm":        sum(1 for x in r if x[1] == dst),
            "ct_src_ltm":        sum(1 for x in r if x[0] == src),
            "ct_src_dport_ltm":  sum(1 for x in r if x[0] == src and x[2] == dport),
            "ct_dst_sport_ltm":  sum(1 for x in r if x[1] == dst and x[2] == dport),
            "ct_dst_src_ltm":    sum(1 for x in r if x[0] == src and x[1] == dst),
            "ct_state_ttl":      sum(1 for x in r if x[4] == state),
        }

    def _analyze(self, f):
        try:
            dur = max(f["last_ts"] - f["start_ts"], 0.0)
            sp, dp = f["spkts"], f["dpkts"]
            sb, db = f["sbytes"], f["dbytes"]
            smean = sb / sp if sp else 0.0
            dmean = db / dp if dp else 0.0
            rate  = (sp + dp) / dur if dur > 0 else 0.0
            sload = sb * 8.0 / dur if dur > 0 else 0.0
            dload = db * 8.0 / dur if dur > 0 else 0.0
            def _ipt(ts):
                if len(ts) < 2: return 0.0, 0.0
                d = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
                return (sum(d) / len(d),
                        _stats_mod.stdev(d) if len(d) >= 2 else 0.0)
            sinpkt, sjit = _ipt(f["fwd_ts"])
            dinpkt, djit = _ipt(f["bwd_ts"])
            tcprtt = (f["ack_ts"] - f["syn_ts"]) if (f["syn_ts"] and f["ack_ts"]) else 0.0
            synack = (f["synack_ts"] - f["syn_ts"]) if (f["syn_ts"] and f["synack_ts"]) else 0.0
            ackdat = (f["ack_ts"] - f["synack_ts"]) if (f["synack_ts"] and f["ack_ts"]) else 0.0

            dport, proto = f["dport"], f["proto"]
            service = self._service_for(dport, proto)
            state = "FIN" if (f["has_syn"] and f["has_ack"] and dp) else ("CON" if f["has_ack"] else "INT")
            ct = self._ct_features(f["src_ip"], f["dst_ip"], dport, service, state)
            with self._recent_lock:
                self._recent.append((f["src_ip"], f["dst_ip"], dport, service, state))
            is_sm = 1 if (f["src_ip"] == f["dst_ip"] and f["sport"] == dport) else 0

            row = {
                "srcip": f["src_ip"], "dstip": f["dst_ip"], "proto": proto,
                "service": service, "state": state,
                "sport": f["sport"], "dport": dport, "dur": dur, "rate": rate,
                "spkts": sp, "dpkts": dp, "sbytes": sb, "dbytes": db,
                "sttl": f["sttl"], "dttl": f["dttl"], "swin": f["swin"], "dwin": f["dwin"],
                "synack": synack, "ackdat": ackdat, "smean": smean, "dmean": dmean,
                "sload": sload, "dload": dload, "sloss": 0, "dloss": 0,
                "sinpkt": sinpkt, "dinpkt": dinpkt, "sjit": sjit, "djit": djit,
                "stcpb": 0, "dtcpb": 0, "tcprtt": tcprtt,
                "trans_depth": 0, "response_body_len": 0,
                "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0,
                "is_sm_ips_ports": is_sm,
            }
            row.update(ct)
            flow_df = pd.DataFrame([row])
            verdict, conf, src_engine = engine.analyze_flow(flow_df)
            self._maybe_alert(f, verdict, conf, src_engine, proto, service)
        except Exception:
            pass

    def _maybe_alert(self, f, verdict, conf, src_engine, proto, service):
        v   = str(verdict).upper()
        eng = str(src_engine).upper()
        if v in ("NORMAL", "BASTION_CLEAN", "PREPROCESSING_ERROR", ""):
            return
        # ── Per-source correlation (false-positive control) ────────────────
        # Empirically the supervised multi-class models mislabel ~5-8% of
        # NORMAL flows even with COMPLETE bidirectional features (an inherent
        # property of the classifier on a real-world test set). To stay quiet
        # on normal browsing AND catch real attacks, alerts only fire when one
        # of these strict conditions is met:
        #
        #   1. SIGNATURE_DB    -> immediate (payload-verified, precise)
        #   2. ANOMALY/SENTINEL>= 0.85 -> immediate (the zero-day signal)
        #   3. ML/DL strong (>=0.92) AND corroborated by >=2 other suspicious
        #      flows from the SAME source within 120s. A single ML/DL hit on a
        #      one-off flow is treated as inconclusive (the model's known FP
        #      rate dominates), so we wait for the pattern.
        #
        # This mirrors how Suricata, Snort+SOC analysts, and commercial IDS
        # like Darktrace handle ML output: never auto-alert on a one-shot ML
        # verdict, always require either a precise rule hit or a behavioral
        # pattern across multiple flows.
        src = f["src_ip"]; now = time.time()
        is_sig     = "SIGNATURE" in eng
        is_anomaly = "ANOMALY" in eng or "SENTINEL" in eng
        with self._ev_lock:
            dq = self._evidence[src]
            if conf >= _anomaly_gate:
                dq.append(now)
            while dq and dq[0] < now - 120.0:
                dq.popleft()
            same_src_count = len(dq)
        ml_corroborated = (conf >= 0.92 and same_src_count >= 3)
        # ── Option A gate ────────────────────────────────────────────────────
        # When LIVE_ML_ALERTS is False (default), only the signature/heuristic
        # layer may raise a LIVE alert. The flow-level ML/DL/Anomaly verdict is
        # still computed above (kept for forensic scoring) but does NOT alert on
        # the wire — this is what stops the false "zero-day on a ping" floods.
        if not LIVE_ML_ALERTS:
            if not is_sig:
                return
        elif not (is_sig or (is_anomaly and conf >= _anomaly_gate) or ml_corroborated):
            return

        ts_now = datetime.datetime.now().isoformat()
        mitre  = _mitre_from_verdict(verdict, src_engine)
        alert  = {
            "id": 0, "srcip": f["src_ip"], "dstip": f["dst_ip"],
            "proto": proto, "service": service,
            "sport": f["sport"], "dport": f["dport"],
            "verdict": verdict, "confidence": round(conf, 4),
            "source_engine": src_engine, "engine": src_engine,
            "timestamp": ts_now,
            "severity": "HIGH" if conf >= 0.85 else "MEDIUM",
            "layer": src_engine, "mitre_id": mitre,
        }
        _save_alert(alert)
        global session_threat_count, session_layer_counts
        session_threat_count += 1
        ekey = {"DL-SENSEI": "DL_LAYER", "BASTION_CLEAN": "SIGNATURE_DB"}.get(
            src_engine.upper(), src_engine.upper())
        session_layer_counts[ekey] = session_layer_counts.get(ekey, 0) + 1
        evt = {
            "type": "THREAT_DETECTED", "No.": session_threat_count,
            "verdict": verdict, "confidence": round(conf, 4),
            "engine": src_engine, "source_engine": src_engine,
            "src_ip": f["src_ip"], "dst_ip": f["dst_ip"],
            "srcip": f["src_ip"], "dstip": f["dst_ip"],
            "proto": proto, "timestamp": ts_now, "mitre_id": mitre,
            "severity": alert["severity"], "total_threats": session_threat_count,
        }
        if self._loop and not self._loop.is_closed():
            asyncio.run_coroutine_threadsafe(_broadcast(_json_safe(evt)), self._loop)


def _mitre_from_verdict(verdict: str, engine: str) -> str:
    v = verdict.upper()
    if "SCAN" in v or "RECONNAISSANCE" in v: return "T1046"
    if "BRUTE" in v or "BACKDOOR" in v:      return "T1110"
    if "DOS" in v or "FLOOD" in v:           return "T1498"
    if "EXPLOIT" in v:                        return "T1190"
    if "FUZZ" in v or "ANALYSIS" in v:       return "T1595"
    if "ANOMALY" in v or "ZERO" in v:        return "T1211"
    if "SHELL" in v:                          return "T1059"
    if "WORM" in v:                           return "T1105"
    if engine == "ML_ENSEMBLE":               return "T1071"
    if engine == "ANOMALY":                   return "T1211"
    return "T1040"

_live_flow_tracker = _LiveFlowTracker()

# Ring buffer: last 5000 raw packet dicts for CSV export
from collections import deque
_packet_ring: deque = deque(maxlen=5000)
# Raw scapy packet ring for PCAP export (separate, holds actual Packet objects)
_raw_packet_ring: deque = deque(maxlen=5000)

# ─────────────────────────────────────────────────────────────
# ACTIVE POLICY STATE
# Loaded from settings on startup; updated in real-time when
# the admin toggles a policy in the Command & Control panel.
# ─────────────────────────────────────────────────────────────
_active_policies: dict = {
    "autoIsolate":    False,
    "mfaEnforce":     False,
    "stealthMode":    False,
    "deepInspection": True,
    "ghostProtocol":  False,
}
_policy_lock = threading.Lock()

# Set of IPs currently quarantined by Auto-Isolate policy
_auto_isolated_ips: set = set()
_isolated_lock = threading.Lock()

def _load_policies_from_settings():
    """Sync _active_policies and detection thresholds from settings.json on startup."""
    global _alert_threshold, _ml_threshold, _anomaly_gate, _dpi_target
    s = _load_settings()
    with _policy_lock:
        for k in _active_policies:
            if k in s:
                _active_policies[k] = bool(s[k])
    # Clamps keep the detection gates inside sane operating bounds no matter
    # what ends up in settings.json.
    _alert_threshold = max(0.50, min(0.95, s.get("sigConfFloor", 70) / 100.0))
    _ml_threshold    = max(0.40, min(0.95, s.get("mlVoteThreshold", 60) / 100.0))
    _anomaly_gate    = max(0.70, min(0.99, 1.0 - s.get("anomalySensitivity", 50) * 0.003))
    # DPI never survives an engine restart. It's a live investigative tool
    # aimed at whatever a host's IP is RIGHT NOW; a stale target from a
    # previous session would silently skew thresholds for an unrelated IP.
    _dpi_target = ""
    if s.get("dpi_enabled") or s.get("dpi_target"):
        s["dpi_enabled"] = False
        s["dpi_target"]  = ""
        try:    _save_settings(s)
        except Exception: pass

def _apply_auto_isolate(ip: str):
    """
    Block a threat source IP using Windows Firewall (netsh).
    Requires the backend to be running as Administrator.
    """
    import subprocess
    with _isolated_lock:
        if ip in _auto_isolated_ips:
            return   # Already isolated
        _auto_isolated_ips.add(ip)
    rule_name = f"BASTION-AUTO-ISOLATE-{ip.replace('.', '_')}"
    try:
        # Block all inbound traffic from the threat IP
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}",
            "enable=yes",
            "description=BASTION IDS Auto-Isolate: confirmed threat source",
        ], capture_output=True, timeout=5)
        # Also block outbound (prevent C2 callbacks)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}-OUT",
            "dir=out", "action=block",
            f"remoteip={ip}",
            "enable=yes",
            "description=BASTION IDS Auto-Isolate: outbound block",
        ], capture_output=True, timeout=5)
        print(f"[POLICY:AUTO-ISOLATE] Blocked {ip} via Windows Firewall", flush=True)
    except Exception as ex:
        print(f"[POLICY:AUTO-ISOLATE] Failed to block {ip}: {ex}", flush=True)

def _remove_auto_isolate(ip: str):
    """Remove Windows Firewall block rule for an IP."""
    import subprocess
    with _isolated_lock:
        _auto_isolated_ips.discard(ip)
    rule_name = f"BASTION-AUTO-ISOLATE-{ip.replace('.', '_')}"
    try:
        subprocess.run(["netsh","advfirewall","firewall","delete","rule",
                        f"name={rule_name}"], capture_output=True, timeout=5)
        subprocess.run(["netsh","advfirewall","firewall","delete","rule",
                        f"name={rule_name}-OUT"], capture_output=True, timeout=5)
        print(f"[POLICY:AUTO-ISOLATE] Released {ip}", flush=True)
    except Exception as ex:
        print(f"[POLICY:AUTO-ISOLATE] Failed to release {ip}: {ex}", flush=True)

def _apply_ghost_protocol(enable: bool):
    """
    Ghost Protocol: Block ARP replies from this host and disable ICMP echo response.
    On Windows this uses Windows Firewall to block ICMP echo-request (incoming pings).
    """
    import subprocess
    rule = "BASTION-GHOST-PROTOCOL-ICMP"
    try:
        if enable:
            subprocess.run(["netsh","advfirewall","firewall","add","rule",
                            f"name={rule}", "dir=in", "action=block",
                            "protocol=icmpv4:8,any",  # block ICMP echo
                            "enable=yes",
                            "description=BASTION Ghost Protocol: suppress ICMP responses"],
                           capture_output=True, timeout=5)
            print("[POLICY:GHOST] ICMP echo responses suppressed", flush=True)
        else:
            subprocess.run(["netsh","advfirewall","firewall","delete","rule",
                            f"name={rule}"], capture_output=True, timeout=5)
            print("[POLICY:GHOST] ICMP echo responses restored", flush=True)
    except Exception as ex:
        print(f"[POLICY:GHOST] Error: {ex}", flush=True)

def _apply_stealth_mode(enable: bool):
    """
    Stealth Mode: Block incoming port scan probes (syn-only to closed ports).
    Also reduces topology visibility by blocking mDNS and NetBIOS broadcasts.
    """
    import subprocess
    rule_scan = "BASTION-STEALTH-PORTSCAN"
    rule_mdns = "BASTION-STEALTH-MDNS"
    try:
        if enable:
            # Block mDNS (5353) so this host doesn't appear in mDNS browsers
            subprocess.run(["netsh","advfirewall","firewall","add","rule",
                            f"name={rule_mdns}", "dir=in", "action=block",
                            "protocol=udp", "localport=5353",
                            "enable=yes",
                            "description=BASTION Stealth: hide from mDNS discovery"],
                           capture_output=True, timeout=5)
            print("[POLICY:STEALTH] mDNS visibility suppressed", flush=True)
        else:
            subprocess.run(["netsh","advfirewall","firewall","delete","rule",
                            f"name={rule_mdns}"], capture_output=True, timeout=5)
            print("[POLICY:STEALTH] Normal network visibility restored", flush=True)
    except Exception as ex:
        print(f"[POLICY:STEALTH] Error: {ex}", flush=True)

# High-risk country ASN prefixes (simplified — production would use MaxMind/ip2location)
# These are illustrative public prefixes known for high threat activity
_GEO_FENCE_RANGES: list = []

def _is_geo_fenced(ip: str) -> bool:
    """Return True if the IP should be geo-fenced."""
    import ipaddress
    with _policy_lock:
        if not _active_policies.get("geofence"):
            return False
    try:
        addr = ipaddress.ip_address(ip)
        # Skip RFC1918 private addresses — geo-fence only applies to public IPs
        if addr.is_private or addr.is_loopback or addr.is_multicast:
            return False
        # Check against loaded geo-fence ranges
        for net in _GEO_FENCE_RANGES:
            if addr in net:
                return True
    except Exception:
        pass
    return False

def _update_policy(key: str, value: bool):
    """Apply a policy change immediately — called when settings/update is received."""
    with _policy_lock:
        _active_policies[key] = value
    if key == "ghostProtocol":
        threading.Thread(target=_apply_ghost_protocol, args=(value,), daemon=True).start()
    elif key == "stealthMode":
        threading.Thread(target=_apply_stealth_mode, args=(value,), daemon=True).start()
    elif key == "autoIsolate" and not value:
        # Disable → release all isolations
        with _isolated_lock:
            ips_to_release = list(_auto_isolated_ips)
        for ip in ips_to_release:
            threading.Thread(target=_remove_auto_isolate, args=(ip,), daemon=True).start()
    print(f"[POLICY] {key} → {'ENABLED' if value else 'DISABLED'}", flush=True)

# Network I/O tracking
_net_last      = None
_net_last_time = None

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
_alert_buffer:     list  = []   # in-memory write buffer (flushed to disk in batches)
_alert_flush_size: int   = 50   # flush to disk every N new alerts
_alert_flush_time: float = 0.0  # timestamp of last flush
_ALERT_FLUSH_INTERVAL    = 5.0  # also flush every 5 seconds regardless of count

# Seed counters from alerts.json at startup.
# alerts.json is cleared on every restart (above), so this always starts at 0.
# The disk counter and ring are kept for the case where someone edits the file
# externally — a cheap scan confirms it's empty and skips all parsing.
try:
    _alerts_file_path = os.path.join(BASE_DIR, "alerts.json")
    if os.path.exists(_alerts_file_path):
        with open(_alerts_file_path, "r", encoding="utf-8", errors="ignore") as _af:
            _raw_head = _af.read(512)   # just peek — if empty/[] skip all parsing
        if len(_raw_head.strip()) > 2:   # not empty / not "[]"
            with open(_alerts_file_path, "r", encoding="utf-8", errors="ignore") as _af:
                _raw = _af.read()
            _alerts_disk_count = _raw.count('"id"')
            try:
                _all_seed = json.loads(_raw)
                for _a in _all_seed[-500:]:
                    _recent_alerts.append(_a)
            except Exception:
                pass
            del _raw
        else:
            _alerts_disk_count = 0
    else:
        _alerts_disk_count = 0
except Exception:
    _alerts_disk_count = 0

def _save_alert(alert: dict):
    """
    Thread-safe append to the in-memory alert buffer.
    Flushes to alerts.json when EITHER:
      • the buffer reaches _alert_flush_size new alerts, OR
      • _ALERT_FLUSH_INTERVAL seconds have elapsed since the last flush.
    This avoids reading + rewriting the entire file on every single alert.
    """
    global _alert_buffer, _alert_flush_time, _alerts_disk_count
    with _alerts_lock:
        try:
            # Stamp with current session ID so reports can filter to just this session
            if "session" not in alert:
                alert = {**alert, "session": _current_session_id}
            _alert_buffer.append(alert)
            _recent_alerts.append(alert)   # keep ring current
            now = time.time()
            if (len(_alert_buffer) >= _alert_flush_size or
                    now - _alert_flush_time >= _ALERT_FLUSH_INTERVAL):
                existing = []
                if os.path.exists(CONFIG["ALERTS_FILE"]):
                    try:
                        with open(CONFIG["ALERTS_FILE"], "r") as f:
                            existing = json.load(f)
                    except Exception:
                        existing = []
                existing.extend(_alert_buffer)
                _alert_buffer = []
                _alert_flush_time = now
                trimmed = existing[-50000:]
                with open(CONFIG["ALERTS_FILE"], "w") as f:
                    json.dump(trimmed, f, separators=(",", ":"))
                _alerts_disk_count = len(trimmed)   # keep counter in sync
        except Exception:
            pass

def _flush_alerts_now():
    """Force-flush any buffered alerts to disk immediately (call on shutdown/sweep end)."""
    global _alert_buffer, _alert_flush_time, _alerts_disk_count
    with _alerts_lock:
        if not _alert_buffer:
            return
        try:
            existing = []
            if os.path.exists(CONFIG["ALERTS_FILE"]):
                try:
                    with open(CONFIG["ALERTS_FILE"], "r") as f:
                        existing = json.load(f)
                except Exception:
                    existing = []
            existing.extend(_alert_buffer)
            _alert_buffer = []
            _alert_flush_time = time.time()
            trimmed = existing[-50000:]
            with open(CONFIG["ALERTS_FILE"], "w") as f:
                json.dump(trimmed, f, separators=(",", ":"))
            _alerts_disk_count = len(trimmed)   # keep counter in sync
        except Exception:
            pass

def _load_alerts(max_entries: int = 100_000) -> list:
    """Load alerts from disk, capped at max_entries to keep RAM usage bounded.

    Includes automatic corruption recovery: if the JSON file is truncated or
    malformed (common after a large concurrent sweep write), it attempts to
    salvage the valid prefix by truncating at the last complete JSON object.
    """
    try:
        with _alerts_lock:
            if not os.path.exists(CONFIG["ALERTS_FILE"]):
                return []
            with open(CONFIG["ALERTS_FILE"], "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            if not raw.strip():
                return []
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # Corruption recovery: find the last complete '}' before a ','
                # or ']' and reconstruct a valid JSON array from the prefix.
                last_ok = raw.rfind("},")
                if last_ok == -1:
                    last_ok = raw.rfind("}")
                if last_ok > 0:
                    try:
                        data = json.loads(raw[:last_ok + 1] + "]")
                        # Re-write the repaired file so future reads are clean
                        trimmed = data[-max_entries:]
                        with open(CONFIG["ALERTS_FILE"], "w") as _wf:
                            json.dump(trimmed, _wf)
                        data = trimmed
                    except Exception:
                        return []
                else:
                    return []
            return data[-max_entries:] if len(data) > max_entries else data
    except Exception:
        return []

_SETTINGS_DEFAULTS = {
    "systemName":"Bastion IDS","interface":"Auto","retentionDays":30,
    "cpuLimit":80,"ramLimit":80,"cnnWeight":40,"lstmWeight":35,
    "sigWeight":25,"autoIsolate":False,
    "mfaEnforce":False,"stealthMode":False,"deepInspection":True,
    "ghostProtocol":False,"apiKey":CONFIG["AUTH_KEY"],
    "logLevel":"INFO","alertThreshold":0.70,"anomalyThreshold":0.75,
    # Detection sensitivity sliders. Deliberately NOT named sigWeight /
    # mlThreshold — those keys carried a different meaning (engine balance
    # weights) in older installs and stale values would poison thresholds.
    "sigConfFloor":70,"mlVoteThreshold":60,"anomalySensitivity":50,
}

# Keys with no default that are still legitimate persisted state.
_SETTINGS_EXTRA_KEYS = {
    "dpi_target", "dpi_enabled", "quarantined_ips", "last_quarantine",
    "system_mode",
}

# The only keys allowed to exist in settings.json. Anything else — stray
# request fields ({policy, value, key}), retired toggles from old UI builds —
# is dropped on both load and update so junk cannot accumulate.
_SETTINGS_ALLOWED_KEYS = set(_SETTINGS_DEFAULTS) | _SETTINGS_EXTRA_KEYS

def _load_settings() -> dict:
    try:
        if os.path.exists(CONFIG["SETTINGS_FILE"]):
            with open(CONFIG["SETTINGS_FILE"]) as f:
                on_disk = json.load(f)
            # Merge: defaults first, then on-disk values override.
            # This ensures newly-added default fields are always present.
            merged = {**_SETTINGS_DEFAULTS, **on_disk}
            return {k: v for k, v in merged.items() if k in _SETTINGS_ALLOWED_KEYS}
    except Exception:
        pass
    return dict(_SETTINGS_DEFAULTS)

def _save_settings(data: dict):
    with open(CONFIG["SETTINGS_FILE"], "w") as f:
        json.dump(data, f, indent=2)

# ─────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    print("BASTION API v2.0 STARTING — 4-Layer Detection Pipeline Ready")
    # Warm up psutil's CPU sampler so cpu_percent(interval=None) returns
    # a real value immediately instead of 0.0 on the first health poll.
    psutil.cpu_percent(interval=None)
    # ── ML inference warmup ───────────────────────────────────────────────
    # TensorFlow/Keras lazy-initialises its inference graph on the FIRST
    # call to model.predict().  Without a warmup the first /api/v1/analyze
    # request takes 10-15 s instead of <1 s.  Run a silent dummy inference
    # at startup so every subsequent real request responds fast.
    def _warmup():
        try:
            dummy = pd.DataFrame([{
                "proto":"tcp","service":"http","state":"CON","dur":0.0,"rate":0.0,
                "spkts":1,"dpkts":0,"sbytes":60,"dbytes":0,"sttl":64,"dttl":64,
                "sload":0.0,"dload":0.0,"sloss":0,"dloss":0,"sinpkt":0.0,"dinpkt":0.0,
                "sjit":0.0,"djit":0.0,"swin":0,"stcpb":0,"dtcpb":0,"dwin":0,
                "tcprtt":0.0,"synack":0,"ackdat":0,"smean":60,"dmean":0,
                "trans_depth":0,"response_body_len":0,"ct_srv_src":0,"ct_state_ttl":0,
                "ct_dst_ltm":0,"ct_src_dport_ltm":0,"ct_dst_sport_ltm":0,"ct_dst_src_ltm":0,
                "is_ftp_login":0,"ct_ftp_cmd":0,"ct_flw_http_mthd":0,"ct_src_ltm":0,
                "ct_srv_dst":0,"is_sm_ips_ports":0,"sport":0,"dport":80,
            }])
            engine.analyze_flow(dummy)
            print("[Warmup] ML inference graph pre-initialised — first /analyze will be fast", flush=True)
        except Exception as _wex:
            print(f"[Warmup] skipped: {_wex}", flush=True)
    import threading as _thr
    _thr.Thread(target=_warmup, daemon=True).start()

# ─────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────
@app.get("/api/v1/health")
async def health_check():
    global _net_last, _net_last_time
    mem   = psutil.virtual_memory()
    disk  = psutil.disk_usage("/")
    now   = time.time()
    curr_net = psutil.net_io_counters()
    rx, tx   = 0.0, 0.0
    if _net_last and _net_last_time:
        dt = now - _net_last_time
        if dt > 0:
            rx = (curr_net.bytes_recv - _net_last.bytes_recv) / dt
            tx = (curr_net.bytes_sent - _net_last.bytes_sent) / dt
    _net_last, _net_last_time = curr_net, now
    # Non-blocking CPU (returns cached value from psutil's background sampler)
    # The first call may return 0.0 until the background interval fires — that's OK.
    cpu_val  = psutil.cpu_percent(interval=None)
    ram_val  = mem.percent
    # Alert count — read the O(1) counter, never touch alerts.json here.
    # Reading the full alerts.json (potentially several MB / 50k entries) inside
    # an async handler blocks the event loop and causes the frontend to see
    # the backend as unreachable, producing the red/green engine-status flapping.
    try:
        alerts_total = _alerts_disk_count + len(_alert_buffer)
    except Exception:
        alerts_total = 0
    # Refresh engine status dynamically — models may have loaded lazily after startup
    try:
        model_st = engine.get_model_status()
    except Exception:
        model_st = ENGINE_STATUS   # fallback to startup snapshot
    return {
        "status":          "ONLINE",
        "timestamp":       datetime.datetime.now().isoformat(),
        # Usage metrics — both key variants for frontend compatibility
        "cpu_usage":       cpu_val,
        "ram_usage":       ram_val,
        "cpu_percent":     cpu_val,   # alias expected by SystemHealth / AdminManagement
        "ram_percent":     ram_val,   # alias expected by SystemHealth / AdminManagement
        "storage_usage":   float(disk.percent),
        "net_rx":          round(rx, 1),
        "net_tx":          round(tx, 1),
        "uptime":          str(datetime.timedelta(seconds=int(now - boot_time))),
        "signatures_active": ENGINE_STATUS.get("signatures_active", 0),
        "alerts_total":    alerts_total,
        "layers_active":   ENGINE_STATUS.get("layers_active", 0),
        # Live alert-confidence gate — reflects the Signature Confidence Floor
        # slider so the UI can show the real operating threshold.
        "detection_threshold": _alert_threshold,
        # Nested model status (original shape)
        "model_status":    model_st,
        # Flattened model flags at root level — expected by frontend components
        "ml_rf":           model_st.get("ml_rf", False),
        "ml_xgb":          model_st.get("ml_xgb", False),
        "ml_cat":          model_st.get("ml_cat", False),
        "dl":              model_st.get("dl", False),
        "anomaly":         model_st.get("anomaly", False),
        "signature_engine": model_st.get("signature_engine", False),
        "is_capturing":    is_sniffing,
        "current_interface": current_interface or "all",
        "lockdown_active": _lockdown_active,
        "mode":            "LOCKDOWN" if _lockdown_active else ("CAPTURING" if is_sniffing else "ACTIVE"),
        # Flows = live capture + batch sweep combined so Operations Center shows real numbers
        "packets_processed": packet_counter + session_flow_count,
        "sniffer_error":   _sniffer_error,
        # Interface health: warn if only ARP seen (wrong interface / virtual adapter)
        "interface_warning": _get_interface_warning(),
    }

def _get_interface_warning() -> str | None:
    """Return a warning string if the active capture interface is only seeing broadcast/ARP traffic.

    Three possible scenarios:
      (a) User is on a virtual adapter (VMnet, VEthernet) — recommend the real Wi-Fi/Ethernet
      (b) User is on the *real* Wi-Fi but Npcap promiscuous mode is off or the adapter
          is in infrastructure mode — explain the limitation, don't suggest switching
      (c) Genuinely no traffic — let the user know
    """
    if not is_sniffing or not _packet_ring:
        return None
    pkts = list(_packet_ring)
    if len(pkts) < 25:
        return None   # too early to judge — wait for more packets

    protos = {p.get("Protocol", "?") for p in pkts}
    non_broadcast = protos - {"ARP", "ETH", "?"}
    if non_broadcast:
        return None   # real IP traffic is flowing — no issue

    # Identify whether the current interface itself looks virtual
    cur = (current_interface or "").lower()
    is_virtual = any(tok in cur for tok in (
        "vmnet", "vethernet", "vmware", "hyper-v", "virtualbox", "vbox",
        "loopback", "pseudo", "tunnel", "isatap", "teredo", "tap-",
    ))
    is_wifi = any(tok in cur for tok in ("wi-fi", "wifi", "wireless", "802.11"))

    try:
        import psutil as _psu
        all_stats = _psu.net_if_stats()
        all_addrs = _psu.net_if_addrs()
        candidates = []
        for name, addrs in all_addrs.items():
            st = all_stats.get(name)
            if not st or not st.isup:
                continue
            name_l = name.lower()
            # Skip non-routable / virtual / itself
            if any(tok in name_l for tok in (
                "loopback", "pseudo", "bluetooth", "vmnet", "vethernet",
                "vmware", "hyper-v", "virtualbox", "vbox",
                "tunnel", "isatap", "teredo", "tap-",
            )):
                continue
            # Skip the currently selected interface — never recommend itself
            if name == current_interface or name_l == cur:
                continue
            ipv4 = next((a.address for a in addrs
                         if a.family == 2 and not a.address.startswith("169.254")
                         and a.address != "127.0.0.1"), None)
            if ipv4:
                candidates.append((name, ipv4))

        def _score(n):
            nl = n.lower()
            if "ethernet" in nl or "lan" in nl: return 3   # wired beats wifi for IDS
            if "wi-fi" in nl or "wifi" in nl or "wireless" in nl: return 2
            return 1
        candidates.sort(key=lambda x: _score(x[0]), reverse=True)
    except Exception:
        candidates = []

    # Scenario A: virtual adapter, real alternative available
    if is_virtual and candidates:
        rec_name, rec_ip = candidates[0]
        return (f"⚠ Only broadcast packets on virtual adapter '{current_interface}' — "
                f"switch to '{rec_name}' ({rec_ip}) for real network traffic.")

    # Scenario B: on real Wi-Fi adapter
    if is_wifi:
        if candidates:
            wired = [c for c in candidates if "ethernet" in c[0].lower() or "lan" in c[0].lower()]
            if wired:
                rec_name, rec_ip = wired[0]
                return (f"⚠ Only broadcast packets visible on Wi-Fi adapter '{current_interface}'. "
                        f"Wi-Fi in infrastructure mode only sees YOUR traffic + broadcasts. "
                        f"Connect to '{rec_name}' ({rec_ip}) wired for full LAN visibility, "
                        f"or generate traffic from this host (open a browser) to confirm capture works.")
        return (f"⚠ Only broadcast packets visible on Wi-Fi adapter '{current_interface}'. "
                f"This is normal — Wi-Fi adapters only see YOUR machine's traffic and broadcasts. "
                f"Open a browser or ping a host to generate traffic that will be captured. "
                f"For full network visibility, use a wired connection or enable Npcap promiscuous mode.")

    # Scenario C: not virtual, not Wi-Fi — could be Ethernet in switched network
    if candidates:
        rec_name, rec_ip = candidates[0]
        return (f"⚠ Only broadcast packets on '{current_interface}'. "
                f"If this is a switched network you'll only see traffic to/from this host. "
                f"Alternative interface available: '{rec_name}' ({rec_ip}).")

    # No alternatives — give a generic explanation
    return (f"⚠ Only broadcast traffic seen on '{current_interface}'. "
            f"In switched networks you can only capture traffic to/from this host. "
            f"For full network visibility you need a SPAN/mirror port or monitor-mode adapter.")

# ─────────────────────────────────────────────────────────────
# STARTUP LOG (for dashboard "system messages" panel)
# ─────────────────────────────────────────────────────────────
@app.get("/api/v1/startup-log")
async def get_startup_log():
    """Return engine initialization messages for the dashboard."""
    return {"log": ENGINE_STARTUP_LOG}

# ─────────────────────────────────────────────────────────────
# NETWORK TOPOLOGY
# ─────────────────────────────────────────────────────────────

# MAC OUI → vendor map (first 8 chars of normalised MAC, e.g. "aa:bb:cc")
_MAC_OUI: dict = {
    # Apple
    "a4:83:e7":"Apple","3c:15:c2":"Apple","ac:87:a3":"Apple",
    "28:cf:e9":"Apple","f0:18:98":"Apple","88:e9:fe":"Apple",
    "00:a0:dd":"Apple","40:33:1a":"Apple","8c:85:90":"Apple",
    "dc:2b:61":"Apple","70:48:0f":"Apple","f4:31:c3":"Apple",
    "6c:40:08":"Apple","a8:86:dd":"Apple","00:50:e4":"Apple",
    "48:d7:05":"Apple","bc:f5:ac":"Apple","7c:d1:c3":"Apple",
    "3c:06:30":"Apple","04:52:f3":"Apple",
    # Samsung (Android)
    "78:d6:f0":"Samsung","8c:f5:a3":"Samsung","b8:5e:7b":"Samsung",
    "00:07:ab":"Samsung","cc:07:ab":"Samsung","a4:23:05":"Samsung",
    "50:01:bb":"Samsung","24:4b:03":"Samsung","84:11:9e":"Samsung",
    "d0:22:be":"Samsung","78:9e:d0":"Samsung","94:51:03":"Samsung",
    # Huawei (Android)
    "00:e0:fc":"Huawei","70:f9:6d":"Huawei","9c:28:ef":"Huawei",
    "c0:b8:83":"Huawei","28:31:52":"Huawei","b4:cd:27":"Huawei",
    # Xiaomi (Android)
    "f8:a4:5f":"Xiaomi","64:b4:73":"Xiaomi","00:ec:0a":"Xiaomi",
    # OnePlus (Android)
    "98:0c:a5":"OnePlus","28:3f:69":"OnePlus",
    # Microsoft
    "00:50:f2":"Microsoft","28:18:78":"Microsoft","7c:1e:52":"Microsoft",
    # Cisco
    "c8:4c:75":"Cisco","00:1b:d5":"Cisco","00:26:cb":"Cisco",
    "58:f3:9c":"Cisco","00:50:0f":"Cisco","e8:ba:70":"Cisco",
    # Raspberry Pi (Linux)
    "b8:27:eb":"Raspberry Pi","dc:a6:32":"Raspberry Pi","e4:5f:01":"Raspberry Pi",
    # VMware (virtual)
    "00:50:56":"VMware","00:0c:29":"VMware","00:05:69":"VMware",
    # Dell
    "14:18:77":"Dell","18:66:da":"Dell","f8:ca:b8":"Dell",
    # HP
    "10:60:4b":"HP","00:1b:78":"HP","3c:d9:2b":"HP",
    # Lenovo
    "54:ee:75":"Lenovo","48:51:b7":"Lenovo","00:23:ae":"Lenovo",
    # Netgear
    "00:14:6c":"Netgear","a0:21:b7":"Netgear","20:e5:2a":"Netgear",
    # TP-Link
    "50:c7:bf":"TP-Link","a8:57:4e":"TP-Link","14:cc:20":"TP-Link",
}

def _vendor_from_mac(mac: str) -> str:
    """Return vendor name from MAC OUI prefix."""
    if not mac or mac in ("?", "local"):
        return ""
    m = mac.lower().replace("-", ":")
    prefix6 = m[:8]   # xx:xx:xx
    return _MAC_OUI.get(prefix6, "")

def _os_from_ttl(ttl: int) -> str:
    """Estimate OS family from ICMP/TCP TTL value (coarse fallback only)."""
    if ttl <= 0:     return "Unknown"
    if ttl <= 64:    return "Linux / Unix"
    if ttl <= 128:   return "Windows"
    return "Cisco / Network Device"

def _fingerprint_os(ttl: int, mac: str = "", tcp_window: int = 0,
                    tcp_options: list = None, ports: set = None,
                    hostname: str = "", banner_hints: dict = None) -> str:
    """
    Multi-factor OS fingerprinting (nmap-style confidence chain).
    Priority: MAC OUI → hostname hints → TCP window+options (p0f) → ports → TTL fallback.
    Returns a human-readable OS string with version hints where possible.
    """
    if tcp_options  is None: tcp_options  = []
    if ports        is None: ports        = set()
    if banner_hints is None: banner_hints = {}

    vendor = _vendor_from_mac(mac)

    # 1. MAC OUI overrides (highest confidence — hardware doesn't lie)
    if vendor == "Apple":
        mobile_ports = {5353, 62078}
        if ports & mobile_ports:
            return "Apple iOS 14+ (iPhone/iPad)"
        if tcp_window == 65535:
            return "Apple macOS 12+ (Monterey/Ventura)"
        return "Apple macOS / iOS"
    if vendor == "Samsung":
        return "Android (Samsung)"
    if vendor in ("Huawei", "Xiaomi", "OnePlus"):
        return f"Android ({vendor})"
    if vendor == "Raspberry Pi":
        return "Linux — Raspberry Pi OS"
    if vendor == "VMware":
        return "Virtual Machine (VMware)"
    if vendor in ("VirtualBox", "Microsoft"):
        # Microsoft MACs appear on Hyper-V VMs and Azure VMs too
        if ttl in range(60, 65):
            return "Linux (Microsoft / Hyper-V VM)"
        return "Windows (Hyper-V / Azure VM)"
    if vendor == "Cisco":
        if 443 in ports or 8443 in ports:
            return "Cisco IOS XE (HTTPS mgmt)"
        return "Cisco IOS / Network Device"
    if vendor in ("Netgear", "TP-Link", "D-Link", "Linksys", "ASUS", "Belkin"):
        return f"Router / AP Firmware ({vendor})"

    # 2. Hostname hints (reverse-DNS often reveals OS / device class)
    if hostname:
        hl = hostname.lower()
        if any(x in hl for x in ["iphone","ipad","macbook","apple","airplay","airdrop"]):
            return "Apple iOS / macOS"
        if any(x in hl for x in ["android","samsung","pixel","nexus"]):
            return "Android"
        if any(x in hl for x in ["win10","win11","msft","microsoft","desktop","laptop"]):
            return "Windows 10/11"
        if "windows" in hl:
            return "Windows"
        if any(x in hl for x in ["router","gateway","cisco","ubnt","mikrotik","asus-rt"]):
            return "Network Device / Router"
        if any(x in hl for x in ["ubuntu","debian","centos","fedora","arch","kali"]):
            h = next((x for x in ["ubuntu","debian","centos","fedora","arch","kali"] if x in hl), "")
            return f"Linux ({h.capitalize()})" if h else "Linux / Unix"
        if "raspberr" in hl:
            return "Linux — Raspberry Pi OS"
        if any(x in hl for x in ["nas","synology","qnap","freenas","truenas"]):
            return "NAS / Storage (Linux)"
        if any(x in hl for x in ["printer","hp","epson","brother","canon"]):
            return "Network Printer"
        if "android" in hl:
            return "Android"

    # 3. TCP window size + options (p0f-inspired — moderately confident)
    if tcp_window:
        opts_str = str(tcp_options)
        has_ts   = any(isinstance(o, tuple) and o[0] == 8  for o in tcp_options)
        has_sack = any(isinstance(o, tuple) and o[0] == 4  for o in tcp_options)
        has_nop  = "NOP" in opts_str
        has_mss  = any(isinstance(o, tuple) and o[0] == 2  for o in tcp_options)

        if tcp_window == 65535 and has_ts:
            if ttl in range(60, 65):
                return "Apple macOS (BSD stack)"
            return "Apple macOS / FreeBSD"
        if tcp_window == 65535 and has_nop and ttl in range(126, 129):
            return "Windows 10 / Server 2019"
        if tcp_window == 64240:
            if ttl in range(60, 65):
                return "Linux (Kernel 5.x — Ubuntu/Debian)"
            if ttl in range(126, 129):
                return "Windows 10 / Server 2016+"
            return "Linux (Kernel 4.x–5.x)"
        if tcp_window == 29200 and ttl in range(60, 65):
            return "Linux (Kernel 5.x)"
        if tcp_window == 8192 and has_nop and ttl in range(126, 129):
            return "Windows Vista / 7 / Server 2008"
        if tcp_window in (65535, 8192, 16384) and ttl in range(126, 129):
            return "Windows (8/10/Server)"
        if tcp_window == 5840 and ttl in range(60, 65):
            return "Linux (Kernel 2.4–3.x)"
        if tcp_window in (4128, 512):
            return "Cisco IOS"
        if tcp_window in (16384, 32768) and ttl > 240:
            return "Cisco / Network Device"
        if tcp_window == 32768 and ttl in range(60, 65):
            return "Linux / OpenBSD"
        if tcp_window == 4380 and ttl > 240:
            return "Juniper JunOS"

    # 4. Port + banner hints (high specificity, lower coverage)
    if banner_hints.get("rdp") or 3389 in ports:
        if ttl in range(126, 129):
            return "Windows (RDP — likely Win10/11)"
        return "Windows (RDP enabled)"
    if banner_hints.get("winrm") or 5985 in ports:
        return "Windows (WinRM — PowerShell remoting)"
    if banner_hints.get("smb") or 445 in ports:
        if ttl in range(126, 129):
            return "Windows (SMB — Active Directory candidate)"
        return "Windows / Samba (SMB)"
    if 62078 in ports:
        return "Apple iOS (iTunes Wi-Fi Sync)"
    if banner_hints.get("ssh") or 22 in ports:
        if ttl in range(60, 65):
            return "Linux / Unix (SSH)"
        if ttl in range(126, 129):
            return "Windows (OpenSSH)"
    if 5353 in ports:   # mDNS
        if vendor == "Apple" or ttl in range(60, 65):
            return "Apple macOS / iOS (mDNS)"
        return "Linux / Unix (Avahi mDNS)"
    if 9100 in ports:
        return "Network Printer (JetDirect)"
    if {8080, 8443, 80, 443} & ports and ttl > 240:
        return "Network Device (HTTP mgmt)"

    # 5. TTL-only fallback (lowest confidence — coarse classification)
    if ttl <= 0:   return "Unknown"
    if ttl <= 64:  return "Linux / Unix"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco / Network Device"
    return "Unknown"

@app.get("/api/v1/topology")
async def fetch_topology(interface: str = None):
    """
    Returns the topology cache immediately (no blocking ARP scan on the HTTP path).
    The background _topology_refresh_loop keeps the cache fresh every 30 seconds.
    If the cache is empty (first boot, scan not finished yet), return a minimal
    placeholder so the frontend renders without the 'discovery failed' error.
    """
    global last_topology_interface
    if interface:
        last_topology_interface = interface
        # User selected a specific interface — trigger an async refresh for that iface
        threading.Thread(
            target=lambda: _trigger_iface_refresh(interface), daemon=True
        ).start()

    with _topology_cache_lock:
        cached = dict(_topology_cache)

    # If cache is still empty (server just started, scan in progress) return minimal node
    if not cached["nodes"]:
        cached = {
            "nodes": [{"id":"CORE-IDS","type":"server","label":"Bastion Host",
                       "status":"scanning","x":500,"y":280,"ip":"127.0.0.1",
                       "mac":"local","os":"Bastion IDS v2.0","ttl":0}],
            "connections": [],
            "interface": interface or "auto",
            "total_devices": 0,
            "scanning": True,
        }

    cached["interface"] = interface or last_topology_interface or "auto"
    return cached

def _trigger_iface_refresh(iface: str):
    """Immediately run an ARP scan for a specific interface and update the cache."""
    import math, time as _time
    try:
        nodes, connections, target_subnet, _ = _run_arp_scan(iface)
        # Subnet-specific filtering — only include live devices in this interface's subnet
        subnet_prefix = ".".join(target_subnet.split(".")[:3]) + "." if target_subnet else None
        # Only include devices seen in the last 5 minutes — stops stale hosts that
        # disconnected hours ago from cluttering the topology view.
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=5)
        with _device_lock:
            live_devs = dict(_discovered_devices)
        existing_ips = {n["ip"] for n in nodes}
        for ip, info in live_devs.items():
            if not _is_lan_ip(ip):
                continue
            if subnet_prefix and not ip.startswith(subnet_prefix):
                continue
            if ip in existing_ips or ip in ("0.0.0.0", "255.255.255.255"):
                continue
            # Active-host filter
            try:
                ls = datetime.datetime.fromisoformat(info.get("last_seen", ""))
                if ls < cutoff:
                    continue   # stale — don't show
            except Exception:
                continue
            i = len(nodes)
            angle = math.radians(i * 30 - 90)
            r = 250
            nodes.append({
                "id": f"LIVE-{ip.replace('.','_')}",
                "type": "workstation",
                "label": info.get("hostname") or f"Host {ip}",
                "status": "active",
                "x": round(500 + r * math.cos(angle), 1),
                "y": round(280 + r * math.sin(angle), 1),
                "ip": ip, "mac": info.get("mac","?"),
                "os": info.get("os","Unknown"), "ttl": info.get("ttl",0),
                "hostname": info.get("hostname",""),
                "pkt_count": info.get("pkt_count",0),
                "source": "live_capture",
            })
            existing_ips.add(ip)
            connections.append({"from":"CORE-IDS","to":f"LIVE-{ip.replace('.','_')}","speed":"live"})
        with _topology_cache_lock:
            _topology_cache.update({
                "nodes":         nodes,
                "connections":   connections,
                "interface":     iface,
                "total_devices": len(nodes) - 1,
                "target_subnet": target_subnet,
            })
    except Exception:
        pass

@app.post("/api/v1/topology/scan")
async def topology_scan_now(body: dict = Body({})):
    """
    Blocking full ARP scan for a given interface.
    Called by the frontend 'Rescan Network' button — runs synchronously in a
    thread-pool worker so FastAPI doesn't block the event loop.
    Returns the fresh topology data immediately so the frontend can update
    without waiting for the next background-loop cycle.
    """
    global last_topology_interface
    import math, asyncio as _asyncio, concurrent.futures as _cf

    iface = body.get("interface") or last_topology_interface
    if iface:
        last_topology_interface = iface

    def _do_scan():
        nodes, connections, target_subnet, host_ip = _run_arp_scan(iface)
        subnet_prefix = ".".join(target_subnet.split(".")[:3]) + "." if target_subnet else None
        # Active-host filter: only include devices with packets in the last 5 minutes
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=5)
        with _device_lock:
            live_devs = dict(_discovered_devices)
        existing_ips = {n["ip"] for n in nodes}
        for ip, info in live_devs.items():
            if not _is_lan_ip(ip):
                continue
            if subnet_prefix and not ip.startswith(subnet_prefix):
                continue
            if ip in existing_ips or ip in ("0.0.0.0", "255.255.255.255"):
                continue
            try:
                ls = datetime.datetime.fromisoformat(info.get("last_seen", ""))
                if ls < cutoff:
                    continue
            except Exception:
                continue
            idx = len(nodes)
            angle = math.radians(idx * 30 - 90)
            r = 250
            nodes.append({
                "id": f"LIVE-{ip.replace('.','_')}",
                "type": "workstation",
                "label": info.get("hostname") or f"Host {ip}",
                "status": "active",
                "x": round(500 + r * math.cos(angle), 1),
                "y": round(280 + r * math.sin(angle), 1),
                "ip": ip, "mac": info.get("mac","?"),
                "os": info.get("os","Unknown"), "ttl": info.get("ttl",0),
                "hostname": info.get("hostname",""),
                "pkt_count": info.get("pkt_count",0),
                "source": "live_capture",
            })
            existing_ips.add(ip)
            connections.append({"from":"CORE-IDS","to":f"LIVE-{ip.replace('.','_')}","speed":"live"})
        result = {
            "nodes":         nodes,
            "connections":   connections,
            "interface":     iface or "auto",
            "total_devices": len(nodes) - 1,
            "target_subnet": target_subnet,
        }
        with _topology_cache_lock:
            _topology_cache.update(result)
        return result

    # Run blocking ARP scan in a thread-pool worker (non-blocking for the event loop)
    loop = _asyncio.get_event_loop()
    with _cf.ThreadPoolExecutor(max_workers=1) as pool:
        result = await loop.run_in_executor(pool, _do_scan)
    return result


@app.get("/api/v1/topology/devices")
async def get_all_devices(include_stale: bool = False, active_window_sec: int = 300):
    """Return discovered devices.

    By default returns ONLY active devices (last_seen within `active_window_sec`
    seconds — 5 minutes).  Pass include_stale=true to get every device ever
    observed.  Each device gets an "is_active" field for the frontend to colour.

    A device is considered active if its `last_seen` is within the window OR
    its IP is currently in the live ARP topology cache (gateway/router/etc.).
    """
    now = datetime.datetime.now()
    cutoff = now - datetime.timedelta(seconds=max(60, int(active_window_sec)))
    # IPs currently in the topology cache count as active even if no recent packets
    with _topology_cache_lock:
        cached_ips = {n.get("ip") for n in _topology_cache.get("nodes", []) if n.get("ip")}

    with _device_lock:
        devs = []
        for ip, info in _discovered_devices.items():
            d = dict(info)
            d["ports"] = sorted(list(d.get("ports", set())))
            # Parse last_seen → datetime to compare
            try:
                ls = datetime.datetime.fromisoformat(d.get("last_seen", ""))
                is_active = ls >= cutoff
            except Exception:
                is_active = False
            if ip in cached_ips:
                is_active = True
            d["is_active"] = is_active
            if not is_active and not include_stale:
                continue
            devs.append(d)
    # Sort active first, then by most recent
    devs.sort(key=lambda x: (not x.get("is_active", False), x.get("last_seen", "")), reverse=False)
    return {
        "devices":      devs,
        "count":        len(devs),
        "active_count": sum(1 for d in devs if d.get("is_active")),
        "window_sec":   active_window_sec,
    }

_VIRTUAL_IFACE_HINTS = (
    "vmnet", "vmware", "vethernet", "virtual", "loopback", "bluetooth",
    "hyper-v", "default switch", "npcap loopback", "wan miniport",
    "teredo", "isatap", "tap-", "tunnel", "docker",
)

def _iface_is_virtual(name: str) -> bool:
    nl = (name or "").lower()
    return any(h in nl for h in _VIRTUAL_IFACE_HINTS)

def _default_route_ip() -> str:
    """IP of the interface that owns the machine's default route.

    Uses a UDP socket that is 'connected' but sends nothing — the OS picks the
    egress interface, and getsockname() reveals its source IP. This is the most
    reliable cross-machine way to identify the real active NIC (no hardcoding).
    """
    import socket
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))   # no packet actually sent for UDP
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        if s is not None:
            try: s.close()
            except Exception: pass

@app.get("/api/v1/network/interfaces")
async def get_interfaces():
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    route_ip = _default_route_ip()
    result = []
    for name, stat in stats.items():
        ipv4 = next((a.address for a in addrs.get(name, [])
                     if a.family == 2), "")
        result.append({
            "name": name, "ip": ipv4,
            "speed": stat.speed, "is_up": stat.isup,
            "virtual": _iface_is_virtual(name),
            "has_default_route": bool(ipv4) and ipv4 == route_ip,
            "recommended": False,
        })

    # Recommended = the interface an IDS should watch: a REAL physical NIC that
    # is up and has an IP. Preference Wi-Fi > Ethernet > other physical. We do
    # NOT follow the default route here because an active VPN pushes the default
    # route onto a tunnel adapter, which is not what we want to monitor.
    def _phys_rank(i):
        if not (i["is_up"] and i["ip"] and not i["virtual"]):
            return 99
        nl = i["name"].lower()
        if any(k in nl for k in ("wi-fi", "wifi", "wireless", "wlan")): return 0
        if any(k in nl for k in ("ethernet", "eth", "lan")):            return 1
        return 2
    candidates = [i for i in result if _phys_rank(i) < 99]
    if candidates:
        best = min(candidates, key=_phys_rank)
        best["recommended"] = True

    # Physical first, recommended at the very top; virtual/down last.
    result.sort(key=lambda i: (
        not i["recommended"], i["virtual"], not i["is_up"], not i["ip"],
    ))
    return result

# ─────────────────────────────────────────────────────────────
# LIVE CAPTURE (WebSocket + multi-interface)
# ─────────────────────────────────────────────────────────────
async def _broadcast(data: dict):
    dead = []
    for ws in list(active_websockets):
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        try: active_websockets.remove(ws)
        except ValueError: pass

# ── In-memory device + flow tracking for live capture ────────────────────────
_discovered_devices: dict = {}   # ip -> {mac, os, ttl, hostname, ports, first_seen, last_seen, pkt_count}
_flow_table:         dict = {}   # (src,dst,sport,dport,proto) -> {spkts,dpkts,sbytes,dbytes,start}
_device_lock = threading.Lock()

def _resolve_hostname(ip: str) -> str:
    import socket
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def _port_to_service(port: int) -> str:
    _SVC = {
        20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",
        53:"DNS",67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",
        123:"NTP",135:"RPC",139:"SMB",143:"IMAP",161:"SNMP",
        389:"LDAP",443:"TLS",445:"SMB",465:"SMTPS",514:"SYSLOG",
        587:"SMTP",636:"LDAPS",993:"IMAPS",995:"POP3S",
        1433:"MSSQL",1521:"ORACLE",3306:"MYSQL",3389:"RDP",
        5432:"POSTGRES",5900:"VNC",6379:"REDIS",8080:"HTTP-ALT",
        8443:"HTTPS-ALT",27017:"MONGODB",
    }
    return _SVC.get(port, "")

def _is_lan_ip(ip: str) -> bool:
    """Return True only for RFC 1918 / loopback / link-local addresses.
    Public internet IPs must never appear in the local device table."""
    import ipaddress as _ipmod   # local import guards against module-level shadowing
    try:
        a = _ipmod.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False

def _update_device(ip: str, mac: str = "", ttl: int = 0, port: int = 0,
                   tcp_window: int = 0):
    # Only track LAN/RFC1918 addresses — never public internet IPs
    if not ip or ip in ("0.0.0.0", "255.255.255.255") or not _is_lan_ip(ip):
        return
    with _device_lock:
        now = datetime.datetime.now().isoformat()
        if ip not in _discovered_devices:
            _discovered_devices[ip] = {
                "ip": ip, "mac": mac or "?",
                "os": _fingerprint_os(ttl=ttl, mac=mac or "") if ttl else "Unknown",
                "ttl": ttl, "hostname": "", "ports": set(),
                "first_seen": now, "last_seen": now, "pkt_count": 0,
                "services": [], "vendor": _vendor_from_mac(mac or ""),
                "tcp_window": tcp_window,
            }
            # Async hostname resolution (non-blocking)
            def _resolve(_ip=ip):
                h = _resolve_hostname(_ip)
                if h:
                    with _device_lock:
                        if _ip in _discovered_devices:
                            _discovered_devices[_ip]["hostname"] = h
                            # Re-fingerprint now we have hostname
                            d2 = _discovered_devices[_ip]
                            d2["os"] = _fingerprint_os(
                                ttl=d2.get("ttl", 0), mac=d2.get("mac", ""),
                                tcp_window=d2.get("tcp_window", 0),
                                ports=d2.get("ports", set()),
                                hostname=h,
                            )
            threading.Thread(target=_resolve, daemon=True).start()
        d = _discovered_devices[ip]
        d["last_seen"] = now
        d["pkt_count"] += 1
        if mac and mac != "?":
            d["mac"] = mac
            d["vendor"] = _vendor_from_mac(mac)
        if ttl:
            d["ttl"] = ttl
        if tcp_window and tcp_window > d.get("tcp_window", 0):
            d["tcp_window"] = tcp_window
        # Re-run fingerprint whenever we get new signal
        if ttl or mac or tcp_window:
            d["os"] = _fingerprint_os(
                ttl=d.get("ttl", 0), mac=d.get("mac", ""),
                tcp_window=d.get("tcp_window", 0),
                ports=d.get("ports", set()),
                hostname=d.get("hostname", ""),
            )
        if port:
            d["ports"].add(port)
            svc = _port_to_service(port)
            if svc and svc not in d["services"]:
                d["services"].append(svc)

def _process_packet(pkt, loop):
    global packet_counter, session_flow_count
    if not is_sniffing:
        return
    # Count every live packet toward the Operations Center total_analyzed counter
    session_flow_count += 1
    try:
        _process_packet_inner(pkt, loop)
    except Exception as _pp_ex:
        print(f"[_process_packet ERROR] {type(_pp_ex).__name__}: {_pp_ex}", flush=True)

def _process_packet_inner(pkt, loop):
    global packet_counter, session_flow_count
    try:
        import ipaddress  # defensive — guarantees ipaddress is in local scope
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2   import ARP, Ether
        try:
            from scapy.layers.dns import DNS
        except Exception:
            DNS = None

        now = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        pkt_len = len(pkt)

        # ── ARP: device discovery gold mine ──────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            src_ip  = arp.psrc  or ""
            src_mac = arp.hwsrc or ""
            dst_ip  = arp.pdst  or ""
            if src_ip and src_ip not in ("0.0.0.0", "255.255.255.255"):
                _update_device(src_ip, src_mac)
            with _packet_lock:
                packet_counter += 1; pkt_no = packet_counter
            pkt_info = {
                "No.": pkt_no, "Time": now,
                "Source": src_ip or src_mac, "Destination": dst_ip,
                "Protocol": "ARP", "Length": pkt_len,
                "Info": f"Who has {dst_ip}? Tell {src_ip}" if arp.op == 1 else f"{src_ip} is at {src_mac}",
                "verdict": "NORMAL", "confidence": 0.0, "source_engine": "BASTION_CLEAN",
                "src_port": 0, "dst_port": 0, "srcip": src_ip, "dstip": dst_ip,
                "proto": "arp", "timestamp": now, "flags": "",
                "src_mac": src_mac, "dst_mac": arp.hwdst or "",
                "src_vendor": _oui_lookup(src_mac),
            }
            safe_arp = _json_safe(pkt_info)
            _packet_ring.append(safe_arp)
            _raw_packet_ring.append(pkt)
            asyncio.run_coroutine_threadsafe(_broadcast(safe_arp), loop)
            return

        # ── IPv6 packets ──────────────────────────────────────────────────────
        # Windows uses IPv6 heavily (DNS, TLS, mDNS, neighbour discovery, modern
        # browsers).  Scapy uses the 'IPv6' layer (NOT 'IP') for these, so without
        # explicit handling every IPv6 packet fell through to the MAC-only fallback.
        try:
            from scapy.layers.inet6 import IPv6 as _IPv6Layer
        except Exception:
            _IPv6Layer = None

        if _IPv6Layer and pkt.haslayer(_IPv6Layer):
            ip6      = pkt[_IPv6Layer]
            src_ip   = ip6.src
            dst_ip   = ip6.dst
            src_mac  = pkt[Ether].src if pkt.haslayer(Ether) else ""
            sport, dport = 0, 0
            proto_name   = "IPv6"
            payload      = b""
            flags_v6     = ""

            if pkt.haslayer(TCP):
                t = pkt[TCP]; proto_name = "TCP"
                sport, dport = t.sport, t.dport
                flags_v6 = str(t.flags); payload = bytes(t.payload)
            elif pkt.haslayer(UDP):
                u = pkt[UDP]; proto_name = "UDP"
                sport, dport = u.sport, u.dport; payload = bytes(u.payload)

            # Protocol display name (same logic as IPv4 path)
            display6 = proto_name
            p6 = lambda *pp: any(p in pp for p in (sport, dport))
            if p6(53):          display6 = "DNS"
            elif p6(443, 8443): display6 = "TLS"
            elif p6(80, 8080):  display6 = "HTTP"
            elif p6(22):        display6 = "SSH"
            elif p6(123):       display6 = "NTP"
            elif p6(587, 465):  display6 = "SMTP"
            elif p6(3389):      display6 = "RDP"

            info6 = f"{src_ip}:{sport} → {dst_ip}:{dport}" if sport else f"{src_ip} → {dst_ip}"
            if DNS and pkt.haslayer(DNS):
                try:
                    d6 = pkt[DNS]
                    if d6.qd:
                        info6 = f"Query: {d6.qd.qname.decode(errors='replace')}"
                except Exception:
                    pass

            with _packet_lock:
                packet_counter += 1; pkt_no = packet_counter

            pkt_info = {
                "No.": pkt_no, "Time": now,
                "Source": src_ip, "Destination": dst_ip,
                "Protocol": display6, "Length": pkt_len, "Info": info6,
                "verdict": "NORMAL", "confidence": 0.0, "source_engine": "BASTION_CLEAN",
                "src_port": sport, "dst_port": dport,
                "srcip": src_ip, "dstip": dst_ip,
                "proto": proto_name.lower(), "timestamp": now,
                "flags": flags_v6, "ttl": ip6.hlim,
            }
            safe_v6 = _json_safe(pkt_info)
            _packet_ring.append(safe_v6)
            _raw_packet_ring.append(pkt)
            asyncio.run_coroutine_threadsafe(_broadcast(safe_v6), loop)
            return

        # ── Non-IP / non-ARP (raw Ethernet, VLAN, unknown EtherType) ─────────
        if not pkt.haslayer(IP):
            # Only broadcast if we have a proper Ethernet frame to parse;
            # silently drop 802.11-encapsulated frames without an Eth header.
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                with _packet_lock:
                    packet_counter += 1; pkt_no = packet_counter
                pkt_info = {
                    "No.": pkt_no, "Time": now,
                    "Source": eth.src, "Destination": eth.dst,
                    "Protocol": "ETH", "Length": pkt_len,
                    "Info": f"EtherType 0x{eth.type:04x}",
                    "verdict": "NORMAL", "confidence": 0.0, "source_engine": "BASTION_CLEAN",
                    "src_port": 0, "dst_port": 0, "srcip": "", "dstip": "",
                    "proto": "eth", "timestamp": now, "flags": "",
                }
                safe_eth = _json_safe(pkt_info)
                _packet_ring.append(safe_eth)
                _raw_packet_ring.append(pkt)
                asyncio.run_coroutine_threadsafe(_broadcast(safe_eth), loop)
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        ttl    = ip.ttl

        # Update device table for both src and dst
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        _update_device(src_ip, src_mac, ttl)
        _update_device(dst_ip, "", 0)

        sport, dport = 0, 0
        flags, payload = "", b""
        proto_name = "IP"
        tcp_win = 0

        if pkt.haslayer(TCP):
            t = pkt[TCP]; proto_name = "TCP"
            sport, dport = t.sport, t.dport
            flags = str(t.flags); payload = bytes(t.payload)
            tcp_win = t.window
            _update_device(src_ip, src_mac, ttl, sport, tcp_window=tcp_win)
            _update_device(dst_ip, "", 0, dport)
        elif pkt.haslayer(UDP):
            u = pkt[UDP]; proto_name = "UDP"
            sport, dport = u.sport, u.dport
            payload = bytes(u.payload)
            _update_device(src_ip, src_mac, ttl, sport)
            _update_device(dst_ip, "", 0, dport)
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"
            _update_device(src_ip, src_mac, ttl)
            _update_device(dst_ip, "", 0)

        # ── Protocol display name ─────────────────────────────────────────────
        display_proto = proto_name
        any_port = lambda *pp: any(p in pp for p in (sport, dport))
        if any_port(53):    display_proto = "DNS"
        elif any_port(80, 8080, 8000): display_proto = "HTTP"
        elif any_port(443, 8443):      display_proto = "TLS"
        elif any_port(22):             display_proto = "SSH"
        elif any_port(20, 21):         display_proto = "FTP"
        elif any_port(25, 587, 465):   display_proto = "SMTP"
        elif any_port(67, 68):         display_proto = "DHCP"
        elif any_port(123):            display_proto = "NTP"
        elif any_port(445, 139):       display_proto = "SMB"
        elif any_port(3389):           display_proto = "RDP"
        elif proto_name == "ICMP":     display_proto = "ICMP"

        # ── Broadcast / multicast destination guard ──────────────────────────
        # Signature rules that detect DDoS amplification (NTP, DNS, SSDP) fire
        # on the *response* packet.  When the destination is a broadcast or
        # multicast address the packet is normal LAN infrastructure traffic, not
        # an amplification attack aimed at a real victim.  Skip all signature
        # matching for such packets to eliminate NTP/SSDP DDoS false positives.
        _is_broadcast_dst = (
            dst_ip.endswith(".255") or
            dst_ip == "255.255.255.255" or
            dst_ip.startswith("224.") or   # IPv4 multicast
            dst_ip.startswith("239.")       # local multicast
        )

        # DPI: flag packets to/from the active DPI target IP
        _is_dpi_pkt = bool(_dpi_target) and (src_ip == _dpi_target or dst_ip == _dpi_target)

        # ── Signature engine (Layer 1 — only layer suitable for per-packet) ──
        verdict, conf_val, source_engine = "NORMAL", 0.0, "BASTION_CLEAN"
        if not _is_broadcast_dst:
            try:
                flow_df = pd.DataFrame([{
                    "proto": proto_name.lower(), "service": display_proto.lower(),
                    "state": "CON" if flags and "S" in flags else "INT",
                    "dur": 0.0, "rate": 0.0,
                    "spkts": 1, "dpkts": 0,
                    "sbytes": pkt_len, "dbytes": 0,
                    "smean": pkt_len, "dmean": 0,
                    "sttl": ttl, "dttl": 64,
                    "swin": getattr(pkt.getlayer(TCP), "window", 0) if proto_name == "TCP" else 0,
                    "synack": 1 if flags and "S" in flags else 0,
                    "ackdat": 1 if flags and "A" in flags else 0,
                    # Raw TCP flags byte — lets signature engine evaluate Snort flags: expressions
                    # exactly (FIN/NULL/XMAS stealth scan detection, SYN-flood, etc.)
                    "tcp_flags_raw": (int(pkt[TCP].flags) if pkt.haslayer(TCP) else -1),
                    "sloss": 0, "dloss": 0, "sinpkt": 0.0, "dinpkt": 0.0,
                    "sjit": 0.0, "djit": 0.0,
                    "sport": sport, "dport": dport,
                    "srcip": src_ip, "dstip": dst_ip,
                    # extra zero-features so bridge doesn't error
                    "sload": 0.0, "dload": 0.0,
                    "stcpb": 0, "dtcpb": 0, "dwin": 0,
                    "tcprtt": 0.0, "trans_depth": 0, "response_body_len": 0,
                    "ct_srv_src": 0, "ct_state_ttl": 0, "ct_dst_ltm": 0,
                    "ct_src_dport_ltm": 0, "ct_dst_sport_ltm": 0, "ct_dst_src_ltm": 0,
                    "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0,
                    "ct_src_ltm": 0, "ct_srv_dst": 0, "is_sm_ips_ports": 0,
                }])
                matched, sig_msg, sig_conf, sig_sev, sig_sid, sig_ct = \
                    engine.sig_engine.match(flow_df, payload)
                if matched:
                    verdict = sig_msg; conf_val = sig_conf; source_engine = "SIGNATURE_DB"
                    # ── Suppress ET INFO / ET POLICY in live capture ─────────────
                    # These are informational Snort rules (classtype:misc-activity,
                    # signature_severity Informational) that fire on normal browsing
                    # traffic (fetch() calls, CDN lookups, etc.).  They add zero
                    # threat value in live-capture mode and generate UI noise.
                    _v = verdict.upper()
                    if not _is_dpi_pkt and ("ET INFO " in _v or "ET POLICY " in _v or
                            sig_ct.lower() in ("misc-activity", "not-suspicious")):
                        verdict = "NORMAL"; conf_val = 0.0; source_engine = "BASTION_CLEAN"
            except Exception:
                pass

        # ── Live flow tracker → full ML/DL/Anomaly pipeline ─────────────────
        if not _is_broadcast_dst:
            _live_flow_tracker.record(
                src_ip, dst_ip, proto_name.lower(), sport, dport,
                pkt_len, ttl, flags, tcp_win,
            )

        # ── HTTP POST brute-force heuristic ─────────────────────────────────
        # Detects tools like Hydra (http-post-form), Burp Intruder, etc.
        # Only fires when the same src_ip repeatedly POSTs to the identical
        # URL path on the same dst_ip within a 30-second sliding window.
        # Normal web browsing never produces 8+ POSTs to the same login path.
        if (verdict == "NORMAL" and proto_name == "TCP"
                and dport in (80, 8080, 8000, 5000) and payload):
            _pl_head = payload[:12].lower()
            if _pl_head.startswith(b"post "):
                try:
                    _fl = payload.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                    _parts = _fl.split(" ")
                    _path = _parts[1] if len(_parts) >= 2 else "/"
                    # Normalise to path only (strip query string for stable keying)
                    _path = _path.split("?", 1)[0] or "/"
                except Exception:
                    _path = "/"
                _hk    = f"hpost:{src_ip}:{dst_ip}:{_path}"
                _now_h = time.time()
                with _http_post_lock:
                    # Check cooldown first (avoid updating state if still cooling)
                    if _now_h - _http_post_fired.get(_hk, 0.0) >= _HTTP_POST_COOLDOWN:
                        _dq = _http_post_events.get(_hk)
                        if _dq is None:
                            _dq = _deque()
                            _http_post_events[_hk] = _dq
                        # Trim entries outside the sliding window
                        while _dq and _dq[0] < _now_h - _HTTP_POST_WINDOW:
                            _dq.popleft()
                        _dq.append(_now_h)
                        if len(_dq) >= _HTTP_POST_THRESHOLD:
                            verdict       = f"Brute-Force Attack: HTTP Form Auth {_path}"
                            conf_val      = 0.91
                            source_engine = "SIGNATURE_DB"
                            _http_post_fired[_hk]  = _now_h
                            _http_post_events[_hk] = _deque()   # reset counter after fire
                    # Periodic memory cleanup — cap tracker at 2000 unique keys
                    if len(_http_post_events) > 2000:
                        _dead = [k for k, v in _http_post_events.items() if not v]
                        for _dk in _dead[:1000]:
                            _http_post_events.pop(_dk, None)
                            _http_post_fired.pop(_dk, None)

        # ── BEHAVIOURAL ANOMALY ENGINE (live zero-day) ──────────────────────
        # Fires on signatureless attack behaviour, gated so normal traffic is
        # silent. Only runs when no signature already matched this packet.
        if verdict == "NORMAL":
            _anom_hit = None   # (verdict, confidence) when a detector trips

            # (1) ICMP covert channel — large data payloads inside echo packets.
            if proto_name == "ICMP":
                try:
                    _icmp_data = len(bytes(pkt[ICMP].payload)) if pkt.haslayer(ICMP) else 0
                except Exception:
                    _icmp_data = 0
                if _icmp_data >= _ICMP_DATA_MIN:
                    _ak = f"icmpcc:{src_ip}:{dst_ip}"
                    _now_a = time.time()
                    with _anom_lock:
                        if _now_a - _anom_fired.get(_ak, 0.0) >= _ANOM_COOLDOWN:
                            _dq = _anom_events.setdefault(_ak, _deque())
                            while _dq and _dq[0] < _now_a - _ANOM_WINDOW:
                                _dq.popleft()
                            _dq.append(_now_a)
                            if len(_dq) >= _ICMP_DATA_THRESH:
                                _anom_hit = ("Novel Attack: ICMP Covert Channel / Tunneling", 0.94)
                                _anom_fired[_ak] = _now_a
                                _anom_events[_ak] = _deque()

            # (2) DNS tunnelling / exfiltration — oversized encoded query labels.
            elif DNS is not None and pkt.haslayer(DNS) and dport == 53:
                try:
                    _qd = pkt[DNS].qd
                    _qname = _qd.qname.decode("ascii", errors="replace").rstrip(".") if _qd else ""
                except Exception:
                    _qname = ""
                if _qname:
                    _labels = _qname.split(".")
                    _longest = max((len(l) for l in _labels), default=0)
                    if _longest >= _DNS_LABEL_MIN or len(_qname) >= _DNS_QNAME_MIN:
                        _ak = f"dnstun:{src_ip}"
                        _now_a = time.time()
                        with _anom_lock:
                            if _now_a - _anom_fired.get(_ak, 0.0) >= _ANOM_COOLDOWN:
                                _dq = _anom_events.setdefault(_ak, _deque())
                                while _dq and _dq[0] < _now_a - _ANOM_WINDOW:
                                    _dq.popleft()
                                _dq.append(_now_a)
                                if len(_dq) >= _DNS_TUNNEL_THRESH:
                                    _anom_hit = ("Novel Attack: DNS Tunneling / Exfiltration", 0.93)
                                    _anom_fired[_ak] = _now_a
                                    _anom_events[_ak] = _deque()

            if _anom_hit is not None:
                verdict, conf_val = _anom_hit
                source_engine = "ANOMALY"

        with _packet_lock:
            packet_counter += 1; pkt_no = packet_counter

        info_str = f"{src_ip}:{sport} → {dst_ip}:{dport}"
        if DNS and pkt.haslayer(DNS):
            try:
                dns = pkt[DNS]
                if dns.qd:
                    info_str = f"Query: {dns.qd.qname.decode(errors='replace')}"
            except Exception:
                pass

        # ── Enhanced Wireshark-style fields ──────────────────────────────────
        eth_src = pkt[Ether].src if pkt.haslayer(Ether) else ""
        eth_dst = pkt[Ether].dst if pkt.haslayer(Ether) else ""
        ip_id   = getattr(ip, 'id', 0)
        ip_tos  = getattr(ip, 'tos', 0)
        ip_frag = getattr(ip, 'frag', 0)
        ip_df   = bool(getattr(ip, 'flags', 0) & 0x2)   # Don't Fragment
        ip_mf   = bool(getattr(ip, 'flags', 0) & 0x1)   # More Fragments
        tcp_seq, tcp_ack_n, tcp_win_v, tcp_urgent_v = 0, 0, 0, 0
        tcp_flags_detail = ""
        udp_len_v = 0
        if proto_name == "TCP" and pkt.haslayer(TCP):
            t = pkt[TCP]
            tcp_seq          = getattr(t, 'seq', 0)
            tcp_ack_n        = getattr(t, 'ack', 0)
            tcp_win_v        = getattr(t, 'window', 0)
            tcp_urgent_v     = getattr(t, 'urgptr', 0)
            # Human-readable flags string: FIN SYN RST PSH ACK URG ECE CWR
            _flag_names = {0x01:'FIN',0x02:'SYN',0x04:'RST',0x08:'PSH',
                           0x10:'ACK',0x20:'URG',0x40:'ECE',0x80:'CWR'}
            raw_f = int(t.flags)
            tcp_flags_detail = " ".join(v for k,v in sorted(_flag_names.items()) if raw_f & k)
        elif proto_name == "UDP" and pkt.haslayer(UDP):
            udp_len_v = getattr(pkt[UDP], 'len', 0)
        # Payload hex + ASCII (first 256 bytes, capped for WebSocket size)
        # Gated by deepInspection policy — when off, payload fields are cleared
        with _policy_lock:
            _dpi_on = _active_policies.get("deepInspection", True)
        _pay_active = _dpi_on or _is_dpi_pkt
        _pay = payload[:256] if _pay_active else b""
        pay_hex   = " ".join(f"{b:02x}" for b in _pay) if _pay_active else ""
        pay_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in _pay) if _pay_active else ""
        pay_len   = len(payload)

        pkt_info = {
            "No.": pkt_no, "Time": now,
            "Source": src_ip, "Destination": dst_ip,
            "Protocol": display_proto, "Length": pkt_len,
            "Info": info_str,
            "verdict": verdict, "confidence": round(conf_val, 4),
            "source_engine": source_engine,
            "src_port": sport, "dst_port": dport,
            "srcip": src_ip, "dstip": dst_ip,
            "proto": proto_name.lower(), "timestamp": now,
            "flags": flags,
            "ttl": ttl,
            # Ethernet layer
            "src_mac": eth_src, "dst_mac": eth_dst,
            "src_vendor": _oui_lookup(eth_src),
            # IP layer extras
            "ip_id": ip_id, "ip_tos": ip_tos, "ip_frag": ip_frag,
            "ip_df": ip_df, "ip_mf": ip_mf,
            # TCP extras
            "tcp_seq": tcp_seq, "tcp_ack": tcp_ack_n,
            "tcp_win": tcp_win_v, "tcp_urgent": tcp_urgent_v,
            "tcp_flags_detail": tcp_flags_detail,
            # UDP extras
            "udp_len": udp_len_v,
            # Payload
            "payload_hex": pay_hex, "payload_ascii": pay_ascii, "payload_len": pay_len,
            "dpi_inspected": _is_dpi_pkt,
        }

        _pkt_alert_thresh = _alert_threshold * 0.80 if _is_dpi_pkt else _alert_threshold
        if conf_val >= _pkt_alert_thresh and verdict.upper() not in ("NORMAL", "BASTION_CLEAN"):
            ts_now = datetime.datetime.now().isoformat()
            _save_alert({**pkt_info, "id": pkt_no, "timestamp": ts_now})
            global session_threat_count, session_layer_counts
            session_threat_count += 1
            eng_key = {"DL-SENSEI":"DL_LAYER","BASTION_CLEAN":"SIGNATURE_DB"}.get(
                source_engine.upper(), source_engine.upper())
            session_layer_counts[eng_key] = session_layer_counts.get(eng_key, 0) + 1

            # ── Policy: Auto-Isolate ──────────────────────────────────────────
            with _policy_lock:
                do_isolate = _active_policies.get("autoIsolate", False)
            isolated_now = False
            if do_isolate and src_ip and src_ip not in ("0.0.0.0", "127.0.0.1"):
                threading.Thread(
                    target=_apply_auto_isolate, args=(src_ip,), daemon=True
                ).start()
                isolated_now = True

            # ── Broadcast THREAT_DETECTED so LiveMonitor can update its counter
            threat_evt = {
                "type":        "THREAT_DETECTED",
                "No.":         pkt_no,
                "verdict":     verdict,
                "confidence":  conf_val,
                "engine":      source_engine,
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
                "timestamp":   ts_now,
                "total_threats": session_threat_count,
                "auto_isolated": isolated_now,
            }
            asyncio.run_coroutine_threadsafe(_broadcast(_json_safe(threat_evt)), loop)

        safe_info = _json_safe(pkt_info)
        _packet_ring.append(safe_info)
        _raw_packet_ring.append(pkt)
        asyncio.run_coroutine_threadsafe(_broadcast(safe_info), loop)
    except Exception as _ex:
        import traceback as _tb
        print(f"[_process_packet_inner ERROR] {type(_ex).__name__}: {_ex}", flush=True)
        print(_tb.format_exc(), flush=True)

# Default: capture IPv4 + ARP only. IPv6 is opt-in via a custom BPF preset in the UI.
# This prevents Windows' high-volume IPv6 traffic (mDNS, ND, browser TLS) from drowning
# out IPv4 flows. Users who need IPv6 can set "any traffic" or a custom BPF in LiveMonitor.
_active_bpf_filter = "ip or arp"

def _sniffer_loop(loop, iface=None, bpf=None):
    global is_sniffing, _sniffer_error
    _sniffer_error = None
    from scapy.all import sniff, conf as scapy_conf
    scapy_conf.promisc = True
    filt = bpf if bpf else _active_bpf_filter

    def _run(filter_str):
        sniff(
            iface=iface if iface else None,
            prn=lambda p: _process_packet(p, loop),
            store=False,
            filter=filter_str if filter_str else None,
            stop_filter=lambda p: not is_sniffing,
            promisc=True,
        )

    try:
        _run(filt)
    except Exception as ex:
        err_msg = str(ex)
        print(f"[Sniffer] Error: {err_msg}", flush=True)
        # If the BPF filter was rejected try again without it
        if filt and any(k in err_msg.lower() for k in ("filter", "bpf", "syntax", "compile")):
            print("[Sniffer] BPF rejected — retrying without filter", flush=True)
            try:
                _run("")
                return  # succeeded without filter
            except Exception as ex2:
                err_msg = str(ex2)
                print(f"[Sniffer] Still failed: {ex2}", flush=True)
        # Determine friendly hint
        if "admin" in err_msg.lower() or "permission" in err_msg.lower() or "access" in err_msg.lower():
            hint = "⚠ Administrator access required — restart via START_BASTION.bat (run as admin)"
        elif "npcap" in err_msg.lower() or "winpcap" in err_msg.lower():
            hint = "⚠ Npcap not found — install Npcap from https://npcap.com"
        else:
            hint = f"⚠ Capture failed: {err_msg}"
        _sniffer_error = hint
        is_sniffing = False
        # Broadcast the error to all connected WebSocket clients so the UI shows it
        try:
            err_info = {"type": "CAPTURE_ERROR", "error": hint}
            asyncio.run_coroutine_threadsafe(_broadcast(err_info), loop)
        except Exception:
            pass

def _restart_sniffer(loop, iface=None, bpf=None):
    global sniff_thread, is_sniffing, current_interface, _active_bpf_filter, _sniffer_error, _current_session_id
    is_sniffing = False
    _sniffer_error = None  # clear any previous error on restart
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join(timeout=3)
    current_interface = iface
    if bpf:
        _active_bpf_filter = bpf
    # Mint a fresh session ID each time capture starts — alerts from this point
    # forward carry this ID so report generation can filter to just this session.
    _current_session_id = datetime.datetime.now().strftime("session_%Y%m%d_%H%M%S")
    is_sniffing = True
    _live_flow_tracker.start(loop)
    sniff_thread = threading.Thread(
        target=_sniffer_loop, args=(loop, iface, _active_bpf_filter), daemon=True)
    sniff_thread.start()

@app.get("/api/v1/capture/export-csv")
async def export_capture_csv():
    """Export the in-memory packet ring buffer as CSV."""
    import io, csv
    pkts = list(_packet_ring)
    if not pkts:
        raise HTTPException(status_code=404, detail="No packets captured yet")
    fields = list(pkts[0].keys())
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(pkts)
    buf.seek(0)
    from fastapi.responses import StreamingResponse
    ts    = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    iface = (current_interface or "all").replace(" ", "_")
    fname = f"BASTION-IDS_{ts}_{iface}_capture.csv"
    return StreamingResponse(iter([buf.getvalue()]),
                             media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.get("/api/v1/capture/export-pcap")
async def export_capture_pcap():
    """Export the raw packet ring buffer as a PCAP file using Scapy."""
    import io, tempfile
    from fastapi.responses import StreamingResponse
    pkts = list(_raw_packet_ring)
    if not pkts:
        raise HTTPException(status_code=404, detail="No packets in ring buffer")
    try:
        from scapy.all import wrpcap
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name
        wrpcap(tmp_path, pkts)
        with open(tmp_path, "rb") as f:
            data = f.read()
        os.unlink(tmp_path)
        ts    = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        iface = (current_interface or "all").replace(" ", "_")
        fname = f"BASTION-IDS_{ts}_{iface}_capture.pcap"
        return StreamingResponse(
            iter([data]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={fname}"}
        )
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"PCAP export failed: {ex}")

@app.get("/api/v1/capture/stats")
async def capture_stats():
    """Return live capture statistics, including interface health warning."""
    pkts = list(_packet_ring)
    threat_count = sum(1 for p in pkts if p.get("verdict") not in ("NORMAL","BASTION_CLEAN",""))
    proto_dist = {}
    for p in pkts:
        pr = p.get("Protocol","?")
        proto_dist[pr] = proto_dist.get(pr, 0) + 1

    # ── Interface health analysis ─────────────────────────────────────────────
    # If capture is active and the ring contains ONLY ARP packets (no IP, TCP,
    # UDP, HTTP, DNS, TLS…), it almost always means the wrong interface is
    # selected: the sniffer is on a virtual/NAT adapter that only receives
    # broadcast traffic while real IP flows arrive on a different NIC.
    iface_warning = None
    recommended_iface = None
    non_broadcast_protos = {k for k in proto_dist if k not in ("ARP","ETH","?")}
    arp_only = len(pkts) > 15 and not non_broadcast_protos and "ARP" in proto_dist

    if is_sniffing and arp_only:
        cur = (current_interface or "").lower()
        # Identify which interfaces are real (not virtual VMware/VirtualBox/Hyper-V)
        import psutil as _psu
        all_ifaces = _psu.net_if_addrs()
        all_stats  = _psu.net_if_stats()
        real_ifaces = []
        for name, addrs in all_ifaces.items():
            stats = all_stats.get(name)
            if not stats or not stats.isup:
                continue
            # Skip loopback, virtual VMware, Hyper-V, Bluetooth, null
            name_l = name.lower()
            if any(tok in name_l for tok in ("loopback","pseudo","bluetooth","vmnet","vethernet","local area connection*","tunnel","isatap","teredo")):
                continue
            ipv4 = next((a.address for a in addrs if a.family == 2
                         and not a.address.startswith("169.254")), None)
            if ipv4:
                real_ifaces.append((name, ipv4))

        if real_ifaces:
            # Prefer Wi-Fi / Ethernet over virtual adapters
            def _score(n):
                nl = n.lower()
                if "wi-fi" in nl or "wifi" in nl or "wireless" in nl: return 3
                if "ethernet" in nl or "lan" in nl: return 2
                return 1
            real_ifaces.sort(key=lambda x: _score(x[0]), reverse=True)
            rec_name, rec_ip = real_ifaces[0]
            recommended_iface = rec_name
            iface_warning = (
                f"Only ARP packets captured on '{current_interface}' — this is likely a "
                f"VMware/virtual adapter that sees only broadcast traffic. "
                f"Switch to '{rec_name}' ({rec_ip}) to capture real IP/HTTP traffic."
            )

    return {
        "total_packets": len(pkts),
        "threat_packets": threat_count,
        "is_capturing": is_sniffing,
        "interface": current_interface or "all",
        "protocol_distribution": proto_dist,
        "interface_warning": iface_warning,
        "recommended_interface": recommended_iface,
    }

@app.websocket("/api/v1/live-traffic")
async def websocket_endpoint(websocket: WebSocket):
    global is_sniffing, sniff_thread, current_interface
    # Auth check — browsers send the key as a query param or header
    ws_key = (websocket.headers.get("x-authority") or
              websocket.headers.get("X-Authority") or
              websocket.query_params.get("key") or "")
    if not _check_auth(ws_key):
        await websocket.close(code=4001, reason="UNAUTHORIZED")
        return
    await websocket.accept()
    active_websockets.append(websocket)
    loop = asyncio.get_running_loop()
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
                cmd   = payload.get("action", raw)
                iface = payload.get("interface") or None
            except Exception:
                cmd   = raw
                iface = current_interface

            bpf = payload.get("bpf") if isinstance(payload, dict) else None

            if cmd == "START":
                _restart_sniffer(loop, iface, bpf)
                await websocket.send_json(
                    {"system": f"CAPTURE STARTED on interface: {iface or 'ALL'}"})
            elif cmd == "STOP":
                is_sniffing = False
                _flush_alerts_now()   # persist buffered live-capture alerts
                await websocket.send_json({"system": "CAPTURE STOPPED"})
            elif cmd == "RESTART":
                _packet_ring.clear()
                _raw_packet_ring.clear()
                _restart_sniffer(loop, iface, bpf)
                await websocket.send_json({"system": "CAPTURE RESTARTED — buffer cleared"})
            elif cmd == "STATUS":
                await websocket.send_json({
                    "system": "STATUS",
                    "is_capturing": is_sniffing,
                    "interface": current_interface,
                    "packets_processed": packet_counter,
                    "buffer_size": len(_packet_ring),
                })
    except WebSocketDisconnect:
        try: active_websockets.remove(websocket)
        except ValueError: pass
        _flush_alerts_now()   # persist any buffered live-capture alerts on disconnect

# ─────────────────────────────────────────────────────────────
# SINGLE FLOW ANALYSIS (used by demo scripts and custom clients)
# ─────────────────────────────────────────────────────────────
@app.post("/api/v1/analyze")
async def analyze_single_flow(request: Request,
                               x_authority: str = Header(None)):
    if _lockdown_active:
        raise HTTPException(status_code=423, detail="SYSTEM LOCKDOWN ACTIVE — all analysis suspended. Release lockdown in Command & Control.")
    """
    Analyze a single network flow through the full 4-layer pipeline.
    Body: { "flow": { <feature_dict> }, "payload_hex": "optional hex bytes" }
    Returns: { verdict, confidence, engine, mitre_id }
    """
    global packet_counter
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    flow_data = body.get("flow", body)   # allow flat body OR {flow: {...}}
    payload_hex = body.get("payload_hex", "")
    raw_payload = bytes.fromhex(payload_hex) if payload_hex else None
    # force_ml=True: skip signature engine, go straight to ML/DL/Anomaly layers.
    force_ml   = bool(body.get("force_ml", False))

    if not flow_data:
        raise HTTPException(status_code=400, detail="No flow data provided")

    try:
        flow_df = pd.DataFrame([flow_data])
        import functools as _ft
        loop = asyncio.get_event_loop()

        if force_ml:
            # Bypass Layer 1 (signature) — run only ML ensemble, DL, and Anomaly.
            def _ml_only(df):
                from utils.feature_bridge import bridge
                flow_clean, _ = bridge(df)
                X_ml, X_dl = engine._transform(flow_clean)

                # Layer 2: ML Ensemble
                experts = []
                for name, model in [("RF", engine.rf), ("XGB", engine.xgb), ("CAT", engine.cat)]:
                    if model is None: continue
                    try:
                        prob  = model.predict_proba(X_ml)[0]
                        idx   = int(np.argmax(prob))
                        conf  = float(np.max(prob))
                        label = engine._decode(idx)
                        experts.append({"name": name, "label": label, "conf": conf})
                    except Exception:
                        continue
                malicious = [e for e in experts if e["label"].upper() != "NORMAL" and e["conf"] >= _ml_threshold]
                if len(malicious) < 2:
                    soft = [e for e in experts if e["label"].upper() != "NORMAL" and e["conf"] >= max(0.50, _ml_threshold - 0.10)]
                    if len(soft) >= 2:
                        lbls = [e["label"].upper() for e in soft]
                        if lbls.count(lbls[0]) >= 2:
                            malicious = [e for e in soft if e["label"].upper() == lbls[0]]
                if len(malicious) >= 2 or any(e["conf"] >= 0.92 for e in malicious):
                    top = max(malicious, key=lambda x: x["conf"])
                    return top["label"].upper(), top["conf"], "ML_ENSEMBLE"

                # Layer 3: DL
                if engine.dl is not None:
                    try:
                        try:   dl_p = engine.dl.predict(X_ml, verbose=0)[0]
                        except: dl_p = engine.dl.predict(X_dl, verbose=0)[0]
                        dl_idx  = int(np.argmax(dl_p))
                        dl_conf = float(np.max(dl_p))
                        dl_lbl  = engine._decode(dl_idx)
                        if dl_lbl.upper() != "NORMAL" and dl_conf >= 0.82:
                            return dl_lbl.upper(), dl_conf, "DL-SENSEI"
                    except Exception:
                        pass

                # Layer 4: Anomaly
                ar = engine._anomaly_check(X_ml)
                if ar is not None:
                    score, verdict = ar
                    return verdict, score, "ANOMALY"

                return "NORMAL", 0.0, "BASTION_CLEAN"

            verdict, conf, source_engine = await loop.run_in_executor(None, _ml_only, flow_df)
        else:
            # Full 4-layer pipeline (signature first, then ML/DL/Anomaly)
            verdict, conf, source_engine = await loop.run_in_executor(
                None, _ft.partial(engine.analyze_flow, flow_df, raw_payload)
            )
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {ex}")

    # Resolve MITRE mapping client-side (basic lookup)
    MITRE_QUICK = {
        "dos": "T1498", "denial": "T1498", "flood": "T1498",
        "exploit": "T1190", "fuzz": "T1190",
        "recon": "T1595", "scan": "T1595", "probe": "T1595",
        "backdoor": "T1543", "shellcode": "T1059",
        "worm": "T1210", "lateral": "T1210",
        "brute": "T1110", "zero-day": "T1211",
        "anomaly": "T1036", "suspicious": "T1036",
    }
    v_lower = str(verdict).lower()
    mitre_id = next((tid for kw, tid in MITRE_QUICK.items() if kw in v_lower), None)

    conf_norm = float(conf) if float(conf) <= 1.0 else float(conf) / 100.0

    # Save as alert if malicious
    if str(verdict).upper() not in ("NORMAL", "BASTION_CLEAN"):
        with _packet_lock:
            packet_counter += 1

        alert = {
            "id":            packet_counter,
            "timestamp":     datetime.datetime.now().isoformat(),
            "srcip":         str(flow_data.get("srcip", "DEMO_SRC")),
            "dstip":         str(flow_data.get("dstip", "DEMO_DST")),
            "proto":         str(flow_data.get("proto", "tcp")),
            "dsport":        flow_data.get("dsport", flow_data.get("dport", 0)),
            "verdict":       str(verdict),
            "confidence":    conf_norm,
            "source_engine": str(source_engine),
            "mitre_id":      mitre_id,
        }
        _save_alert(alert)

        # Update session layer counts + broadcast to Live Feed
        global session_threat_count, session_layer_counts
        session_threat_count += 1
        _eng_key = {"DL-SENSEI": "DL_LAYER", "BASTION_CLEAN": "SIGNATURE_DB"}.get(
            str(source_engine).upper(), str(source_engine).upper())
        session_layer_counts[_eng_key] = session_layer_counts.get(_eng_key, 0) + 1

        threat_evt = {
            "type":       "THREAT_DETECTED",
            "No.":        packet_counter,
            "verdict":    str(verdict),
            "confidence": conf_norm,
            "engine":     str(source_engine),
            "source_engine": str(source_engine),
            "src_ip":     alert["srcip"],
            "dst_ip":     alert["dstip"],
            "srcip":      alert["srcip"],
            "dstip":      alert["dstip"],
            "proto":      alert["proto"],
            "timestamp":  alert["timestamp"],
            "mitre_id":   mitre_id,
            "severity":   "HIGH" if conf_norm >= 0.85 else "MEDIUM",
        }
        await _broadcast(threat_evt)

    return {
        "verdict":    str(verdict),
        "confidence": conf_norm,
        "engine":     str(source_engine),
        "mitre_id":   mitre_id,
    }

# ─────────────────────────────────────────────────────────────
# FILE INGEST & SWEEP
# ─────────────────────────────────────────────────────────────
def _parse_pcap_to_df(path: str, limit: int = None) -> pd.DataFrame:
    """Parse PCAP using feature bridge for proper flow extraction."""
    try:
        from utils.feature_bridge import read_pcap_as_flows
        flows = read_pcap_as_flows(path, max_flows=limit)  # None = no limit
        return flows
    except Exception:
        # Fallback: basic scapy parse
        from scapy.all import rdpcap, IP, TCP, UDP
        rows = []
        pkts = rdpcap(path, count=limit or 500)
        for i, p in enumerate(pkts):
            if not p.haslayer(IP): continue
            sport = p[TCP].sport if p.haslayer(TCP) else (p[UDP].sport if p.haslayer(UDP) else 0)
            dport = p[TCP].dport if p.haslayer(TCP) else (p[UDP].dport if p.haslayer(UDP) else 0)
            rows.append({
                "srcip":str(p[IP].src),"dstip":str(p[IP].dst),
                "proto":"tcp" if p.haslayer(TCP) else "udp",
                "sport":sport,"dport":dport,
                "sbytes":len(p),"spkts":1,"sttl":p[IP].ttl,
                "timestamp":str(datetime.datetime.fromtimestamp(float(p.time)))
            })
        return pd.DataFrame(rows)

@app.post("/api/v1/ingest")
async def ingest_telemetry(file: UploadFile = File(...),
                            x_authority: str = Header(None)):
    if _lockdown_active:
        raise HTTPException(status_code=423, detail="SYSTEM LOCKDOWN ACTIVE — file ingest suspended. Release lockdown in Command & Control.")
    file_path = os.path.join(CONFIG["UPLOAD_DIR"], file.filename)
    with open(file_path, "wb") as buf:
        shutil.copyfileobj(file.file, buf)
    try:
        ext = file.filename.lower()
        total_rows = None
        PREVIEW = 100  # show 100 rows in preview table (paginated client-side)

        if ext.endswith(".csv"):
            # Count total rows without loading everything
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    total_rows = sum(1 for _ in f) - 1  # subtract header
            except Exception:
                pass
            df = pd.read_csv(file_path, nrows=PREVIEW).fillna(0)
        elif ext.endswith((".pcap", ".pcapng")):
            df = _parse_pcap_to_df(file_path, limit=PREVIEW)
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [l.strip() for l in f.readlines()[:PREVIEW]]
            df = pd.DataFrame({"raw_log_entry": lines})

        if df.empty:
            raise ValueError("Empty or unparsable file")

        resp = {
            "status":     "SUCCESS",
            "filename":   file.filename,
            "columns":    list(df.columns),
            "preview":    df.head(PREVIEW).to_dict(orient="records"),
        }
        if total_rows is not None:
            resp["total_rows"] = total_rows
        return resp
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))

def _check_memory_pressure() -> bool:
    """Return True if free RAM is critically low (< 400 MB).
    Called before and during heavy sweep operations to prevent OOM crashes."""
    try:
        mem = psutil.virtual_memory()
        return mem.available < 400 * 1024 * 1024   # 400 MB threshold
    except Exception:
        return False

def _run_analysis_pipeline(filename: str):
    """
    Background sweep — full-dataset batch analysis with parallel ML predictions.
    No row limit — processes the entire uploaded file.
    Progress is streamed via sweep_progress[filename] including stage label, pct,
    rate and ETA so the frontend progress bar stays active throughout all phases.
    """
    import time as _time

    def _upd(**kw):
        """Thread-safe progress update helper."""
        sweep_progress[filename].update(kw)

    path = os.path.join(CONFIG["UPLOAD_DIR"], filename)
    sweep_progress[filename] = {
        "status":       "RUNNING",
        "stage":        "loading",       # human-readable phase label
        "pct":          0,               # overall % complete (0-100)
        "processed":    0,               # rows fully processed (Step 4)
        "total":        0,
        "hits":         0,
        "layer_counts": {},
        "rate_rps":     0,
        "eta_seconds":  None,
    }
    BATCH_THRESHOLD = 0.50
    SAFE_VERDICTS   = {"NORMAL", "BASTION_CLEAN", ""}
    _sweep_start    = _time.time()

    try:
        ext = filename.lower()
        if ext.endswith(".csv"):
            # Stream large files via chunks to avoid OOM.
            # Progress is reported per-chunk so the frontend shows activity
            # immediately — even before the full file is in memory.
            file_bytes = os.path.getsize(path)
            chunks = []
            rows_loaded = 0
            for chunk in pd.read_csv(
                path,
                chunksize=50_000,
                low_memory=False,
                encoding="latin-1",
                on_bad_lines="skip",
            ):
                chunks.append(chunk.fillna(0))
                rows_loaded += len(chunk)
                # Estimate progress 0→4% based on byte position (rough but visible)
                try:
                    byte_pos = sum(c.memory_usage(deep=False).sum() for c in chunks)
                    load_pct = min(4, int(byte_pos / max(file_bytes, 1) * 4))
                except Exception:
                    load_pct = min(4, len(chunks) // 5)
                _upd(
                    stage=f"loading_file ({rows_loaded:,} rows read…)",
                    pct=load_pct,
                    processed=rows_loaded,
                    total=max(rows_loaded, 1),
                )
            df_raw = pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame()
        elif ext.endswith((".pcap", ".pcapng")):
            _upd(stage="parsing_pcap", pct=1)
            df_raw = _parse_pcap_to_df(path, limit=None)
        else:
            _upd(stage="loading_log", pct=1)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            df_raw = pd.DataFrame({"raw_log_entry": lines})

        total = len(df_raw)
        _upd(total=total, stage="feature_bridge", pct=5)
        hits = []
        layer_counts = {"SIGNATURE_DB":0,"ML_ENSEMBLE":0,"DL_LAYER":0,"ANOMALY":0}

        # ── STEP 1: Feature bridge on entire batch ──────────────────
        df = df_raw.copy()
        try:
            from utils.feature_bridge import bridge as feature_bridge
            bridged, _ = feature_bridge(df)
            if bridged is not None and not bridged.empty:
                df = bridged
        except Exception:
            pass

        # ── STEP 2: Batch preprocess for ML/DL/Anomaly ───────────────────
        # A single preprocessor.transform on the whole DataFrame so no
        # inference step runs inside the slow per-row loop.
        _upd(stage="preprocessing", pct=10)
        X_batch = None

        # Memory guard: if free RAM < 400 MB, skip batch ML inference and
        # fall back to signature-only analysis to prevent OOM crash.
        _mem_ok = not _check_memory_pressure()
        if not _mem_ok:
            _upd(_warn_mem="Low memory — skipping batch ML inference to prevent OOM")

        try:
            if _mem_ok:
                X_batch = engine.preprocessor.transform(df)
        except Exception as _ex:
            _upd(_err_preprocess=str(_ex))

        # ── STEP 2.5: Vectorised Signature Scan (Layer 1) ────────────────────
        # Runs port-based and flag-based rule matching across all rows using
        # pandas vectorised ops — no per-row Python loop, so effectively free.
        # Covers the main NMAP/scan/C2/brute-force patterns the Snort rules detect.
        _upd(stage="signature_scan", pct=8)
        sig_results = [None] * total
        try:
            _sc = df.copy() if isinstance(df, pd.DataFrame) else pd.DataFrame()
            # Normalise column names to lower-case for consistent lookup
            _sc.columns = [c.lower() for c in _sc.columns]
            _sport = _sc.get("sport", _sc.get("src_port", pd.Series([0]*total)))
            _dport = _sc.get("dsport", _sc.get("dport", _sc.get("dst_port", pd.Series([0]*total))))
            _proto = _sc.get("proto", pd.Series(["tcp"]*total)).astype(str).str.lower()

            try: _sport = pd.to_numeric(_sport, errors="coerce").fillna(0).astype(int)
            except: _sport = pd.Series([0]*total)
            try: _dport = pd.to_numeric(_dport, errors="coerce").fillna(0).astype(int)
            except: _dport = pd.Series([0]*total)

            # ── TCP flag parsing ─────────────────────────────────────────────
            # Rows without a parseable flag value get sentinel -1 and are
            # EXCLUDED from all flag-based rules. A -1 sentinel is all-ones in
            # two's complement, so `-1 & mask == mask` matches everything —
            # feeding it into the masks below would flag every TCP row.
            _FLAG_NAME_BITS   = {"FIN":0x01,"SYN":0x02,"RST":0x04,"PSH":0x08,
                                 "ACK":0x10,"URG":0x20,"ECE":0x40,"CWR":0x80}
            _FLAG_LETTER_BITS = {"F":0x01,"S":0x02,"R":0x04,"P":0x08,
                                 "A":0x10,"U":0x20,"E":0x40,"C":0x80}

            def _parse_flag_cell(v):
                """Accept numeric (2), scapy letters (FA, PA), or names (FIN,PSH,URG)."""
                try:
                    f = float(v)
                    if f == f:            # not NaN
                        return int(f)
                except (TypeError, ValueError):
                    pass
                s = str(v).strip().upper()
                if not s or s in ("NAN", "NONE", "-"):
                    return -1
                if s.startswith("0X"):
                    try:    return int(s, 16)
                    except ValueError: return -1
                bits = 0
                if any(sep in s for sep in (",", "+", "|", " ")) or s in _FLAG_NAME_BITS:
                    for tok in s.replace("+", ",").replace("|", ",").replace(" ", ",").split(","):
                        bits |= _FLAG_NAME_BITS.get(tok.strip(), 0)
                    return bits if bits else -1
                for ch in s:
                    b = _FLAG_LETTER_BITS.get(ch)
                    if b is None:
                        return -1         # unknown letter — treat as unparseable
                    bits |= b
                return bits if bits else -1

            _flags_src = None
            for _col in ("tcp_flags_raw", "tcp_flags", "flags", "tcp_flags_detail"):
                if _col in _sc.columns:
                    _flags_src = _sc[_col]
                    break
            if _flags_src is not None:
                try:    _flags = _flags_src.apply(_parse_flag_cell).astype(int)
                except Exception: _flags = pd.Series([-1]*total)
            else:
                _flags = pd.Series([-1]*total)
            _flags_valid = _flags >= 0

            # Ports exclusively associated with attack tools / common RATs / reverse shells
            # (deliberately excludes ambiguous ports like 6379/Redis, 27017/MongoDB)
            _C2_PORTS = {4444,5554,6666,7777,8888,1337,31337,12345,54321,9999}

            # NULL scan: tcp + flags == 0
            _null_mask   = _flags_valid & (_proto == "tcp") & (_flags == 0)
            # XMAS scan: tcp + EXACTLY FIN+PSH+URG (0x29). Exact match — a
            # subset test would also hit rare-but-legit FIN+PSH+ACK+URG teardowns.
            _xmas_mask   = _flags_valid & (_proto == "tcp") & (_flags == 0x29)
            # SYN+FIN (invalid combination — stealth scan indicator)
            _synfin_mask = _flags_valid & (_proto == "tcp") & ((_flags & 0x03) == 0x03)
            # C2 port hit (source or destination)
            _c2_mask     = _dport.isin(_C2_PORTS) | _sport.isin(_C2_PORTS)

            for i in np.where(_null_mask.values)[0]:
                if sig_results[i] is None:
                    sig_results[i] = ("NMAP Null Scan: TCP stealth scan (all flags clear)", 0.91)
            for i in np.where(_xmas_mask.values)[0]:
                if sig_results[i] is None:
                    sig_results[i] = ("NMAP XMAS Scan: TCP stealth scan (FIN+PSH+URG)", 0.91)
            for i in np.where(_synfin_mask.values)[0]:
                if sig_results[i] is None:
                    sig_results[i] = ("Malformed Packet: SYN+FIN stealth probe", 0.88)
            for i in np.where(_c2_mask.values)[0]:
                if sig_results[i] is None:
                    dp = int(_dport.iloc[i]); sp = int(_sport.iloc[i])
                    port_val = dp if dp in _C2_PORTS else sp
                    sig_results[i] = (f"Suspicious C2 Traffic: Port {port_val}", 0.82)
        except Exception:
            pass

        # ── STEP 3: ALL predictions fully vectorised ──────────────────
        # Each layer stores results as a parallel array indexed by row.
        # Failures of individual models are caught per-model so one bad
        # model cannot silently abort the rest.

        ml_results  = [None] * total   # (verdict, conf)
        dl_results  = [None] * total   # (verdict, conf)
        if_results  = [None] * total   # (verdict, conf)

        if X_batch is not None:
            # 3a. ML Ensemble — run each model and update pct as each completes
            ml_preds = {}
            _ml_models = [("RF", engine.rf, 20), ("XGB", engine.xgb, 35), ("CAT", engine.cat, 50)]
            for model_name, model, pct_after in _ml_models:
                if model is None:
                    _upd(pct=pct_after)
                    continue
                _upd(stage=f"ml_inference:{model_name}", pct=pct_after - 10)
                try:
                    proba = model.predict_proba(X_batch)   # (n, n_classes)
                    ml_preds[model_name] = proba
                except Exception:
                    pass   # model incompatible — skip, others still run
                _upd(pct=pct_after)

            _upd(stage="ml_collation", pct=55)
            if ml_preds:
                # ── Step 1: Pre-compute safe label INDEX SET (integer ops only) ──
                # Comparing integer indices is ~10× faster than np.isin on object
                # string arrays for 175k rows × 3 models.
                try:
                    _le_classes = engine.label_encoder.classes_
                    _safe_int_idx = np.array(
                        [i for i, c in enumerate(_le_classes)
                         if str(c).upper() in SAFE_VERDICTS],
                        dtype=np.int64
                    )
                    # classes_ lookup: int index → upper-case label string
                    _idx_to_label = {i: str(c).upper() for i, c in enumerate(_le_classes)}
                    _use_int_path = True
                except Exception:
                    _use_int_path = False

                # ── Step 2: Per-model: argmax + conf + malicious mask (integer path) ──
                _model_idxs:  list = []   # int argmax arrays (n_rows,)
                _model_confs: list = []   # float conf arrays (n_rows,)
                _row_arange = np.arange(total)

                for name, proba in ml_preds.items():
                    idxs  = np.argmax(proba, axis=1)                  # (n_rows,) int
                    confs = proba[_row_arange, idxs]                  # (n_rows,) float
                    _model_idxs.append(idxs)
                    _model_confs.append(confs)

                _upd(pct=57)
                n_models = len(_model_idxs)

                # ── Step 3: Boolean malicious mask — integer isin (fast) ──────────
                mal_masks = []
                for mi in range(n_models):
                    if _use_int_path:
                        not_safe = ~np.isin(_model_idxs[mi], _safe_int_idx)
                    else:
                        # Fallback: decode to strings and compare
                        lbls     = np.array([engine._decode(int(x)).upper()
                                             for x in _model_idxs[mi]])
                        not_safe = ~np.isin(lbls, np.array(list(SAFE_VERDICTS)))
                    above_thr = _model_confs[mi] >= BATCH_THRESHOLD
                    mal_masks.append(not_safe & above_thr)

                # ── Step 4: Eligibility: ≥2 models agree OR single ≥0.85 conf ────
                mal_matrix   = np.stack(mal_masks, axis=0)      # (n_models, n_rows)
                conf_matrix  = np.stack(_model_confs, axis=0)   # (n_models, n_rows)
                mal_count    = mal_matrix.sum(axis=0)
                masked_conf  = np.where(mal_matrix, conf_matrix, 0.0)
                max_mal_conf = masked_conf.max(axis=0)

                eligible     = (mal_count >= 2) | ((mal_count >= 1) & (max_mal_conf >= 0.85))
                eligible_idx = np.where(eligible)[0]

                _upd(pct=59, stage=f"ml_collation: {len(eligible_idx):,} threat rows")

                # ── Step 5: Vectorized best-model selection for eligible rows ─────
                if len(eligible_idx) > 0:
                    elig_conf_mat = conf_matrix[:, eligible_idx]   # (n_models, n_elig)
                    elig_mal_mat  = mal_matrix[:, eligible_idx]    # (n_models, n_elig)
                    elig_masked   = np.where(elig_mal_mat, elig_conf_mat, 0.0)
                    best_mi       = np.argmax(elig_masked, axis=0)  # (n_elig,) model idx
                    best_confs    = elig_conf_mat[best_mi, np.arange(len(eligible_idx))]

                    for j, row_i in enumerate(eligible_idx):
                        mi = int(best_mi[j])
                        if elig_mal_mat[mi, j]:
                            lbl_idx = int(_model_idxs[mi][row_i])
                            label   = (_idx_to_label.get(lbl_idx)
                                       if _use_int_path
                                       else engine._decode(lbl_idx).upper())
                            if label:
                                ml_results[row_i] = (label, float(best_confs[j]))

            # 3b. DL Specialist — single batch call (vastly faster than per-row)
            _upd(stage="dl_inference", pct=60)
            if engine.dl is not None:
                try:
                    # predict() returns numpy; force conversion to avoid slow Tensor indexing
                    dl_prob_batch = np.array(engine.dl.predict(X_batch, verbose=0))
                    dl_idx_batch  = np.argmax(dl_prob_batch, axis=1)
                    dl_conf_batch = dl_prob_batch[np.arange(total), dl_idx_batch]
                    for i in range(total):
                        lbl  = engine._decode(int(dl_idx_batch[i]))
                        conf = float(dl_conf_batch[i])
                        if lbl.upper() not in SAFE_VERDICTS and conf >= 0.85:
                            dl_results[i] = (lbl.upper(), conf)
                except Exception:
                    pass
            _upd(pct=70)

            # 3c. Isolation Forest — vectorised decision function
            _upd(stage="anomaly_detection", pct=72)
            if engine.isolation_forest is not None:
                try:
                    if_dec = np.array(engine.isolation_forest.decision_function(X_batch))
                    thresh = (engine.anomaly_config["isolation_forest"]["threshold"]
                              if engine.anomaly_config else -0.15)
                    bad = if_dec < thresh
                    for i in np.where(bad)[0]:
                        dec   = float(if_dec[i])
                        score = round(min(1.0, max(0.0,
                            (thresh - dec) / (abs(thresh) + 1e-9))), 4)
                        if score >= 0.50:
                            if_results[i] = (
                                "Anomaly: Isolation Forest — Novel Traffic Pattern",
                                score,
                            )
                except Exception:
                    pass
            _upd(pct=78)

        # ── STEP 4: Per-row loop — alert collation only (all inference done) ──
        # No ML/DL/anomaly inside this loop — just array lookups + file writes.
        _upd(stage="collating_alerts", pct=80)

        # IP extraction: prefer bridged df columns (correct headers for headerless UNSW)
        # over raw df_raw which may have first-data-row as column names.
        _ip_cols = {"srcip", "dstip", "proto", "dsport", "dport", "sport",
                    "timestamp", "Timestamp", "service", "state"}
        _has_ip_cols_raw = "srcip" in df_raw.columns or "Source_IP" in df_raw.columns
        _has_ip_cols_df  = "srcip" in df.columns
        if _has_ip_cols_df and not _has_ip_cols_raw and len(df) == total:
            # Bridged df has proper UNSW column names; use it for metadata extraction
            meta_values = df.values
            meta_cols   = list(df.columns)
        else:
            meta_values = df_raw.values
            meta_cols   = list(df_raw.columns)

        df_raw_values = df_raw.values   # still used for raw_row output
        df_raw_cols   = list(df_raw.columns)
        _loop_start   = _time.time()

        # ── Build a single "hit index" that merges all three layers ──────────────
        # Only rows that were flagged by at least one layer need metadata extraction.
        # This avoids iterating all N rows in pure Python; the inner loop only runs
        # for actual hits (typically 1–50% of the dataset, never 100%).
        hit_index: dict = {}   # row_idx -> (verdict, conf, source)
        for i in range(total):
            if sig_results[i] is not None:
                hit_index[i] = (*sig_results[i], "SIGNATURE_DB")
            elif ml_results[i] is not None:
                hit_index[i] = (*ml_results[i], "ML_ENSEMBLE")
            elif dl_results[i] is not None:
                hit_index[i] = (*dl_results[i], "DL_LAYER")
            elif if_results[i] is not None:
                hit_index[i] = (*if_results[i], "ANOMALY")

        _upd(stage=f"collating_alerts ({len(hit_index):,} candidates)", pct=82)

        def _get_meta(meta_row: dict, raw_row: dict, *keys) -> str:
            """Try multiple column-name variants, return first non-empty hit."""
            for k in keys:
                v = meta_row.get(k) or raw_row.get(k)
                if v is not None and str(v).strip() not in ("", "0", "0.0", "nan"):
                    return str(v).strip()
            return "UNKNOWN"

        _UPD_EVERY = max(1, min(5_000, max(1, len(hit_index)) // 20))
        _hit_list  = sorted(hit_index.items())   # process in row order

        for hit_n, (i, (verdict, conf, source)) in enumerate(_hit_list):
            if hit_n % _UPD_EVERY == 0:
                loop_elapsed = _time.time() - _loop_start
                rate         = hit_n / max(loop_elapsed, 0.001) if hit_n > 0 else 0
                remaining    = (len(_hit_list) - hit_n) / max(rate, 0.001) if rate > 0 else None
                sweep_pct    = 82 + int(hit_n / max(len(_hit_list), 1) * 15)
                _upd(processed=i, rate_rps=round(rate, 1),
                     eta_seconds=round(remaining) if remaining else None,
                     pct=min(sweep_pct, 97), hits=len(hits))

            if conf < BATCH_THRESHOLD or verdict.upper() in SAFE_VERDICTS:
                continue

            layer_counts[source] = layer_counts.get(source, 0) + 1
            meta_row = dict(zip(meta_cols, meta_values[i]))
            raw_row  = dict(zip(df_raw_cols, df_raw_values[i]))

            src   = _get_meta(meta_row, raw_row, "srcip", "Source_IP", "Source", "src_ip", "src", "SrcIP", "Src IP")
            dst   = _get_meta(meta_row, raw_row, "dstip", "Target_IP", "Destination", "dst_ip", "dst", "DstIP", "Dst IP")
            proto = _get_meta(meta_row, raw_row, "proto", "Protocol", "protocol")
            dport = _get_meta(meta_row, raw_row, "dsport", "dport", "Dst Port", "dst_port", "DstPort")
            ts    = _get_meta(meta_row, raw_row, "timestamp", "Timestamp", "Stime")
            if ts == "UNKNOWN":
                ts = datetime.datetime.now().isoformat()

            alert = {
                "id":            i + 1,
                "timestamp":     ts,
                "srcip": src, "dstip": dst, "Source": src, "Destination": dst,
                "proto":         proto,
                "dport":         dport,
                "verdict":       verdict.upper(),
                "confidence":    round(float(conf), 4),
                "source_engine": source,
                "session":       filename,          # backward compat: named session queries
                "server_session": _current_session_id,  # NEW: tags alert to this server boot
                "raw_row":       {k: str(v) for k, v in raw_row.items()
                                  if not isinstance(v, (bytes, bytearray))},
            }
            hits.append(alert)

        # ── Bulk-save hits ────────────────────────────────────────────────────────
        # Sweep results represent deliberate forensic analysis; we keep them all but
        # cap the TOTAL on-disk store at 100 000 entries to prevent alerts.json from
        # growing without bound when large datasets (50k–500k rows) are uploaded.
        # Live-capture alerts (session != None) already carry a session ID; they are
        # merged with sweep hits and the tail-100k slice is written atomically.
        _MAX_DISK_ALERTS = 100_000
        _flush_alerts_now()
        if hits:
            with _alerts_lock:
                try:
                    existing = []
                    if os.path.exists(CONFIG["ALERTS_FILE"]):
                        with open(CONFIG["ALERTS_FILE"], "r") as f:
                            try: existing = json.load(f)
                            except: pass
                    # All alerts (live-capture + previous sweeps) are now session-tagged.
                    # Keep the most recent entries across all sources, then append new hits.
                    combined = (existing + hits)[-_MAX_DISK_ALERTS:]
                    with open(CONFIG["ALERTS_FILE"], "w") as f:
                        json.dump(combined, f, separators=(",", ":"))
                    # Update disk counter + feed recent-alerts ring with sweep results
                    _alerts_disk_count = len(combined)
                    for _h in hits[-500:]:       # add most severe sweep hits to ring
                        _recent_alerts.append(_h)
                except Exception:
                    pass

        global session_threat_count, session_flow_count
        _upd(processed=total, hits=len(hits), layer_counts=layer_counts,
             status="COMPLETE", stage="done", pct=100,
             rate_rps=0, eta_seconds=0)
        session_threat_count += len(hits)
        session_flow_count   += total
        # sweep alerts are stamped with server_session=_current_session_id so
        # "current" session reports find them automatically — no set tracking needed.

        # ── Memory cleanup after large sweep ─────────────────────────────────
        # Large DataFrames + model output arrays can easily exhaust RAM on 1 M+
        # row files.  Explicitly delete heavy objects and run GC so the backend
        # process stays alive for subsequent requests.
        try:
            del df_raw, df, hits
            if X_batch is not None:
                del X_batch
            import gc as _gc
            _gc.collect()
        except Exception:
            pass

    except Exception as ex:
        _upd(status=f"ERROR: {ex}", stage="error", pct=0)
        # Even on failure, release memory and collect garbage to prevent OOM
        try:
            import gc as _gc
            _gc.collect()
        except Exception:
            pass

@app.post("/api/v1/sweep/{filename}")
async def trigger_sweep(filename: str, tasks: BackgroundTasks,
                         x_authority: str = Header(None)):
    if _lockdown_active:
        raise HTTPException(status_code=423, detail="SYSTEM LOCKDOWN ACTIVE — sweep analysis suspended. Release lockdown in Command & Control.")
    tasks.add_task(_run_analysis_pipeline, filename)
    return {"status":"SWEEP_QUEUED","filename":filename}

@app.get("/api/v1/sweep/progress/{filename}")
async def sweep_status(filename: str):
    return sweep_progress.get(filename,
                               {"status":"NOT_FOUND","processed":0,"total":0,"hits":0})

@app.get("/api/v1/sweep/stats")
async def sweep_global_stats():
    """Session-scoped stats (since this backend process started — no historical pollution)."""
    # Aggregate layer counts from all completed batch sweeps
    _NORM = {"DL-SENSEI": "DL_LAYER"}
    agg = {"SIGNATURE_DB": 0, "ML_ENSEMBLE": 0, "DL_LAYER": 0, "ANOMALY": 0}
    for p in sweep_progress.values():
        if isinstance(p, dict) and p.get("status") == "COMPLETE":
            lc = p.get("layer_counts", {})
            for raw_k, v in lc.items():
                k = _NORM.get(raw_k, raw_k)
                agg[k] = agg.get(k, 0) + v
    # Merge in live-capture per-layer counts (already normalised)
    for k, v in session_layer_counts.items():
        agg[k] = agg.get(k, 0) + v

    # Use ONLY in-memory counters — never read alerts.json here.
    # alerts.json is cleared on restart; all counters are authoritative.
    _ADMIN_V = {"NORMAL", "LOCKDOWN", "BASTION_CLEAN", "", "OPERATOR"}

    # Total threats: use O(1) in-memory counter (disk counter + unflushed buffer)
    effective_threats = max(session_threat_count,
                            _alerts_disk_count + len(_alert_buffer))

    # Average confidence: sample from the in-memory ring (up to 500 recent alerts).
    # This is a representative sample with zero disk I/O.
    try:
        _confs = [a.get("confidence", 0) for a in list(_recent_alerts)
                  if (a.get("verdict") or "").upper() not in _ADMIN_V]
        avg_conf = round(sum(_confs) / len(_confs), 4) if _confs else 0.0
    except Exception:
        avg_conf = 0.0

    return {
        "total_analyzed":    session_flow_count,
        "total_threats":     effective_threats,
        "avg_confidence":    avg_conf,
        "sessions_run":      len(sweep_progress),
        "is_capturing":      is_sniffing,
        "packets_processed": packet_counter + session_flow_count,
        "layer_counts":      agg,
    }

@app.post("/api/v1/sweep/stats/reset")
async def reset_sweep_stats(x_authority: str = Header(None)):
    """Reset session-level flow and threat counters (Operations Center reset)."""
    global session_threat_count, session_flow_count, session_layer_counts
    session_threat_count = 0
    session_flow_count   = 0
    session_layer_counts = {"SIGNATURE_DB": 0, "ML_ENSEMBLE": 0, "DL_LAYER": 0, "ANOMALY": 0}
    return {"status": "RESET", "message": "Session counters cleared — Operations Center reset"}

# ─────────────────────────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────────────────────────
@app.get("/api/v1/alerts")
async def fetch_alerts(limit: int = 300, session: str = None, full: bool = False):
    """Return alerts for display.

    • Default (no params): returns last ≤300 from the in-memory ring — O(1), never
      touches disk.  Fast enough for any live UI feed.
    • ?session=<filename>: reads disk to find session-specific sweep results.
    • ?full=true: reads the complete alerts.json (export / report use only).
    """
    if full or session:
        # Disk read — only for export or session-specific sweep results.
        # Run in executor so this heavy I/O doesn't block the event loop.
        def _disk_fetch():
            raw = _load_alerts()
            if session:
                # Match on either "session" (sweep filename) OR "server_session"
                # (server boot ID) so both live-capture and sweep alerts are found.
                raw = [a for a in raw
                       if a.get("session") == session or a.get("server_session") == session]
            raw.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return raw[:limit] if not full else raw
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _disk_fetch)
    # Fast path — read from in-memory ring (no disk I/O)
    ring = list(_recent_alerts)
    ring.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return ring[:limit]

@app.get("/api/v1/alerts/recent")
async def fetch_recent_alerts(limit: int = 50):
    ring = list(_recent_alerts)
    ring.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"alerts": ring[:limit]}

@app.delete("/api/v1/alerts")
async def clear_alerts(x_authority: str = Header(None)):
    global session_threat_count, session_layer_counts, _alerts_disk_count, _alert_buffer
    with _alerts_lock:
        with open(CONFIG["ALERTS_FILE"], "w") as f:
            json.dump([], f)
        # CRITICAL: reset all in-memory counters inside the same lock so they stay
        # consistent with the now-empty file. Without this the counter stayed at 95k.
        _alerts_disk_count = 0
        _recent_alerts.clear()
        _alert_buffer = []
    # Reset session counters so the Operations Center shows correct post-purge values
    session_threat_count  = 0
    session_layer_counts  = {"SIGNATURE_DB": 0, "ML_ENSEMBLE": 0, "DL_LAYER": 0, "ANOMALY": 0}
    # Also reset all sweep hit counters so stats are clean
    for p in sweep_progress.values():
        if isinstance(p, dict):
            p["hits"] = 0
            if "layer_counts" in p:
                p["layer_counts"] = {"SIGNATURE_DB": 0, "ML_ENSEMBLE": 0, "DL_LAYER": 0, "ANOMALY": 0}
    return {"status": "ALERTS_CLEARED", "session_reset": True, "counter_reset": True}


# ─────────────────────────────────────────────────────────────────────────────
# ALERTS ARCHIVE — permanent storage controlled by the admin
#
# Design:
#   • alerts.json  = EPHEMERAL session file, cleared on every server restart.
#                    Holds only the current capture session.
#   • alerts_archive.json = PERMANENT store.  Written only when the admin
#                    explicitly clicks "Save to Archive".  Never auto-cleared.
#                    Can only be cleared via DELETE /api/v1/alerts/archive.
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/alerts/archive")
async def save_to_archive(x_authority: str = Header(None)):
    """
    Append all current session alerts to the permanent archive.
    Only the admin can call this.  The archive is never auto-cleared.
    """
    if not _check_auth(x_authority):
        raise HTTPException(status_code=403, detail="Forbidden")

    def _do_archive():
        # Flush any buffered alerts to disk first
        _flush_alerts_now()

        # Load current session alerts
        session_alerts = _load_alerts()
        if not session_alerts:
            return {"status": "NOTHING_TO_SAVE", "saved": 0}

        archive_path = CONFIG["ARCHIVE_FILE"]
        with _alerts_lock:
            # Load existing archive (if any)
            existing: list = []
            if os.path.exists(archive_path):
                try:
                    with open(archive_path, "r", encoding="utf-8", errors="replace") as af:
                        existing = json.load(af)
                    if not isinstance(existing, list):
                        existing = []
                except Exception:
                    existing = []

            # Build a set of existing IDs to avoid duplicates
            existing_ids = {a.get("id") for a in existing}
            new_alerts   = [a for a in session_alerts if a.get("id") not in existing_ids]

            combined = existing + new_alerts
            with open(archive_path, "w", encoding="utf-8") as af:
                json.dump(combined, af)

        return {
            "status":   "SAVED",
            "saved":     len(new_alerts),
            "archive_total": len(combined),
        }

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do_archive)


@app.delete("/api/v1/alerts/archive")
async def clear_archive(x_authority: str = Header(None)):
    """Permanently erase the alert archive.  Admin-only, irreversible."""
    if not _check_auth(x_authority):
        raise HTTPException(status_code=403, detail="Forbidden")
    archive_path = CONFIG["ARCHIVE_FILE"]
    with _alerts_lock:
        with open(archive_path, "w", encoding="utf-8") as af:
            json.dump([], af)
    return {"status": "ARCHIVE_CLEARED"}


@app.get("/api/v1/alerts/archive")
async def get_archive(
    limit: int = 200,
    offset: int = 0,
    x_authority: str = Header(None)
):
    """Return paginated archived alerts, newest first."""
    if not _check_auth(x_authority):
        raise HTTPException(status_code=403, detail="Forbidden")
    archive_path = CONFIG["ARCHIVE_FILE"]
    if not os.path.exists(archive_path):
        return {"alerts": [], "total": 0}

    def _read():
        try:
            with open(archive_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return {"alerts": [], "total": 0}
            data_sorted = list(reversed(data))
            page = data_sorted[offset: offset + limit]
            return {"alerts": page, "total": len(data)}
        except Exception:
            return {"alerts": [], "total": 0}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _read)


@app.get("/api/v1/alerts/archive/stats")
async def archive_stats(x_authority: str = Header(None)):
    """Return archive summary without loading all data — O(1) scan."""
    if not _check_auth(x_authority):
        raise HTTPException(status_code=403, detail="Forbidden")
    archive_path = CONFIG["ARCHIVE_FILE"]
    if not os.path.exists(archive_path):
        return {"total": 0, "size_kb": 0, "exists": False}

    def _stats():
        size = os.path.getsize(archive_path)
        # Count '"id"' occurrences for a fast estimate
        with open(archive_path, "r", encoding="utf-8", errors="ignore") as af:
            raw = af.read()
        count = raw.count('"id"')
        # Get date range from a quick JSON parse of first/last entries
        first_ts = last_ts = None
        try:
            data = json.loads(raw)
            if data:
                first_ts = data[0].get("timestamp","")
                last_ts  = data[-1].get("timestamp","")
        except Exception:
            pass
        return {
            "total":    count,
            "size_kb":  round(size / 1024, 1),
            "exists":   True,
            "first_ts": first_ts,
            "last_ts":  last_ts,
        }

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _stats)


@app.get("/api/v1/alerts/count")
async def get_alert_count():
    """Return alert counts using the O(1) counter — never reads alerts.json."""
    disk_total = _alerts_disk_count + len(_alert_buffer)
    # Use session_threat_count as a lower-bound safety net: sweep results update
    # session_threat_count immediately but disk_count only after the async write
    # completes. If disk_count is 0 while session_count > 0, the write is in flight.
    total = max(disk_total, session_threat_count)
    return {
        "total":   total,
        "on_disk": _alerts_disk_count,
        "session": session_threat_count,
    }

# ─────────────────────────────────────────────────────────────
# DETECTION LOG SESSION STORE
#
# alerts.json only holds the CURRENT app run (cleared on every start).
# Analysts can snapshot the current run into a named detection log that
# survives restarts. Saved logs live in data/detection_logs/ and are removed
# only by uninstalling or by an explicit delete from the UI.
# ─────────────────────────────────────────────────────────────
_DETLOG_DIR   = os.path.join(os.path.dirname(CONFIG["ALERTS_FILE"]), "data", "detection_logs")
_DETLOG_INDEX = os.path.join(_DETLOG_DIR, "index.json")
_detlog_lock  = threading.Lock()

# Verdicts that are operator/system events, not threats — mirrors the UI filter.
_NON_THREAT_VERDICTS = {"NORMAL", "LOCKDOWN", "BASTION_CLEAN", "", "OPERATOR"}

# mtime-keyed cache so paging through a big alert file re-reads it only when
# the file actually changed, not on every page click.
_alert_page_cache = {"path": None, "mtime": 0.0, "data": []}

def _read_alerts_file_cached(path: str) -> list:
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return []
    c = _alert_page_cache
    if c["path"] == path and c["mtime"] == mt:
        return c["data"]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = []
    except Exception:
        data = []
    c["path"], c["mtime"], c["data"] = path, mt, data
    return data

def _detlog_read_index() -> list:
    try:
        with open(_DETLOG_INDEX, "r", encoding="utf-8") as f:
            idx = json.load(f)
        return idx if isinstance(idx, list) else []
    except Exception:
        return []

def _detlog_write_index(idx: list):
    os.makedirs(_DETLOG_DIR, exist_ok=True)
    with open(_DETLOG_INDEX, "w", encoding="utf-8") as f:
        json.dump(idx, f, indent=2)

def _filter_page_alerts(alerts: list, severity: str, q: str,
                        offset: int, limit: int) -> dict:
    """One pass: threat filter + severity/search filter + stats + page slice."""
    q_low = (q or "").lower()
    sev   = (severity or "ALL").upper()
    total = high = med = 0
    conf_sum = 0.0
    mitre_ids: set = set()
    matched: list = []
    for a in alerts:
        v = str(a.get("verdict") or a.get("attack_type") or "").upper()
        if v in _NON_THREAT_VERDICTS:
            continue
        total += 1
        a_sev = str(a.get("severity", "")).upper() or ("HIGH" if float(a.get("confidence", 0) or 0) >= 0.85 else "MEDIUM")
        if a_sev == "HIGH": high += 1
        elif a_sev == "MEDIUM": med += 1
        try:    conf_sum += float(a.get("confidence", 0) or 0)
        except (TypeError, ValueError): pass
        if a.get("mitre_id"): mitre_ids.add(a["mitre_id"])
        # severity / search filters apply to the LIST, stats stay whole-session
        if sev != "ALL" and a_sev != sev:
            continue
        if q_low:
            hay = " ".join(str(a.get(k, "")) for k in
                           ("verdict", "attack_type", "srcip", "dstip", "Source",
                            "Destination", "mitre_id", "source_engine")).lower()
            if q_low not in hay:
                continue
        matched.append(a)
    # Newest first
    matched.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
    page = matched[offset:offset + limit]
    avg_conf = (conf_sum / total) if total else 0.0
    return {
        "alerts":   page,
        "filtered": len(matched),
        "stats": {
            "total":       total,
            "high":        high,
            "medium":      med,
            "low":         max(0, total - high - med),
            "avg_confidence": round(avg_conf * 100, 1) if avg_conf <= 1.0 else round(avg_conf, 1),
            "mitre_unique": len(mitre_ids),
        },
    }

@app.get("/api/v1/session/alerts")
async def get_session_alerts(limit: int = 20, offset: int = 0,
                             severity: str = "ALL", q: str = "",
                             log_id: str = "current"):
    """Paginated full-session alert feed with whole-session stats.

    log_id: "current" pages the live alerts.json; any other value pages a
    saved detection log from data/detection_logs/.
    """
    limit  = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    if log_id == "current":
        _flush_alerts_now()   # include the freshest buffered alerts
        path = CONFIG["ALERTS_FILE"]
    else:
        safe = os.path.basename(str(log_id))
        path = os.path.join(_DETLOG_DIR, f"{safe}.json")
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail=f"Detection log {log_id} not found")

    def _work():
        alerts = _read_alerts_file_cached(path)
        return _filter_page_alerts(alerts, severity, q, offset, limit)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _work)
    result["log_id"] = log_id
    return result

@app.post("/api/v1/detlogs/save")
async def save_detection_log(request: Request):
    """Snapshot the current session's threats into a permanent detection log."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    _flush_alerts_now()

    def _work():
        alerts = _read_alerts_file_cached(CONFIG["ALERTS_FILE"])
        threats = [a for a in alerts
                   if str(a.get("verdict") or a.get("attack_type") or "").upper()
                   not in _NON_THREAT_VERDICTS]
        if not threats:
            return {"status": "NOTHING_TO_SAVE",
                    "message": "No threats in the current session to save."}
        log_id = f"detlog_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        label  = (body.get("label") or "").strip() or \
                 f"Session {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
        with _detlog_lock:
            os.makedirs(_DETLOG_DIR, exist_ok=True)
            with open(os.path.join(_DETLOG_DIR, f"{log_id}.json"), "w",
                      encoding="utf-8") as f:
                json.dump(threats, f, separators=(",", ":"))
            idx = _detlog_read_index()
            idx.append({
                "id":       log_id,
                "label":    label,
                "saved_at": datetime.datetime.now().isoformat(),
                "count":    len(threats),
            })
            _detlog_write_index(idx)
        return {"status": "SAVED", "id": log_id, "label": label,
                "count": len(threats),
                "message": f"Detection log saved — {len(threats):,} threats stored permanently."}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _work)

@app.get("/api/v1/detlogs")
async def list_detection_logs():
    """List saved detection logs, newest first."""
    idx = _detlog_read_index()
    idx.sort(key=lambda x: x.get("saved_at", ""), reverse=True)
    return {"logs": idx}

@app.delete("/api/v1/detlogs/{log_id}")
async def delete_detection_log(log_id: str):
    """Permanently remove one saved detection log."""
    safe = os.path.basename(log_id)
    path = os.path.join(_DETLOG_DIR, f"{safe}.json")
    with _detlog_lock:
        idx  = _detlog_read_index()
        kept = [e for e in idx if e.get("id") != safe]
        if len(kept) == len(idx) and not os.path.exists(path):
            raise HTTPException(status_code=404, detail=f"Detection log {log_id} not found")
        _detlog_write_index(kept)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            raise HTTPException(status_code=500, detail="Log file could not be removed")
    return {"status": "DELETED", "id": safe}

@app.post("/api/v1/quarantine")
async def quarantine_host(request: Request, x_authority: str = Header(None)):
    """Log a quarantine action and store the blocked IP in settings."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    ip        = body.get("ip", "")
    protocol  = body.get("protocol", "")
    reason    = body.get("reason", "")
    ts        = datetime.datetime.now().isoformat()
    if not ip:
        raise HTTPException(status_code=400, detail="ip required")
    # Persist to settings
    try:
        settings = _load_settings()
        quarantined = settings.get("quarantined_ips", [])
        if ip not in quarantined:
            quarantined.append(ip)
        settings["quarantined_ips"] = quarantined
        settings["last_quarantine"] = {"ip": ip, "protocol": protocol, "reason": reason, "at": ts}
        _save_settings(settings)
    except Exception:
        pass
    # Apply actual Windows Firewall block (same mechanism as Auto-Isolate)
    threading.Thread(target=_apply_auto_isolate, args=(ip,), daemon=True).start()
    # Log as an alert entry
    _save_alert({
        "id": int(time.time()),
        "timestamp": ts,
        "srcip": ip, "dstip": "Bastion_Network",
        "verdict": "QUARANTINED",
        "confidence": 1.0,
        "source_engine": "OPERATOR",
        "protocol": protocol,
        "reason": reason,
        "session": None,
    })
    return {"status": "QUARANTINED", "ip": ip, "at": ts, "firewall_rule": f"BASTION-AUTO-ISOLATE-{ip.replace('.','_')}"}

@app.patch("/api/v1/alerts/{alert_id}/commit")
async def commit_alert(alert_id: str, request: Request,
                       x_authority: str = Header(None)):
    """Persist analyst verification + notes against a specific alert record."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    verification  = body.get("verification", "")
    analyst_notes = body.get("analyst_notes", "")
    committed_at  = body.get("committed_at", datetime.datetime.now().isoformat())

    with _alerts_lock:
        if not os.path.exists(CONFIG["ALERTS_FILE"]):
            raise HTTPException(status_code=404, detail="Alert database empty")
        with open(CONFIG["ALERTS_FILE"], "r") as f:
            try:
                alerts = json.load(f)
            except Exception:
                alerts = []

        # Match by id field (stored as int or str)
        matched = False
        for a in alerts:
            if str(a.get("id", "")) == str(alert_id):
                a["analyst_verification"] = verification
                a["analyst_notes"]        = analyst_notes
                a["committed_at"]         = committed_at
                a["analyst_committed"]    = True
                matched = True
                break

        if not matched:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

        with open(CONFIG["ALERTS_FILE"], "w") as f:
            json.dump(alerts, f, separators=(",", ":"))
        committed_alert = a

    # Every commit also lands in the analyst feedback store — this is what the
    # per-layer precision statistics are computed from, and it is browsable in
    # Command & Control (Analyst Feedback Log).
    if _feedback is not None and verification in ("confirm", "false"):
        try:
            _feedback.add_feedback(
                committed_alert,
                "CORRECT" if verification == "confirm" else "FALSE_ALARM",
                note=analyst_notes or None,
            )
        except Exception:
            pass   # feedback store failure must never block the alert commit

    return {
        "status": "COMMITTED",
        "alert_id": alert_id,
        "verification": verification,
        "committed_at": committed_at,
    }

# ─────────────────────────────────────────────────────────────
# ANALYST FEEDBACK MECHANISM
#
# Lets an analyst confirm or correct a verdict ("Correct" / "False Alarm",
# optionally with the true attack label). Feedback is stored and later used to
# retrain and continuously improve the detection models — closing the loop
# between live detection and model learning.
# ─────────────────────────────────────────────────────────────
try:
    from core import feedback as _feedback
except Exception as _fb_ex:                      # pragma: no cover
    _feedback = None
    print(f"[WARN] feedback module load failed: {_fb_ex}")


@app.post("/api/v1/feedback")
async def submit_feedback(request: Request):
    """
    Record an analyst's judgement on an alert.

    Body:
      {
        "alert": { ...the alert dict... }   # or just {"id": <id>}
        "judgement": "CORRECT" | "FALSE_ALARM",
        "true_label": "Normal",   # optional
        "note": "free text"       # optional
      }
    """
    if _feedback is None:
        raise HTTPException(status_code=503, detail="feedback module unavailable")
    try:
        body = await request.json()
    except Exception:
        body = {}

    alert = body.get("alert")
    # Allow passing only an alert id — look it up in the current session.
    if not alert and body.get("alert_id") is not None:
        target = str(body.get("alert_id"))
        alert = next((a for a in list(_recent_alerts)
                      if str(a.get("id")) == target), {"id": body.get("alert_id")})
    if not isinstance(alert, dict):
        raise HTTPException(status_code=400, detail="alert object or alert_id required")

    try:
        record = _feedback.add_feedback(
            alert,
            body.get("judgement", ""),
            true_label=body.get("true_label"),
            note=body.get("note"),
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    return {"status": "FEEDBACK_RECORDED", "record": record}


@app.get("/api/v1/feedback")
async def list_feedback():
    """Return all stored analyst feedback records."""
    if _feedback is None:
        raise HTTPException(status_code=503, detail="feedback module unavailable")
    return _feedback.load_feedback()


@app.get("/api/v1/feedback/stats")
async def feedback_statistics():
    """Summary of feedback gathered (counts, per-engine breakdown, retrain set size)."""
    if _feedback is None:
        raise HTTPException(status_code=503, detail="feedback module unavailable")
    stats = _feedback.feedback_stats()
    stats["retraining_examples"] = len(_feedback.export_retraining_set())
    return stats

# ─────────────────────────────────────────────────────────────
# SETTINGS
# ─────────────────────────────────────────────────────────────
@app.get("/api/v1/settings/config")
async def get_config():
    return _load_settings()

@app.post("/api/v1/settings/update")
async def update_config(request: Request):
    try:
        data = await request.json()
        current = _load_settings()
        # Only whitelisted keys are persisted — request metadata like
        # {policy, value} or retired UI fields must never reach settings.json.
        current.update({k: v for k, v in data.items() if k in _SETTINGS_ALLOWED_KEYS})
        _save_settings(current)

        # ── Live detection threshold sync ───────────────────────────────────
        global _alert_threshold, _ml_threshold, _anomaly_gate, _dpi_target
        if any(k in data for k in ("sigConfFloor", "mlVoteThreshold", "anomalySensitivity")):
            _alert_threshold = max(0.50, min(0.95, current.get("sigConfFloor", 70) / 100.0))
            _ml_threshold    = max(0.40, min(0.95, current.get("mlVoteThreshold", 60) / 100.0))
            _anomaly_gate    = max(0.70, min(0.99, 1.0 - current.get("anomalySensitivity", 50) * 0.003))
        if "dpi_target" in data or "dpi_enabled" in data:
            _dpi_target = current.get("dpi_target", "") if current.get("dpi_enabled") else ""

        # ── Real-time policy enforcement ────────────────────────────────────
        # If the update contains a 'policy' key/value pair from the admin UI,
        # apply the policy effect immediately (not just store it).
        _POLICY_KEYS = {"autoIsolate","mfaEnforce",
                        "stealthMode","deepInspection","ghostProtocol"}
        policy_key = data.get("policy")
        policy_val = data.get("value")
        if policy_key in _POLICY_KEYS and isinstance(policy_val, bool):
            _update_policy(policy_key, policy_val)

        # Also handle bulk policy updates (e.g. direct key in payload)
        for k in _POLICY_KEYS:
            if k in data and isinstance(data[k], bool) and policy_key != k:
                _update_policy(k, data[k])

        return {"status":"SAVED","config":current}
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))

@app.get("/api/v1/policies/status")
async def get_policy_status():
    """Return currently active policy states and isolation list."""
    with _policy_lock:
        policies = dict(_active_policies)
    with _isolated_lock:
        isolated = list(_auto_isolated_ips)
    return {
        "policies":       policies,
        "isolated_ips":   isolated,
        "isolation_count": len(isolated),
    }

@app.post("/api/v1/policies/release")
async def release_isolated_ip(request: Request):
    """Manually release an auto-isolated IP."""
    try:
        data = await request.json()
        ip = data.get("ip", "")
        if ip:
            threading.Thread(target=_remove_auto_isolate, args=(ip,), daemon=True).start()
            return {"status": "RELEASED", "ip": ip}
        raise HTTPException(status_code=400, detail="ip required")
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))

@app.post("/api/v1/neural/reset")
async def neural_reset():
    global engine
    try:
        if engine is not None:
            engine._predict_cache = {}
            if hasattr(engine, '_flow_cache'):
                engine._flow_cache.clear()
        return {"status": "FLUSHED", "message": "Inference cache cleared. Models remain loaded — next prediction starts from a clean state."}
    except Exception as ex:
        return {"status": "PARTIAL", "message": f"Cache clear attempted: {ex}"}

@app.post("/api/v1/roll-key")
async def roll_key():
    import secrets
    new_key = f"BASTION-{secrets.token_hex(8).upper()}"
    cfg = _load_settings()
    cfg["apiKey"] = new_key
    _save_settings(cfg)
    return {"status":"KEY_ROTATED","new_key":new_key}

@app.post("/api/v1/flush")
async def flush_logs():
    global _alerts_disk_count, _alert_buffer
    with _alerts_lock:
        with open(CONFIG["ALERTS_FILE"],"w") as f:
            json.dump([],f)
        _alerts_disk_count = 0
        _recent_alerts.clear()
        _alert_buffer = []
    return {"status":"FLUSHED"}

@app.post("/api/v1/maint")
async def maintenance_mode():
    try:
        with _alerts_lock:
            with open(CONFIG["ALERTS_FILE"], "r") as f:
                alerts = json.load(f)
            seen = set()
            deduped = []
            for a in alerts:
                key = a.get("id") or a.get("timestamp","")
                if key not in seen:
                    seen.add(key)
                    deduped.append(a)
            removed = len(alerts) - len(deduped)
            with open(CONFIG["ALERTS_FILE"], "w") as f:
                json.dump(deduped, f)
        return {"status": "COMPLETE", "message": f"Alert log compacted — {removed} duplicate entries removed, {len(deduped)} records retained."}
    except Exception as ex:
        return {"status": "ERROR", "message": "Maintenance could not complete. Alert log may be empty or unreadable."}

@app.post("/api/v1/wipe")
async def wipe_system():
    global _alerts_disk_count, _alert_buffer
    with _alerts_lock:
        with open(CONFIG["ALERTS_FILE"],"w") as f:
            json.dump([],f)
        _alerts_disk_count = 0
        _recent_alerts.clear()
        _alert_buffer = []
    _save_settings(_load_settings())
    return {"status":"WIPED","message":"Alert logs and volatile data cleared."}

@app.post("/api/v1/restart")
async def restart_engine():
    return {"status":"RESTART_ACKNOWLEDGED",
            "message":"Use the restart button in the launcher to restart the full backend."}

@app.post("/api/v1/lockdown")
async def hard_lockdown(x_authority: str = Header(None)):
    """
    Hard Lockdown: halt all active capture, flush the packet ring, and
    reset session threat counter so operators start from a known-clean state.
    Does NOT affect the backend process itself — use the launcher for that.
    """
    global is_sniffing, sniff_thread, session_threat_count, session_flow_count, session_layer_counts, _lockdown_active
    _lockdown_active = True
    # Stop any running capture
    was_running = is_sniffing
    is_sniffing = False
    _live_flow_tracker.stop()
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join(timeout=3)
    # Flush in-memory buffers
    _packet_ring.clear()
    _raw_packet_ring.clear()
    # Reset session counters so the dashboard reflects the post-lockdown baseline
    session_threat_count  = 0
    session_flow_count    = 0
    session_layer_counts  = {"SIGNATURE_DB": 0, "ML_ENSEMBLE": 0, "DL_LAYER": 0, "ANOMALY": 0}
    # Log lockdown in the dashboard startup log (admin action, not an attack alert)
    ts = datetime.datetime.now().isoformat()
    ENGINE_STARTUP_LOG.append(
        f"[{ts}] OPERATOR: Hard lockdown executed — capture halted, buffers flushed"
    )
    return {
        "status":      "LOCKDOWN_ACTIVE",
        "capture_was": "RUNNING" if was_running else "IDLE",
        "buffers":     "FLUSHED",
        "counters":    "RESET",
        "message":     "Capture halted. Packet buffers flushed. Session counters reset. Forensic log entry written.",
    }

@app.post("/api/v1/lockdown/release")
async def release_lockdown(x_authority: str = Header(None)):
    """
    Release Hard Lockdown: clear the lockdown flag so the system can resume
    normal analysis. Capture must be restarted manually via the Live Monitor.
    """
    global _lockdown_active
    _lockdown_active = False
    ts = datetime.datetime.now().isoformat()
    ENGINE_STARTUP_LOG.append(
        f"[{ts}] OPERATOR: Lockdown released — system returned to operational state"
    )
    return {
        "status":  "LOCKDOWN_RELEASED",
        "message": "Lockdown cleared. System returned to operational state. Restart capture in Live Monitor.",
    }

# ─────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────
@app.get("/api/v1/capture/session_id")
async def get_current_session_id():
    """Return the ID of the current capture session for use by the report generator."""
    return {"session_id": _current_session_id, "is_capturing": is_sniffing}


@app.post("/api/v1/reports/generate")
async def generate_report(request: Request,
                           tasks: BackgroundTasks,
                           x_authority: str = Header(None)):
    """Generate a forensic report from current alerts or a session file.

    session_id behaviour:
      "current"  → only alerts from the active/most-recent capture session
      "all"      → all stored alerts (last 2 000 entries)
      <explicit> → filter alerts whose 'session' field matches the given string
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    formats    = body.get("formats", ["json","html","pdf"])
    # Default to "current" so clicking Generate Report during/after a session
    # always produces a report specific to that session, not the entire history.
    session_id = body.get("session_id", "current")

    # ── Snapshot _current_session_id before yielding to executor thread ──────
    # Capture restarts reset _current_session_id; snapshotting here ensures the
    # report filter stays anchored to the session that was active when the user
    # clicked "Generate Report", even if a capture restart races with the thread.
    _snap_sess_id = _current_session_id

    # ── Load and filter alerts — optimised single-pass loader ────────────────
    # Returns (sample: list, total_count: int) in a single disk pass.
    # Uses a fixed-size rolling deque so memory stays bounded regardless of
    # how many session alerts exist on disk (e.g. 95k sweep results).
    _MAX_REPORT_ALERTS = 2000

    def _prepare_alerts():
        """Fast alert loader for report generation.
        Returns (sample_list, total_count).

        PERFORMANCE STRATEGY
        ────────────────────
        For "current" session (the common case after a large sweep):
          • Total count  — uses the O(1) in-memory counter (_alerts_disk_count)
                           instead of reading the entire alerts.json.
          • Sample       — pulled from in-memory ring + write buffer.
                           No disk I/O needed for the sample when ring ≥ 100.
          • Fast-path skips the 80 MB disk read that caused 90s generation.

        For named sessions or "all" — full disk read (these are uncommon and
        typically involve small datasets, so the cost is acceptable).
        """
        seen_ids: set    = set()
        total_count: int = 0
        sample: _deque   = _deque(maxlen=_MAX_REPORT_ALERTS)

        if session_id == "current":
            # ── Fast path: ring + buffer only, counter for total ─────────────
            # 1. Unflushed write buffer
            with _alerts_lock:
                for a in list(_alert_buffer):
                    s   = a.get("session", "")
                    srv = a.get("server_session", "")
                    if s == _snap_sess_id or srv == _snap_sess_id:
                        total_count += 1
                        seen_ids.add(a.get("id"))
                        sample.append(a)
                # Grab disk counter inside the same lock for consistency
                _disk_cnt = _alerts_disk_count

            # 2. Recent-alerts ring (last 500 sweep hits + live-capture hits)
            for a in list(_recent_alerts):
                aid = a.get("id")
                s   = a.get("session", "")
                srv = a.get("server_session", "")
                if (s == _snap_sess_id or srv == _snap_sess_id) and aid not in seen_ids:
                    total_count += 1
                    seen_ids.add(aid)
                    sample.append(a)

            # Total: disk counter is authoritative (O(1), no disk read needed)
            # Add ring's contribution to the total already counted above.
            # disk_count includes everything ever flushed; subtract the ring's
            # portion that's already in total_count to avoid double-counting.
            # Simpler: just use the disk counter as the session total since it
            # covers the full sweep, and ring is a subset.
            real_total = max(_disk_cnt + len(_alert_buffer), total_count)

            # If ring is very thin (< 50 entries), fall back to disk for sample
            if len(sample) < 50 and real_total > 0:
                _flush_alerts_now()
                try:
                    _disk_data = _load_alerts()
                    for a in _disk_data:
                        aid = a.get("id")
                        s   = a.get("session", "")
                        srv = a.get("server_session", "")
                        if (s == _snap_sess_id or srv == _snap_sess_id) and aid not in seen_ids:
                            seen_ids.add(aid)
                            sample.append(a)
                except Exception:
                    pass

            return list(sample), real_total

        # ── Slow path: full disk read for named or "all" sessions ────────────
        def _matches(a: dict) -> bool:
            if session_id == "all":
                return True
            return a.get("session") == session_id

        with _alerts_lock:
            for a in list(_alert_buffer):
                if _matches(a):
                    total_count += 1
                    seen_ids.add(a.get("id"))
                    sample.append(a)

        for a in list(_recent_alerts):
            aid = a.get("id")
            if _matches(a) and aid not in seen_ids:
                total_count += 1
                seen_ids.add(aid)
                sample.append(a)

        _flush_alerts_now()
        try:
            for a in _load_alerts():
                aid = a.get("id")
                if _matches(a) and aid not in seen_ids:
                    total_count += 1
                    seen_ids.add(aid)
                    sample.append(a)
        except Exception:
            pass

        return list(sample), total_count

    loop = asyncio.get_event_loop()
    alerts, total_in_store = await loop.run_in_executor(None, _prepare_alerts)
    # alerts is already limited to _MAX_REPORT_ALERTS

    # ── Build session_meta ────────────────────────────────────────────────────
    client_meta = body.get("session_meta", {}) or {}
    # Determine a human-readable source label — never use raw "current" as filename
    _source_raw = (body.get("source")
                   or client_meta.get("source")
                   or (f"live_{_current_session_id}" if session_id == "current" else session_id)
                   or "session")
    session_meta = {
        "mode":           body.get("mode", client_meta.get("report_type", "analysis")),
        "source":         _source_raw,
        "start_time":     body.get("start_time", datetime.datetime.now().isoformat()),
        "end_time":       datetime.datetime.now().isoformat(),
        "duration":       body.get("duration", "N/A"),
        "interface":      body.get("interface", current_interface or "N/A"),
        "session_id":     _current_session_id,
        # Show TOTAL store count in the report header, not just the capped sample
        "total_flows":    total_in_store,
        "report_sample":  (f"Most recent {len(alerts):,} of {total_in_store:,} session alerts"
                           if total_in_store > _MAX_REPORT_ALERTS else
                           f"All {total_in_store:,} session alerts"),
        "engine_version": "Bastion IDS v2.0",
        **client_meta,   # allow frontend to inject alert_id, analyst_notes, etc.
    }

    try:
        from utils.report_generator import generate_report as gen_report
        # ── All I/O + PDF/HTML generation run in a thread — non-blocking ──────
        result = await loop.run_in_executor(None, gen_report, alerts, session_meta, formats)
        partial = result.get("errors", {})
        response_body = {
            "status":    "PARTIAL" if partial else "SUCCESS",
            "report_id": result["report_id"],
            "paths":     result["paths"],
            "total_alerts_in_session": total_in_store,
        }
        if partial:
            response_body["format_errors"] = partial
        return response_body
    except Exception as ex:
        import traceback
        tb = traceback.format_exc()
        print(f"[report_generate ERROR] {ex}\n{tb}", flush=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {ex}")

@app.get("/api/v1/reports/list")
async def list_reports():
    reports = []
    for f in os.listdir(CONFIG["REPORTS_DIR"]):
        fp = os.path.join(CONFIG["REPORTS_DIR"], f)
        reports.append({
            "filename": f,
            "size_kb": round(os.path.getsize(fp) / 1024, 1),
            "modified": datetime.datetime.fromtimestamp(
                os.path.getmtime(fp)).isoformat(),
        })
    reports.sort(key=lambda x: x["modified"], reverse=True)
    return {"reports": reports}

@app.get("/api/v1/reports/download/{filename}")
async def download_report(filename: str):
    """Download a generated report file.

    CRITICAL DESIGN NOTE: We intentionally do NOT use FastAPI's FileResponse here.
    FileResponse sends HTTP 200 headers first, then opens the file lazily during the
    async send phase.  If the file is missing/corrupted at that point, the resulting
    FileNotFoundError propagates AFTER headers have been committed, which makes it
    impossible for Starlette to send a proper error response — instead it re-raises
    the exception through the middleware stack and crashes the ASGI worker.

    Fix: read the file fully inside the async endpoint function (in a thread executor
    so the event loop is not blocked).  Any OSError/FileNotFoundError raised here is
    caught by FastAPI's normal exception handlers and converted to a proper HTTP error
    response — the server stays up regardless.
    """
    # Sanitise: reject any directory traversal attempt
    safe = os.path.basename(filename)
    if not safe or safe != filename.replace("/", "").replace("\\", ""):
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = os.path.join(CONFIG["REPORTS_DIR"], safe)

    # ── Read file bytes in a thread (non-blocking) ────────────────────────────
    def _read_file():
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        size = os.path.getsize(path)
        if size == 0:
            raise ValueError(f"Report file is empty: {safe}")
        with open(path, "rb") as fh:
            return fh.read()

    try:
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, _read_file)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Report not found: {safe}")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Cannot read report file: {e}")

    # Return raw bytes — always force attachment (never inline PDF/HTML preview)
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe}"',
            "Content-Length": str(len(content)),
            "Cache-Control": "no-store",
        },
    )

@app.delete("/api/v1/reports/clear")
async def clear_reports(x_authority: str = Header(None)):
    """Delete all generated reports from the reports directory."""
    count = 0
    for f in os.listdir(CONFIG["REPORTS_DIR"]):
        try:
            os.remove(os.path.join(CONFIG["REPORTS_DIR"], f))
            count += 1
        except Exception:
            pass
    return {"status": "CLEARED", "deleted": count}

# ─────────────────────────────────────────────────────────────
# STATIC FILES — explicit routes instead of app.mount("/", ...)
# Using app.mount("/", StaticFiles(...)) shadows WebSocket routes in
# Starlette 0.52+ because the Mount ASGI app intercepts ALL scope types
# (including websocket) for matching paths, returning 404 before the WS
# handler can fire.  Explicit GET routes only handle scope type "http",
# so WebSocket routes defined above are always reached first.
# ─────────────────────────────────────────────────────────────
dist_dir = os.path.join(BASE_DIR, "app-desktop", "dist")

if os.path.exists(dist_dir):
    # Serve the Vite-built assets directory (hashed JS/CSS bundles)
    app.mount("/assets", StaticFiles(directory=os.path.join(dist_dir, "assets")), name="assets")

    @app.get("/favicon.svg", include_in_schema=False)
    async def _favicon():
        p = os.path.join(dist_dir, "favicon.svg")
        return FileResponse(p) if os.path.exists(p) else JSONResponse({}, 404)

    @app.get("/icons.svg", include_in_schema=False)
    async def _icons():
        p = os.path.join(dist_dir, "icons.svg")
        return FileResponse(p) if os.path.exists(p) else JSONResponse({}, 404)

    # SPA catch-all — must be LAST; only fires for HTTP GET, never for WebSocket
    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa(full_path: str, request: Request):
        # Never serve the SPA for API or WebSocket paths — return 404 so
        # FastAPI's WebSocket handler and API routes get a clean shot.
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        # Try exact file first (CSS, fonts, images that may live outside /assets)
        candidate = os.path.join(dist_dir, full_path)
        if full_path and os.path.isfile(candidate):
            return FileResponse(candidate)
        # Fall through to index.html for all SPA client-side routes
        return FileResponse(os.path.join(dist_dir, "index.html"))

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Pass `app` directly (not the string "api_server:app") so uvicorn does NOT
    # re-import this module — which would run BastionEngine.__init__ a second time.
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=48217,
        reload=False,
        log_level="warning",
    )
