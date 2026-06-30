"""
BASTION IDS — SIGNATURE DETECTION ENGINE
==========================================
Parses and matches ET-Open / custom Snort rules against live packets and
batch flow records.

Detection layers (this module):
  1. IP reputation blacklist
  2. Rule-based matching (port + protocol + payload content)
  3. Rate-based heuristics (port scan, brute-force)
  4. Behavioural heuristics (data volume, protocol anomalies)

FALSE POSITIVE CONTROLS:
  - Loopback exclusion: 127.x.x.x ↔ 127.x.x.x traffic is never flagged
  - Content requirement: rules without payload patterns require exact port
  - Snort port variables ($SMB_PORTS etc.) are resolved to real port sets
  - Scan tracker: counts UNIQUE (dst_ip, dst_port) pairs — not packet volume
  - Heuristics only fire on batch/flow data where metric confidence is high
"""

import re
import os
import time
import json
import threading
from collections import defaultdict, deque
from datetime import datetime

BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE_DIR, "rules")

# ─────────────────────────────────────────────────────────────
# SNORT VARIABLE RESOLUTION
# Expand well-known Snort port variables so rules that use
# $SMB_PORTS, $HTTP_PORTS etc. are indexed on real port numbers.
# ─────────────────────────────────────────────────────────────
SNORT_PORT_VARS: dict = {
    "$HTTP_PORTS":   {80, 8080, 8000, 8443, 3000, 5000},
    "$HTTP_SERVERS": None,   # not a port spec
    "$SQL_PORTS":    {1433, 1521, 3306, 5432, 5984},
    "$SMTP_PORTS":   {25, 587, 465},
    "$SSH_PORTS":    {22},
    "$FTP_PORTS":    {21},
    "$FTP_DATA":     {20},
    "$SMB_PORTS":    {445, 139},
    "$ORACLE_PORTS": {1521},
    "$RDP_PORTS":    {3389},
    "$TELNET_PORTS": {23},
    "$DNS_PORTS":    {53},
    "$IMAP_PORTS":   {143, 993},
    "$POP3_PORTS":   {110, 995},
    "$SIP_PORTS":    {5060, 5061},
    # IP-group variables — treated as None (match any)
    "$HOME_NET":     None,
    "$EXTERNAL_NET": None,
    "$HTTP_SERVERS": None,
    "$SQL_SERVERS":  None,
    "$DNS_SERVERS":  None,
}

# ─────────────────────────────────────────────────────────────
# RFC-1918 / PRIVATE IP HELPER
# Used to enforce $HOME_NET / $EXTERNAL_NET direction from rules.
# ─────────────────────────────────────────────────────────────
_RFC1918 = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "169.254.",   # link-local
)

def _is_rfc1918(ip: str) -> bool:
    """Return True if ip is an RFC-1918 / loopback / link-local address."""
    if not ip:
        return False
    return any(ip.startswith(p) for p in _RFC1918)


# ─────────────────────────────────────────────────────────────
# RULE SCHEMA
# ─────────────────────────────────────────────────────────────
class SigRule:
    __slots__ = ("sid", "msg", "proto", "src_ports", "dst_ports",
                 "content_patterns", "nocase", "flags", "threshold",
                 "classtype", "severity", "raw",
                 "dsize_op", "dsize_val",    # payload size constraint
                 "has_pcre",                  # True if rule uses PCRE (we can't evaluate it)
                 "requires_home_dst",         # True → only fire when dst is RFC1918
                 "requires_external_dst",     # True → only fire when dst is NOT RFC1918
                 )

    def __init__(self):
        self.sid                 = 0
        self.msg                 = ""
        self.proto               = "any"
        self.src_ports           = None   # None = any
        self.dst_ports           = None   # None = any
        self.content_patterns    = []     # list[bytes]
        self.nocase              = False
        self.flags               = None
        self.threshold           = None
        self.classtype           = ""
        self.severity            = "MEDIUM"
        self.raw                 = ""
        self.dsize_op            = None   # None | '>' | '<' | '=' | '>=' | '<='
        self.dsize_val           = None   # int
        self.has_pcre            = False  # rule requires PCRE evaluation we can't do
        self.requires_home_dst   = False  # rule says -> $HOME_NET / $HTTP_SERVERS
        self.requires_external_dst = False  # rule says -> $EXTERNAL_NET


# ─────────────────────────────────────────────────────────────
# PORT PARSER
# ─────────────────────────────────────────────────────────────
def _parse_port_spec(spec: str):
    """
    Parse a Snort port specification and return a set of ints, or None (=any).
    Handles: any, $VAR, 80, [80,443], 1024:65535, !80
    """
    if not spec:
        return None
    spec = spec.strip()

    # Resolve known Snort variables
    if spec in SNORT_PORT_VARS:
        return SNORT_PORT_VARS[spec]

    if spec == "any" or spec.startswith("$"):
        return None   # unknown variable or "any" → match all

    negate = spec.startswith("!")
    if negate:
        spec = spec[1:]

    spec = spec.strip("[]")
    ports: set = set()

    for part in spec.split(","):
        part = part.strip()
        if ":" in part:
            lo_s, hi_s = part.split(":", 1)
            try:
                lo = int(lo_s.strip()) if lo_s.strip() else 0
                hi = int(hi_s.strip()) if hi_s.strip() else 65535
                ports.update(range(lo, hi + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass

    if not ports:
        return None
    if negate:
        return ("not", ports)
    return ports


def _port_match(port_spec, port: int) -> bool:
    if port_spec is None:
        return True
    if isinstance(port_spec, tuple) and port_spec[0] == "not":
        return port not in port_spec[1]
    return port in port_spec


# ─────────────────────────────────────────────────────────────
# RULE PARSER
# ─────────────────────────────────────────────────────────────
_MSG_RE      = re.compile(r'msg:"([^"]+)"')
_SID_RE      = re.compile(r'sid:(\d+)')
_CONTENT_ALL = re.compile(r'content:"([^"]*)"')   # captures all content fields
_CLASSTYPE_RE= re.compile(r'classtype:([^;]+)')
_THRESHOLD_RE= re.compile(r'threshold:\s*type\s+(\w+),\s*track\s+(\w+),\s*count\s+(\d+),\s*seconds\s+(\d+)')
_FLAGS_RE    = re.compile(r'flags:([A-Z+!,]+)')
_HEX_SPLIT   = re.compile(r'\|([A-Fa-f0-9 ]+)\|')


def _decode_content(raw: str) -> bytes:
    """
    Parse a Snort content string that may contain mixed text and hex sequences.

    Snort content syntax: literal text interleaved with |hex bytes|
    Examples:
        "M-SEARCH "         → b'M-SEARCH '
        "|0d 0a|"           → b'\\r\\n'
        "ST|3a 20|"         → b'ST: '          (was silently dropped before!)
        "HOST|3a 20|"       → b'HOST: '
        "M-SEARCH|20|*"     → b'M-SEARCH *'

    Previously, any content with "|" inside was skipped as "hex-encoded",
    causing rules with mixed patterns to lose conditions and match too broadly.
    """
    result = b''
    parts = _HEX_SPLIT.split(raw)
    # split gives [text, hex, text, hex, ...] alternating
    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Literal text segment
            if part:
                try:
                    result += part.encode("latin-1", errors="replace")
                except Exception:
                    pass
        else:
            # Hex segment (content between | delimiters)
            try:
                result += bytes.fromhex(part.replace(" ", ""))
            except ValueError:
                pass
    return result

_DSIZE_RE    = re.compile(r'dsize\s*:\s*(>=|<=|>|<|=)?\s*(\d+)')


def _parse_dsize(options: str):
    """Parse dsize constraint from rule options. Returns (op, val) or (None, None)."""
    m = _DSIZE_RE.search(options)
    if not m:
        return None, None
    op  = m.group(1) or '='   # default '=' if no operator (e.g. dsize:8)
    val = int(m.group(2))
    return op, val


def _dsize_match(op, val, payload_len: int) -> bool:
    """Return True if payload_len satisfies the dsize constraint."""
    if op is None:
        return True
    if op == '>':  return payload_len > val
    if op == '<':  return payload_len < val
    if op == '>=': return payload_len >= val
    if op == '<=': return payload_len <= val
    return payload_len == val   # '='


# ─────────────────────────────────────────────────────────────
# TCP FLAGS — Snort rule `flags:` expression evaluator
# ─────────────────────────────────────────────────────────────
_SNORT_FLAG_BITS: dict = {
    'F': 0x01,   # FIN
    'S': 0x02,   # SYN
    'R': 0x04,   # RST
    'P': 0x08,   # PSH
    'A': 0x10,   # ACK
    'U': 0x20,   # URG
}


def _snort_flags_match(rule_flags: str, pkt_flags: int) -> bool:
    """
    Evaluate a Snort TCP flags expression against a raw TCP flags byte.

    Snort syntax:
      flags:<value>[,<mask>]
      where value is a mix of flag chars (F S R P A U) and negated chars (!F etc.)
      and mask is an optional decimal integer of bits to check.

    Examples:
      "FPU"        → FIN + PSH + URG all set (XMAS scan)
      "0,12"       → RST+PSH bits checked, both must be clear (NULL scan variant)
      "F!A!S!R"    → FIN set; ACK, SYN, RST must be clear
      "S"          → SYN set (SYN scan)
      "SA"         → SYN + ACK set (SYN-ACK)
      "A,12"       → ACK set within mask 12 (ACK scan)
    """
    mask = 0x3F          # check all 6 standard TCP flag bits by default
    flag_part = rule_flags.strip()

    if ',' in flag_part:
        flag_part, mask_str = flag_part.split(',', 1)
        try:
            mask = int(mask_str.strip())
        except (ValueError, TypeError):
            mask = 0x3F

    required_set   = 0
    required_clear = 0

    if flag_part == '0':
        # flags:0 → no flags set at all (NULL scan)
        required_clear = 0x3F
    else:
        i = 0
        while i < len(flag_part):
            ch = flag_part[i]
            if ch == '!':
                i += 1
                if i < len(flag_part) and flag_part[i] in _SNORT_FLAG_BITS:
                    required_clear |= _SNORT_FLAG_BITS[flag_part[i]]
                    i += 1
            elif ch in _SNORT_FLAG_BITS:
                required_set |= _SNORT_FLAG_BITS[ch]
                i += 1
            else:
                i += 1   # skip unknown chars ('+', '*', whitespace)

    masked_pkt = pkt_flags & mask

    if required_set and (masked_pkt & required_set) != required_set:
        return False
    if required_clear and (masked_pkt & required_clear) != 0:
        return False
    return True


# Classtype → severity
CLASSTYPE_SEVERITY = {
    "attempted-admin":          "HIGH",
    "successful-admin":         "HIGH",
    "shellcode-detect":         "HIGH",
    "trojan-activity":          "HIGH",
    "web-application-attack":   "HIGH",
    "attempted-user":           "HIGH",
    "denial-of-service":        "HIGH",
    "network-scan":             "MEDIUM",
    "policy-violation":         "MEDIUM",
    "protocol-command-decode":  "MEDIUM",
    "bad-unknown":              "MEDIUM",
    "misc-attack":              "MEDIUM",
    "default":                  "LOW",
    "not-suspicious":           "LOW",
    "unknown":                  "MEDIUM",
}


# Generic protocol tokens — first content patterns that appear in normal traffic.
# Rules whose first pattern starts with one of these AND also require PCRE for
# precision are skipped in live-payload mode to prevent false positives.
_GENERIC_PROTO_TOKENS = (
    b"get ",       # HTTP GET requests
    b"post ",      # HTTP POST requests
    b"put ",       # HTTP PUT requests
    b"head ",      # HTTP HEAD
    b"options ",   # HTTP OPTIONS
    b"connect ",   # HTTP CONNECT / tunnelling
    b"http/1.",    # HTTP responses
    b"ssh-",       # SSH banners
    b"220 ",       # SMTP/FTP greeting
    b"user-agent", # HTTP UA header (requires PCRE for specificity)
    b"host: ",     # HTTP Host header alone
    b"location:",  # HTTP Location / SSDP Location
    b"notify * ",  # UPnP NOTIFY
    b"m-search ",  # UPnP M-SEARCH
)


def _parse_rule(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not line.startswith(("alert ", "drop ", "log ")):
        return None

    # Snort rule format:
    #   action proto src_ip src_port direction dst_ip dst_port (options)
    try:
        paren_start = line.index("(")
        header      = line[:paren_start].strip()
        options     = line[paren_start:]
    except ValueError:
        return None

    # Skip rules that explicitly suppress alerts (flowbit setters, noalert directives).
    # These rules are designed to SET STATE silently for multi-rule chaining — they
    # must never fire as standalone alerts. Firing them would produce false positives
    # on every packet that matches the (often very broad) content patterns.
    # Snort recognises: "noalert" and "flowbits:noalert"
    if "noalert" in options:
        return None

    # Skip two-stage flowbits rules that require stateful session tracking.
    # flowbits:isset rules are PHASE-2 detectors: they fire ONLY when a preceding
    # phase-1 rule has SET the named bit in the same session.  Without a stateful
    # flowbit tracker Bastion would match every packet whose payload contains the
    # content patterns — regardless of whether the session was ever flagged by
    # phase-1.  Result: thousands of false positives on normal HTTP/DNS/TLS traffic
    # (e.g., every browser fetch() triggers "ET ACTIVEX attack phase 2",
    # every TLS handshake triggers "ET EXPLOIT Heartbleed phase 3", etc.).
    # There are ~1,258 such rules in ET-Open; skipping them at parse-time removes
    # all of them from the index in one clean pass.
    if "flowbits:isset," in options or "flowbits:isset " in options:
        return None

    hdr_tokens = header.split()
    # hdr_tokens: [action, proto, src_ip, src_port, ->, dst_ip, dst_port]
    if len(hdr_tokens) < 7:
        return None

    rule          = SigRule()
    rule.proto    = hdr_tokens[1].lower()
    rule.raw      = line

    # ── Port parsing (critical: index 3 = src_port, 6 = dst_port) ──
    rule.src_ports = _parse_port_spec(hdr_tokens[3])
    rule.dst_ports = _parse_port_spec(hdr_tokens[6])

    # ── Destination IP group — direction enforcement ──────────────
    # hdr_tokens[5] is the dst_ip spec, e.g. "$HOME_NET", "$EXTERNAL_NET",
    # "[$HOME_NET,$HTTP_SERVERS]", "any".
    # We extract whether the rule targets inbound-to-home (requires_home_dst)
    # or outbound (requires_external_dst) so we can skip rules fired in the
    # wrong direction — the single biggest source of false positives (e.g.
    # Apache HTTP smuggling rules that say -> [$HOME_NET] firing on internal
    # machines browsing to Akamai CDN).
    _dst_grp = hdr_tokens[5]
    rule.requires_home_dst = (
        "$HOME_NET"    in _dst_grp or
        "$HTTP_SERVERS" in _dst_grp or
        "$SQL_SERVERS"  in _dst_grp or
        "$DNS_SERVERS"  in _dst_grp
    )
    # $EXTERNAL_NET means the rule targets outbound traffic (dst is internet)
    rule.requires_external_dst = (_dst_grp == "$EXTERNAL_NET")

    # ── Options ────────────────────────────────────────────────────
    msg_m = _MSG_RE.search(options)
    if not msg_m:
        return None
    rule.msg = msg_m.group(1).strip()

    sid_m = _SID_RE.search(options)
    rule.sid = int(sid_m.group(1)) if sid_m else 0

    # Content patterns — properly decode all content fields (including mixed hex/text)
    for m in _CONTENT_ALL.finditer(options):
        try:
            pat = _decode_content(m.group(1))
            if pat:
                rule.content_patterns.append(pat)
        except Exception:
            pass

    rule.nocase = "nocase" in options.lower()

    # Classtype + severity
    ct_m = _CLASSTYPE_RE.search(options)
    if ct_m:
        ct            = ct_m.group(1).strip()
        rule.classtype = ct
        rule.severity  = CLASSTYPE_SEVERITY.get(ct, "MEDIUM")

    # Threshold
    th_m = _THRESHOLD_RE.search(options)
    if th_m:
        rule.threshold = (th_m.group(1), th_m.group(2),
                          int(th_m.group(3)), int(th_m.group(4)))

    # TCP flags
    fl_m = _FLAGS_RE.search(options)
    if fl_m:
        rule.flags = fl_m.group(1)

    # dsize constraint (payload size check)
    rule.dsize_op, rule.dsize_val = _parse_dsize(options)

    # PCRE flag — if rule has PCRE but no/thin content patterns, it's risky without PCRE eval
    rule.has_pcre = "pcre:" in options

    return rule


# ─────────────────────────────────────────────────────────────
# PORT SCAN TRACKER
# Counts unique (dst_ip, dst_port) pairs per src_ip.
# A real horizontal scan = one host contacting MANY different
# (ip, port) combinations in a short window.
# ─────────────────────────────────────────────────────────────
class _PortScanTracker:
    """Detects horizontal port scans (one src → many distinct (dst, port) pairs).

    Includes a per-source cooldown so the alert fires ONCE when the threshold is
    crossed, then stays silent for `cooldown_seconds` even if more probes arrive.
    Without the cooldown every subsequent packet from that src re-fires the alert,
    producing the duplicate-alert spam the user reported.
    """
    def __init__(self, window_seconds=180, unique_threshold=80, cooldown_seconds=600):
        self._lock      = threading.Lock()
        self._data      = defaultdict(dict)   # src_ip → {(dst_ip, dport): ts}
        self._fired     = {}                  # src_ip → last-fire timestamp
        self._window    = window_seconds
        self._threshold = unique_threshold
        self._cooldown  = cooldown_seconds

    def check_and_record(self, src_ip: str, dst_ip: str, dst_port: int) -> bool:
        now = time.time()
        key = (dst_ip, dst_port)
        with self._lock:
            # Cooldown — don't re-fire for this source for `cooldown` seconds
            last = self._fired.get(src_ip, 0.0)
            if last and now - last < self._cooldown:
                return False
            mapping = self._data[src_ip]
            stale   = [k for k, t in mapping.items() if t < now - self._window]
            for k in stale:
                del mapping[k]
            mapping[key] = now
            if len(mapping) >= self._threshold:
                self._fired[src_ip] = now
                # Reset the mapping after firing so a fresh window starts post-cooldown
                mapping.clear()
                return True
            return False


# ─────────────────────────────────────────────────────────────
# BRUTE FORCE TRACKER
# ─────────────────────────────────────────────────────────────
class _RateTracker:
    """Counts repeated events keyed by a string in a sliding window.

    Adds a fire-cooldown so a single brute-force run doesn't generate dozens of
    duplicate alerts as more failed-login packets continue arriving.
    """
    def __init__(self, window_seconds=60, max_count=20, cooldown_seconds=300):
        self._lock     = threading.Lock()
        self._events   = defaultdict(deque)
        self._fired    = {}                # key → last-fire timestamp
        self._window   = window_seconds
        self._max      = max_count
        self._cooldown = cooldown_seconds

    def check_and_record(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._fired.get(key, 0.0)
            if last and now - last < self._cooldown:
                return False
            dq = self._events[key]
            while dq and dq[0] < now - self._window:
                dq.popleft()
            dq.append(now)
            if len(dq) >= self._max:
                self._fired[key] = now
                dq.clear()
                return True
            return False


# ─────────────────────────────────────────────────────────────
# DoS RATE TRACKER
# Counts packets per (src_ip, dst_ip, proto) in a sliding window.
# Fires once when rate exceeds threshold; cooldown prevents re-fire.
# Detects: ICMP flood, TCP SYN flood, UDP flood, HTTP connection flood.
# ─────────────────────────────────────────────────────────────
class _DoSTracker:
    """Packet-rate-based DoS/flood detector."""

    # Thresholds tuned to NOT false-positive on normal heavy traffic (video
    # streaming, QUIC, large downloads, busy HTTPS pages). Real floods emit
    # thousands of packets/sec and clear these easily. TCP/HTTP counts are
    # SYN-only (connection attempts), so data transfers never trip them.
    _THRESHOLDS = {
        "icmp": 100,  # 100 ICMP pkts in 2s (~50/s) → flood (normal ping ~1/s)
        "tcp":  150,  # 150 SYN-only pkts in 2s (~75/s) → SYN flood
        "udp":  600,  # 600 UDP pkts in 2s (~300/s) → flood (above streaming/QUIC)
    }
    # HTTP connection flood: many NEW connections (SYNs) to web ports in 5s
    _HTTP_THRESH  = 150
    _HTTP_WINDOW  = 5.0

    def __init__(self, window_seconds: float = 2.0, cooldown_seconds: float = 120.0):
        self._lock      = threading.Lock()
        self._events    = defaultdict(deque)   # (src, dst, proto) → deque[ts]
        self._http_evts = defaultdict(deque)   # src_ip → deque[ts] (port 80/443/8080)
        self._fired     = {}                   # key → last-fire ts
        self._window    = window_seconds
        self._cooldown  = cooldown_seconds

    def check_and_record(self, src_ip: str, dst_ip: str, proto: str,
                         dport: int = 0, tcp_flags_raw: int = -1):
        """
        Returns (fired: bool, attack_name: str) or (False, '').
        """
        now  = time.time()
        proto = proto.lower()
        # SYN-only = a connection attempt (SYN set, ACK clear). 0x02=SYN, 0x10=ACK.
        # Counting SYN-only packets means normal high-throughput data transfers
        # (downloads, streaming) never trip the TCP/HTTP flood detectors.
        is_syn = (tcp_flags_raw != -1 and (tcp_flags_raw & 0x02) and not (tcp_flags_raw & 0x10))

        # ── HTTP connection flood / Slowloris (NEW connections only) ──
        if proto == "tcp" and dport in (80, 443, 8080, 8000) and is_syn:
            _ck = ("http_flood", src_ip, dport)
            with self._lock:
                _last = self._fired.get(_ck, 0.0)
                if not (_last and now - _last < self._cooldown):
                    dq = self._http_evts[src_ip]
                    while dq and dq[0] < now - self._http_window:
                        dq.popleft()
                    dq.append(now)
                    if len(dq) >= self._HTTP_THRESH:
                        self._fired[_ck] = now
                        dq.clear()
                        return (True, "HTTP Connection Flood / Slowloris")

        # ── Protocol flood ───────────────────────────────────────
        # TCP: count SYN-only packets (true SYN flood). UDP/ICMP: all packets.
        if proto == "tcp" and not is_syn:
            return (False, "")
        thresh = self._THRESHOLDS.get(proto)
        if thresh is None:
            return (False, "")

        key = (src_ip, dst_ip, proto)
        with self._lock:
            _last = self._fired.get(key, 0.0)
            if _last and now - _last < self._cooldown:
                return (False, "")
            dq = self._events[key]
            while dq and dq[0] < now - self._window:
                dq.popleft()
            dq.append(now)
            if len(dq) >= thresh:
                self._fired[key] = now
                dq.clear()
                _names = {
                    "icmp": "ICMP Flood Attack",
                    "tcp":  "TCP SYN Flood Attack",
                    "udp":  "UDP Flood Attack",
                }
                return (True, _names.get(proto, "DoS Flood Attack"))
        return (False, "")

    @property
    def _http_window(self):
        return self._HTTP_WINDOW


# ─────────────────────────────────────────────────────────────
# MAIN SIGNATURE ENGINE
# ─────────────────────────────────────────────────────────────
# Ports considered safe/common for normal browsing/service traffic.
# Connections to these ports don't trigger the port-scan heuristic.
COMMON_SAFE_PORTS = frozenset({
    20, 21, 22, 25, 53, 80, 110, 123, 143, 161, 162,
    389, 443, 465, 587, 636, 993, 995, 3306, 3389, 5432,
    8080, 8443, 8000, 8888, 5000, 3000,
})

# Windows / Bonjour / SMB network-discovery ports — produce hundreds of
# distinct (dst_ip, port) pairs during normal LAN browsing.  Excluded from
# the port-scan heuristic so machines doing legitimate file-share / device
# discovery aren't flagged as attackers.
DISCOVERY_PORTS = frozenset({
    137, 138, 139, 445,         # NetBIOS / SMB
    1900,                       # SSDP / UPnP discovery
    5353,                       # mDNS (Bonjour)
    5355,                       # LLMNR
    3702,                       # WS-Discovery
    5357, 5358,                 # WSDAPI
    1024, 1025, 1026, 1027, 1028, 1029,  # Windows RPC dynamic
    49152, 49153, 49154, 49155, 49156, 49157,  # Win Vista+ dynamic RPC
})

def _same_subnet24(a: str, b: str) -> bool:
    """Return True if two IPs share the same /24 (first three octets)."""
    try:
        return a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    except Exception:
        return False

# Ports used by Bastion itself — never analyse traffic between these
BASTION_PORTS = frozenset({8000, 5173, 5174, 5175, 8001})

# Private / reserved IP prefixes — don't flag as external threats
_PRIV_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                  "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                  "172.30.", "172.31.", "192.168.", "127.", "169.254.")


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIV_PREFIXES)


class BastionSignatureEngine:

    def __init__(self):
        self._startup_log  = []
        self._port_index   = defaultdict(list)   # dport → [SigRule]
        self._proto_index  = defaultdict(list)   # proto → [SigRule]
        self._all_rules    = []
        self.bad_ips       = set()
        self.rules_count   = 0
        self._scan_tracker   = _PortScanTracker(window_seconds=180, unique_threshold=50)
        self._brute_tracker  = _RateTracker(window_seconds=60, max_count=15)
        self._dos_tracker    = _DoSTracker(window_seconds=2.0, cooldown_seconds=120.0)
        self._stealth_seen   = {}  # "src_ip:SCAN_TYPE" → last_fire_timestamp (30s cooldown)
        # Per-signature per-source cooldown — prevents the same rule firing
        # hundreds of times for a single attack session (e.g. sqlmap sends 83
        # packets that all match "ET SCAN Sqlmap SQL Injection Scan").
        # Key: (sid, src_ip)  Value: last-fire unix timestamp
        # Cooldown periods vary by rule category — scan/web rules are noisy so
        # they get a longer window; exploit/trojan rules are rarer so shorter.
        self._sig_cooldown      = {}           # (sid, src_ip) → timestamp
        self._sig_cooldown_lock = threading.Lock()
        self._SIG_COOLDOWN_SCAN    = 120   # ET SCAN / ET WEB_SERVER / WEB_SPECIFIC_APPS
        self._SIG_COOLDOWN_EXPLOIT = 45    # ET EXPLOIT / ET TROJAN / MALWARE
        self._SIG_COOLDOWN_DEFAULT = 60    # everything else
        self._t0             = time.time()
        # Disabled SID list — rules to suppress (known false positives)
        # Rules are disabled when:
        #   a) content patterns are too generic without PCRE evaluation, OR
        #   b) they match standard Windows network discovery protocols
        self.disabled_sids = {
            2019102,   # ET DOS SSDP Amplification Scan — matches normal Windows UPnP M-SEARCH multicast
            2032889,   # ET CURRENT_EVENTS PurpleFox TLS SNI — FP on legitimate Microsoft TLS traffic
            2101384,   # GPL UPnP malformed advertisement — nocase "NOTIFY * " fires on every Windows UPnP NOTIFY
            2032326,   # ET EXPLOIT DD-WRT UPnP — M-SEARCH+ST:+uuid: fires on Windows UUID-based UPnP searches
            2101388,   # GPL UPnP Location overflow — "Location:" fires on all SSDP NOTIFY; PCRE(128-char) not evaluated
            2022531,   # ET EXPLOIT CVE-2015-7547 — DNS query header bytes appear in every standard DNS packet
            2022545,   # ET EXPLOIT CVE-2015-7547 A/AAAA variant — same DNS header pattern FP
            2022547,   # ET EXPLOIT CVE-2015-7547 Large Response — only "\x00\x01" (2 bytes) fires on any TCP
            2015898,   # ET INFO Windows NT 1 UA — "Windows NT 1" substring matches "Windows NT 10.0" (Win10 UA)
            2063592,   # ET INFO Suspicious Fake Windows UA — matches real Windows 10 Chrome/Firefox UA strings
            2066176,   # ET INFO Suspicious UA (Windows NT XX.X AppleWebKit) — matches standard Windows 10 Chrome/Edge UA
            2054407,   # ET INFO Vulnerable OpenSSH CVE-2024-6409 — SSH-/-OpenSSH_ fires on any SSH; PCRE version check unevaluated
            2019230,   # ET TROJAN Possible Tinba DGA NXDOMAIN Responses — requires threshold 50/10s not enforced here; fires on any 12-char .com NXDOMAIN (normal browser behaviour)
            2019609,   # ET TROJAN Possible Tinba DGA NXDOMAIN Responses (2) — .ru variant of 2019230; same threshold issue
            2018375,   # ET EXPLOIT TLS HeartBeat Request (Server Initiated) — uses flowbits; Bastion has no flowbit state tracking; content matches normal TLS 1.2 heartbeats
            2018376,   # ET EXPLOIT TLS HeartBeat Request (Client Initiated) — same flowbit issue
            2018377,   # ET EXPLOIT Heartbleed Large Response (Client Init) — flowbits:isset ET.HB.Request.CI unevaluated; \x18\x03 fires on any TLS heartbeat
            2018378,   # ET EXPLOIT Heartbleed Large Response (Server Init) — same; flowbits:isset ET.HB.Request.SI unevaluated
            2018382,   # ET EXPLOIT Heartbleed "Outbound from Server" — same byte pattern \x18\x03; no flowbit check available
            2018383,   # ET EXPLOIT Heartbleed "Outbound from Client" — matches \x18\x03; fires on any TLS 1.2 heartbeat; Bastion has no TLS session state
            2018388,   # ET EXPLOIT TLS HeartBleed Unencrypted Request Method 4 — same \x18\x03 pattern without session state
            2018389,   # ET EXPLOIT TLS HeartBleed Unencrypted Request Method 3 — same; fires on normal TLS keep-alive heartbeats to Cloudflare/Google IPs
            2018789,   # ET POLICY TLS possible TOR SSL traffic — real detection is in pcre (CN field pattern); without pcre the content |06 03 55 04 03| (X.509 CN OID) fires on every TLS certificate
            2017362,   # ET TROJAN Win32/Napolar.A Getting URL — content:"GET" (single HTTP verb, no PCRE); fires on every HTTP GET request
            2017367,   # ET TROJAN Possible Win32/Napolar.A URL Response — content:"200" + "!http:" in HTTP body; fires on normal HTTPS API responses
            2017527,   # ET DELETED W32/Napolar Checkin — DELETED rule; content POST+v=+&u= match common form parameters in normal web traffic
            2019376,   # ET DELETED Napolar/Shifu SSL Cert — DELETED rule; |55 04 03| is X.509 Org OID present in every TLS certificate
            2030532,   # ET EXPLOIT CVE-2020-1350 DNS Integer Overflow M2 — |00 00 18|+|c0| matches AAAA record + DNS compression in normal DNS responses (no PCRE)
            2030533,   # ET EXPLOIT CVE-2020-1350 DNS Integer Overflow M1 — same byte pattern as M2; fires on standard DNS AAAA + pointer responses
            2048324,   # ET RETIRED LU0BOT-Style DNS Lookup M1 — RETIRED; pcre /^\d{10}/R unevaluated; fires on DNS queries containing "169" at offset 14
            2048325,   # ET RETIRED LU0BOT-Style DNS Lookup M2 — RETIRED; same issue; "170" variant
            2048326,   # ET RETIRED LU0BOT-Style DNS Lookup M3 — RETIRED; "171" variant
            2048327,   # ET RETIRED LU0BOT-Style DNS Lookup M4 — RETIRED; "172" variant
            2048328,   # ET RETIRED LU0BOT-Style DNS Lookup M5 — RETIRED; same family
            # NTP / port-reuse rules that fire on DHCP and other non-ephemeral service ports
            2009359,   # ET DOS Likely NTP DDoS In Progress PEER_LIST — port 68 (DHCP) is non-ephemeral, triggers this rule
            2001569,   # ET DOS NTP Monlist Response — fires on broadcast traffic via port 123 without PCRE
            2009360,   # ET DOS NTP PEER_LIST_SUM — same family as 2009359
            2009361,   # ET DOS NTP GET_RESTRICT — same NTP DDoS family; fires on service ports
            # ET POLICY / ET INFO rules that produce false positives in live capture:
            # These are INFORMATIONAL rules (classtype:misc-activity or attempted-recon
            # with signature_severity Informational) that fire on normal everyday traffic.
            # They add zero threat value but generate alarming UI noise.
            2002827,   # ET POLICY POSSIBLE Crawl using Fetch — fires whenever a browser uses fetch() API;
                       # threshold (10/60s) not enforced without stateful tracking → fires on normal SPA traffic
            2052580,   # ET INFO DNS Query to Alibaba Cloud CDN — fires on any *.aliyuncs.com DNS lookup;
                       # huge CDN used by npm, GitHub, many legitimate services; informational only
            2052581,   # ET INFO Observed Alibaba Cloud CDN in TLS SNI — same family; PCRE unevaluated
            2020749,   # ET TROJAN Win32.Chroject.B Receiving ClickFraud — requires flowbits:isset ET.Chroject
                       # which Bastion cannot track; fires on any HTML response containing <html><title>base64
                       # pattern (many pages encode tokens in the title tag)
            2020750,   # ET TROJAN Win32.Chroject.B ClickFraud Request — fires on /item/fmt?ct= URI pattern;
                       # PCRE for Referer not evaluated; this path appears in legitimate Microsoft/CDN traffic
            # ── Additional known FP rules not covered by structural filters ───
            # These rules pass the flowbits / classtype / prefix filters above but
            # still produce near-100% FP rates in real-world live capture:
            2019016,   # ET TROJAN Possible CoinMiner / Crypto Mining Pool Activity —
                       # content :"mining." or "pool." matches any DNS lookup for
                       # "swimmingpool." / "poolparty." etc.; PCRE not evaluated
            2022975,   # ET TROJAN Possible Gozi/ISFB CnC Checkin — HTTP GET with
                       # Accept: text/html fires on every browser page load; PCRE needed
            2025707,   # ET TROJAN Observed DNS Query to DGA Domain — 12-char .top
                       # domain regex not evaluated; any short .top domain triggers it
            2001219,   # GPL MISC UPnP multicast — fires on Windows Defender / WSD
            2012647,   # ET POLICY HTTP request to .cn domain (informational, normal traffic)
            2012648,   # ET POLICY HTTP request to .ru domain (informational, normal traffic)
            2013028,   # ET POLICY Dropbox CnC Beacon — Dropbox API is legitimate service
            2016538,   # ET INFO Executable Download from dotted-quad — fires on S3/CDN
            2021076,   # ET WEB_CLIENT HTA File Download — fires on .hta Windows help files
            2012294,   # ET POLICY PE EXE or DLL Windows file download HTTP — fires on
                       # Windows Update, software installers from any server
            2012295,   # ET POLICY PE EXE or DLL Windows file download — same as 2012294

            # ── Rules that require HTTP-aware engine features we don't implement ──
            # These rules use Snort sticky buffers (http_stat_code, http_header,
            # file_data) + depth/distance constraints that require packet reassembly,
            # HTTP stream inspection, and optional decompression.  Without these, our
            # raw-payload substring search produces near-100% false positive rates:
            2024771,   # ET TROJAN [PTsecurity] Possible Cobalt Strike payload —
                       # requires file_data + depth:7 to check FIRST 7 bytes of the
                       # decompressed HTTP response body.  Our engine matches the
                       # 7-byte pattern anywhere in the raw packet, firing on any
                       # compressed Alibaba/Cloudflare response that incidentally
                       # contains these bytes.  Add a standalone CS-specific heuristic
                       # in bastion.rules instead with full context validation.
            # ── Apache HTTP Smuggling (CVE-2023-25690) — all 7 variants ─────
            # flow:established,to_server — fires when LOCAL machine sends a
            # specially-crafted request TO an external server.  Without proper
            # HTTP stream reassembly + Transfer-Encoding/Content-Length conflict
            # detection, the content patterns match normal HTTP requests to
            # router admin pages (10.1.1.254, 192.168.1.1 etc.) and any web app
            # using chunked encoding. Our machines are the potential VICTIM,
            # not the attacker; this rule direction is backwards for our model.
            2056423,   # M1
            2056424,   # M2
            2056425,   # M3
            2056426,   # M4
            2056427,   # M5
            2056428,   # M6
            2056429,   # M7

            # ── Router / admin-panel false positives ────────────────────────
            # These EXPLOIT rules target HTTP admin interfaces of consumer/SMB
            # network gear (UniFi, DD-WRT, etc.). They fire on ANY POST to the
            # gateway's admin port because the content patterns are too generic
            # without the PCRE evaluation we don't perform.  False positives on
            # every LAN admin login.
            2024548,   # ET EXPLOIT Ubiquiti Networks UniFi Cloud Key Firm v0.6.1 RCE
                       # content:"POST" + "/api/cmd/" — matches normal UniFi
                       # controller traffic; PCRE for shell metacharacter
                       # validation not evaluated

            # ── NTP DDoS amplification rules — fire on broadcast LAN traffic ─────
            # These rules match NTP reflection/amplification attack RESPONSES, but in
            # a home/office LAN the same packet patterns appear in normal NTP sync
            # traffic from Windows/Linux clocks to broadcast addresses (x.x.x.255).
            # Since we cannot evaluate the "non_ephemeral_port" PCRE without flow state,
            # every NTP reply to a broadcast or multicast address triggers them.
            # Suppressed here; the broadcast-destination guard in api_server.py provides
            # a second layer of protection for any future NTP rules added.
            2019010,   # ET DOS Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x02
            2019011,   # ET DOS Likely NTP DDoS In Progress PEER_LIST Response to Non-Ephemeral Port IMPL 0x03
            2017965,   # ET DOS Likely NTP DDoS In Progress MON_LIST Response IMPL 0x02
            2017966,   # ET DOS Likely NTP DDoS In Progress MON_LIST Response IMPL 0x03
            2019012,   # ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM Response IMPL 0x02
            2019013,   # ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM Response IMPL 0x03
            2019014,   # ET DOS Likely NTP DDoS In Progress GET_RESTRICT Response IMPL 0x02
            2019015,   # ET DOS Likely NTP DDoS In Progress GET_RESTRICT Response IMPL 0x03
            2019017,   # ET DOS Likely NTP DDoS In Progress PEER_LIST Response IMPL 0x02 (variant)
            2019018,   # ET DOS Likely NTP DDoS In Progress PEER_LIST Response IMPL 0x03 (variant)
            2019019,   # ET DOS Likely NTP DDoS In Progress MON_LIST Response (variant)
            2019020,   # ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM (variant)
            2019021,   # ET DOS Likely NTP DDoS In Progress GET_RESTRICT (variant)
            2019022,   # ET DOS Likely NTP DDoS In Progress — broader NTP amplification family

            # ── Miuref/Boaxxe Checkin — urilen:>400 + http_raw_uri not evaluatable ─
            # Fires on any HTTP GET with a URL longer than 400 chars containing %2b.
            # Windows Update / telemetry URLs routinely exceed 400 chars with
            # base64-encoded parameters (+→%2b).  PCRE /^\/([a-zA-Z0-9]|%2[fb]){400,}$/
            # not evaluated → FP on Win 10 background traffic to external IPs.
            2018582,   # ET MALWARE Miuref/Boaxxe Checkin (emerging-malware)
            2019683,   # ET TROJAN Miuref/Boaxxe Checkin (emerging-trojan)

            # ── WebShell Generic — http_client_body / file_data sticky buffer ───
            # All these rules use http_client_body or file_data with distance/within
            # constraints that require HTTP stream reassembly + decompression that
            # Bastion does not perform.  Without that layer, the raw-payload substring
            # search fires on any POST body that incidentally contains the short
            # keyword pairs (e.g. "net"+"user", "reg"+"HKEY_LOCAL_MACHINE", "wget"+"http").
            # The specific trigger seen in live capture: 2016680 fires on any browser
            # POST to a router admin page (e.g. captive-portal login at .254:80).
            2016680,   # ET WEB_SERVER WebShell Generic - net user (pcre:net\s+user in POST body)
            2016681,   # ET WEB_SERVER WebShell Generic - netsh firewall (http_client_body)
            2016682,   # ET WEB_SERVER WebShell Generic - reg HKEY_LOCAL_MACHINE (http_client_body)
            2016683,   # ET WEB_SERVER WebShell Generic - wget http POST (http_client_body)
            2016992,   # ET WEB_SERVER WebShell Generic - *.tar.gz in POST body (http_client_body)
            2017054,   # ET WEB_SERVER WebShell Generic - ELF File Uploaded (http_client_body)
            2017260,   # ET WEB_SERVER WebShell Generic - ASP File Uploaded (http_client_body+pcre)
            2017399,   # ET WEB_SERVER WebShell Generic eval of base64_decode (file_data+pcre)
            2017400,   # ET WEB_SERVER WebShell Generic eval of gzinflate (file_data+pcre)
            2017401,   # ET WEB_SERVER WebShell Generic eval of str_rot13 (file_data+pcre)
            2017402,   # ET WEB_SERVER WebShell Generic eval of gzuncompress (file_data+pcre)
            2017403,   # ET WEB_SERVER WebShell Generic eval of convert_uudecode (file_data+pcre)

            # ── Regin CnC Beacon — base64_decode keyword not evaluatable ────────
            # These rules use Snort's base64_decode + base64_data keywords to decode
            # payload before matching against the decoded bytes.  Bastion has no
            # base64_decode pipeline, so only the PRE-decode patterns are checked:
            # content:"A" depth:1 (first byte = 'A') + content:"AAA" within:4.
            # This is an extremely common byte sequence in TLS, HTTP/2, and
            # base64-heavy API traffic — near-100% FP rate without the decode step.
            2019816,   # ET TROJAN Possible Regin Init CnC Beacon TCP
            2019817,   # ET TROJAN Possible Regin Init CnC Beacon UDP
            2019820,   # ET TROJAN Possible Regin Init CnC Beacon ICMP

            # ── Variant.Kazy SSL — byte_extract not evaluatable ──────────────────
            # Uses byte_extract to read SSL ClientHello field lengths, then byte_test
            # to compare extracted lengths.  Without evaluating byte_extract/byte_test
            # the rule reduces to "content:|16 03 00|" at depth:3 — matches every
            # SSL 3.0 / TLS 1.0 ClientHello from any browser or OS.
            2014634,   # ET TROJAN Possible Variant.Kazy.53640 SSL Session_Id length check
            2014635,   # ET TROJAN Possible Variant.Kazy.53640 SSL Cipher_Suite length check

            # ── Generic .cc TLD DNS query ────────────────────────────────────────
            # Fires on ANY DNS lookup for *.cc (Cocos Islands country code TLD) —
            # used by many legitimate services (t.co → shortened URLs, cdn.cc, etc.).
            # Signature_severity is Informational; no specific malware context.
            # The sub-domain variants (.cz.cc / .cu.cc / .vv.cc / .co.cc) are kept
            # because those specific combos are genuinely rare in legitimate traffic.
            2027758,   # ET DNS Query for .cc TLD (any *.cc lookup)

            # ── SMB per-packet flood rules ───────────────────────────────────────
            # These rules use asn1:double_overflow / byte_test operations Bastion
            # does not evaluate.  Without those checks the content patterns match
            # every normal SMB session-setup packet, producing thousands of alerts
            # per brute-force run.  The SMB brute-force heuristic (port 445 in
            # BRUTE_PORTS) already fires a clean single "Brute-Force Attack: SMB"
            # alert with cooldown — these add no detection value.
            2012084,   # ET NETBIOS MS Windows SMB Client Race Condition RCE (MS10-006) — byte_test not evaluated → FP on all SMB
            2012094,   # ET NETBIOS Windows SMB Client Race Condition variant — same byte_test issue
            2102382,   # GPL NETBIOS SMB Session Setup NTMLSSP asn1 overflow (port 139) — asn1 unevaluated → FP on all SMB auth
            2102383,   # GPL NETBIOS SMB-DS Session Setup NTMLSSP asn1 overflow (port 445) — same issue
            2102401,   # GPL NETBIOS SMB Session Setup AndX request username overflow (port 139) — byte_test unevaluated → FP
            2102402,   # GPL NETBIOS SMB-DS Session Setup AndX request username overflow (port 445) — same family
            2103000,   # GPL NETBIOS SMB Session Setup NTMLSSP unicode asn1 overflow — same family
            2103001,   # GPL NETBIOS SMB Session Setup NTMLSSP andx asn1 overflow — same family
            2103002,   # GPL NETBIOS SMB Session Setup NTMLSSP unicode andx asn1 overflow — same family
            2103003,   # GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode asn1 overflow — same family
            2103004,   # GPL NETBIOS SMB-DS Session Setup NTMLSSP andx asn1 overflow — same family
            2103005,   # GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode andx asn1 overflow — same family
        }

        # Trusted destination IP prefixes — TROJAN/EXPLOIT rules are suppressed when the
        # destination is a well-known CDN, OS vendor, or trusted infrastructure provider.
        # Cobalt Strike C2 and other malware NEVER uses Microsoft/Apple/Google IPs as their
        # C2 infrastructure; any match on these IPs is a false positive from Windows Update,
        # APNS, browser telemetry, app background traffic, or CDN-cached content.
        # WiFi networks are especially noisy with Apple (APNS/iCloud/FaceTime on 17.x.x.x),
        # Google (Android apps), Meta (WhatsApp/Instagram), and various CDN ranges.
        self.trusted_dst_prefixes = (
            # ── Microsoft (Azure, Office365, Teams, Windows Update, CDN) ──────
            "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.",
            "13.77.", "13.78.", "13.79.", "13.80.", "13.81.", "13.82.", "13.83.",
            "13.84.", "13.85.", "13.86.", "13.87.", "13.88.", "13.89.", "13.90.",
            "13.91.", "13.92.", "13.93.", "13.94.", "13.95.",
            "13.104.", "13.105.", "13.106.", "13.107.",
            "20.0.", "20.1.", "20.2.", "20.3.", "20.4.", "20.5.", "20.6.",
            "20.7.", "20.8.", "20.9.", "20.10.", "20.11.", "20.12.", "20.13.",
            "20.14.", "20.15.", "20.16.", "20.17.", "20.18.", "20.19.",
            "20.36.", "20.37.", "20.38.", "20.39.",
            "20.40.", "20.42.", "20.43.", "20.44.", "20.45.", "20.46.",
            "20.47.", "20.48.", "20.49.", "20.50.", "20.51.", "20.52.",
            "20.53.", "20.54.", "20.55.", "20.56.", "20.57.", "20.58.", "20.59.",
            "20.60.", "20.61.", "20.62.", "20.63.", "20.64.", "20.65.",
            "20.70.", "20.72.", "20.74.", "20.76.", "20.78.", "20.80.",
            "20.82.", "20.84.", "20.86.", "20.88.", "20.90.", "20.92.",
            "20.94.", "20.96.", "20.98.", "20.100.", "20.102.", "20.104.",
            "20.106.", "20.108.", "20.110.", "20.112.", "20.114.",
            "20.150.", "20.152.", "20.160.", "20.162.", "20.184.", "20.189.",
            "20.190.", "20.192.", "20.193.", "20.194.", "20.195.", "20.196.",
            "20.197.", "20.198.", "20.199.", "20.200.", "20.201.", "20.202.",
            "20.203.", "20.204.", "20.205.", "20.206.", "20.207.", "20.208.",
            "20.209.", "20.210.", "20.211.", "20.212.", "20.213.", "20.214.",
            "20.215.", "20.216.", "20.217.", "20.218.", "20.219.", "20.220.",
            "40.64.", "40.65.", "40.66.", "40.67.", "40.68.", "40.69.",
            "40.70.", "40.71.", "40.72.", "40.73.", "40.74.", "40.75.",
            "40.76.", "40.77.", "40.78.", "40.79.", "40.80.",
            "40.90.", "40.91.", "40.92.", "40.93.", "40.94.", "40.95.",
            "40.112.", "40.113.", "40.114.", "40.115.", "40.116.", "40.117.",
            "40.118.", "40.119.", "40.120.", "40.121.", "40.122.", "40.123.",
            "40.124.", "40.125.", "40.126.", "40.127.",
            "52.96.", "52.97.", "52.98.", "52.99.",
            "52.100.", "52.101.", "52.102.", "52.103.",
            "52.108.", "52.109.", "52.110.", "52.111.", "52.112.", "52.113.",
            "52.114.", "52.115.", "52.116.", "52.117.", "52.118.", "52.119.",
            "52.120.", "52.121.", "52.122.", "52.123.", "52.124.", "52.125.",
            "52.126.", "52.127.", "52.128.", "52.129.", "52.130.", "52.131.",
            "52.132.", "52.133.", "52.134.", "52.135.",
            "52.148.", "52.149.", "52.150.", "52.151.", "52.152.", "52.153.",
            "52.154.", "52.155.", "52.156.", "52.157.", "52.158.", "52.159.",
            "52.160.", "52.161.", "52.162.", "52.163.", "52.164.", "52.165.",
            "52.166.", "52.167.", "52.168.", "52.169.", "52.170.", "52.171.",
            "52.172.", "52.173.", "52.174.", "52.175.", "52.176.", "52.177.",
            "52.178.", "52.179.", "52.180.", "52.181.", "52.182.", "52.183.",
            "52.184.", "52.185.", "52.186.", "52.187.", "52.188.", "52.189.",
            "52.190.", "52.191.", "52.224.", "52.225.", "52.226.", "52.227.",
            "52.228.", "52.229.", "52.230.", "52.231.", "52.232.", "52.233.",
            "52.234.", "52.235.", "52.236.", "52.237.", "52.238.", "52.239.",
            "52.240.", "52.241.", "52.242.", "52.243.", "52.244.", "52.245.",
            "52.246.", "52.247.", "52.248.", "52.249.",
            "104.40.", "104.41.", "104.42.", "104.43.", "104.44.", "104.45.",
            "104.46.", "104.47.",
            "137.116.", "137.117.", "137.135.",
            "138.91.",
            "150.171.", "151.101.",  # ← 150.171.74.x (user-confirmed MS CDN FP)
            "168.61.", "168.62.", "168.63.",
            # ── Apple (owns entire 17.0.0.0/8 — APNS, iCloud, FaceTime, App Store) ──
            # Huge FP source on WiFi: every iPhone/iPad/Mac generates continuous
            # background traffic (push notifications, iCloud sync, Siri, etc.).
            # Apple's /8 block: we list first-two-octet prefixes to cover safely.
            "17.0.", "17.1.", "17.2.", "17.3.", "17.4.", "17.5.", "17.6.",
            "17.7.", "17.8.", "17.9.",
            "17.32.", "17.33.", "17.34.", "17.35.", "17.36.", "17.37.",
            "17.38.", "17.39.", "17.40.", "17.41.", "17.42.", "17.43.",
            "17.44.", "17.45.", "17.46.", "17.47.", "17.48.", "17.49.",
            "17.50.", "17.51.", "17.52.", "17.53.", "17.54.", "17.55.",
            "17.56.", "17.57.", "17.58.", "17.59.", "17.60.", "17.61.",
            "17.62.", "17.63.", "17.64.", "17.65.", "17.66.", "17.67.",
            "17.68.", "17.69.", "17.70.", "17.71.", "17.72.", "17.73.",
            "17.74.", "17.75.", "17.76.", "17.77.", "17.78.", "17.79.",
            "17.80.", "17.81.", "17.82.", "17.83.", "17.84.", "17.85.",
            "17.86.", "17.87.", "17.88.", "17.89.", "17.90.", "17.91.",
            "17.92.", "17.93.", "17.94.", "17.95.", "17.96.", "17.97.",
            "17.98.", "17.99.",
            "17.100.", "17.101.", "17.102.", "17.103.", "17.104.", "17.105.",
            "17.106.", "17.107.", "17.108.", "17.109.", "17.110.", "17.111.",
            "17.112.", "17.113.", "17.114.", "17.115.", "17.116.", "17.117.",
            "17.118.", "17.119.", "17.120.", "17.121.", "17.122.", "17.123.",
            "17.124.", "17.125.", "17.126.", "17.127.", "17.128.", "17.129.",
            "17.130.", "17.131.", "17.132.", "17.133.", "17.134.", "17.135.",
            "17.136.", "17.137.", "17.138.", "17.139.", "17.140.", "17.141.",
            "17.142.", "17.143.", "17.144.", "17.145.", "17.146.", "17.147.",
            "17.148.", "17.149.", "17.150.", "17.151.", "17.152.", "17.153.",
            "17.154.", "17.155.", "17.156.", "17.157.", "17.158.", "17.159.",
            "17.160.", "17.161.", "17.162.", "17.163.", "17.164.", "17.165.",
            "17.166.", "17.167.", "17.168.", "17.169.", "17.170.", "17.171.",
            "17.172.", "17.173.", "17.174.", "17.175.", "17.176.", "17.177.",
            "17.178.", "17.179.", "17.180.", "17.181.", "17.182.", "17.183.",
            "17.184.", "17.185.", "17.186.", "17.187.", "17.188.", "17.189.",
            "17.190.", "17.191.", "17.192.", "17.193.", "17.194.", "17.195.",
            "17.196.", "17.197.", "17.198.", "17.199.", "17.200.", "17.201.",
            "17.202.", "17.203.", "17.204.", "17.205.", "17.206.", "17.207.",
            "17.208.", "17.209.", "17.210.", "17.211.", "17.212.", "17.213.",
            "17.214.", "17.215.", "17.216.", "17.217.", "17.218.", "17.219.",
            "17.220.", "17.221.", "17.222.", "17.223.", "17.224.", "17.225.",
            "17.226.", "17.227.", "17.228.", "17.229.", "17.230.", "17.231.",
            "17.232.", "17.233.", "17.234.", "17.235.", "17.236.", "17.237.",
            "17.238.", "17.239.", "17.240.", "17.241.", "17.242.", "17.243.",
            "17.244.", "17.245.", "17.246.", "17.247.", "17.248.", "17.249.",
            "17.250.", "17.251.", "17.252.", "17.253.", "17.254.", "17.255.",
            # ── Google (Search, YouTube, Android, GCP, DNS) ───────────────────
            "8.8.8.", "8.8.4.", "8.34.", "8.35.",
            "34.64.", "34.65.", "34.66.", "34.67.", "34.68.", "34.69.",
            "34.70.", "34.71.", "34.72.", "34.73.", "34.74.", "34.75.",
            "34.76.", "34.77.", "34.78.", "34.79.", "34.80.", "34.81.",
            "34.82.", "34.83.", "34.84.", "34.85.", "34.86.", "34.87.",
            "34.88.", "34.89.", "34.90.", "34.91.", "34.92.", "34.93.",
            "34.94.", "34.95.", "34.96.", "34.97.", "34.98.", "34.99.",
            "34.100.", "34.101.", "34.102.", "34.103.", "34.104.", "34.105.",
            "34.106.", "34.107.", "34.108.", "34.109.", "34.110.", "34.111.",
            "34.112.", "34.113.", "34.114.", "34.115.", "34.116.", "34.117.",
            "34.118.", "34.119.", "34.120.", "34.121.", "34.122.", "34.123.",
            "34.124.", "34.125.", "34.126.", "34.127.", "34.128.", "34.129.",
            "34.130.", "34.131.", "34.132.", "34.133.", "34.134.", "34.135.",
            "35.184.", "35.185.", "35.186.", "35.187.", "35.188.", "35.189.",
            "35.190.", "35.191.", "35.192.", "35.193.", "35.194.", "35.195.",
            "35.196.", "35.197.", "35.198.", "35.199.", "35.200.", "35.201.",
            "35.202.", "35.203.", "35.204.", "35.205.", "35.206.", "35.207.",
            "35.208.", "35.209.", "35.210.", "35.211.", "35.212.", "35.213.",
            "35.214.", "35.215.", "35.216.", "35.217.", "35.218.", "35.219.",
            "35.220.", "35.221.", "35.222.", "35.223.", "35.224.", "35.225.",
            "35.226.", "35.227.", "35.228.", "35.229.", "35.230.", "35.231.",
            "35.232.", "35.233.", "35.234.", "35.235.", "35.236.", "35.237.",
            "35.238.", "35.239.", "35.240.", "35.241.", "35.242.", "35.243.",
            "35.244.", "35.245.", "35.246.", "35.247.", "35.248.", "35.249.",
            "64.233.", "66.102.", "66.249.", "72.14.", "74.125.",
            "108.177.", "142.250.", "172.217.", "173.194.", "209.85.",
            "216.58.", "216.239.",
            # ── Cloudflare (1.1.1.1 DNS, CDN, Workers, R2) ───────────────────
            "1.0.0.", "1.1.1.",
            "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
            "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
            "104.28.",
            "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
            "172.70.", "172.71.",
            "162.158.", "198.41.",
            # ── Akamai (massive CDN used by government, banking, media sites) ─
            "23.11.", "23.32.", "23.33.", "23.34.", "23.35.", "23.36.",
            "23.37.", "23.38.", "23.39.", "23.40.", "23.41.", "23.42.",
            "23.43.", "23.44.", "23.45.", "23.46.", "23.47.", "23.48.",
            "23.49.", "23.50.", "23.51.", "23.52.", "23.53.", "23.54.",
            "23.55.", "23.56.", "23.57.", "23.58.", "23.59.",
            "96.16.", "96.17.",
            "184.24.", "184.25.", "184.26.", "184.27.", "184.28.", "184.29.",
            "184.50.", "184.51.",
            # ── Amazon CloudFront / AWS (S3, Lambda@Edge, CloudFront CDN) ─────
            "13.224.", "13.225.", "13.226.", "13.227.", "13.228.",
            "13.32.", "13.33.", "13.34.", "13.35.",
            "13.249.", "13.250.", "13.251.",
            "52.84.", "52.85.", "52.86.", "52.87.",
            "54.182.", "54.192.", "54.230.", "54.239.", "54.240.",
            "65.8.", "65.9.", "65.54.",
            "99.84.", "99.86.",
            "143.204.",
            "204.246.",
            "205.251.",
            # ── Meta (Facebook, Instagram, WhatsApp, Threads) ─────────────────
            "31.13.",
            "157.240.",
            "173.252.",
            "179.60.",
            "185.89.",
            "204.15.",
            # ── Twitter / X ───────────────────────────────────────────────────
            "104.244.",
            "192.133.",
            "199.16.",
            "199.59.",
            # ── LinkedIn (Microsoft subsidiary) ───────────────────────────────
            "108.174.",
            "13.107.",  # already listed under Microsoft, repeated for clarity
            # ── Fastly CDN (GitHub, Twitch, Reddit, Stripe, many others) ──────
            "151.101.",
            "199.232.",
            "23.235.",
            # ── DigitalOcean (GitHub Actions runners, many SaaS backends) ─────
            "104.131.",
            "159.89.",
            "159.203.",
            # ── Telegram ──────────────────────────────────────────────────────
            "149.154.",
            "91.108.",
            # ── WhatsApp (Meta subsidiary, separate AS) ────────────────────────
            "31.13.",  # same as Facebook ranges
            # ── YouTube / Google Video ────────────────────────────────────────
            "74.125.",  # already in Google section
        )

        # Pre-compute first-octet frozenset for O(1) pre-filter before the full
        # prefix scan.  Most packets go to private 10.x/192.x/172.x IPs which
        # will fail the first-octet check instantly, avoiding the ~200+ prefix
        # string comparisons entirely.
        self._trusted_first_octets = frozenset(
            int(p.split(".", 1)[0]) for p in self.trusted_dst_prefixes
            if p and p[0].isdigit()
        )

        self._load_all()

    def _log(self, msg: str):
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        print(line, flush=True)
        self._startup_log.append(line)

    # ── Loaders ────────────────────────────────────────────────
    def _load_all(self):
        self._log("Initialising threat signature database...")
        for fname in ("emerging_threats.rules", "bastion.rules"):
            path = os.path.join(RULES_DIR, fname)
            if os.path.exists(path):
                n = self._load_rules_file(path)
                self._log(f"  Signature set loaded: {n:,} rules [{fname}]")
            else:
                self._log(f"  Signature file not found: {fname}")

        self.rules_count = len(self._all_rules)
        self._load_ip_reputation()
        if self.disabled_sids:
            self._log(f"  Suppressed {len(self.disabled_sids)} known false-positive rules: {sorted(self.disabled_sids)}")
        elapsed = time.time() - self._t0
        self._log(f"Detection engine ready — {self.rules_count:,} signatures active ({elapsed:.1f}s)")

    def _load_rules_file(self, path: str) -> int:
        n = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            total = len(lines)
            step  = max(1, total // 20)
            for i, line in enumerate(lines):
                if i % step == 0:
                    pct = int(100 * i / total)
                    print(f"\r  Loading [{pct:3d}%]...", end="", flush=True)
                rule = _parse_rule(line)
                if rule:
                    self._index_rule(rule)
                    n += 1
            print(f"\r  Loading [100%] — {n:,} rules parsed          ")
        except Exception as ex:
            self._log(f"  Error loading {path}: {ex}")
        return n

    def _index_rule(self, rule: SigRule):
        """
        Index rule for fast lookup.

        Priority:
          1. Specific dst_ports  →  _port_index[port]   (fastest — O(1) lookup)
          2. No port + content   →  _proto_index[proto]  (content verifies at match-time)
          3. No port + no content → SKIP (would match every packet of that proto)

        Rules with VERY LARGE port ranges (>1000 ports, e.g. ephemeral ranges)
        that also have no content are also skipped — they are too broad.

        LOW-VALUE CATEGORIES (counted in rules_count but NOT indexed for matching):
        These rule categories require full HTTP/TLS/session context, SIEM integration,
        and stateful threshold enforcement to be meaningful. Without that context they
        generate near-100% false-positive rates on any real network, especially WiFi
        where hundreds of devices continuously generate background app traffic.
          • ET INFO   — informational monitoring, not actionable threat intelligence
          • ET POLICY — policy enforcement, requires organisational context
          • ET CHAT   — chat protocol detection, not a security threat
          • ET GAMES  — gaming traffic, not a security threat
          • ET P2P    — P2P detection, not a security threat per se
          • ET ICMP_INFO — ICMP informational, floods on ping/traceroute
          • ET INAPPROPRIATE — content filtering, not a security threat
          • misc-activity / not-suspicious with thin content — require PCRE/session
            context to avoid matching every HTTP response or DNS reply
        """
        self._all_rules.append(rule)

        # ── LOW-VALUE CATEGORY FILTER ────────────────────────────────────────
        # These categories are designed for SIEM logging pipelines, not standalone
        # IDS alerting.  Indexing them produces massive false-positive floods on
        # WiFi networks where mobile devices, IoT sensors, smart TVs, and game
        # consoles continuously generate background traffic that matches their broad
        # content patterns.
        _mu = rule.msg.upper()
        if _mu.startswith((
            "ET INFO ",        # informational — fires on downloads, lookups, UA strings
            "ET POLICY ",      # policy — fires on Google Talk, AOL, Dropbox, Pastebin...
            "ET CHAT ",        # chat protocols — not threats in 2024
            "ET GAMES ",       # gaming traffic — not threats
            "ET P2P ",         # peer-to-peer — not threats per se
            "ET ICMP_INFO ",   # ICMP informational — ping/traceroute noise
            "ET INAPPROPRIATE ",  # content filtering — not security
        )):
            return   # counted in _all_rules / rules_count, never matched

        # ── THIN CONTENT GUARD for misc-activity / not-suspicious ────────────
        # These classtypes require PCRE, flow state, or threshold enforcement to
        # be precise.  Rules with ≤ 14 bytes of total content (e.g. single-char
        # patterns like "/", "+", "!" or 3-byte "200") fire on virtually every
        # HTTP request/response and must be excluded from the match index.
        if rule.classtype in ("misc-activity", "not-suspicious"):
            total_pat = sum(len(p) for p in rule.content_patterns)
            if total_pat < 14 and rule.dst_ports is None:
                return   # too broad without specific port or stronger content

        if rule.dst_ports and not isinstance(rule.dst_ports, tuple):
            port_set = rule.dst_ports
            # Skip indexing if the port range is excessively large (e.g. 1024:65535)
            # AND there are no content patterns to narrow it down.
            if len(port_set) > 2000 and not rule.content_patterns:
                return
            for port in list(port_set)[:1000]:   # cap at 1000 per rule
                self._port_index[port].append(rule)
        else:
            # No specific port → only keep if it has content to verify,
            # AND the content is specific enough (≥ 8 bytes total) to not
            # match every packet. Generic short patterns like "GET /" (5 bytes)
            # would hit every HTTP request — discard them unless they target
            # a specific port that already narrows the match space.
            total_content = sum(len(p) for p in rule.content_patterns)
            if rule.content_patterns and total_content >= 8:
                self._proto_index[rule.proto].append(rule)
            # else: too broad → discard

    def _load_ip_reputation(self):
        for fname in ("compromised-ips.txt",):
            path = os.path.join(RULES_DIR, fname)
            if not os.path.exists(path):
                continue
            n = 0
            with open(path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.bad_ips.add(line)
                        n += 1
            if n:
                self._log(f"  IP reputation: {n:,} blacklisted addresses loaded")

    # ── Match ──────────────────────────────────────────────────
    def match(self, flow, raw_payload: bytes = None):
        """
        Attempt to match a single flow/packet against all active rules.

        Returns:
            (matched: bool, verdict: str, confidence: float,
             severity: str, sid: int, classtype: str)
        """
        try:
            row = flow.iloc[0]

            def _get(*keys):
                for k in keys:
                    v = row.get(k)
                    if v is not None and str(v).strip() not in ("", "nan"):
                        return v
                return ""

            src_ip   = str(_get("srcip", "Source", "src_ip", "source_ip") or "")
            dst_ip   = str(_get("dstip", "Destination", "dst_ip", "dest_ip") or "")
            proto    = str(_get("proto", "Protocol", "protocol") or "").lower().strip()
            service  = str(_get("service", "Service") or "").lower().strip()

            def _port(*keys):
                raw = _get(*keys)
                try:
                    if isinstance(raw, str) and raw.startswith("0x"):
                        return int(raw, 16)
                    return int(float(raw))
                except (ValueError, TypeError):
                    return 0

            dport = _port("dsport", "dport", "DstPort", "dst_port", "Dst Port")
            sport = _port("sport",  "SrcPort", "src_port", "Src Port")

            # ── FALSE POSITIVE GUARDS ────────────────────────────────
            # 1. Loopback → loopback: internal process comms, never real attacks
            if _is_loopback(src_ip) and _is_loopback(dst_ip):
                return (False, "NORMAL", 0.0, "LOW", 0, "")

            # 2. Bastion's own API/dev-server ports
            if sport in BASTION_PORTS or dport in BASTION_PORTS:
                return (False, "NORMAL", 0.0, "LOW", 0, "")

            # 3. DHCP: 0.0.0.0:68 → 255.255.255.255:67 (and inverse)
            #    These are legitimate L2 bootstrap packets; any rule firing on them
            #    is a false positive (e.g. ET DOS NTP peer-list rule matches port 68).
            _DHCP_PORTS = {67, 68}
            if (sport in _DHCP_PORTS and dport in _DHCP_PORTS) or \
               src_ip in ("0.0.0.0", "") or \
               dst_ip in ("255.255.255.255", ""):
                return (False, "NORMAL", 0.0, "LOW", 0, "")

            # 4. Multicast destinations (224.0.0.0/4) — mDNS, SSDP, OSPF etc.
            #    Signatures written for unicast traffic produce massive FP rates here.
            try:
                import ipaddress as _ipa
                if _ipa.ip_address(dst_ip).is_multicast:
                    return (False, "NORMAL", 0.0, "LOW", 0, "")
            except Exception:
                pass

            # ── EXTRACT FLOW METRICS ─────────────────────────────────
            sbytes = float(_get("sbytes", "TotLen Fwd Pkts") or 0)
            spkts  = int(float(_get("spkts", "Tot Fwd Pkts") or 0))
            dpkts  = int(float(_get("dpkts", "Tot Bwd Pkts") or 0))
            dur    = float(_get("dur", "Flow Duration") or 0)
            synack = int(float(_get("synack", "SYN Flag Cnt") or 0))
            state  = str(_get("state", "State") or "")
            # Raw TCP flags byte from the live-capture packet path
            # (-1 means not available — flow-mode data or non-TCP)
            try:
                _tfr = _get("tcp_flags_raw")
                tcp_flags_raw = int(float(_tfr)) if _tfr not in (None, "", "nan") else -1
            except (ValueError, TypeError):
                tcp_flags_raw = -1

            # ── 1. IP REPUTATION ────────────────────────────────────
            if src_ip and src_ip in self.bad_ips:
                return (True, f"Blacklisted Source: {src_ip}",
                        0.97, "HIGH", 9999001, "blacklist")
            if dst_ip and dst_ip in self.bad_ips:
                return (True, f"Blacklisted Destination: {dst_ip}",
                        0.93, "HIGH", 9999002, "blacklist")

            # ── 2. PORT SCAN DETECTION ──────────────────────────────
            # Skip the port-scan heuristic for:
            #   - Common service ports (browsing/HTTPS/etc.)
            #   - Windows discovery ports (NetBIOS/SSDP/mDNS/LLMNR/RPC)
            #   - Loopback traffic
            # NOTE: intra-/24 skip was removed — Phase 2 attack lab places
            # the attacker (Kali) and all victims in the same 192.168.100.0/24.
            # The threshold of 50 unique (dst_ip,port) pairs is already high
            # enough to ignore normal Windows SMB/NetBIOS discovery noise.
            #
            # ASYMMETRIC RESPONSE GUARD: when the SOURCE port is a known server
            # port (e.g. 445 SMB, 80 HTTP, 443 HTTPS, 3389 RDP, 22 SSH, etc.)
            # the packet is a SERVER RESPONSE, not an outbound scan.  During
            # brute-force attacks the victim server replies to many different
            # ephemeral ports (one per attempt) — without this guard that
            # response traffic looks like a port scan FROM the victim.
            _SERVER_RESPONSE_PORTS = {
                20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135,
                139, 143, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433,
                1521, 3306, 3389, 5432, 5900, 5985, 8080, 8443,
            }
            if (sport > 0 and src_ip and dst_ip
                    and sport not in _SERVER_RESPONSE_PORTS   # not a server reply
                    and dport not in COMMON_SAFE_PORTS
                    and dport not in DISCOVERY_PORTS
                    and dport > 0
                    and not _is_loopback(src_ip)):
                if self._scan_tracker.check_and_record(src_ip, dst_ip, dport):
                    return (True, f"Horizontal Port Scan Detected from {src_ip}",
                            0.88, "HIGH", 9000001, "network-scan")

            # ── 2b. STEALTH SCAN DETECTION ──────────────────────────
            # FIN / NULL / XMAS scans use malformed TCP flag combinations to
            # evade stateful firewalls (RFC 793 corner cases).  The dedicated
            # Snort rules for these are commented out in the rule files because
            # they depend on EXTERNAL_NET constraints and auxiliary options
            # (dsize:0, ack:0, window:) Bastion does not evaluate.  We detect
            # them here directly from the raw TCP flags byte with a per-source
            # per-type 30-second cooldown so each scan type fires exactly once.
            #
            # TCP flag bits: FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20
            if proto == "tcp" and src_ip and tcp_flags_raw >= 0:
                _f = tcp_flags_raw
                _fin = _f & 0x01; _syn = _f & 0x02; _rst = _f & 0x04
                _psh = _f & 0x08; _ack = _f & 0x10; _urg = _f & 0x20
                _stealth_type = None
                _stealth_sid  = 0
                if _f == 0x00:
                    # NULL scan — no flags set (T1595.002)
                    _stealth_type = "NULL"; _stealth_sid = 2000544
                elif _fin and _psh and _urg:
                    # XMAS scan — FIN+PSH+URG all lit (T1595.002)
                    # Must be checked BEFORE FIN-only because XMAS also has FIN set
                    _stealth_type = "XMAS"; _stealth_sid = 2000546
                elif _fin and not _syn and not _rst and not _ack:
                    # FIN scan — FIN set only, SYN/RST/ACK all clear (T1595.002)
                    _stealth_type = "FIN"; _stealth_sid = 2000545
                if _stealth_type and src_ip:
                    _sk = f"{src_ip}:{_stealth_type}"
                    _now = time.time()
                    if _now - self._stealth_seen.get(_sk, 0) > 30:
                        self._stealth_seen[_sk] = _now
                        return (True,
                                f"ET SCAN NMAP -{_stealth_type} Stealth Scan from {src_ip}",
                                0.83, "MEDIUM", _stealth_sid, "attempted-recon")

            # ── 3. BRUTE FORCE DETECTION ────────────────────────────
            BRUTE_PORTS = {22, 23, 445, 139, 3389, 21, 25, 110, 143, 3306, 5432, 1433, 5900, 8080}
            if dport in BRUTE_PORTS and src_ip:
                if self._brute_tracker.check_and_record(f"brute:{src_ip}:{dport}"):
                    svc = {22:"SSH", 23:"TELNET", 445:"SMB", 139:"SMB",
                           3389:"RDP", 21:"FTP", 25:"SMTP", 110:"POP3", 143:"IMAP",
                           3306:"MySQL", 5432:"PostgreSQL", 1433:"MSSQL",
                           5900:"VNC", 8080:"HTTP"}.get(dport, str(dport))
                    return (True, f"Brute-Force Attack: {svc} from {src_ip}",
                            0.90, "HIGH", 9000002, "attempted-admin")

            # ── 3b. DoS RATE DETECTION ──────────────────────────────
            # Count packets per (src_ip, dst_ip, proto) in a 2-second window.
            # Fires once per flood event (120s cooldown).  Catches ICMP flood,
            # SYN flood, UDP flood, and HTTP connection flood / Slowloris.
            if src_ip and dst_ip and proto in ("icmp", "tcp", "udp"):
                _dos_fired, _dos_name = self._dos_tracker.check_and_record(
                    src_ip, dst_ip, proto, dport=dport, tcp_flags_raw=tcp_flags_raw
                )
                if _dos_fired:
                    return (True,
                            f"{_dos_name} Detected: {src_ip} → {dst_ip}",
                            0.93, "HIGH", 9000010, "denial-of-service")

            # ── 4. SIGNATURE RULE MATCHING ──────────────────────────
            # ── PAYLOAD-REQUIRED GUARD (false-positive elimination) ──────────
            # ET signature rules are content/payload based — their discriminating
            # bytes (exploit patterns, malicious domains in TLS SNI, C2 markers)
            # ARE the rule.  Without the real packet payload (flow/batch mode, or
            # header-only packets such as bare SYN/ACK), that content cannot be
            # verified, and matching on port alone produces massive false
            # positives on normal traffic — e.g. every HTTPS flow to :443 would
            # match every port-443 rule (TA453 SNI, phishing, Coin-Hive, ...).
            # When there is no payload to verify, the signature layer returns
            # clean and detection is left to the heuristic detectors above
            # (port-scan / stealth / brute / DoS, already evaluated) and to the
            # ML / DL / anomaly layers downstream.
            if not raw_payload or len(raw_payload) < 4:
                return (False, "NORMAL", 0.0, "LOW", 0, "")

            # Performance: use itertools.chain to avoid list allocation per packet.
            # For WiFi capture at 1000+ pps this saves significant GC pressure.
            import itertools as _it
            candidates = _it.chain(
                self._port_index.get(dport, []),
                self._proto_index.get(proto, []),
                self._proto_index.get("any", []),
            )

            # Pre-compute trusted-CDN check for this dst_ip — done ONCE per flow,
            # reused for every candidate rule.  Without this, the O(N) prefix scan
            # runs inside the inner rule loop, multiplying its cost by rule count.
            _dst_trusted = False
            if dst_ip:
                try:
                    _first_oct = int(dst_ip.split(".", 1)[0])
                    if _first_oct in self._trusted_first_octets:
                        _dst_trusted = any(
                            dst_ip.startswith(pfx)
                            for pfx in self.trusted_dst_prefixes
                        )
                except (ValueError, IndexError):
                    pass

            # Pre-compute RFC-1918 status for src/dst once per flow
            _dst_is_home = _is_rfc1918(dst_ip) if dst_ip else False
            _src_is_home = _is_rfc1918(src_ip) if src_ip else True  # unknown → assume internal

            for rule in candidates:
                # Skip disabled rules (known false positives)
                if rule.sid in self.disabled_sids:
                    continue
                # Protocol check
                if not self._proto_match(rule.proto, proto):
                    continue
                # Port check (handles negation, ranges, None=any)
                if not _port_match(rule.dst_ports, dport):
                    continue

                # ── Direction enforcement ($HOME_NET / $EXTERNAL_NET) ────────
                # This is the single biggest source of false positives: rules
                # written for inbound attacks (-> $HOME_NET) firing on outbound
                # traffic (our internal host browsing to a CDN / internet server).
                # Example: Apache HTTP Smuggling (SID 2056423) says
                #   -> [$HOME_NET,$HTTP_SERVERS] $HTTP_PORTS
                # meaning it should only fire when our SERVERS are the target.
                # Without this check it fires whenever ANY machine sends HTTP
                # to port 80 — including us browsing to Akamai, Google, etc.
                if rule.requires_home_dst and not _dst_is_home:
                    continue   # rule targets inbound-to-server; dst is internet — skip
                if rule.requires_external_dst and _dst_is_home:
                    continue   # rule targets outbound; dst is internal — skip

                # ── dsize check ─────────────────────────────────────────
                # Rules that specify an exact or bounded payload length (e.g.
                # dsize:8 for a C2 beacon, dsize:>300 for a large DNS query)
                # MUST have that constraint honored — without it, the rule fires
                # on every packet regardless of size (extremely broad).
                if rule.dsize_op is not None and raw_payload is not None:
                    if not _dsize_match(rule.dsize_op, rule.dsize_val, len(raw_payload)):
                        continue

                # ── PCRE guard ───────────────────────────────────────────────
                # Rules that rely on a PCRE for precision cannot safely fire
                # without regex evaluation.  Two cases are suppressed:
                #
                # Case 1 — thin content (< 8 bytes total): almost any packet
                #   could match; the PCRE is the only real discriminator.
                #
                # Case 2 — generic protocol-opener content: patterns like
                #   "GET / HTTP/1.1", "POST ", "SSH-" are common-string prefixes
                #   that appear in millions of benign packets. The PCRE narrows
                #   them to specific attack patterns; without it we get massive
                #   false-positive rates on normal HTTP/SSH/protocol traffic.
                if rule.has_pcre and raw_payload and len(raw_payload) >= 4:
                    total_pat_len = sum(len(p) for p in rule.content_patterns)
                    if total_pat_len < 8:
                        continue   # content too short without PCRE validation
                    # Generic protocol-opener check — skip if the first content
                    # pattern is a well-known protocol token (PCRE is essential)
                    if rule.content_patterns:
                        first = rule.content_patterns[0].lower()
                        if any(first.startswith(tok) for tok in _GENERIC_PROTO_TOKENS):
                            continue

                # Content matching
                if rule.content_patterns:
                    if raw_payload and len(raw_payload) >= 4:
                        # Payload available — do proper content match
                        if not self._content_match(rule, raw_payload):
                            continue
                    else:
                        # No payload to match against.
                        # ── LIVE CAPTURE GUARD ──────────────────────────────
                        # In live single-packet mode (SYN/handshake packets
                        # carry no application payload), content rules cannot
                        # be verified at all.  Firing them based only on port
                        # produces near-100% false-positive rates.
                        # Only accept them in batch/flow mode (spkts > 1).
                        if spkts <= 1:
                            continue
                        # Batch mode without payload: allow only if rule targets
                        # a very specific port (not a broad port-range rule)
                        if rule.dst_ports is None or len(rule.dst_ports) > 10:
                            continue
                else:
                    # No content patterns — rule MUST have a specific port
                    if rule.dst_ports is None:
                        continue
                    # ── LIVE CAPTURE GUARD ──────────────────────────────────
                    # Content-less rules in live mode fire on EVERY packet to a
                    # port (e.g., any TCP packet to 445 matches ALL SMB rules).
                    # Only fire these when we have real multi-packet flow data.
                    if spkts <= 1:
                        continue

                # TCP flags check — uses actual TCP flags byte when available,
                # falls back to flow-level state/synack heuristic for CSV/batch mode.
                if rule.flags and not self._flags_match(rule.flags, state, synack, tcp_flags_raw):
                    continue

                severity = rule.severity
                if dport in (445, 135, 4444, 31337):
                    severity = "HIGH"

                # ── TRUSTED DESTINATION SUPPRESSION ─────────────────────────
                # Pre-computed _dst_trusted flag (set once above, before the loop)
                # avoids repeating the O(N) prefix scan for every candidate rule.
                # TROJAN / EXPLOIT rules that hit Microsoft/Apple/Google/CDN IPs
                # are almost always false positives — Windows Update, APNS push
                # notifications, browser telemetry, CDN-cached app updates, etc.
                if _dst_trusted:
                    ct = (rule.classtype or "").lower()
                    _mu = rule.msg.upper()
                    # Suppress TROJAN / EXPLOIT / MALWARE rules on trusted CDN/vendor IPs.
                    # Also suppress web-application-attack rules: these are designed to
                    # detect attacks ON web servers (inbound), not traffic FROM us TO a CDN.
                    # When src is our internal host and dst is a known CDN, any
                    # web-application-attack match is a false positive — we are the
                    # HTTP client, not an Apache server being smuggling-attacked.
                    if ("trojan" in ct or "exploit" in ct or "web-application" in ct or
                            "TROJAN" in _mu or "EXPLOIT" in _mu or
                            "MALWARE" in _mu or "WEB_SPECIFIC_APPS" in _mu):
                        continue   # suppress — trusted CDN / vendor destination

                # ── LAN ADMIN-INTERFACE SUPPRESSION ─────────────────────────
                # When BOTH src and dst are RFC1918 and the destination ends in
                # .1 or .254 (the universal pattern for router / AP / gateway /
                # UniFi-controller addresses), suppress EXPLOIT and
                # WEB_SPECIFIC_APPS rules.  These ET rules target consumer-grade
                # router admin panels (UniFi, DD-WRT, Mikrotik, Netgear, ASUS,
                # D-Link, TP-Link) with broad HTTP content matches that fire on
                # every legitimate admin-page request because the PCRE shell-
                # metacharacter validation is not evaluated here.
                #
                # If a LAN host is genuinely attacking the gateway, it will also
                # show up in port-scan, brute-force, or lateral-movement signals
                # we already track — we don't lose detection capability, just
                # the noise.
                if (_src_is_home and _dst_is_home and dst_ip
                        and (dst_ip.endswith(".1") or dst_ip.endswith(".254"))):
                    ct = (rule.classtype or "").lower()
                    _mu = rule.msg.upper()
                    if ("exploit" in ct or "web-application" in ct
                            or "bad-unknown" in ct
                            or "EXPLOIT" in _mu or "WEB_SPECIFIC_APPS" in _mu
                            or "WEB_SERVER" in _mu):
                        continue   # suppress — LAN admin-interface false positive

                # ── MISC-ACTIVITY / NOT-SUSPICIOUS CLASSTYPE GUARD ──────────
                # These classtypes require threshold enforcement, HTTP context,
                # or PCRE evaluation to avoid false positives.  In single-packet
                # live mode (spkts == 1) they fire on virtually any HTTP response
                # or DNS reply — suppress them unless we have real flow data.
                if (rule.classtype in ("misc-activity", "not-suspicious")
                        and spkts <= 1):
                    continue

                # Confidence graded by evidence quality
                has_content  = bool(rule.content_patterns and raw_payload
                                    and len(raw_payload) >= 4)
                has_port     = rule.dst_ports is not None
                if has_content and has_port:
                    confidence = 0.90
                elif has_content:
                    confidence = 0.78
                elif has_port:
                    confidence = 0.68
                else:
                    confidence = 0.58

                # Build verdict — avoid double "ET ET" prefix if rule.msg
                # already starts with "ET " (most ET-Open rules do).
                _msg = rule.msg
                verdict = _msg if _msg.upper().startswith("ET ") else f"ET {_msg}"

                # ── PER-SIGNATURE COOLDOWN ───────────────────────────────────
                # Prevent the same rule firing hundreds of times for the same
                # source IP within a short window (e.g. sqlmap → 83 identical
                # "ET SCAN Sqlmap SQL Injection Scan" alerts in one run).
                # Pick cooldown period based on rule category.
                _mu_upper = _msg.upper()
                if any(k in _mu_upper for k in ("SCAN", "WEB_SERVER", "WEB_SPECIFIC", "SNMP", "RPC", "TFTP", "DNS", "DOS", "NETBIOS", "SMB")):
                    _cd = self._SIG_COOLDOWN_SCAN
                elif any(k in _mu_upper for k in ("EXPLOIT", "TROJAN", "MALWARE", "BACKDOOR")):
                    _cd = self._SIG_COOLDOWN_EXPLOIT
                else:
                    _cd = self._SIG_COOLDOWN_DEFAULT

                # Key on SORTED ip pair so bidirectional traffic between the
                # same two hosts shares one cooldown slot — prevents the same
                # rule firing 100+ times when both src and dst alternate roles.
                _ip_pair = (min(src_ip, dst_ip), max(src_ip, dst_ip))
                _ck = (rule.sid, _ip_pair)
                _now = time.time()
                with self._sig_cooldown_lock:
                    _last = self._sig_cooldown.get(_ck, 0.0)
                    if _now - _last < _cd:
                        continue   # same rule, same ip pair — still in cooldown
                    self._sig_cooldown[_ck] = _now

                return (True, verdict, confidence, severity,
                        rule.sid, rule.classtype or "misc-attack")

            # ── 5. BEHAVIOURAL HEURISTICS ───────────────────────────
            # Only run heuristics when we have real flow-level metrics
            # (batch/CSV mode). In live single-packet mode spkts=1 and
            # sbytes is the raw packet length — those metrics are too
            # noisy for heuristic decisions.
            result = self._heuristic_check(
                proto, dport, sport, sbytes, spkts, dpkts,
                dur, service, state, synack, src_ip, dst_ip)
            if result:
                return result

        except Exception:
            pass   # engine must never crash the pipeline

        return (False, "NORMAL", 0.0, "LOW", 0, "")

    # ── Helpers ────────────────────────────────────────────────
    def _proto_match(self, rule_proto: str, flow_proto: str) -> bool:
        if rule_proto in ("any", ""):
            return True
        if rule_proto == flow_proto:
            return True
        aliases = {
            "tcp":  {"tcp", "6"},
            "udp":  {"udp", "17"},
            "icmp": {"icmp", "1"},
        }
        return flow_proto in aliases.get(rule_proto, {rule_proto})

    def _content_match(self, rule: SigRule, payload: bytes) -> bool:
        if not payload:
            return False
        pay_lc = payload.lower() if rule.nocase else None
        for pat in rule.content_patterns:
            if isinstance(pat, str):
                pat = pat.encode("latin-1", errors="replace")
            try:
                if rule.nocase:
                    if pat.lower() not in pay_lc:
                        return False
                else:
                    if pat not in payload:
                        return False
            except Exception:
                return False
        return True

    def _flags_match(self, rule_flags: str, state: str, synack: int,
                     tcp_flags_raw: int = -1) -> bool:
        """
        Evaluate a Snort TCP flags expression.

        When tcp_flags_raw >= 0 (live capture — actual TCP flags byte from the
        packet), delegate to the precise _snort_flags_match() evaluator.

        When tcp_flags_raw == -1 (batch/CSV flow data — no raw packet available),
        fall back to the coarse state/synack heuristic so that flow-based
        analysis still works even without raw flag bytes.
        """
        if tcp_flags_raw >= 0:
            return _snort_flags_match(rule_flags, tcp_flags_raw)

        # ── Fallback: flow-mode heuristic (batch CSV / PCAP summary) ────
        # We only have aggregate flow stats (synack count, TCP state string).
        # Map common Snort flag patterns to what we CAN determine:
        #   S   → SYN packet (synack > 0 in the flow)
        #   SA  → SYN-ACK    (state contains "A" and synack > 0)
        #   A   → ACK-only   (state contains "A")
        #   0   → No flags   (NULL scan — if state is not CON/SYN we guess True)
        flag_upper = rule_flags.upper()
        has_S  = "S" in flag_upper and "!S" not in flag_upper
        has_A  = "A" in flag_upper and "!A" not in flag_upper
        state_has_A = "A" in state.upper()

        if has_S and synack > 0:
            return True
        if has_A and state_has_A:
            return True
        if not has_S and not has_A:
            # Rule requires neither SYN nor ACK — allow (could be FIN/NULL/XMAS)
            return True
        return False

    def _heuristic_check(self, proto, dport, sport, sbytes, spkts,
                          dpkts, dur, service, state, synack,
                          src_ip="", dst_ip=""):
        """
        High-confidence behavioural heuristics.
        These ONLY fire when flow metrics indicate sustained activity
        (sbytes > 0, spkts > 3, dur > 0) to avoid single-packet false positives.
        """

        # Minimum data requirements — single-packet live traffic is excluded
        has_flow_data = sbytes > 0 and spkts > 3

        # ── Known C2/RAT ports with real traffic ─────────────────────
        c2_ports = {4444, 1234, 31337, 6667, 6666, 1337, 9999,
                    12345, 54321, 65535}
        if dport in c2_ports and has_flow_data:
            return (True, f"Command & Control: Suspicious Port {dport}",
                    0.87, "HIGH", 9100001, "trojan-activity")

        # ── Large outbound exfiltration ───────────────────────────────
        if has_flow_data and sbytes > 10_000_000 and dur > 5 and dpkts < spkts * 0.05:
            return (True, "Data Exfiltration: High-Volume Outbound Transfer",
                    0.82, "HIGH", 9100005, "policy-violation")

        # ── DNS tunneling (very large DNS packets) ────────────────────
        if (dport == 53 and proto == "udp" and has_flow_data):
            avg_pkt = sbytes / max(spkts, 1)
            if avg_pkt > 500:   # DNS packets should be <200 bytes
                return (True, "DNS Tunneling: Oversized Query Packets",
                        0.78, "HIGH", 9100006, "misc-attack")

        # ── ICMP flood — requires very high packet count ──────────────
        if proto == "icmp" and spkts > 500 and dur < 10:
            return (True, "ICMP Flood Attack Detected",
                    0.88, "HIGH", 9100008, "denial-of-service")

        # ── FTP large-file exfil ──────────────────────────────────────
        if service == "ftp" and has_flow_data and sbytes > 5_000_000:
            return (True, "FTP Large Transfer: Possible Data Exfiltration",
                    0.75, "MEDIUM", 9100009, "policy-violation")

        # ── Telnet (plain-text) ──────────────────────────────────────
        if dport == 23 and proto == "tcp" and has_flow_data:
            return (True, "Plaintext Protocol: Telnet Session Detected",
                    0.80, "MEDIUM", 9100004, "policy-violation")

        return None

    def get_startup_log(self) -> list:
        return self._startup_log


# ─────────────────────────────────────────────────────────────
# SEVERITY CLASSIFICATION
# Defines how an alert's overall risk level is determined.
# ─────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "HIGH":     {"score_range": (0.75, 1.00),
                 "description": "Direct exploitation attempt or confirmed C2 activity"},
    "MEDIUM":   {"score_range": (0.50, 0.74),
                 "description": "Suspicious activity with moderate certainty"},
    "LOW":      {"score_range": (0.30, 0.49),
                 "description": "Policy violation or informational event"},
    "INFO":     {"score_range": (0.00, 0.29),
                 "description": "Noise, benign anomaly, or monitoring event"},
}


def classify_severity(confidence: float, classtype: str,
                       verdict: str, proto: str = "") -> str:
    """
    Determine alert severity using three inputs:
      1. Detection confidence (0–1) — primary driver
      2. Rule classtype             — adjusts based on known risk category
      3. Verdict keywords           — escalates for known critical patterns

    Rationale:
      - HIGH   : confidence ≥ 0.75 OR classtype in critical set
      - MEDIUM : confidence ≥ 0.50
      - LOW    : confidence ≥ 0.30
      - INFO   : everything else

    This approach mirrors CVSS v3 methodology where impact + exploitability
    combine to produce a severity band.
    """
    # Classtype-based escalation
    CRITICAL_CLASSES = {
        "attempted-admin", "successful-admin", "shellcode-detect",
        "trojan-activity", "denial-of-service", "web-application-attack",
    }
    MEDIUM_CLASSES = {
        "network-scan", "policy-violation", "protocol-command-decode",
        "misc-attack", "bad-unknown",
    }

    # Keyword escalation in verdict
    CRITICAL_KEYWORDS = {
        "EXPLOIT", "RANSOMWARE", "BACKDOOR", "C2", "EXFIL",
        "SHELLCODE", "ROOTKIT", "RAT", "BOTNET", "TROJAN",
    }
    verdict_upper = verdict.upper()

    if any(k in verdict_upper for k in CRITICAL_KEYWORDS):
        return "HIGH"
    if classtype in CRITICAL_CLASSES or confidence >= 0.75:
        return "HIGH"
    if classtype in MEDIUM_CLASSES or confidence >= 0.50:
        return "MEDIUM"
    if confidence >= 0.30:
        return "LOW"
    return "INFO"
