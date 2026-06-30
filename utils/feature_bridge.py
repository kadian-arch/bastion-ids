"""
BASTION IDS — UNIVERSAL FEATURE BRIDGE
=======================================
Converts ANY network traffic source into the UNSW-NB15 42-feature contract
that the trained ML/DL models consume.

Supported inputs:
  1. UNSW-NB15 CSV        — native, pass-through
  2. CICIDS CSV           — column mapping + normalization
  3. Generic CSV          — best-effort column detection + mapping
  4. PCAP file            — Scapy-based flow extraction
  5. Live packet capture  — real-time flow aggregation from Scapy packets

The bridge ensures the system works on ANY network traffic regardless of origin.
"""

import re
import os
import time
import numpy as np
import pandas as pd
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────
# FEATURE CONTRACT (42 features the models expect)
# ─────────────────────────────────────────────────────────────
UNSW_FEATURES = [
    "dur","proto","service","state","spkts","dpkts","sbytes","dbytes",
    "rate","sttl","dttl","sload","dload","sloss","dloss","sinpkt","dinpkt",
    "sjit","djit","swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat",
    "smean","dmean","trans_depth","response_body_len","ct_srv_src","ct_state_ttl",
    "ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm",
    "is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd","ct_src_ltm","ct_srv_dst",
    "is_sm_ips_ports"
]
CAT_FEATURES = ["proto","service","state"]
NUM_FEATURES  = [f for f in UNSW_FEATURES if f not in CAT_FEATURES]

# ─────────────────────────────────────────────────────────────
# PROTOCOL NUMBER → NAME (IANA assignments)
# ─────────────────────────────────────────────────────────────
# Standard column ordering for UNSW-NB15 raw CSV files (no header row)
# 49 columns: 47 features + attack_cat + label
UNSW_RAW_COLS_49 = [
    "srcip","sport","dstip","dsport","proto","state","dur",
    "sbytes","dbytes","sttl","dttl","sloss","dloss","service",
    "sload","dload","spkts","dpkts","swin","dwin","stcpb","dtcpb",
    "smeansz","dmeansz","trans_depth","res_bdy_len","sjit","djit",
    "stime","ltime","sintpkt","dintpkt","tcprtt","synack","ackdat",
    "is_sm_ips_ports","ct_state_ttl","ct_flw_http_mthd","is_ftp_login",
    "ct_ftp_cmd","ct_srv_src","ct_srv_dst","ct_dst_ltm",
    "ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm",
    "ct_src_ltm","attack_cat","label",
]
# Alias map: raw names → UNSW_FEATURES contract names
_UNSW_RAW_ALIAS = {
    "smeansz":    "smean",
    "dmeansz":    "dmean",
    "sintpkt":    "sinpkt",
    "dintpkt":    "dinpkt",
    "res_bdy_len":"response_body_len",
}

# Regex pattern for IPv4 address detection
import re as _re
_IP_PAT = _re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

PROTO_NUM_TO_NAME = {
    0:"hopopt",1:"icmp",2:"igmp",6:"tcp",17:"udp",
    41:"ipv6",43:"ipv6-route",44:"ipv6-frag",47:"gre",
    50:"esp",51:"ah",58:"ipv6-icmp",89:"ospf",
    103:"pim",132:"sctp",255:"reserved"
}
PROTO_NAME_TO_STD = {
    "tcp":"tcp","udp":"udp","icmp":"icmp","icmpv6":"icmp",
    "ipv6-icmp":"icmp","arp":"arp","esp":"esp","gre":"gre",
    "hopopt":"hopopt","igmp":"igmp","6":"tcp","17":"udp","1":"icmp"
}

# ─────────────────────────────────────────────────────────────
# PORT → SERVICE NAME
# ─────────────────────────────────────────────────────────────
PORT_TO_SERVICE = {
    20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",
    53:"dns",67:"dhcp",68:"dhcp",69:"tftp",80:"http",
    110:"pop3",119:"nntp",123:"ntp",137:"netbios-ns",
    138:"netbios-dgm",139:"netbios-ssn",143:"imap",161:"snmp",
    179:"bgp",389:"ldap",443:"https",445:"smb",514:"syslog",
    587:"smtp",636:"ldaps",873:"rsync",993:"imap",995:"pop3",
    1080:"socks",1194:"openvpn",1433:"mssql",1521:"oracle",
    1723:"pptp",3306:"mysql",3389:"rdp",3690:"svn",
    4444:"shell",5432:"postgres",5900:"vnc",5985:"wsman",
    6379:"redis",6667:"irc",8080:"http",8443:"https",
    8888:"http",9200:"elasticsearch",27017:"mongodb",
}

# ─────────────────────────────────────────────────────────────
# CICIDS COLUMN MAP → UNSW FEATURES
# ─────────────────────────────────────────────────────────────
CICIDS_MAP = {
    "Flow Duration":        ("dur",  lambda x: x / 1e6),   # µs → s
    "Protocol":             ("proto",lambda x: PROTO_NUM_TO_NAME.get(int(x) if not pd.isna(x) else 0, "tcp")),
    "Dst Port":             ("_dport", None),               # helper for service lookup
    "Tot Fwd Pkts":         ("spkts", None),
    "Tot Bwd Pkts":         ("dpkts", None),
    "TotLen Fwd Pkts":      ("sbytes", None),
    "TotLen Bwd Pkts":      ("dbytes", None),
    "Flow Pkts/s":          ("rate",  lambda x: min(float(x), 1e7) if not pd.isna(x) else 0),
    "Flow IAT Mean":        ("sinpkt",lambda x: x / 1e6),
    "Bwd IAT Mean":         ("dinpkt",lambda x: x / 1e6 if not pd.isna(x) else 0),
    "Flow IAT Std":         ("sjit",  lambda x: x / 1e6),
    "Bwd IAT Std":          ("djit",  lambda x: x / 1e6 if not pd.isna(x) else 0),
    "Init Fwd Win Byts":    ("swin",  lambda x: max(float(x), 0) if not pd.isna(x) else 0),
    "Init Bwd Win Byts":    ("dwin",  lambda x: max(float(x), 0) if not pd.isna(x) else 0),
    "SYN Flag Cnt":         ("synack",None),
    "ACK Flag Cnt":         ("ackdat",None),
    "Fwd Pkt Len Mean":     ("smean", None),
    "Bwd Pkt Len Mean":     ("dmean", lambda x: x if not pd.isna(x) else 0),
    "TotLen Bwd Pkts":      ("response_body_len", None),
    "Fwd Pkts/s":           ("sload", lambda x: min(float(x), 1e7) if not pd.isna(x) else 0),
    "Bwd Pkts/s":           ("dload", lambda x: min(float(x), 1e7) if not pd.isna(x) else 0),
}

# Generic column name patterns (for unknown CSVs)
GENERIC_PATTERNS = {
    "dur":     ["duration","flow_duration","flow dur","flow_dur","dur"],
    "proto":   ["protocol","proto","ip_proto","network_protocol"],
    "sbytes":  ["source bytes","source_bytes","src_bytes","fwd_bytes","bytes_fwd","totlen_fwd","sbytes"],
    "dbytes":  ["dest bytes","destination bytes","dest_bytes","dst_bytes","bwd_bytes","bytes_bwd","totlen_bwd","dbytes"],
    "spkts":   ["source pkts","source_pkts","src_pkts","fwd_pkts","tot_fwd_pkts","packets_fwd","spkts"],
    "dpkts":   ["dest pkts","destination pkts","dest_pkts","dst_pkts","bwd_pkts","tot_bwd_pkts","packets_bwd","dpkts"],
    "sttl":    ["source ttl","source_ttl","src_ttl","fwd_ttl","ttl_src","ttl_fwd","sttl"],
    "dttl":    ["dest ttl","destination ttl","dest_ttl","dst_ttl","bwd_ttl","ttl_dst","ttl_bwd","dttl"],
    "swin":    ["source win","source_win","win_fwd","src_win","fwd_win","tcp_win_src","swin"],
    "dwin":    ["dest win","destination win","dest_win","win_bwd","dst_win","bwd_win","tcp_win_dst","dwin"],
    "smean":   ["source mean","source_mean","fwd_pkt_len_mean","mean_fwd","avg_pkt_len_fwd","smean"],
    "dmean":   ["dest mean","destination mean","dest_mean","bwd_pkt_len_mean","mean_bwd","avg_pkt_len_bwd","dmean"],
    "sload":   ["source load","source_load","src_load","fwd_load","sload"],
    "dload":   ["dest load","destination load","dest_load","dst_load","bwd_load","dload"],
    "sloss":   ["source loss","source_loss","src_loss","fwd_loss","sloss"],
    "dloss":   ["dest loss","destination loss","dest_loss","dst_loss","bwd_loss","dloss"],
    "sinpkt":  ["src inter pkt","src_inter_pkt","sinpkt","fwd_iat_mean","inter_pkt_src"],
    "dinpkt":  ["dst inter pkt","dst_inter_pkt","dinpkt","bwd_iat_mean","inter_pkt_dst"],
    "sjit":    ["source jitter","source_jitter","sjit","fwd_jitter"],
    "djit":    ["dest jitter","destination jitter","dest_jitter","djit","bwd_jitter"],
    "tcprtt":  ["tcp rtt","tcp_rtt","tcprtt","tcp_round_trip"],
    "synack":  ["syn ack","syn_ack","synack","syn_flag","syn_count","syn_flag_cnt"],
    "ackdat":  ["ack dat","ack_dat","ackdat","ack_flag","ack_count","ack_flag_cnt"],
    "rate":    ["flow_rate","pkt_rate","pkts_per_sec","flow_pkts_s","rate"],
    "stcpb":   ["source tcp base seq","source_tcp_base_seq","stcpb","fwd_init_win"],
    "dtcpb":   ["dest tcp base seq","dest_tcp_base_seq","dtcpb","bwd_init_win"],
    "trans_depth": ["trans depth","trans_depth"],
    "res_bdy_len": ["response body len","response_body_len","res_bdy_len"],
    "ct_state_ttl":["ct state ttl","ct_state_ttl"],
    "ct_srv_src":  ["ct srv src","ct_srv_src"],
    "ct_srv_dst":  ["ct srv dst","ct_srv_dst"],
    "ct_dst_ltm":  ["ct dst ltm","ct_dst_ltm"],
    "ct_src_ltm":  ["ct src ltm","ct_src_ltm"],
    "is_ftp_login":["is ftp login","is_ftp_login"],
    "ct_ftp_cmd":  ["ct ftp cmd","ct_ftp_cmd"],
    "ct_flw_http_mthd":["ct flw http mthd","ct_flw_http_mthd"],
    "is_sm_ips_ports":["is sm ips ports","is_sm_ips_ports"],
}

# ─────────────────────────────────────────────────────────────
# DATASET DETECTOR
# ─────────────────────────────────────────────────────────────
def detect_dataset_format(df: pd.DataFrame) -> str:
    """
    Detect whether a DataFrame is UNSW-NB15, CICIDS, UNSW-NB15 raw (no header),
    or generic.
    Returns: 'unsw' | 'unsw_verbose' | 'unsw_raw' | 'cicids' | 'generic'
    """
    # Normalize column names: always stringify, strip whitespace and BOM
    str_cols   = [str(c) for c in df.columns]
    cols_lower = set(c.lower().strip().lstrip('﻿') for c in str_cols)

    # UNSW-NB15 signature columns (standard abbreviated names)
    unsw_sig = {"dur","proto","service","state","sbytes","dbytes","spkts","dpkts"}
    if unsw_sig.issubset(cols_lower):
        return "unsw"

    # UNSW-NB15 with verbose column names (e.g. "source pkts", "dest bytes")
    unsw_verbose  = {"duration","protocol","service","state","source bytes","dest bytes","source pkts","dest pkts"}
    unsw_verbose2 = {"duration","protocol","service","state","source_bytes","dest_bytes","source_pkts","dest_pkts"}
    if unsw_verbose.issubset(cols_lower) or unsw_verbose2.issubset(cols_lower):
        return "unsw_verbose"

    # CICIDS signature columns
    cicids_sig = {"flow duration","tot fwd pkts","tot bwd pkts","flow pkts/s"}
    if len(cicids_sig.intersection(set(c.lower().strip() for c in str_cols))) >= 3:
        return "cicids"

    # CICIDS 2018 column set (slightly different names)
    cicids2018_sig = {"flow duration","tot fwd pkts","tot bwd pkts"}
    if len(cicids2018_sig.intersection(set(c.lower().strip() for c in str_cols))) >= 2:
        if any("dst port" in c.lower() or "protocol" in c.lower() for c in str_cols):
            return "cicids"

    # Headerless UNSW-NB15 raw files — detected when column 0 looks like an IP
    # address and column count matches the expected 47–49 range.
    # Strip BOM (U+FEFF), zero-width spaces, and other non-printable leading chars.
    if 45 <= len(df.columns) <= 51:
        first_col = _re.sub(r'^[^\d]+', '', str_cols[0].strip())
        if _IP_PAT.match(first_col):
            return "unsw_raw"

    return "generic"


# ─────────────────────────────────────────────────────────────
# CONVERTERS
# ─────────────────────────────────────────────────────────────
def _default_row() -> dict:
    """Return a zero-filled feature row with safe categorical defaults."""
    row = {f: 0 for f in NUM_FEATURES}
    row["proto"]   = "tcp"
    row["service"] = "-"
    row["state"]   = "CON"
    return row


def _port_to_service(port) -> str:
    try:
        return PORT_TO_SERVICE.get(int(float(port)), "-")
    except (ValueError, TypeError):
        return "-"


def convert_unsw(df: pd.DataFrame) -> pd.DataFrame:
    """Pass-through for UNSW-NB15 format — just align columns."""
    cols_lower_map = {c.lower().strip().lstrip('﻿'): c for c in df.columns}
    result = pd.DataFrame()
    for feat in UNSW_FEATURES:
        if feat in df.columns:
            result[feat] = df[feat]
        elif feat in cols_lower_map:
            result[feat] = df[cols_lower_map[feat]]
        elif feat in CAT_FEATURES:
            result[feat] = "-"
        else:
            result[feat] = 0
    return _clean(result)


def convert_unsw_raw(df: pd.DataFrame) -> pd.DataFrame:
    """
    Handle UNSW-NB15 raw CSV files that have NO header row.
    Column 0 is srcip (an IP address), and the file has 47–49 columns.
    We assign the standard UNSW-NB15 column names then call convert_unsw.
    """
    df = df.copy()
    n_cols = len(df.columns)
    # Assign standard UNSW-NB15 column names (drop any excess beyond 49)
    col_names = UNSW_RAW_COLS_49[:n_cols]
    df.columns = col_names
    # Apply alias map: raw column names → UNSW_FEATURES contract names
    df.rename(columns=_UNSW_RAW_ALIAS, inplace=True)
    # Now treat as standard UNSW (named) format
    return convert_unsw(df)


def convert_cicids(df: pd.DataFrame) -> pd.DataFrame:
    """
    Bridge CICIDS 2017/2018 CSV to UNSW feature contract.
    Vectorised — processes entire columns at once instead of row-by-row.
    """
    df = df.copy()
    df.columns = df.columns.str.strip()
    result = pd.DataFrame(index=df.index)

    # Apply column mappings vectorised
    for cicids_col, (unsw_col, transform) in CICIDS_MAP.items():
        if cicids_col not in df.columns or unsw_col == "_dport":
            continue
        col = df[cicids_col]
        if transform is not None:
            try:
                col = col.apply(lambda x: transform(x) if not pd.isna(x) else 0)
            except Exception:
                col = pd.to_numeric(col, errors="coerce").fillna(0)
        result[unsw_col] = col

    # Service from destination port (vectorised)
    if "Dst Port" in df.columns:
        result["service"] = df["Dst Port"].apply(_port_to_service)
    else:
        result["service"] = "-"

    result["state"] = "CON"

    # Fill missing UNSW features with defaults
    for feat in UNSW_FEATURES:
        if feat not in result.columns:
            result[feat] = "-" if feat in CAT_FEATURES else 0

    return _clean(result[UNSW_FEATURES])


def convert_generic(df: pd.DataFrame) -> pd.DataFrame:
    """Best-effort mapping for any unknown CSV format."""
    df_cols_lower = {c.lower().strip(): c for c in df.columns}
    rows = []
    for _, row in df.iterrows():
        feat = _default_row()
        for unsw_feat, patterns in GENERIC_PATTERNS.items():
            for pat in patterns:
                if pat in df_cols_lower:
                    try:
                        feat[unsw_feat] = float(row[df_cols_lower[pat]])
                    except (ValueError, TypeError):
                        pass
                    break
        # Try direct column name match (case-insensitive)
        for unsw_feat in UNSW_FEATURES:
            if unsw_feat in df_cols_lower:
                val = row[df_cols_lower[unsw_feat]]
                feat[unsw_feat] = val if unsw_feat in CAT_FEATURES else _safe_float(val)
        rows.append(feat)
    return _clean(pd.DataFrame(rows, columns=UNSW_FEATURES))


def _safe_float(val, default=0.0) -> float:
    try:
        f = float(val)
        if np.isnan(f) or np.isinf(f):
            return default
        return f
    except (TypeError, ValueError):
        return default


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """Final cleaning pass — enforce correct types and clamp extremes."""
    for col in CAT_FEATURES:
        df[col] = df[col].fillna("-").astype(str).str.lower().str.strip()
    for col in NUM_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        df[col] = df[col].replace([np.inf, -np.inf], 0)
    # Compute derived features if missing
    if "rate" in df.columns:
        dur_mask = (df["dur"] > 0) & (df["rate"] == 0)
        df.loc[dur_mask, "rate"] = (
            (df.loc[dur_mask,"spkts"] + df.loc[dur_mask,"dpkts"]) /
             df.loc[dur_mask,"dur"]
        ).clip(0, 1e7)
    if "smean" in df.columns:
        pkt_mask = (df["spkts"] > 0) & (df["smean"] == 0)
        df.loc[pkt_mask, "smean"] = (df.loc[pkt_mask,"sbytes"] / df.loc[pkt_mask,"spkts"])
    if "dmean" in df.columns:
        pkt_mask2 = (df["dpkts"] > 0) & (df["dmean"] == 0)
        df.loc[pkt_mask2, "dmean"] = (df.loc[pkt_mask2,"dbytes"] / df.loc[pkt_mask2,"dpkts"])
    return df[UNSW_FEATURES]


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────
def bridge(df: pd.DataFrame, label_col: Optional[str] = None) -> Tuple[pd.DataFrame, Optional[pd.Series]]:
    """
    Convert any DataFrame to UNSW-NB15 42-feature format.

    Args:
        df:        Input DataFrame (any format)
        label_col: Optional column name containing ground-truth labels

    Returns:
        (features_df, labels_series_or_None)
    """
    labels = None
    if label_col and label_col in df.columns:
        labels = df[label_col].copy()
        df = df.drop(columns=[label_col])

    fmt = detect_dataset_format(df)
    if fmt == "unsw":
        out = convert_unsw(df)
    elif fmt == "unsw_verbose":
        out = convert_generic(df)   # space-separated names handled via GENERIC_PATTERNS
    elif fmt == "unsw_raw":
        out = convert_unsw_raw(df)  # headerless raw UNSW-NB15 (IP in col 0)
    elif fmt == "cicids":
        out = convert_cicids(df)
    else:
        out = convert_generic(df)

    return out, labels


# ─────────────────────────────────────────────────────────────
# LIVE FLOW AGGREGATOR (for real-time packet capture)
# ─────────────────────────────────────────────────────────────
class LiveFlowAggregator:
    """
    Aggregates individual Scapy packets into flow-level feature records
    compatible with the UNSW-NB15 feature contract.

    A "flow" is defined by the 5-tuple: (src_ip, dst_ip, sport, dport, proto)
    Flows are emitted after TIMEOUT seconds of inactivity or MAX_PKTS packets.
    """
    TIMEOUT  = 5.0    # seconds of inactivity before flow is emitted
    MAX_PKTS = 100    # max packets per flow

    def __init__(self, emit_callback):
        """
        Args:
            emit_callback: callable(flow_df) called when a complete flow is ready
        """
        self._flows   = {}
        self._emit_cb = emit_callback
        self._last_gc = time.time()

    def process_packet(self, pkt) -> None:
        """Add a single Scapy packet to the appropriate flow."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
                return
            ip   = pkt[IP]  if pkt.haslayer(IP)  else pkt[IPv6]
            src  = ip.src
            dst  = ip.dst
            ttl  = getattr(ip, "ttl", 64)
            now  = time.time()

            if pkt.haslayer(TCP):
                tcp    = pkt[TCP]
                proto  = "tcp"
                sport  = tcp.sport
                dport  = tcp.dport
                flags  = str(tcp.flags)
                win    = tcp.window
                payload= bytes(tcp.payload)
            elif pkt.haslayer(UDP):
                udp    = pkt[UDP]
                proto  = "udp"
                sport  = udp.sport
                dport  = udp.dport
                flags  = ""
                win    = 0
                payload= bytes(udp.payload)
            elif pkt.haslayer(ICMP):
                proto  = "icmp"
                sport  = 0
                dport  = 0
                flags  = ""
                win    = 0
                payload= bytes(pkt[ICMP].payload)
            else:
                return

            key = (src, dst, sport, dport, proto)
            pkt_len = len(pkt)

            if key not in self._flows:
                self._flows[key] = self._new_flow(src, dst, sport, dport, proto, now, ttl)

            flow = self._flows[key]
            flow["spkts"]  += 1
            flow["sbytes"] += pkt_len
            flow["_times"].append(now)
            flow["_last"]   = now
            if win > 0:
                flow["swin"] = win
            if flags:
                if "S" in flags: flow["synack"] += 1
                if "A" in flags: flow["ackdat"] += 1
                if "F" in flags: flow["_fins"]  += 1
                if "R" in flags: flow["_rsts"]  += 1

            # Emit if flow complete
            if (flow["spkts"] >= self.MAX_PKTS or
                    now - flow["_start"] >= self.TIMEOUT):
                self._emit(key, flow)

            # Periodic garbage collection
            if now - self._last_gc > 10:
                self._gc(now)

        except Exception:
            pass

    def _new_flow(self, src, dst, sport, dport, proto, now, ttl) -> dict:
        return {
            "dur":0.0,"proto":proto,"service":_port_to_service(dport),"state":"CON",
            "spkts":0,"dpkts":0,"sbytes":0,"dbytes":0,"rate":0.0,
            "sttl":ttl,"dttl":0,"sload":0.0,"dload":0.0,"sloss":0,"dloss":0,
            "sinpkt":0.0,"dinpkt":0.0,"sjit":0.0,"djit":0.0,
            "swin":0,"stcpb":0,"dtcpb":0,"dwin":0,"tcprtt":0.0,
            "synack":0,"ackdat":0,"smean":0.0,"dmean":0.0,
            "trans_depth":0,"response_body_len":0,
            "ct_srv_src":1,"ct_state_ttl":0,"ct_dst_ltm":1,
            "ct_src_dport_ltm":1,"ct_dst_sport_ltm":1,"ct_dst_src_ltm":1,
            "is_ftp_login":1 if dport==21 else 0,
            "ct_ftp_cmd":0,"ct_flw_http_mthd":0,"ct_src_ltm":1,"ct_srv_dst":1,
            "is_sm_ips_ports":1 if (src==dst) else 0,
            # Internal tracking (not model features)
            "_start":now,"_last":now,"_times":[],"_fins":0,"_rsts":0,
            "_srcip":src,"_dstip":dst,"_sport":sport,"_dport":dport,
        }

    def _emit(self, key, flow) -> None:
        """Finalize flow statistics and emit to callback."""
        times  = flow["_times"]
        dur    = flow["_last"] - flow["_start"] if len(times) > 1 else 0.001
        flow["dur"] = round(dur, 6)

        if len(times) > 1:
            iats = np.diff(times)
            flow["sinpkt"] = round(float(np.mean(iats)), 6)
            flow["sjit"]   = round(float(np.std(iats)), 6)

        if dur > 0:
            flow["rate"]  = round((flow["spkts"] + flow["dpkts"]) / dur, 2)
            flow["sload"] = round(flow["sbytes"] * 8 / dur, 2)
            flow["dload"] = round(flow["dbytes"] * 8 / dur, 2)

        if flow["spkts"] > 0:
            flow["smean"] = round(flow["sbytes"] / flow["spkts"], 2)
        if flow["dpkts"] > 0:
            flow["dmean"] = round(flow["dbytes"] / flow["dpkts"], 2)

        # State encoding
        if flow["_fins"] > 0:   flow["state"] = "FIN"
        elif flow["_rsts"] > 0: flow["state"] = "REJ"

        # Clean internal fields
        clean = {k: v for k, v in flow.items() if not k.startswith("_")}
        df = pd.DataFrame([clean])[UNSW_FEATURES]
        df = _clean(df)

        # Add metadata for the alert record
        df.attrs["srcip"]  = flow["_srcip"]
        df.attrs["dstip"]  = flow["_dstip"]
        df.attrs["sport"]  = flow["_sport"]
        df.attrs["dport"]  = flow["_dport"]

        try:
            self._emit_cb(df)
        except Exception:
            pass

        del self._flows[key]

    def _gc(self, now: float) -> None:
        """Emit timed-out flows."""
        expired = [k for k, f in self._flows.items()
                   if now - f["_last"] > self.TIMEOUT]
        for k in expired:
            self._emit(k, self._flows[k])
        self._last_gc = now

    def flush_all(self) -> None:
        """Force emit all pending flows (on capture stop)."""
        now = time.time()
        for k in list(self._flows.keys()):
            self._emit(k, self._flows[k])


# ─────────────────────────────────────────────────────────────
# PCAP READER
# ─────────────────────────────────────────────────────────────
def read_pcap_as_flows(pcap_path: str, max_flows: int = 5000) -> pd.DataFrame:
    """
    Read a PCAP file and return a DataFrame of flow-level features.

    Args:
        pcap_path: Path to .pcap or .pcapng file
        max_flows: Maximum number of flows to extract

    Returns:
        DataFrame with UNSW-NB15 42 features
    """
    try:
        from scapy.all import rdpcap, PcapReader
    except ImportError:
        raise RuntimeError("Scapy not available. Install: pip install scapy")

    flows = []

    def collect(df):
        flows.append(df)

    aggregator = LiveFlowAggregator(emit_callback=collect)

    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                if len(flows) >= max_flows:
                    break
                aggregator.process_packet(pkt)
        aggregator.flush_all()
    except Exception as ex:
        raise RuntimeError(f"PCAP read error: {ex}")

    if not flows:
        return pd.DataFrame(columns=UNSW_FEATURES)

    return pd.concat(flows, ignore_index=True)


# ─────────────────────────────────────────────────────────────
# CSV SMART READER
# ─────────────────────────────────────────────────────────────
def read_csv_universal(path: str, max_rows: int = 100_000) -> Tuple[pd.DataFrame, Optional[str]]:
    """
    Read ANY CSV file, detect its format, and return:
        (feature_df in UNSW contract, detected_label_column_or_None)
    """
    # Try to detect encoding
    df = pd.read_csv(path, nrows=max_rows, low_memory=False)
    df.columns = df.columns.str.strip()

    # Detect label column
    label_col = None
    for candidate in ["attack_cat","label","Label","class","Class","Category","category",
                       "Attack","attack","tag","Tag"]:
        if candidate in df.columns:
            label_col = candidate
            break

    fmt = detect_dataset_format(df)
    features, labels = bridge(df, label_col)
    return features, label_col
