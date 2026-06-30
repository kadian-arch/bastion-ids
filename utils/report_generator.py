"""
BASTION IDS — PROFESSIONAL FORENSIC REPORT GENERATOR  v3.0
===========================================================
Generates comprehensive forensic session reports in three formats:
  · JSON  — machine-readable full data export
  · HTML  — professional dark-theme web report (styled from reference)
  · PDF   — print-ready forensic document (ReportLab)

Design philosophy: match/exceed the reference ForensicsAI report quality.
Color palette from reference: bg=#0f172a, surface=#1e293b, accent=#3b82f6,
danger=#ef4444, warn=#f59e0b, ok=#22c55e, purple=#8b5cf6.
"""

import os, json, html as html_mod
from datetime import datetime
from typing   import List, Dict, Any, Optional

from reportlab.lib             import colors
from reportlab.lib.pagesizes   import A4
from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units       import mm
from reportlab.lib.enums       import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus        import (SimpleDocTemplate, Paragraph, Spacer,
                                       Table, TableStyle, HRFlowable,
                                       PageBreak, KeepTogether)

try:
    from utils.mitre_mappings import get_attack_mapping, build_mitre_summary
except ImportError:
    from mitre_mappings import get_attack_mapping, build_mitre_summary

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# SEVERITY / THEME HELPERS
# ─────────────────────────────────────────────────────────────
SEV_CSS = {
    "CRITICAL": ("rgba(220,38,38,.15)", "#f87171", "rgba(220,38,38,.3)"),
    "HIGH":     ("rgba(245,158,11,.15)", "#fbbf24", "rgba(245,158,11,.3)"),
    "MEDIUM":   ("rgba(37,99,235,.15)",  "#60a5fa", "rgba(37,99,235,.3)"),
    "LOW":      ("rgba(34,197,94,.12)",  "#4ade80", "rgba(34,197,94,.25)"),
    "INFO":     ("rgba(100,116,139,.1)", "#94a3b8", "rgba(100,116,139,.2)"),
}

SEV_COLOR_RL = {
    "CRITICAL": colors.HexColor("#f87171"),
    "HIGH":     colors.HexColor("#fbbf24"),
    "MEDIUM":   colors.HexColor("#60a5fa"),
    "LOW":      colors.HexColor("#4ade80"),
    "INFO":     colors.HexColor("#94a3b8"),
}

THREAT_LEVEL_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f59e0b",
    "MEDIUM":   "#3b82f6",
    "LOW":      "#22c55e",
    "CLEAR":    "#22c55e",
}

ATTACK_INTEL = {
    "Exploits": {
        "severity": "CRITICAL",
        "desc": "Targeted exploitation of known software or protocol vulnerabilities to gain unauthorised access, execute arbitrary code, or escalate privileges.",
        "mitre": ["T1190 · Exploit Public-Facing Application", "T1068 · Exploitation for Privilege Escalation"],
        "ioc": ["Irregular packet sequences targeting specific ports", "Protocol anomalies in connection payloads"],
        "rem": ["Apply vendor patches immediately", "Isolate affected systems", "Deploy WAF rules"],
    },
    "DoS": {
        "severity": "HIGH",
        "desc": "Denial-of-service attacks designed to exhaust target resources, degrade availability, or cause complete service outages.",
        "mitre": ["T1498 · Network Denial of Service", "T1499 · Endpoint Denial of Service"],
        "ioc": ["High packet rate from single source", "ICMP/UDP flood traffic patterns"],
        "rem": ["Enable DDoS protection at perimeter", "Rate-limit suspicious source IPs"],
    },
    "Reconnaissance": {
        "severity": "MEDIUM",
        "desc": "Systematic scanning and probing of network infrastructure to map attack surface, identify live hosts, open ports, and running services.",
        "mitre": ["T1046 · Network Service Discovery", "T1595 · Active Scanning"],
        "ioc": ["Sequential port scan pattern", "High ratio of RST/SYN-only connections"],
        "rem": ["Implement network segmentation", "Deploy honeypots for early detection"],
    },
    "Backdoor": {
        "severity": "CRITICAL",
        "desc": "Covert persistent access mechanisms allowing adversaries to maintain long-term footholds and exfiltrate data without detection.",
        "mitre": ["T1547 · Boot or Logon Autostart Execution", "T1571 · Non-Standard Port"],
        "ioc": ["Persistent outbound connections to unusual IPs", "Recurring connections at regular intervals"],
        "rem": ["Isolate compromised hosts immediately", "Full disk forensic analysis required"],
    },
    "Fuzzers": {
        "severity": "MEDIUM",
        "desc": "Automated fuzzing attacks sending malformed or unexpected inputs to discover software vulnerabilities and crashes.",
        "mitre": ["T1595 · Active Scanning", "T1592 · Gather Victim Host Information"],
        "ioc": ["Malformed packet sequences", "High volume of protocol error responses"],
        "rem": ["Patch identified vulnerabilities", "Implement input validation on all exposed services"],
    },
    "Generic": {
        "severity": "HIGH",
        "desc": "General-purpose attack traffic not fitting a specific category, including mixed attack vectors and unclassified malicious flows.",
        "mitre": ["T1190 · Exploit Public-Facing Application", "T1133 · External Remote Services"],
        "ioc": ["Anomalous traffic patterns", "High confidence ML/signature detection"],
        "rem": ["Review firewall rules", "Increase logging verbosity on affected hosts"],
    },
    "Shellcode": {
        "severity": "CRITICAL",
        "desc": "Binary code injection delivered through network flows to execute directly in target process memory space.",
        "mitre": ["T1055 · Process Injection", "T1059 · Command and Scripting Interpreter"],
        "ioc": ["Non-ASCII payload sequences", "NOP sled patterns in packet payloads"],
        "rem": ["Enable exploit mitigation controls (DEP, ASLR)", "Engage incident response immediately"],
    },
    "Worms": {
        "severity": "CRITICAL",
        "desc": "Self-propagating malware that spreads across networks by exploiting vulnerabilities on remote systems.",
        "mitre": ["T1210 · Exploitation of Remote Services", "T1046 · Network Service Discovery"],
        "ioc": ["Lateral port scanning from internal hosts", "Repeated connection attempts to peer IPs"],
        "rem": ["Block SMB/port 445 at perimeter", "Patch MS17-010 immediately on all hosts"],
    },
    "Analysis": {
        "severity": "MEDIUM",
        "desc": "Network analysis and traffic capture activities indicating adversary reconnaissance or adversary-in-the-middle positioning.",
        "mitre": ["T1040 · Network Sniffing", "T1557 · Adversary-in-the-Middle"],
        "ioc": ["Unusual promiscuous mode detection", "ARP cache poisoning indicators"],
        "rem": ["Enable encrypted communications", "Deploy 802.1X port authentication"],
    },
}


def _sev_badge(sev: str) -> str:
    bg, col, border = SEV_CSS.get(sev.upper(), SEV_CSS["INFO"])
    return (f'<span style="display:inline-block;padding:2px 9px;border-radius:99px;'
            f'font-size:10px;font-weight:700;text-transform:uppercase;'
            f'background:{bg};color:{col};border:1px solid {border}">{sev}</span>')


def _compute_severity(verdict: str, confidence: float) -> str:
    v = verdict.upper()
    if any(k in v for k in ("CRITICAL","SHELL","BACKDOOR","WORM","C2","ZERO")):
        return "CRITICAL"
    if any(k in v for k in ("HIGH","EXPLOIT","DOS","DDOS","SMB")):
        return "HIGH"
    if confidence >= 0.90:
        return "HIGH"
    if confidence >= 0.75:
        return "MEDIUM"
    if verdict.upper() in ("NORMAL", "BENIGN", "BASTION_CLEAN"):
        return "INFO"
    return "MEDIUM"


def _threat_level(sev_counts: dict, total: int) -> str:
    if sev_counts.get("CRITICAL", 0) > 0 or sev_counts.get("HIGH", 0) >= 5:
        return "CRITICAL"
    if sev_counts.get("HIGH", 0) > 0:
        return "HIGH"
    if sev_counts.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    if total > 0:
        return "LOW"
    return "CLEAR"


def _build_recommendations(attack_types: dict, sev_counts: dict) -> List[Dict]:
    recs = []
    at = {k.upper(): v for k, v in attack_types.items()}
    if any(k in at for k in ("DOS","DDOS","ICMP FLOOD")):
        recs.append({"priority": "CRITICAL", "category": "DDoS Mitigation",
            "action": "Deploy rate limiting and upstream traffic scrubbing. Enable DDoS protection on perimeter firewall.",
            "tools": ["Cloudflare DDoS Shield", "AWS Shield", "Arbor Networks"]})
    if any("BRUTE" in k or "RDP" in k or "SSH" in k for k in at):
        recs.append({"priority": "HIGH", "category": "Brute Force Protection",
            "action": "Implement account lockout after 5 failed attempts. Enforce MFA on all remote access (RDP, SSH, VPN).",
            "tools": ["Microsoft Authenticator", "Duo Security", "Fail2Ban"]})
    if any("EXPLOIT" in k or "SHELL" in k for k in at):
        recs.append({"priority": "HIGH", "category": "Patch Management",
            "action": "Immediately audit and patch all internet-facing services. Deploy a Web Application Firewall.",
            "tools": ["Qualys VMDR", "Tenable Nessus", "ModSecurity WAF"]})
    if any("SCAN" in k or "RECON" in k for k in at):
        recs.append({"priority": "MEDIUM", "category": "Network Segmentation",
            "action": "Implement network segmentation to limit lateral movement. Deploy honeypots.",
            "tools": ["Cisco ISE", "Palo Alto NGFW", "Honeyd Honeypot"]})
    if any("SMB" in k or "WORM" in k for k in at):
        recs.append({"priority": "CRITICAL", "category": "Lateral Movement Prevention",
            "action": "Disable SMBv1. Block SMB (port 445) at network perimeter. Isolate affected hosts and verify MS17-010 patches.",
            "tools": ["Microsoft MSRT", "Nmap smb-vuln-ms17-010", "Carbon Black"]})
    if any("BACKDOOR" in k or "C2" in k or "BOT" in k for k in at):
        recs.append({"priority": "CRITICAL", "category": "Incident Response",
            "action": "IMMEDIATE: Isolate affected hosts. Initiate full forensic investigation. Reset all credentials.",
            "tools": ["Volatility (memory forensics)", "Autopsy", "TheHive IR Platform"]})
    if any("SUSPICIOUS" in k or "ZERO" in k or "ANOMALY" in k for k in at):
        recs.append({"priority": "HIGH", "category": "Zero-Day Response",
            "action": "Capture full packet dump for analysis. Submit samples to threat intelligence platforms.",
            "tools": ["VirusTotal", "AlienVault OTX", "MISP Threat Sharing"]})
    if not recs:
        recs.append({"priority": "LOW", "category": "Continued Monitoring",
            "action": "No high-severity threats detected. Continue monitoring with current settings.",
            "tools": ["Bastion IDS Live Monitor", "Network Traffic Analyzer"]})
    return recs


# ─────────────────────────────────────────────────────────────
# DATA BUILDER
# ─────────────────────────────────────────────────────────────
def build_report_data(alerts: List[Dict], session_meta: Dict) -> Dict:
    now = datetime.now()
    layer_counts = {"SIGNATURE_DB": 0, "ML_ENSEMBLE": 0, "DL-SENSEI": 0,
                    "DL_LAYER": 0, "ANOMALY": 0, "NORMAL": 0, "OTHER": 0}
    sev_counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    attack_types = {}
    top_sources  = {}
    top_targets  = {}
    enriched     = []

    # Cache MITRE lookups — many alerts share the same verdict string.
    # Without caching, get_attack_mapping() is called O(N) times; with caching
    # it's called once per unique verdict.  At 2 000 alerts there are typically
    # fewer than 30 unique verdicts, so this cuts lookup work by ~98%.
    _mitre_cache: Dict[str, Any] = {}

    for a in alerts:
        verdict = str(a.get("verdict", "UNKNOWN"))
        conf    = float(a.get("confidence", 0))
        source  = str(a.get("source_engine", a.get("engine", "OTHER")))
        src_ip  = str(a.get("srcip",  a.get("Source", "?")))
        dst_ip  = str(a.get("dstip",  a.get("Destination", "?")))
        sev     = _compute_severity(verdict, conf)

        bucket  = source if source in layer_counts else "OTHER"
        layer_counts[bucket] = layer_counts.get(bucket, 0) + 1
        sev_counts[sev]      = sev_counts.get(sev, 0) + 1
        attack_types[verdict] = attack_types.get(verdict, 0) + 1
        top_sources[src_ip]  = top_sources.get(src_ip, 0) + 1
        top_targets[dst_ip]  = top_targets.get(dst_ip, 0) + 1

        if verdict not in _mitre_cache:
            _mitre_cache[verdict] = get_attack_mapping(verdict)
        mitre = _mitre_cache[verdict]
        pt    = mitre.get("primary_technique") or {}
        enriched.append({**a, "severity": sev,
            "mitre_technique_id":   pt.get("id", "N/A"),
            "mitre_technique_name": pt.get("name", "Unknown"),
            "mitre_tactic":         pt.get("tactic", "Unknown"),
            "mitre_description":    mitre.get("description", ""),
            "kill_chain":           mitre.get("kill_chain", "Unknown"),
            "ioc_list":             mitre.get("ioc", []),
            "mitigations":          pt.get("mitigations", []),
        })

    # Build per-attack-type severity (highest severity seen for that verdict)
    # Used in the category distribution table so it matches the per-alert counters.
    _SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    attack_type_sev: Dict[str, str]   = {}   # verdict → highest severity
    attack_type_mitre: Dict[str, str] = {}   # verdict → MITRE tags string
    for a in enriched:
        v   = str(a.get("verdict", "UNKNOWN"))
        sev = a.get("severity", "MEDIUM")
        prev = attack_type_sev.get(v, "INFO")
        if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(prev, 0):
            attack_type_sev[v] = sev
        if v not in attack_type_mitre:
            mid  = a.get("mitre_technique_id", "")
            mnam = a.get("mitre_technique_name", "")
            if mid and mid != "N/A":
                attack_type_mitre[v] = f"{mid} · {mnam}" if mnam and mnam != "Unknown" else mid

    mitre_summary  = build_mitre_summary(enriched)
    overall_threat = _threat_level(sev_counts, len(alerts))
    top_sources    = sorted(top_sources.items(), key=lambda x: -x[1])[:10]
    top_targets    = sorted(top_targets.items(), key=lambda x: -x[1])[:10]
    top_attacks    = sorted(attack_types.items(), key=lambda x: -x[1])[:10]
    recs           = _build_recommendations(attack_types, sev_counts)

    # File-friendly session label for naming
    src_raw   = str(session_meta.get("source", "session"))
    src_short = os.path.splitext(os.path.basename(src_raw))[0][:24].replace(" ","_")
    report_id = f"BASTION-IDS_{now.strftime('%Y-%m-%d_%H-%M-%S')}_{src_short}"

    return {
        "report_id":      report_id,
        "generated_at":   now.isoformat(),
        "engine_version": session_meta.get("engine_version", "Bastion IDS v2.0"),
        "session":        session_meta,
        "summary": {
            "total_alerts":        len(alerts),          # sample count (sev_counts derive from this)
            "total_flows_in_session": int(session_meta.get("total_flows") or len(alerts)),
            "threat_level":        overall_threat,
            "severity_counts":     sev_counts,
            "layer_attribution":   layer_counts,
            "unique_attack_types": len(attack_types),
            "unique_source_ips":   len(set(a.get("srcip","") for a in alerts)),
            "benign_count":        sev_counts.get("INFO", 0),
            "attack_type_sev":     attack_type_sev,
            "attack_type_mitre":   attack_type_mitre,
        },
        "top_attacks":    top_attacks,
        "top_sources":    top_sources,
        "top_targets":    top_targets,
        "mitre_summary":  mitre_summary,
        "alerts":         enriched,
        "recommendations": recs,
        "chain_of_custody": {
            "analyst":        "Bastion IDS Automated System",
            "report_time":    now.isoformat(),
            "data_source":    session_meta.get("source", "Unknown"),
            "engine_version": session_meta.get("engine_version", "Bastion IDS v2.0"),
            "integrity":      "SHA-256 verification recommended on raw capture file",
            "classification": "CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY",
        },
    }


# ─────────────────────────────────────────────────────────────
# JSON EXPORT
# ─────────────────────────────────────────────────────────────
def export_json(report_data: Dict, filename: str) -> str:
    path = os.path.join(REPORTS_DIR, filename + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)
    return path


# ─────────────────────────────────────────────────────────────
# HTML EXPORT  — Carbon Intelligence premium dark theme
# ─────────────────────────────────────────────────────────────
def export_html(report_data: Dict, filename: str) -> str:
    path = os.path.join(REPORTS_DIR, filename + ".html")
    r    = report_data
    s    = r["summary"]
    m    = r["mitre_summary"]
    tl   = s["threat_level"]
    tl_c = THREAT_LEVEL_COLOR.get(tl, "#ef4444")

    # ── KPI counts ──
    sample_size  = s["total_alerts"]
    total_flows  = s.get("total_flows_in_session") or sample_size
    _scale       = total_flows / max(sample_size, 1)
    threats_raw  = sample_size - s["severity_counts"].get("INFO", 0)
    total        = total_flows
    threats      = round(threats_raw * _scale)
    # Benign = flows that were processed but NOT flagged as threats.
    # For live capture sessions, benign_count is derived from packets_processed
    # (stored in session meta), not from INFO alerts (which are never generated
    # in live-capture mode).  Fall back to 0 if that data isn't available.
    session_mode = str(r.get("session", {}).get("session_mode", "")).upper()
    pkts_proc    = int(r.get("session", {}).get("packets_processed", 0))
    if session_mode in ("LIVE_CAPTURE", "LIVE") and pkts_proc > threats:
        benign = pkts_proc - threats
    elif session_mode in ("LIVE_CAPTURE", "LIVE"):
        benign = None   # unknown — can't determine from alerts alone
    else:
        benign = total_flows - threats

    high         = round((s["severity_counts"].get("CRITICAL", 0) +
                          s["severity_counts"].get("HIGH", 0)) * _scale)
    avg_conf     = (sum(float(a.get("confidence", 0)) for a in r["alerts"]) /
                   max(len(r["alerts"]), 1) * 100)

    # Per-attack-type severity and MITRE (computed from actual alerts, not static table)
    at_sev   = s.get("attack_type_sev",   {})
    at_mitre = s.get("attack_type_mitre", {})

    # ── Threat distribution table rows ──
    dist_rows = ""
    for at, cnt in r["top_attacks"]:
        # Severity: use per-attack severity from enriched alerts (accurate),
        # fall back to ATTACK_INTEL static table, then to MEDIUM.
        info   = ATTACK_INTEL.get(str(at), {})
        sev    = at_sev.get(str(at)) or info.get("severity", "MEDIUM")
        bg, col, brd = SEV_CSS.get(sev, SEV_CSS["MEDIUM"])
        pct_t  = f"{cnt/max(total,1)*100:.1f}%"
        pct_th = f"{cnt/max(threats,1)*100:.1f}%" if threats > 0 else "N/A"
        # MITRE: prefer per-alert mapping (uses actual get_attack_mapping()),
        # fall back to static ATTACK_INTEL table, then to "Pending analysis".
        mitre  = at_mitre.get(str(at)) or " · ".join(info.get("mitre", [])[:2]) or "Pending analysis"
        dist_rows += f"""
        <tr>
          <td><b>{html_mod.escape(str(at))}</b></td>
          <td>{cnt:,}</td>
          <td>{pct_t}</td>
          <td>{pct_th}</td>
          <td><span style="display:inline-block;padding:2px 9px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase;background:{bg};color:{col};border:1px solid {brd}">{sev}</span></td>
          <td style="font-size:11px;color:var(--muted)">{html_mod.escape(mitre)}</td>
        </tr>"""

    # ── Attack intel cards ──
    attack_cards = ""
    for at, cnt in r["top_attacks"][:6]:
        info  = ATTACK_INTEL.get(str(at), {})
        sev   = info.get("severity", "MEDIUM")
        bg, col, brd = SEV_CSS.get(sev, SEV_CSS["MEDIUM"])
        iocs  = "".join(f"<li>{html_mod.escape(i)}</li>" for i in info.get("ioc", [])[:3])
        rems  = "".join(
            f'<li style="display:flex;gap:10px;align-items:flex-start;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px;color:var(--muted)">'
            f'<span style="flex-shrink:0;width:20px;height:20px;border-radius:50%;background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--accent)">{idx+1}</span>'
            f'<span>{html_mod.escape(rem)}</span></li>'
            for idx, rem in enumerate(info.get("rem", [])[:3]))
        mitre_tags = "".join(
            f'<span style="background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.2);border-radius:4px;padding:1px 7px;font-size:10px;color:#93c5fd;margin:2px">{html_mod.escape(t)}</span>'
            for t in info.get("mitre", [])[:2])
        attack_cards += f"""
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:16px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px">
            <div>
              <span style="font-size:15px;font-weight:700;color:#fff">{html_mod.escape(str(at))}</span>
              <span style="color:var(--muted);font-size:12px;margin-left:10px">{cnt:,} detections</span>
            </div>
            <span style="display:inline-block;padding:2px 9px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase;background:{bg};color:{col};border:1px solid {brd}">{sev}</span>
          </div>
          <p style="color:var(--muted);font-size:12px;margin-bottom:14px;line-height:1.6">{html_mod.escape(info.get('desc',''))}</p>
          <div style="margin-bottom:10px">{mitre_tags}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
            <div>
              <h4 style="font-size:10px;font-weight:700;color:var(--faint);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Indicators of Compromise</h4>
              <ul style="list-style:none;padding:0">{''.join(f'<li style="font-size:11px;color:var(--muted);padding:2px 0;padding-left:14px;position:relative">&#8250; {html_mod.escape(i)}</li>' for i in info.get("ioc",[]))}</ul>
            </div>
            <div>
              <h4 style="font-size:10px;font-weight:700;color:var(--faint);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Remediation Steps</h4>
              <ul style="list-style:none;padding:0">{rems}</ul>
            </div>
          </div>
        </div>"""

    # ── Alert log table rows ──
    alert_rows = ""
    for a in r["alerts"][:200]:
        sev   = a.get("severity", "MEDIUM")
        bg, col, brd = SEV_CSS.get(sev, SEV_CSS["MEDIUM"])
        conf  = float(a.get("confidence", 0)) * 100
        ts    = str(a.get("timestamp", "?"))[:19]
        src   = html_mod.escape(str(a.get("srcip",  a.get("Source", "?"))))
        dst   = html_mod.escape(str(a.get("dstip",  a.get("Destination", "?"))))
        verd  = html_mod.escape(str(a.get("verdict", "?")))[:60]
        tech  = html_mod.escape(str(a.get("mitre_technique_id", "N/A")))
        eng   = html_mod.escape(str(a.get("source_engine", "?")))
        alert_rows += f"""
        <tr>
          <td style="color:var(--muted);font-size:11px">{ts}</td>
          <td><span style="display:inline-block;padding:2px 9px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase;background:{bg};color:{col};border:1px solid {brd}">{sev}</span></td>
          <td style="font-weight:600;color:#e2e8f0;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{verd}</td>
          <td style="font-family:monospace;color:#f87171;font-weight:600">{src}</td>
          <td style="font-family:monospace;color:#60a5fa">{dst}</td>
          <td style="font-size:11px"><span style="background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.2);border-radius:4px;padding:1px 7px;color:#93c5fd">{tech}</span></td>
          <td style="color:var(--ok);font-weight:700;font-family:monospace">{conf:.1f}%</td>
          <td style="color:var(--muted);font-size:11px">{eng}</td>
        </tr>"""

    # ── Detection layer probability bars ──
    la = s["layer_attribution"]
    layer_bars = ""
    layer_defs = [
        ("L1 · Signature Engine",  la.get("SIGNATURE_DB", 0),           "#ef4444"),
        ("L2 · ML Ensemble",       la.get("ML_ENSEMBLE", 0),            "#3b82f6"),
        ("L3 · Deep Learning",     la.get("DL-SENSEI", 0)+la.get("DL_LAYER", 0), "#8b5cf6"),
        ("L4 · Anomaly Sentinel",  la.get("ANOMALY", 0),                "#f59e0b"),
    ]
    for lbl, cnt, col in layer_defs:
        pct = min(100, int(cnt / max(total, 1) * 100))
        layer_bars += f"""
        <div style="display:flex;align-items:center;gap:8px;padding:3px 0;font-size:10px;margin-bottom:8px">
          <div style="width:160px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0">{lbl}</div>
          <div style="flex:1;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden">
            <div style="height:100%;border-radius:3px;background:{col};width:{pct}%"></div>
          </div>
          <div style="width:60px;text-align:right;color:var(--faint);font-family:monospace">{cnt:,} ({pct}%)</div>
        </div>"""

    # ── Recommendation cards ──
    rec_cards = ""
    pri_col = {"CRITICAL": "#ef4444", "HIGH": "#f59e0b", "MEDIUM": "#3b82f6", "LOW": "#22c55e"}
    for i, rec in enumerate(r.get("recommendations", [])):
        pc = pri_col.get(rec["priority"], "#94a3b8")
        tools = ", ".join(rec.get("tools", []))
        rec_cards += f"""
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px 24px;margin-bottom:14px;border-left:4px solid {pc}">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
            <span style="display:inline-block;padding:2px 9px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase;background:{pc}22;color:{pc};border:1px solid {pc}44">{rec['priority']}</span>
            <span style="font-size:13px;font-weight:700;color:#e2e8f0">{html_mod.escape(rec['category'])}</span>
          </div>
          <p style="color:var(--muted);font-size:13px;line-height:1.7;margin-bottom:8px">{html_mod.escape(rec['action'])}</p>
          <p style="color:var(--accent);font-size:12px"><b style="color:var(--faint)">Recommended Tools:</b> {html_mod.escape(tools)}</p>
        </div>"""

    # ── MITRE table ──
    mitre_rows = ""
    for tactic, count in sorted(m.get("tactics_observed", {}).items(), key=lambda x: -x[1]):
        width = min(100, int(count / max(total, 1) * 500))
        mitre_rows += f"""
        <tr>
          <td style="color:#e2e8f0;font-weight:600">{html_mod.escape(tactic)}</td>
          <td>
            <div style="background:rgba(255,255,255,.06);border-radius:3px;height:6px;width:100%">
              <div style="background:var(--accent);width:{width}%;height:6px;border-radius:3px"></div>
            </div>
          </td>
          <td style="color:var(--accent);font-weight:700;text-align:right;font-family:monospace">{count}</td>
        </tr>"""

    # ── Source IP rows ──
    src_rows = ""
    for ip, cnt in r["top_sources"]:
        risk = "CRITICAL" if cnt > 50 else "HIGH" if cnt > 10 else "MEDIUM" if cnt > 3 else "LOW"
        bg, col, brd = SEV_CSS.get(risk, SEV_CSS["LOW"])
        src_rows += f"""
        <tr>
          <td style="font-family:monospace;color:#f87171;font-weight:700">{html_mod.escape(str(ip))}</td>
          <td style="color:var(--accent);font-weight:700;font-family:monospace">{cnt:,}</td>
          <td style="font-family:monospace;font-size:11px;color:var(--muted)">{cnt/max(total,1)*100:.1f}%</td>
          <td><span style="display:inline-block;padding:2px 9px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase;background:{bg};color:{col};border:1px solid {brd}">{'High-volume attacker' if cnt>50 else 'Active threat source' if cnt>10 else 'Elevated activity' if cnt>3 else 'Low activity'}</span></td>
        </tr>"""

    # ── Target IP rows ──
    tgt_rows = ""
    for ip, cnt in r.get("top_targets", []):
        risk = "CRITICAL" if cnt > 50 else "HIGH" if cnt > 10 else "MEDIUM" if cnt > 3 else "LOW"
        bg, col, brd = SEV_CSS.get(risk, SEV_CSS["LOW"])
        tgt_rows += f"""
        <tr>
          <td style="font-family:monospace;color:#60a5fa;font-weight:700">{html_mod.escape(str(ip))}</td>
          <td style="color:var(--accent);font-weight:700;font-family:monospace">{cnt:,}</td>
          <td style="font-family:monospace;font-size:11px;color:var(--muted)">{cnt/max(total,1)*100:.1f}%</td>
          <td><span style="display:inline-block;padding:2px 9px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase;background:{bg};color:{col};border:1px solid {brd}">{'Heavily targeted' if cnt>50 else 'Frequent target' if cnt>10 else 'Moderate target' if cnt>3 else 'Low volume'}</span></td>
        </tr>"""

    # ── Attack timeline: group alerts by hour ──
    timeline_bars = ""
    try:
        from collections import Counter
        hour_counts: Counter = Counter()
        for a in r["alerts"]:
            ts = str(a.get("timestamp", ""))
            if len(ts) >= 13:
                h = ts[:13]   # "YYYY-MM-DDTHH" or "YYYY-MM-DD HH"
                hour_counts[h] += 1
        if hour_counts:
            sorted_hours = sorted(hour_counts.items())
            max_h = max(v for _, v in sorted_hours) if sorted_hours else 1
            for h, cnt in sorted_hours[-24:]:   # last 24 buckets
                label = h[11:] if len(h) > 10 else h
                pct   = int(cnt / max_h * 100)
                bar_c = "#ef4444" if pct > 70 else "#f59e0b" if pct > 30 else "#3b82f6"
                timeline_bars += f"""
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;font-size:10px">
                  <div style="width:36px;color:var(--faint);text-align:right;flex-shrink:0">{label[:5]}</div>
                  <div style="flex:1;background:rgba(255,255,255,.05);border-radius:2px;height:8px;overflow:hidden">
                    <div style="width:{pct}%;height:100%;background:{bar_c};border-radius:2px"></div>
                  </div>
                  <div style="width:40px;color:var(--muted);text-align:left;font-family:monospace">{cnt:,}</div>
                </div>"""
    except Exception:
        pass

    def _sec(accent: str, title: str, count_label: str) -> str:
        return f"""
        <div style="font-size:12px;font-weight:700;color:{accent};text-transform:uppercase;letter-spacing:1.5px;
                    border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:16px;display:flex;align-items:center;gap:8px">
          <span style="display:block;width:3px;height:14px;background:{accent};border-radius:2px;flex-shrink:0"></span>
          {title}
          <span style="margin-left:auto;font-size:10px;font-weight:400;color:var(--faint);font-family:monospace">{count_label}</span>
        </div>"""

    # ── New premium HTML (Carbon Intelligence theme) ──────────────────────
    # Color constants for easy reference inside f-strings
    _C = {
        "bg":      "#07101F",
        "surf":    "#0C1929",
        "card":    "#111F33",
        "border":  "#1C3050",
        "accent":  "#22D3EE",
        "accent2": "#0E7490",
        "danger":  "#F43F5E",
        "warn":    "#FB923C",
        "ok":      "#34D399",
        "purple":  "#A78BFA",
        "text":    "#E8F4FF",
        "muted":   "#7A98B8",
        "faint":   "#2E4560",
        "dim":     "#1A3050",
    }

    SEV_PILL_NEW = {
        "CRITICAL": ("rgba(244,63,94,.14)", "#F87171", "rgba(244,63,94,.3)"),
        "HIGH":     ("rgba(251,146,60,.13)", "#FBB975", "rgba(251,146,60,.3)"),
        "MEDIUM":   ("rgba(34,211,238,.12)", "#67E8F9", "rgba(34,211,238,.28)"),
        "LOW":      ("rgba(52,211,153,.12)", "#6EE7B7", "rgba(52,211,153,.28)"),
        "INFO":     ("rgba(122,152,184,.1)", "#94B4C8", "rgba(122,152,184,.2)"),
    }

    def _pill(sev: str, label: str = None) -> str:
        bg, col, brd = SEV_PILL_NEW.get(sev.upper(), SEV_PILL_NEW["INFO"])
        lbl = label or sev
        return (f'<span style="display:inline-block;padding:1px 8px;border-radius:99px;'
                f'font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;'
                f'background:{bg};color:{col};border:1px solid {brd}">{lbl}</span>')

    def _sh(icon: str, num: str, title: str, accent: str) -> str:
        """Section heading with left accent bar, icon, counter chip."""
        return (
            f'<div style="display:flex;align-items:center;gap:10px;'
            f'border-bottom:1px solid {_C["border"]};padding-bottom:10px;margin-bottom:18px">'
            f'<span style="display:block;width:3px;height:18px;background:{accent};'
            f'border-radius:2px;flex-shrink:0"></span>'
            f'<span style="font-size:10px;font-weight:700;color:{accent};'
            f'text-transform:uppercase;letter-spacing:1.8px">{icon} {num}</span>'
            f'<span style="font-size:14px;font-weight:700;color:{_C["text"]}">{title}</span>'
            f'</div>'
        )

    # ── Rebuild display vars using new pills ──
    dist_rows2 = ""
    for at, cnt in r["top_attacks"]:
        info   = ATTACK_INTEL.get(str(at), {})
        sev    = info.get("severity", "MEDIUM")
        pct_t  = f"{cnt/max(total,1)*100:.1f}%"
        pct_th = f"{cnt/max(threats,1)*100:.1f}%" if threats > 0 else "N/A"
        mitre  = " · ".join(info.get("mitre", ["N/A"])[:2])
        dist_rows2 += (
            f'<tr><td style="font-weight:600;color:{_C["text"]}">{html_mod.escape(str(at))}</td>'
            f'<td style="font-family:monospace;color:{_C["accent"]};font-weight:700">{cnt:,}</td>'
            f'<td style="color:{_C["muted"]}">{pct_t}</td>'
            f'<td style="color:{_C["muted"]}">{pct_th}</td>'
            f'<td>{_pill(sev)}</td>'
            f'<td style="font-size:11px;color:{_C["faint"]}">{html_mod.escape(mitre)}</td></tr>'
        )

    attack_cards2 = ""
    for at, cnt in r["top_attacks"][:6]:
        info  = ATTACK_INTEL.get(str(at), {})
        sev   = info.get("severity", "MEDIUM")
        bg, col, brd = SEV_PILL_NEW.get(sev, SEV_PILL_NEW["MEDIUM"])
        ioc_li = "".join(
            f'<li style="padding:3px 0 3px 14px;position:relative;font-size:11px;'
            f'color:{_C["muted"]};border-bottom:1px solid {_C["faint"]}20">'
            f'<span style="position:absolute;left:0;color:{_C["accent"]}">&#x276F;</span>'
            f'{html_mod.escape(i)}</li>'
            for i in info.get("ioc", [])[:3])
        rem_li = "".join(
            f'<li style="display:flex;gap:8px;align-items:flex-start;padding:4px 0;'
            f'border-bottom:1px solid {_C["faint"]}18;font-size:11px;color:{_C["muted"]}">'
            f'<span style="flex-shrink:0;width:18px;height:18px;border-radius:50%;'
            f'background:{_C["accent"]}18;border:1px solid {_C["accent"]}30;'
            f'display:flex;align-items:center;justify-content:center;'
            f'font-size:9px;font-weight:800;color:{_C["accent"]}">{idx+1}</span>'
            f'<span>{html_mod.escape(rem)}</span></li>'
            for idx, rem in enumerate(info.get("rem", [])[:3]))
        mitre_chips = "".join(
            f'<span style="background:{_C["accent"]}12;border:1px solid {_C["accent"]}22;'
            f'border-radius:4px;padding:1px 7px;font-size:10px;'
            f'color:{_C["accent"]};margin:2px 2px 0 0">{html_mod.escape(t)}</span>'
            for t in info.get("mitre", [])[:2])
        attack_cards2 += (
            f'<div style="background:{_C["card"]};border:1px solid {_C["border"]};'
            f'border-radius:10px;padding:20px;margin-bottom:14px;'
            f'border-top:2px solid {col}">'
            f'<div style="display:flex;align-items:center;justify-content:space-between;'
            f'margin-bottom:10px;flex-wrap:wrap;gap:8px">'
            f'<div><span style="font-size:15px;font-weight:700;color:{_C["text"]}">'
            f'{html_mod.escape(str(at))}</span>'
            f'<span style="color:{_C["muted"]};font-size:12px;margin-left:10px">'
            f'{cnt:,} detections</span></div>{_pill(sev)}</div>'
            f'<p style="color:{_C["muted"]};font-size:12px;margin-bottom:12px;line-height:1.6">'
            f'{html_mod.escape(info.get("desc",""))}</p>'
            f'<div style="margin-bottom:12px">{mitre_chips}</div>'
            f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">'
            f'<div><h4 style="font-size:10px;font-weight:700;color:{_C["faint"]};'
            f'text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">'
            f'Indicators of Compromise</h4><ul style="list-style:none;padding:0">{ioc_li}</ul></div>'
            f'<div><h4 style="font-size:10px;font-weight:700;color:{_C["faint"]};'
            f'text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">'
            f'Remediation Steps</h4><ul style="list-style:none;padding:0">{rem_li}</ul></div>'
            f'</div></div>'
        )

    alert_rows2 = ""
    for a in r["alerts"][:200]:
        sev   = a.get("severity", "MEDIUM")
        conf  = float(a.get("confidence", 0)) * 100
        ts    = str(a.get("timestamp", "?"))[:19]
        src   = html_mod.escape(str(a.get("srcip",  a.get("Source", "?"))))
        dst   = html_mod.escape(str(a.get("dstip",  a.get("Destination", "?"))))
        verd  = html_mod.escape(str(a.get("verdict", "?")))[:60]
        tech  = html_mod.escape(str(a.get("mitre_technique_id", "N/A")))
        eng   = html_mod.escape(str(a.get("source_engine", "?")))
        tact  = html_mod.escape(str(a.get("mitre_tactic", "")))[:20]
        alert_rows2 += (
            f'<tr><td style="color:{_C["muted"]};font-size:10px;font-family:monospace">{ts}</td>'
            f'<td>{_pill(sev)}</td>'
            f'<td style="font-weight:600;color:{_C["text"]};max-width:240px;'
            f'overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{verd}</td>'
            f'<td style="font-family:monospace;color:#F87171;font-size:11px">{src}</td>'
            f'<td style="font-family:monospace;color:#67E8F9;font-size:11px">{dst}</td>'
            f'<td><span style="background:{_C["accent"]}12;border:1px solid {_C["accent"]}22;'
            f'border-radius:4px;padding:1px 7px;font-size:10px;color:{_C["accent"]}">'
            f'{tech}</span></td>'
            f'<td style="color:{_C["ok"]};font-weight:700;font-family:monospace;font-size:11px">'
            f'{conf:.1f}%</td>'
            f'<td style="color:{_C["muted"]};font-size:10px">{eng}</td></tr>'
        )

    la2 = s["layer_attribution"]
    layer_bars2 = ""
    layer_defs2 = [
        ("L1  Signature Engine",  la2.get("SIGNATURE_DB", 0), _C["danger"]),
        ("L2  ML Ensemble",       la2.get("ML_ENSEMBLE", 0),  _C["accent"]),
        ("L3  Deep Learning",     la2.get("DL-SENSEI", 0)+la2.get("DL_LAYER", 0), _C["purple"]),
        ("L4  Anomaly Sentinel",  la2.get("ANOMALY", 0),      _C["warn"]),
        ("Benign / Cleared",      la2.get("NORMAL", 0),       _C["ok"]),
    ]
    for lbl, cnt, col in layer_defs2:
        pct = min(100, int(cnt / max(total, 1) * 100))
        layer_bars2 += (
            f'<div style="display:grid;grid-template-columns:170px 1fr 80px;'
            f'align-items:center;gap:10px;margin-bottom:10px">'
            f'<div style="font-size:10px;font-weight:600;color:{_C["muted"]};'
            f'font-family:monospace;letter-spacing:.3px">{lbl}</div>'
            f'<div style="height:6px;background:{_C["faint"]}40;border-radius:3px;overflow:hidden">'
            f'<div style="height:100%;border-radius:3px;background:{col};width:{pct}%;'
            f'transition:width .4s ease"></div></div>'
            f'<div style="font-family:monospace;font-size:10px;color:{_C["faint"]};text-align:right">'
            f'{cnt:,} ({pct}%)</div></div>'
        )

    mitre_rows2 = ""
    for tactic, count in sorted(m.get("tactics_observed", {}).items(), key=lambda x: -x[1]):
        width = min(100, int(count / max(total, 1) * 600))
        mitre_rows2 += (
            f'<tr><td style="color:{_C["text"]};font-weight:600">{html_mod.escape(tactic)}</td>'
            f'<td><div style="background:{_C["faint"]}40;border-radius:3px;height:6px;width:100%">'
            f'<div style="background:{_C["purple"]};width:{width}%;height:6px;border-radius:3px"></div>'
            f'</div></td>'
            f'<td style="color:{_C["purple"]};font-weight:700;text-align:right;'
            f'font-family:monospace">{count}</td></tr>'
        )

    src_rows2, tgt_rows2 = "", ""
    for ip, cnt in r["top_sources"]:
        risk = "CRITICAL" if cnt > 50 else "HIGH" if cnt > 10 else "MEDIUM" if cnt > 3 else "LOW"
        label = "High-volume attacker" if cnt>50 else "Active threat source" if cnt>10 else "Elevated activity" if cnt>3 else "Low activity"
        src_rows2 += (
            f'<tr><td style="font-family:monospace;color:#F87171;font-weight:700">'
            f'{html_mod.escape(str(ip))}</td>'
            f'<td style="color:{_C["accent"]};font-weight:700;font-family:monospace">{cnt:,}</td>'
            f'<td style="font-size:11px;color:{_C["muted"]}">{cnt/max(total,1)*100:.1f}%</td>'
            f'<td>{_pill(risk, label)}</td></tr>'
        )
    for ip, cnt in r.get("top_targets", []):
        risk  = "CRITICAL" if cnt > 50 else "HIGH" if cnt > 10 else "MEDIUM" if cnt > 3 else "LOW"
        label = "Heavily targeted" if cnt>50 else "Frequent target" if cnt>10 else "Moderate target" if cnt>3 else "Low volume"
        tgt_rows2 += (
            f'<tr><td style="font-family:monospace;color:#67E8F9;font-weight:700">'
            f'{html_mod.escape(str(ip))}</td>'
            f'<td style="color:{_C["accent"]};font-weight:700;font-family:monospace">{cnt:,}</td>'
            f'<td style="font-size:11px;color:{_C["muted"]}">{cnt/max(total,1)*100:.1f}%</td>'
            f'<td>{_pill(risk, label)}</td></tr>'
        )

    rec_cards2 = ""
    pri_colors = {"CRITICAL": _C["danger"], "HIGH": _C["warn"], "MEDIUM": _C["accent"], "LOW": _C["ok"]}
    for i, rec in enumerate(r.get("recommendations", [])):
        pc    = pri_colors.get(rec["priority"], _C["muted"])
        tools = ", ".join(rec.get("tools", []))
        rec_cards2 += (
            f'<div style="background:{_C["card"]};border:1px solid {_C["border"]};'
            f'border-radius:10px;padding:18px 22px;margin-bottom:12px;'
            f'border-left:3px solid {pc}">'
            f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">'
            f'{_pill(rec["priority"])}'
            f'<span style="font-size:13px;font-weight:700;color:{_C["text"]}">'
            f'{html_mod.escape(rec["category"])}</span></div>'
            f'<p style="color:{_C["muted"]};font-size:12px;line-height:1.7;margin-bottom:8px">'
            f'{html_mod.escape(rec["action"])}</p>'
            f'<p style="font-size:11px"><span style="color:{_C["faint"]}">Recommended: </span>'
            f'<span style="color:{_C["accent"]}">{html_mod.escape(tools)}</span></p></div>'
        )

    timeline_bars2 = ""
    try:
        from collections import Counter as _Ctr
        hc: _Ctr = _Ctr()
        for a in r["alerts"]:
            ts = str(a.get("timestamp", ""))
            if len(ts) >= 13:
                hc[ts[:13]] += 1
        if hc:
            sh = sorted(hc.items())
            mx = max(v for _, v in sh) if sh else 1
            for h, cnt in sh[-24:]:
                label = h[11:] if len(h) > 10 else h
                pct   = int(cnt / mx * 100)
                bar_c = (_C["danger"] if pct > 70 else _C["warn"] if pct > 30 else _C["accent"])
                timeline_bars2 += (
                    f'<div style="display:grid;grid-template-columns:42px 1fr 48px;'
                    f'align-items:center;gap:8px;margin-bottom:5px;font-size:10px">'
                    f'<div style="color:{_C["faint"]};font-family:monospace;text-align:right">'
                    f'{label[:5]}</div>'
                    f'<div style="background:{_C["faint"]}30;border-radius:2px;'
                    f'height:10px;overflow:hidden">'
                    f'<div style="width:{pct}%;height:100%;background:{bar_c};border-radius:2px">'
                    f'</div></div>'
                    f'<div style="color:{_C["muted"]};font-family:monospace">{cnt:,}</div></div>'
                )
    except Exception:
        pass

    coc_rows = "".join(
        f'<tr><td style="color:{_C["faint"]};font-size:10px;text-transform:uppercase;'
        f'letter-spacing:.08em;white-space:nowrap;font-weight:600">'
        f'{html_mod.escape(k.replace("_"," ").title())}</td>'
        f'<td style="font-family:monospace;color:{_C["muted"]};font-size:11px">'
        f'{html_mod.escape(str(v))}</td></tr>'
        for k, v in r["chain_of_custody"].items()
    )

    tl_glow = (
        f"0 0 0 1px {tl_c}33, 0 0 12px {tl_c}22"
        if tl in ("CRITICAL", "HIGH") else "none"
    )

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Bastion IDS — Forensic Intelligence Report {html_mod.escape(r['report_id'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth;-webkit-text-size-adjust:100%}}
body{{
  background:{_C["bg"]};
  color:{_C["text"]};
  font-family:'Segoe UI',Inter,system-ui,-apple-system,sans-serif;
  font-size:13px;line-height:1.55;
  min-height:100vh;
}}

/* ── WATERMARK ── */
body::after{{
  content:'BASTION IDS';
  position:fixed;top:50%;left:50%;
  transform:translate(-50%,-50%) rotate(-35deg);
  font-size:110px;font-weight:900;letter-spacing:18px;
  color:rgba(34,211,238,.025);pointer-events:none;
  z-index:0;white-space:nowrap;
}}

/* ── CLASSIFICATION RIBBON ── */
.ribbon{{
  background:linear-gradient(90deg,#7f0010,#b91c1c,#7f0010);
  color:#fff;text-align:center;padding:5px 0;
  font-size:10px;font-weight:800;letter-spacing:2.5px;text-transform:uppercase;
  position:sticky;top:0;z-index:1000;border-bottom:1px solid #991b1b;
}}

/* ── LAYOUT ── */
.page{{max-width:1280px;margin:0 auto;padding:0 32px 60px;position:relative;z-index:1}}

/* ── REPORT HEADER ── */
.rpt-header{{
  display:grid;grid-template-columns:1fr auto;gap:24px;align-items:start;
  padding:32px 0 24px;border-bottom:1px solid {_C["border"]};margin-bottom:36px;
}}
.rpt-branding{{}}
.rpt-logo{{
  font-size:11px;font-weight:800;color:{_C["accent"]};
  letter-spacing:3px;text-transform:uppercase;margin-bottom:8px;
  display:flex;align-items:center;gap:8px;
}}
.rpt-logo::before{{
  content:'';display:block;width:24px;height:3px;
  background:{_C["accent"]};border-radius:2px;
}}
.rpt-title{{font-size:26px;font-weight:800;color:#fff;line-height:1.15;margin-bottom:10px}}
.rpt-meta{{display:flex;flex-wrap:wrap;gap:16px;margin-top:12px}}
.rpt-meta-item{{
  display:flex;flex-direction:column;gap:2px;
}}
.rpt-meta-label{{font-size:9px;font-weight:700;color:{_C["faint"]};text-transform:uppercase;letter-spacing:.8px}}
.rpt-meta-val{{font-size:11px;color:{_C["muted"]};font-family:monospace}}
.threat-panel{{
  background:{_C["card"]};border:1px solid {_C["border"]};border-radius:12px;
  padding:20px 24px;text-align:center;min-width:180px;
  box-shadow:{tl_glow};
}}
.threat-label{{font-size:9px;font-weight:800;color:{_C["faint"]};letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}}
.threat-level{{font-size:32px;font-weight:900;color:{tl_c};line-height:1;margin-bottom:4px;letter-spacing:1px}}
.threat-sub{{font-size:10px;color:{_C["muted"]}}}

/* ── KPI GRID ── */
.kpi-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:40px}}
.kpi{{
  background:{_C["card"]};border:1px solid {_C["border"]};border-radius:10px;
  padding:18px 14px;text-align:center;position:relative;overflow:hidden;
}}
.kpi::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--kc,{_C["accent"]});
}}
.kpi-val{{font-size:28px;font-weight:800;line-height:1;font-family:monospace}}
.kpi-lbl{{color:{_C["muted"]};font-size:9px;margin-top:8px;text-transform:uppercase;letter-spacing:.8px;font-weight:600}}

/* ── SECTION CARD ── */
.sec{{
  background:{_C["surf"]};border:1px solid {_C["border"]};border-radius:12px;
  padding:24px 28px;margin-bottom:28px;
}}

/* ── TABLES ── */
.tbl-outer{{border-radius:8px;overflow:hidden;border:1px solid {_C["border"]}}}
table{{width:100%;border-collapse:collapse}}
thead tr{{background:linear-gradient(90deg,#0D2540,#0A1D35)}}
th{{
  padding:10px 13px;font-size:9px;font-weight:700;color:{_C["muted"]};
  text-transform:uppercase;letter-spacing:.8px;text-align:left;
}}
td{{
  padding:8px 13px;border-bottom:1px solid {_C["border"]}18;
  font-size:12px;vertical-align:middle;
}}
tr:nth-child(even) td{{background:rgba(255,255,255,.015)}}
tr:hover td{{background:{_C["accent"]}08;transition:background .15s}}
tr:last-child td{{border-bottom:none}}

/* ── BARS ── */
.bar-track{{background:{_C["faint"]}30;border-radius:3px;height:6px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:3px;transition:width .4s ease}}

/* ── FOOTER ── */
.rpt-footer{{
  border-top:1px solid {_C["border"]};padding-top:20px;margin-top:48px;
  display:grid;grid-template-columns:1fr auto;gap:16px;align-items:end;
}}
.footer-left{{}}
.footer-brand{{
  font-size:12px;font-weight:700;color:{_C["accent"]};letter-spacing:1px;margin-bottom:4px
}}
.footer-legal{{font-size:10px;color:{_C["faint"]};line-height:1.6}}
.footer-right{{text-align:right}}
.footer-kadian{{font-size:10px;color:{_C["faint"]};font-weight:600;letter-spacing:.5px}}
.footer-ts{{font-size:10px;color:{_C["faint"]}80;margin-top:2px}}

/* ── PRINT ── */
@media print{{
  body::after{{display:none}}
  .ribbon{{position:static}}
  body{{background:#fff;color:#1a1a2e}}
  .rpt-header,.sec,.kpi{{border:1px solid #dde3ec}}
  .kpi,.sec{{background:#f8fbff}}
  thead tr{{background:#0D2540!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .threat-panel{{border:1px solid #dde3ec;background:#f8fbff}}
  .tbl-outer{{border:1px solid #dde3ec}}
}}
</style>
</head>
<body>

<!-- CLASSIFICATION RIBBON -->
<div class="ribbon">&#9888;&#xfe0e; CONFIDENTIAL — AUTHORIZED SECURITY PERSONNEL ONLY &#9888;&#xfe0e;</div>

<div class="page">

<!-- ══════════════════════════════════════════════════
     REPORT HEADER
     ══════════════════════════════════════════════════ -->
<div class="rpt-header">
  <div class="rpt-branding">
    <div class="rpt-logo">Bastion IDS &nbsp;/&nbsp; Forensic Intelligence Report</div>
    <div class="rpt-title">Network Threat Analysis<br/>& Incident Intelligence Brief</div>
    <div class="rpt-meta">
      <div class="rpt-meta-item">
        <span class="rpt-meta-label">Report ID</span>
        <span class="rpt-meta-val">{html_mod.escape(r['report_id'])}</span>
      </div>
      <div class="rpt-meta-item">
        <span class="rpt-meta-label">Generated (UTC)</span>
        <span class="rpt-meta-val">{r['generated_at'][:19]}</span>
      </div>
      <div class="rpt-meta-item">
        <span class="rpt-meta-label">Engine Version</span>
        <span class="rpt-meta-val">{html_mod.escape(r['engine_version'])}</span>
      </div>
      <div class="rpt-meta-item">
        <span class="rpt-meta-label">Data Source</span>
        <span class="rpt-meta-val">{html_mod.escape(str(r['session'].get('source','N/A')))[:48]}</span>
      </div>
      <div class="rpt-meta-item">
        <span class="rpt-meta-label">Session Mode</span>
        <span class="rpt-meta-val">{str(r['session'].get('mode','Unknown')).upper()}</span>
      </div>
    </div>
  </div>
  <div class="threat-panel">
    <div class="threat-label">Overall Threat Level</div>
    <div class="threat-level">{tl}</div>
    <div class="threat-sub">{round(s['severity_counts'].get('CRITICAL',0)*_scale):,} critical &nbsp;·&nbsp; {round(s['severity_counts'].get('HIGH',0)*_scale):,} high</div>
  </div>
</div>

<!-- ══════════════════════════════════════════════════
     § 1. EXECUTIVE SUMMARY
     ══════════════════════════════════════════════════ -->
<div class="sec">
{_sh("◈", "01", "Executive Summary", _C["accent"])}
  <p style="color:{_C["muted"]};font-size:12.5px;line-height:1.75;margin-bottom:22px;max-width:900px">
    This forensic session processed <strong style="color:{_C["text"]}">{total:,} security events</strong>
    and identified <strong style="color:{_C["danger"]}">{threats:,} threat flows</strong>
    ({threats/max(total,1)*100:.1f}% of total traffic).
    {f'<strong style="color:{_C["ok"]}">{benign:,}</strong> flows were processed without triggering any detection rule.' if benign is not None else 'Benign flow count is not tracked in live-capture mode — only flagged events are stored.'}
    MITRE ATT&amp;CK&#174; analysis mapped adversarial activity to
    <strong style="color:{_C["accent"]}">{m.get('unique_tactics',0)} tactics</strong> and
    <strong style="color:{_C["accent"]}">{m.get('unique_techniques',0)} techniques</strong>.
    Average detection confidence across all flagged events: <strong style="color:{_C["purple"]}">{avg_conf:.1f}%</strong>.
  </p>
  <div class="kpi-grid">
    <div class="kpi" style="--kc:{_C['accent']}">
      <div class="kpi-val" style="color:{_C['accent']}">{total:,}</div>
      <div class="kpi-lbl">Total Events</div>
    </div>
    <div class="kpi" style="--kc:{_C['danger']}">
      <div class="kpi-val" style="color:{_C['danger']}">{threats:,}</div>
      <div class="kpi-lbl">Threats Detected</div>
    </div>
    <div class="kpi" style="--kc:{_C['ok']}">
      <div class="kpi-val" style="color:{_C['ok']}">{f'{benign:,}' if benign is not None else 'N/A'}</div>
      <div class="kpi-lbl">{'Benign Cleared' if benign is not None else 'Benign (not tracked)'}</div>
    </div>
    <div class="kpi" style="--kc:{_C['warn']}">
      <div class="kpi-val" style="color:{_C['warn']}">{high:,}</div>
      <div class="kpi-lbl">High / Critical</div>
    </div>
    <div class="kpi" style="--kc:{_C['purple']}">
      <div class="kpi-val" style="color:{_C['purple']}">{avg_conf:.1f}%</div>
      <div class="kpi-lbl">Avg Confidence</div>
    </div>
  </div>
  <!-- Severity breakdown pills -->
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    {''.join(
      f'<div style="background:{SEV_PILL_NEW.get(sv,SEV_PILL_NEW["INFO"])[0]};'
      f'border:1px solid {SEV_PILL_NEW.get(sv,SEV_PILL_NEW["INFO"])[2]};'
      f'border-radius:8px;padding:8px 16px;min-width:90px;text-align:center">'
      f'<div style="font-size:16px;font-weight:800;color:{SEV_PILL_NEW.get(sv,SEV_PILL_NEW["INFO"])[1]};font-family:monospace">'
      f'{s["severity_counts"].get(sv,0):,}</div>'
      f'<div style="font-size:9px;color:{SEV_PILL_NEW.get(sv,SEV_PILL_NEW["INFO"])[1]};'
      f'text-transform:uppercase;letter-spacing:.6px;margin-top:3px;font-weight:700">{sv}</div>'
      f'</div>'
      for sv in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")
    )}
  </div>
</div>

<!-- ══════════════════════════════════════════════════
     § 2. THREAT CATEGORY DISTRIBUTION
     ══════════════════════════════════════════════════ -->
<div class="sec">
{_sh("◉", "02", "Threat Category Distribution", _C["danger"])}
  <div class="tbl-outer">
    <table>
      <thead><tr>
        <th>Attack Category</th><th>Event Count</th><th>% of Traffic</th>
        <th>% of Threats</th><th>Severity</th><th>MITRE Techniques</th>
      </tr></thead>
      <tbody>
      {dist_rows2 if dist_rows2 else f'<tr><td colspan="6" style="text-align:center;padding:28px;color:{_C["faint"]};font-size:11px;letter-spacing:.08em">NO THREATS DETECTED — ALL TRAFFIC CLASSIFIED AS BENIGN</td></tr>'}
      </tbody>
    </table>
  </div>
</div>

<!-- ══════════════════════════════════════════════════
     § 3. DETECTION ENGINE ATTRIBUTION
     ══════════════════════════════════════════════════ -->
<div class="sec">
{_sh("⬡", "03", "Detection Engine Attribution", _C["accent"])}
  <p style="color:{_C["muted"]};font-size:12px;margin-bottom:20px">
    Bastion IDS operates four stacked detection layers. Each layer contributes independently;
    the final verdict is determined by the highest-confidence layer flagging the flow.
  </p>
  {layer_bars2}
</div>

<!-- ══════════════════════════════════════════════════
     § 4. MITRE ATT&CK® COVERAGE
     ══════════════════════════════════════════════════ -->
<div class="sec">
{_sh("◐", "04", "MITRE ATT&CK® Tactics Coverage", _C["purple"])}
  <div style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:18px">
    <div style="background:{_C["card"]};border:1px solid {_C["border"]};border-radius:8px;padding:12px 18px;text-align:center">
      <div style="font-size:22px;font-weight:800;color:{_C["purple"]};font-family:monospace">{m.get('unique_tactics',0)}</div>
      <div style="font-size:9px;color:{_C["muted"]};text-transform:uppercase;letter-spacing:.6px;margin-top:4px">Tactics Observed</div>
    </div>
    <div style="background:{_C["card"]};border:1px solid {_C["border"]};border-radius:8px;padding:12px 18px;text-align:center">
      <div style="font-size:22px;font-weight:800;color:{_C["accent"]};font-family:monospace">{m.get('unique_techniques',0)}</div>
      <div style="font-size:9px;color:{_C["muted"]};text-transform:uppercase;letter-spacing:.6px;margin-top:4px">Unique Techniques</div>
    </div>
    <div style="background:{_C["card"]};border:1px solid {_C["border"]};border-radius:8px;padding:12px 18px;text-align:center">
      <div style="font-size:22px;font-weight:800;color:{_C["ok"]};font-family:monospace">{m.get('techniques_mapped',0)}</div>
      <div style="font-size:9px;color:{_C["muted"]};text-transform:uppercase;letter-spacing:.6px;margin-top:4px">Techniques Mapped</div>
    </div>
  </div>
  <div class="tbl-outer">
    <table>
      <thead><tr>
        <th>ATT&amp;CK Tactic</th><th style="min-width:180px">Activity Volume</th><th style="text-align:right">Count</th>
      </tr></thead>
      <tbody>
      {mitre_rows2 if mitre_rows2 else f'<tr><td colspan="3" style="text-align:center;padding:24px;color:{_C["faint"]};font-size:11px">No MITRE tactics identified in this session</td></tr>'}
      </tbody>
    </table>
  </div>
</div>

<!-- ══════════════════════════════════════════════════
     § 5. ATTACK INTELLIGENCE
     ══════════════════════════════════════════════════ -->
{'<div class="sec">' + _sh("◈", "05", "Attack Intelligence", _C["warn"]) + attack_cards2 + '</div>' if attack_cards2 else ''}

<!-- ══════════════════════════════════════════════════
     § 6 & 7. IP NETWORK INTEL
     ══════════════════════════════════════════════════ -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px">
  {'<div class="sec"><div style="margin-bottom:0">' + _sh("◉", "06", "Top Threat Source IPs", _C["danger"]) + '</div><div class="tbl-outer"><table><thead><tr><th>Source IP</th><th>Alerts</th><th>% Traffic</th><th>Risk</th></tr></thead><tbody>' + (src_rows2 if src_rows2 else f"<tr><td colspan='4' style='text-align:center;padding:20px;color:{_C['faint']}'>No source data</td></tr>") + '</tbody></table></div></div>' if True else ''}
  {'<div class="sec"><div style="margin-bottom:0">' + _sh("◉", "07", "Top Target IPs", _C["accent"]) + '</div><div class="tbl-outer"><table><thead><tr><th>Target IP</th><th>Hits</th><th>% Traffic</th><th>Profile</th></tr></thead><tbody>' + (tgt_rows2 if tgt_rows2 else f"<tr><td colspan='4' style='text-align:center;padding:20px;color:{_C['faint']}'>No target data</td></tr>") + '</tbody></table></div></div>' if True else ''}
</div>

<!-- ══════════════════════════════════════════════════
     § 8. ATTACK TIMELINE
     ══════════════════════════════════════════════════ -->
{('<div class="sec">' + _sh("◷", "08", "Attack Timeline (Hourly Distribution)", _C["purple"]) + '<p style="color:' + _C["muted"] + ';font-size:11px;margin-bottom:16px">Events grouped by hour — bars normalized to peak volume. Red &gt; 70%, amber &gt; 30% of peak.</p>' + timeline_bars2 + '</div>') if timeline_bars2 else ''}

<!-- ══════════════════════════════════════════════════
     § 9. FORENSIC ALERT LOG
     ══════════════════════════════════════════════════ -->
<div class="sec">
{_sh("◎", "09", "Forensic Alert Log", _C["ok"])}
  <p style="color:{_C["muted"]};font-size:11px;margin-bottom:14px">
    Showing <strong>{min(len(r['alerts']),200):,}</strong> of <strong>{total_flows:,}</strong> total session alerts
    (report table capped at 200 rows — download the JSON export for the full dataset).
  </p>
  <div class="tbl-outer">
    <table>
      <thead><tr>
        <th>Timestamp</th><th>Severity</th><th>Verdict / Attack Type</th>
        <th>Source IP</th><th>Destination IP</th>
        <th>MITRE ID</th><th>Confidence</th><th>Engine</th>
      </tr></thead>
      <tbody>
      {alert_rows2 if alert_rows2 else f'<tr><td colspan="8" style="text-align:center;padding:28px;color:{_C["faint"]};font-size:11px">No alerts recorded in this session</td></tr>'}
      </tbody>
    </table>
  </div>
  {f'<p style="color:{_C["faint"]};font-size:10px;margin-top:8px;text-align:right">&#9432; Full dataset ({total_flows:,} alerts) available in the accompanying JSON export.</p>' if total_flows > 200 else ''}
</div>

<!-- ══════════════════════════════════════════════════
     § 10. SECURITY RECOMMENDATIONS
     ══════════════════════════════════════════════════ -->
<div class="sec">
{_sh("◈", "10", "Security Recommendations & Remediation", _C["warn"])}
  <p style="color:{_C["muted"]};font-size:12px;margin-bottom:18px">
    Prioritized remediation actions derived from detected threat patterns and MITRE ATT&amp;CK® mappings.
    Address CRITICAL items immediately; HIGH items within 24 hours; MEDIUM within 7 days.
  </p>
  {rec_cards2}
</div>

<!-- ══════════════════════════════════════════════════
     § 11. CHAIN OF CUSTODY
     ══════════════════════════════════════════════════ -->
<div class="sec">
{_sh("◇", "11", "Chain of Custody &amp; Audit Trail", _C["faint"])}
  <div class="tbl-outer">
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{coc_rows}</tbody>
    </table>
  </div>
  <p style="color:{_C["faint"]};font-size:10.5px;margin-top:14px;line-height:1.6;padding:12px;background:{_C["card"]};border-radius:6px;border-left:2px solid {_C["faint"]}">
    This report was generated automatically by Bastion IDS and represents the system's analytical findings at the time of generation.
    All IP addresses, verdicts, and confidence scores reflect detection engine output only and should be reviewed by a qualified
    security analyst before initiating any enforcement action. MITRE ATT&amp;CK&#174; is a registered trademark of The MITRE Corporation.
  </p>
</div>

<!-- ══════════════════════════════════════════════════
     FOOTER
     ══════════════════════════════════════════════════ -->
<div class="rpt-footer">
  <div class="footer-left">
    <div class="footer-brand">BASTION IDS — FORENSIC INTELLIGENCE REPORT</div>
    <div class="footer-legal">
      MITRE ATT&amp;CK&#174; is a registered trademark of The MITRE Corporation.<br/>
      Handle in accordance with your organisation&#39;s data-classification policy.
      This document is classified <strong style="color:#F87171">CONFIDENTIAL</strong>.
    </div>
  </div>
  <div class="footer-right">
    <div class="footer-kadian">Kadian Inc</div>
    <div class="footer-ts">Report generated {r['generated_at'][:10]}</div>
  </div>
</div>

</div><!-- /page -->
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_out)
    return path


# ─────────────────────────────────────────────────────────────
# PDF EXPORT  — professional A4 document (light theme)
# ─────────────────────────────────────────────────────────────
def export_pdf(report_data: Dict, filename: str) -> str:
    path = os.path.join(REPORTS_DIR, filename + ".pdf")
    r    = report_data
    s    = r["summary"]

    _gen_ts    = r["generated_at"][:19]
    _report_id = r["report_id"]

    # ── Professional light-theme color palette (print-ready) ──
    # Dark text on white background — proper for PDF/print
    C_ROW_A  = colors.white                    # table data rows (even)
    C_ROW_B  = colors.HexColor("#f1f5f9")      # table data rows (odd) — very light gray
    C_HDR    = colors.HexColor("#1e3a5f")      # table header background — dark navy
    C_BLUE   = colors.HexColor("#1d4ed8")      # accent blue (darker = readable on white)
    C_RED    = colors.HexColor("#b91c1c")      # danger red
    C_AMBER  = colors.HexColor("#92400e")      # warning amber (darkened for white bg)
    C_GREEN  = colors.HexColor("#15803d")      # success green
    C_PURPLE = colors.HexColor("#6d28d9")      # purple
    C_TEXT   = colors.HexColor("#0f172a")      # primary text — near-black
    C_MUTED  = colors.HexColor("#334155")      # secondary text — dark slate
    C_FAINT  = colors.HexColor("#64748b")      # tertiary text — medium slate
    C_BORDER = colors.HexColor("#cbd5e1")      # light borders
    C_ACCENT = colors.HexColor("#3b82f6")      # bright blue for decorative elements

    # Threat level hex strings (for inline XML color tags in Paragraphs)
    _TL_HEX = {
        "CRITICAL": "#b91c1c", "HIGH":  "#92400e",
        "MEDIUM":   "#1d4ed8", "LOW":   "#15803d", "CLEAR": "#15803d",
    }
    # ReportLab color objects keyed by threat level
    _TL_COL = {
        "CRITICAL": C_RED, "HIGH": C_AMBER, "MEDIUM": C_BLUE,
        "LOW": C_GREEN, "CLEAR": C_GREEN,
    }

    # Severity → display color (for inline text)
    _SEV_HEX = {
        "CRITICAL": "#b91c1c", "HIGH": "#92400e",
        "MEDIUM":   "#1d4ed8", "LOW":  "#15803d", "INFO": "#475569",
    }

    # ── Header/footer + watermark drawn on every page ──
    def _on_page(canvas, doc):
        canvas.saveState()
        W, H = A4

        # ── WATERMARK — large diagonal "BASTION IDS" across each page ──────
        # Drawn first so it sits behind all other content.
        canvas.saveState()
        wm_color = colors.Color(0.059, 0.231, 0.612, alpha=0.045)   # deep blue, ~4% opacity
        canvas.setFillColor(wm_color)
        canvas.setFont("Helvetica-Bold", 88)
        canvas.translate(W / 2, H / 2)
        canvas.rotate(38)
        canvas.drawCentredString(0, 0, "BASTION IDS")
        canvas.restoreState()

        # ── Header bar — dark navy with blue accent stripe ───────────────────
        canvas.setFillColor(colors.HexColor("#1e3a5f"))
        canvas.rect(0, H - 14*mm, W, 14*mm, fill=1, stroke=0)
        # Left blue accent stripe
        canvas.setFillColor(colors.HexColor("#3b82f6"))
        canvas.rect(0, H - 14*mm, 4, 14*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(colors.white)
        canvas.drawString(10*mm, H - 9*mm, "BASTION IDS — FORENSIC INTELLIGENCE REPORT")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#93c5fd"))
        canvas.drawRightString(W - 10*mm, H - 9*mm, _report_id)

        # ── Footer bar — dark ─────────────────────────────────────────────────
        canvas.setFillColor(colors.HexColor("#0f172a"))
        canvas.rect(0, 0, W, 10*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(10*mm, 3.5*mm, "CONFIDENTIAL — FOR AUTHORIZED SECURITY PERSONNEL ONLY")
        canvas.drawCentredString(W / 2, 3.5*mm, f"Generated: {_gen_ts} UTC  |  Page {doc.page}")
        # Kadian Inc — subtle right-side branding in lighter/smaller type
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(colors.HexColor("#475569"))
        canvas.drawRightString(W - 10*mm, 4*mm, "Kadian Inc")

        canvas.restoreState()

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=22*mm, bottomMargin=16*mm,
    )

    # ── Paragraph helpers ──────────────────────────────────
    def _H1(text, color=None):
        """Cover-page large title."""
        return Paragraph(text, ParagraphStyle("h1", fontName="Helvetica-Bold",
            fontSize=26, textColor=color or C_TEXT,
            alignment=TA_CENTER, spaceAfter=6, leading=32))

    def _H2(text, color=None):
        """Section heading."""
        return Paragraph(text, ParagraphStyle("h2", fontName="Helvetica-Bold",
            fontSize=11, textColor=color or C_BLUE,
            spaceBefore=12, spaceAfter=5, leading=15))

    def _body(text):
        return Paragraph(text, ParagraphStyle("body", fontName="Helvetica",
            fontSize=9, textColor=C_MUTED, spaceAfter=4, leading=13))

    def _small(text):
        return Paragraph(text, ParagraphStyle("small", fontName="Helvetica",
            fontSize=8, textColor=C_FAINT, spaceAfter=3, leading=11))

    def _mono(text):
        return Paragraph(text, ParagraphStyle("mono", fontName="Courier",
            fontSize=8, textColor=C_FAINT, spaceAfter=3, leading=11))

    def _section_rule(color=None):
        return HRFlowable(width="100%", thickness=0.5,
                          color=color or C_BLUE, spaceAfter=8)

    # ── Base table style (dark header, light alternating rows, dark text) ──
    tbl_style = TableStyle([
        # Header row
        ("BACKGROUND",    (0, 0), (-1, 0), C_HDR),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 7.5),
        ("TOPPADDING",    (0, 0), (-1, 0), 5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        # Data rows
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 7.5),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
        # All cells
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
    ])

    story = []

    # ═══════════════════════════════════════════════════════
    # COVER PAGE
    # ═══════════════════════════════════════════════════════
    story.append(Spacer(1, 20*mm))

    # Brand name
    story.append(Paragraph("BASTION IDS", ParagraphStyle("brand",
        fontName="Helvetica-Bold", fontSize=13, textColor=C_ACCENT,
        alignment=TA_CENTER, spaceAfter=4, letterSpacing=3)))

    # Main title
    story.append(_H1("Forensic Intelligence Report"))

    # Subtitle
    story.append(Paragraph(
        "Hybrid Signature  |  ML Ensemble  |  Deep Learning  |  Anomaly Detection",
        ParagraphStyle("csub", fontName="Helvetica", fontSize=10,
        textColor=C_FAINT, alignment=TA_CENTER, spaceAfter=18)))

    story.append(HRFlowable(width="100%", thickness=1.5, color=C_ACCENT, spaceAfter=16))

    # Overall Threat Level badge
    tl     = s["threat_level"]
    tl_hex = _TL_HEX.get(tl, "#92400e")
    tl_col = _TL_COL.get(tl, C_AMBER)
    story.append(Paragraph(
        f'Overall Threat Level: <font color="{tl_hex}"><b>{tl}</b></font>',
        ParagraphStyle("tl", fontName="Helvetica-Bold", fontSize=20,
        textColor=C_TEXT, alignment=TA_CENTER, spaceAfter=20)))

    # Cover metadata table — use actual session totals, not capped sample
    _pdf_sample  = s["total_alerts"]
    _pdf_total   = s.get("total_flows_in_session") or _pdf_sample
    _pdf_scale   = _pdf_total / max(_pdf_sample, 1)
    total_a      = _pdf_total   # alias used throughout the PDF body
    threats_n    = round((_pdf_sample - s["severity_counts"].get("INFO", 0)) * _pdf_scale)
    high_crit    = round((s["severity_counts"].get("CRITICAL", 0) +
                          s["severity_counts"].get("HIGH", 0)) * _pdf_scale)
    avg_conf     = (sum(float(a.get("confidence", 0)) for a in r["alerts"]) /
                   max(len(r["alerts"]), 1) * 100)

    cover_meta = [
        ["Field", "Value", "Field", "Value"],
        ["Report ID",      r["report_id"][:36],
         "Generated",      _gen_ts + " UTC"],
        ["Data Source",    str(r["session"].get("source", "N/A"))[:40],
         "Engine",         r["engine_version"]],
        ["Total Flows",    f"{_pdf_total:,}",
         "Session Mode",   str(r["session"].get("mode", "Unknown")).upper()],
        ["Threats Found",  f"{threats_n:,}",
         "High/Critical",  f"{high_crit:,}"],
        ["Attack Types",   str(s["unique_attack_types"]),
         "Unique Sources", str(s["unique_source_ips"])],
    ]
    cm_tbl = Table(cover_meta, colWidths=[30*mm, 60*mm, 30*mm, 52*mm])
    cm_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_HDR),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("BACKGROUND",    (0, 1), (0, -1), colors.HexColor("#f8fafc")),
        ("BACKGROUND",    (2, 1), (2, -1), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR",     (0, 1), (0, -1), C_FAINT),
        ("TEXTCOLOR",     (2, 1), (2, -1), C_FAINT),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (2, 1), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 1), (-1, -1), 8.5),
        ("TEXTCOLOR",     (1, 1), (1, -1), C_TEXT),
        ("TEXTCOLOR",     (3, 1), (3, -1), C_TEXT),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(cm_tbl)
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "CONFIDENTIAL — FOR AUTHORIZED SECURITY PERSONNEL ONLY",
        ParagraphStyle("conf", fontName="Helvetica-Bold", fontSize=9,
        textColor=C_RED, alignment=TA_CENTER)))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Kadian Inc",
        ParagraphStyle("kadian", fontName="Helvetica", fontSize=7.5,
        textColor=C_FAINT, alignment=TA_RIGHT)))
    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════
    story.append(_H2("1.  Executive Summary"))
    story.append(_section_rule())
    story.append(_body(
        f"Bastion IDS analysed <b>{total_a:,}</b> security events and classified "
        f"<b>{threats_n:,}</b> as threat flows ({threats_n / max(total_a, 1) * 100:.1f}% of total traffic). "
        f"<b>{high_crit}</b> events were rated Critical or High severity. "
        f"Average detection confidence across all alerts: <b>{avg_conf:.1f}%</b>. "
        f"MITRE ATT&amp;CK analysis identified "
        f"<b>{r['mitre_summary'].get('unique_tactics', 0)}</b> adversarial tactics "
        f"spanning <b>{r['mitre_summary'].get('unique_techniques', 0)}</b> techniques."
    ))
    story.append(Spacer(1, 8))

    # KPI summary table
    kpi_data = [
        ["Total Events", "Threats Detected", "High / Critical", "Avg Confidence", "Attack Types"],
        [f"{total_a:,}", f"{threats_n:,}", str(high_crit),
         f"{avg_conf:.1f}%", str(s["unique_attack_types"])],
    ]
    kt = Table(kpi_data, colWidths=[34*mm] * 5)
    kt.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_HDR),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 7.5),
        ("TOPPADDING",    (0, 0), (-1, 0), 5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        # Big numbers row
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 1), (-1, 1), 18),
        ("TEXTCOLOR",     (0, 1), (0, 1),  C_BLUE),
        ("TEXTCOLOR",     (1, 1), (1, 1),  C_RED),
        ("TEXTCOLOR",     (2, 1), (2, 1),  C_AMBER),
        ("TEXTCOLOR",     (3, 1), (3, 1),  C_GREEN),
        ("TEXTCOLOR",     (4, 1), (4, 1),  C_PURPLE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("BACKGROUND",    (0, 1), (-1, 1),  colors.HexColor("#f8fafc")),
        ("TOPPADDING",    (0, 1), (-1, 1),  10),
        ("BOTTOMPADDING", (0, 1), (-1, 1),  10),
    ]))
    story.append(kt)
    story.append(Spacer(1, 10))

    # Severity breakdown sub-table
    sc = s["severity_counts"]
    sev_data = [
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        [str(sc.get("CRITICAL", 0)), str(sc.get("HIGH", 0)),
         str(sc.get("MEDIUM", 0)),   str(sc.get("LOW", 0)),
         str(sc.get("INFO", 0))],
    ]
    st2 = Table(sev_data, colWidths=[34*mm] * 5)
    st2.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR",     (0, 0), (0, 0),  C_RED),
        ("TEXTCOLOR",     (1, 0), (1, 0),  C_AMBER),
        ("TEXTCOLOR",     (2, 0), (2, 0),  C_BLUE),
        ("TEXTCOLOR",     (3, 0), (3, 0),  C_GREEN),
        ("TEXTCOLOR",     (4, 0), (4, 0),  C_FAINT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 7),
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 1), (-1, 1), 11),
        ("TEXTCOLOR",     (0, 1), (0, 1),  C_RED),
        ("TEXTCOLOR",     (1, 1), (1, 1),  C_AMBER),
        ("TEXTCOLOR",     (2, 1), (2, 1),  C_BLUE),
        ("TEXTCOLOR",     (3, 1), (3, 1),  C_GREEN),
        ("TEXTCOLOR",     (4, 1), (4, 1),  C_FAINT),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("BACKGROUND",    (0, 1), (-1, 1),  colors.white),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(st2)
    story.append(Spacer(1, 14))

    # ═══════════════════════════════════════════════════════
    # 2. THREAT CATEGORY DISTRIBUTION
    # ═══════════════════════════════════════════════════════
    story.append(_H2("2.  Threat Category Distribution"))
    story.append(_section_rule(C_RED))
    if r["top_attacks"]:
        # Use per-alert severity & MITRE (from enriched alerts, not static table)
        _pdf_at_sev   = s.get("attack_type_sev",   {})
        _pdf_at_mitre = s.get("attack_type_mitre", {})
        td_data = [["Attack Category", "Count", "% of Traffic", "% of Threats", "Severity", "MITRE Context"]]
        for at, cnt in r["top_attacks"]:
            info   = ATTACK_INTEL.get(str(at), {})
            sev    = _pdf_at_sev.get(str(at)) or info.get("severity", "MEDIUM")
            mitre  = (_pdf_at_mitre.get(str(at)) or "; ".join(info.get("mitre", [])[:1]) or "Pending")[:35]
            pct_t  = f"{cnt / max(total_a, 1) * 100:.1f}%"
            pct_th = f"{cnt / max(threats_n, 1) * 100:.1f}%" if threats_n > 0 else "N/A"
            td_data.append([str(at)[:28], f"{cnt:,}", pct_t, pct_th, sev, mitre])
        td_tbl = Table(td_data, colWidths=[46*mm, 18*mm, 20*mm, 20*mm, 20*mm, 48*mm])
        # Color severity cells
        sev_style = TableStyle(list(tbl_style._cmds))
        for row_idx, (at, _) in enumerate(r["top_attacks"], start=1):
            sev  = _pdf_at_sev.get(str(at)) or ATTACK_INTEL.get(str(at), {}).get("severity", "MEDIUM")
            sc_  = {"CRITICAL": C_RED, "HIGH": C_AMBER, "MEDIUM": C_BLUE,
                    "LOW": C_GREEN}.get(sev, C_FAINT)
            sev_style.add("TEXTCOLOR", (4, row_idx), (4, row_idx), sc_)
            sev_style.add("FONTNAME",  (4, row_idx), (4, row_idx), "Helvetica-Bold")
        td_tbl.setStyle(sev_style)
        story.append(td_tbl)
    else:
        story.append(_body("No threats detected — all traffic classified as benign."))
    story.append(Spacer(1, 14))

    # ═══════════════════════════════════════════════════════
    # 3. DETECTION ENGINE ATTRIBUTION
    # ═══════════════════════════════════════════════════════
    story.append(_H2("3.  Detection Engine Attribution"))
    story.append(_section_rule())
    la = s["layer_attribution"]
    layer_rows = [
        ("L1 — Signature Engine",   la.get("SIGNATURE_DB", 0),
         "48 000+ ET-Open / custom rules. Pattern-match against known attack signatures."),
        ("L2 — ML Ensemble",        la.get("ML_ENSEMBLE", 0),
         "Random Forest + XGBoost + CatBoost voting ensemble on 80 network features."),
        ("L3 — Deep Learning",      la.get("DL-SENSEI", 0) + la.get("DL_LAYER", 0),
         "Residual DNN (Sensei) trained on CICIDS2017/2018 + UNSW-NB15 datasets."),
        ("L4 — Anomaly Sentinel",   la.get("ANOMALY", 0),
         "Autoencoder reconstruction error + Isolation Forest outlier detection."),
        ("Benign / Cleared",        la.get("NORMAL", 0),
         "Flows classified as normal traffic by all active detection layers."),
    ]
    ld = [["Detection Layer", "Alerts Flagged", "Coverage", "Description"]]
    for lbl, cnt, desc in layer_rows:
        pct = f"{cnt / max(total_a, 1) * 100:.1f}%"
        ld.append([lbl, f"{cnt:,}", pct, desc])
    lt = Table(ld, colWidths=[44*mm, 22*mm, 16*mm, 90*mm])
    lt.setStyle(tbl_style)
    story.append(lt)
    story.append(Spacer(1, 14))

    # ═══════════════════════════════════════════════════════
    # 4. MITRE ATT&CK COVERAGE
    # ═══════════════════════════════════════════════════════
    story.append(_H2("4.  MITRE ATT&CK® Tactics Coverage"))
    story.append(_section_rule(C_PURPLE))
    mitre_t = r["mitre_summary"].get("tactics_observed", {})
    story.append(_body(
        f"Unique tactics observed: <b>{r['mitre_summary'].get('unique_tactics', 0)}</b>  |  "
        f"Unique techniques: <b>{r['mitre_summary'].get('unique_techniques', 0)}</b>  |  "
        f"Techniques mapped: <b>{r['mitre_summary'].get('techniques_mapped', 0)}</b>"
    ))
    story.append(Spacer(1, 6))
    if mitre_t:
        mt_data = [["MITRE ATT&CK Tactic", "Occurrences", "% Share", "Activity Bar"]]
        max_cnt = max(mitre_t.values()) if mitre_t else 1
        for tac, cnt in sorted(mitre_t.items(), key=lambda x: -x[1]):
            pct_s = f"{cnt / max(total_a, 1) * 100:.1f}%"
            bar_w = int(cnt / max(max_cnt, 1) * 20)
            bar   = "|" * bar_w + "." * (20 - bar_w)
            mt_data.append([tac, f"{cnt:,}", pct_s, bar])
        mt_tbl = Table(mt_data, colWidths=[62*mm, 22*mm, 18*mm, 70*mm])
        mt_tbl.setStyle(tbl_style)
        story.append(mt_tbl)
    else:
        story.append(_body("No MITRE ATT&CK tactics observed in this session."))
    story.append(Spacer(1, 14))

    # ═══════════════════════════════════════════════════════
    # 5. TOP THREAT SOURCES
    # ═══════════════════════════════════════════════════════
    if r.get("top_sources"):
        story.append(_H2("5.  Top Threat Source IPs"))
        story.append(_section_rule(C_RED))
        src_data = [["Source IP Address", "Alert Count", "% of Alerts", "Risk Level"]]
        for ip, cnt in r["top_sources"][:15]:
            risk = ("CRITICAL" if cnt > 50 else "HIGH" if cnt > 10
                    else "MEDIUM" if cnt > 3 else "LOW")
            pct  = f"{cnt / max(total_a, 1) * 100:.1f}%"
            src_data.append([str(ip), f"{cnt:,}", pct, risk])
        src_tbl = Table(src_data, colWidths=[50*mm, 26*mm, 22*mm, 74*mm])
        risk_style = TableStyle(list(tbl_style._cmds))
        for ri, (ip, cnt) in enumerate(r["top_sources"][:15], start=1):
            risk = ("CRITICAL" if cnt > 50 else "HIGH" if cnt > 10
                    else "MEDIUM" if cnt > 3 else "LOW")
            rc_ = {"CRITICAL": C_RED, "HIGH": C_AMBER,
                   "MEDIUM": C_BLUE, "LOW": C_GREEN}.get(risk, C_FAINT)
            risk_style.add("TEXTCOLOR", (3, ri), (3, ri), rc_)
            risk_style.add("FONTNAME",  (3, ri), (3, ri), "Helvetica-Bold")
        src_tbl.setStyle(risk_style)
        story.append(src_tbl)
        story.append(Spacer(1, 14))

    # ═══════════════════════════════════════════════════════
    # 6. FORENSIC ALERT LOG
    # ═══════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(_H2("6.  Forensic Alert Log"))
    story.append(_section_rule(C_GREEN))
    if r["alerts"]:
        story.append(_small(
            f"Displaying first 100 of {len(r['alerts']):,} total alerts. "
            "Full dataset available in the JSON export."
        ))
        story.append(Spacer(1, 4))
        al = [["Timestamp", "Sev", "Verdict / Attack Type", "Source IP",
               "Dest IP", "MITRE ID", "Conf %", "Engine"]]
        for a in r["alerts"][:100]:
            sev  = str(a.get("severity", "MED"))[:4]
            conf = f"{float(a.get('confidence', 0)) * 100:.0f}%"
            al.append([
                str(a.get("timestamp", ""))[:16],
                sev,
                str(a.get("verdict", ""))[:28],
                str(a.get("srcip",  a.get("Source", "?")))[:17],
                str(a.get("dstip",  a.get("Destination", "?")))[:17],
                str(a.get("mitre_technique_id", "N/A")),
                conf,
                str(a.get("source_engine", ""))[:10],
            ])
        al_tbl = Table(al, colWidths=[22*mm, 10*mm, 42*mm, 26*mm, 26*mm, 16*mm, 11*mm, 19*mm])
        al_style = TableStyle(list(tbl_style._cmds))
        # Color severity cells in each data row
        for ri, a in enumerate(r["alerts"][:100], start=1):
            sev = str(a.get("severity", "MEDIUM"))
            sc_ = {"CRITICAL": C_RED, "HIGH": C_AMBER,
                   "MEDIUM": C_BLUE, "LOW": C_GREEN,
                   "INFO": C_FAINT}.get(sev, C_MUTED)
            al_style.add("TEXTCOLOR", (1, ri), (1, ri), sc_)
            al_style.add("FONTNAME",  (1, ri), (1, ri), "Helvetica-Bold")
        al_tbl.setStyle(al_style)
        story.append(al_tbl)
    else:
        story.append(_body("No alerts recorded in this session."))
    story.append(Spacer(1, 14))

    # ═══════════════════════════════════════════════════════
    # 7. SECURITY RECOMMENDATIONS
    # ═══════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(_H2("7.  Security Recommendations"))
    story.append(_section_rule(C_AMBER))
    pri_rl = {"CRITICAL": C_RED, "HIGH": C_AMBER, "MEDIUM": C_BLUE, "LOW": C_GREEN}
    for i, rec in enumerate(r.get("recommendations", []), start=1):
        pc    = pri_rl.get(rec["priority"], C_FAINT)
        tools = ", ".join(rec.get("tools", []))
        story.append(KeepTogether([
            Paragraph(
                f'{i}.  [{rec["priority"]}]  {rec["category"]}',
                ParagraphStyle("rh", fontName="Helvetica-Bold", fontSize=10,
                               textColor=pc, spaceAfter=3)),
            _body(rec["action"]),
            _mono(f"Recommended tools: {tools}"),
            Spacer(1, 10),
        ]))

    # ═══════════════════════════════════════════════════════
    # 8. CHAIN OF CUSTODY
    # ═══════════════════════════════════════════════════════
    story.append(_H2("8.  Chain of Custody & Audit Trail"))
    story.append(_section_rule(C_FAINT))
    coc = [[k.replace("_", " ").title(), str(v)]
           for k, v in r["chain_of_custody"].items()]
    ct  = Table(coc, colWidths=[48*mm, 124*mm])
    coc_style = TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",     (0, 0), (0, -1), C_FAINT),
        ("TEXTCOLOR",     (1, 0), (1, -1), C_TEXT),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])
    ct.setStyle(coc_style)
    story.append(ct)
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER, spaceAfter=8))
    story.append(Paragraph(
        "This report was generated automatically by Bastion IDS. "
        "MITRE ATT&CK® is a registered trademark of The MITRE Corporation. "
        "Handle in accordance with your organisation's data-classification policy.",
        ParagraphStyle("disc", fontName="Helvetica", fontSize=7.5,
        textColor=C_FAINT, alignment=TA_CENTER)))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return path


# ─────────────────────────────────────────────────────────────
# MAIN API
# ─────────────────────────────────────────────────────────────
def generate_report(alerts: List[Dict], session_meta: Dict,
                    formats: List[str] = None) -> Dict:
    if formats is None:
        formats = ["json", "html", "pdf"]

    # build_report_data is pure computation — must run first (single-threaded)
    report_data = build_report_data(alerts, session_meta)
    report_id   = report_data["report_id"]
    paths   = {}
    errors  = {}

    _exporters = {
        "json": export_json,
        "html": export_html,
        "pdf":  export_pdf,
    }

    # ── Run exporters in parallel — JSON/HTML/PDF are fully independent ──────
    # On a typical 2000-alert session: JSON ≈ 0.1s, HTML ≈ 0.5s, PDF ≈ 8-15s.
    # Sequential = ~16s wall-time; parallel = ~max(PDF time) ≈ 8-15s.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _run_exporter(fmt):
        try:
            p = _exporters[fmt](report_data, report_id)
            if os.path.exists(p):
                return fmt, p, None
            return fmt, None, f"Export completed but file missing: {p}"
        except Exception as e:
            import traceback as _tb
            msg = f"{type(e).__name__}: {e}"
            print(f"[report_generator] {fmt.upper()} export failed: {e}\n{_tb.format_exc()}", flush=True)
            return fmt, None, msg

    active_fmts = [f for f in formats if f in _exporters]
    with ThreadPoolExecutor(max_workers=len(active_fmts) or 1) as pool:
        futures = {pool.submit(_run_exporter, fmt): fmt for fmt in active_fmts}
        for fut in as_completed(futures):
            fmt, path, err = fut.result()
            if path:
                paths[fmt] = path
            elif err:
                errors[fmt] = err

    if not paths and errors:
        # All formats failed — raise so the API returns a proper 500
        raise RuntimeError(f"All report formats failed: {errors}")

    # Return only basenames (for download API)
    return {
        "report_id": report_id,
        "paths":     {fmt: os.path.basename(p) for fmt, p in paths.items()},
        "errors":    errors,   # surfaces partial failures to the caller
        "data":      report_data,
    }
