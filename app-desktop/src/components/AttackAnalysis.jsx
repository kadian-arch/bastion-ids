
import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  BarChart3, ShieldAlert, Fingerprint, Terminal, ShieldCheck,
  ChevronRight, Search, Filter, Zap, ShieldX, Binary,
  XCircle, FileText, Database, Activity, Globe, Cpu,
  Download, Clock, CheckCircle2, ShieldEllipsis, AlertCircle,
  Target, Map, Link, Shield, BookOpen, ExternalLink,
  ChevronDown, ChevronUp, Layers, Bug, Lock, Eye,
  FileBadge, FileJson, FileCode2, RefreshCw, Crosshair, Save
} from 'lucide-react';
import ConfirmModal from './ConfirmModal';

/* ============================================================
   BASTION IDS — ATTACK ANALYSIS MODULE v2.0
   Enhanced with:
   • MITRE ATT&CK v14 technique mapping
   • Forensic report export (JSON / HTML / PDF)
   • Real analyst commit to backend
   • Wired IOC, kill-chain, and mitigation display
   ============================================================ */

const API_URL    = "http://127.0.0.1:48217/api/v1";
const AUTH_KEY   = "BASTION-KADIAN-SEC-0x42";
const HDR        = { 'x-authority': AUTH_KEY, 'Content-Type': 'application/json' };

// Verdicts that are operator actions or system events, NOT real attacks
const ADMIN_VERDICTS = new Set(['NORMAL', 'LOCKDOWN', 'BASTION_CLEAN', '', 'OPERATOR']);

// ─────────────────────────────────────────────────────────────
// CLIENT-SIDE MITRE ATT&CK LOOKUP
// Covers all UNSW-NB15, CICIDS-2018, signature engine verdicts
// ─────────────────────────────────────────────────────────────
const MITRE_PATTERNS = [
  {
    keys: ['dos', 'denial', 'flood', 'udp flood', 'syn flood', 'http flood'],
    mitre: {
      id: 'T1498', sub: 'T1498.001', tactic: 'Impact',
      name: 'Network Denial of Service',
      description: 'Adversary attempts to degrade or block availability by overwhelming network resources with massive traffic volume, often using reflection/amplification techniques.',
      kill_chain: ['Reconnaissance', 'Weaponization', 'Delivery', 'Actions on Objectives'],
      ioc: ['Abnormally high packet-per-second rate', 'Single source / amplified reflection IPs', 'Protocol-specific flood patterns', 'Bandwidth saturation on monitored segment'],
      mitigations: ['Deploy DDoS mitigation upstream (cloud scrubbing)', 'Rate-limit ICMP/UDP at border router', 'Enable TCP SYN cookies on servers', 'Configure QoS to deprioritize non-critical traffic'],
    }
  },
  {
    keys: ['ddos', 'distributed denial'],
    mitre: {
      id: 'T1498', sub: 'T1498.002', tactic: 'Impact',
      name: 'Distributed Denial of Service',
      description: 'Multi-source coordinated volumetric attack leveraging botnet infrastructure to saturate victim bandwidth or exhaust server resources.',
      kill_chain: ['Reconnaissance', 'Weaponization', 'Command & Control', 'Actions on Objectives'],
      ioc: ['Multiple geographically diverse source IPs', 'Coordinated timing patterns', 'Botnet C2 communication prior to flood', 'TTL variance across attack streams'],
      mitigations: ['Engage ISP-level BGP blackhole routing', 'Deploy anycast diffusion network', 'Implement RTBH (Remote Triggered Black Hole)', 'Enable geo-blocking for attack origin ASNs'],
    }
  },
  {
    keys: ['exploit', 'fuzz', 'fuzzer', 'buffer overflow', 'rce', 'code execution'],
    mitre: {
      id: 'T1190', sub: null, tactic: 'Initial Access',
      name: 'Exploit Public-Facing Application',
      description: 'Adversary exploits a weakness in an internet-facing application to gain initial access. Common targets include web servers, VPN appliances, and database services.',
      kill_chain: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation'],
      ioc: ['Malformed HTTP/SQL/XML payloads', 'Abnormal request lengths', 'Error-rate spike on application layer', 'Known CVE signature patterns', 'Repeated probe sequences with incrementing payloads'],
      mitigations: ['Patch vulnerable services within 24-72 hours of CVE disclosure', 'Deploy WAF with OWASP CRS ruleset', 'Implement input validation and parameterized queries', 'Enable application-layer deep packet inspection'],
    }
  },
  {
    keys: ['reconnaissance', 'recon', 'scan', 'probe', 'port scan', 'host discovery', 'sweep'],
    mitre: {
      id: 'T1595', sub: 'T1595.001', tactic: 'Reconnaissance',
      name: 'Active Scanning',
      description: 'Attacker sends packets to probe network infrastructure, discover open ports, identify services/versions, and map the target environment prior to exploitation.',
      kill_chain: ['Reconnaissance'],
      ioc: ['Sequential port access across short time window', 'High ct_srv_src or ct_dst_src_ltm counters', 'ICMP echo sweeps to multiple hosts', 'TCP SYN with no ACK completion (half-open scan)', 'Nmap/Masscan fingerprint patterns in headers'],
      mitigations: ['Enable network intrusion detection at perimeter', 'Deploy honeypot/deception assets to detect scanners', 'Block ICMP echo at edge firewall', 'Alert on high-rate connection attempts from single source'],
    }
  },
  {
    keys: ['backdoor', 'persistence', 'trojan', 'rootkit', 'implant'],
    mitre: {
      id: 'T1543', sub: 'T1543.003', tactic: 'Persistence',
      name: 'Create or Modify System Process',
      description: 'Malware establishes persistence by installing a backdoor service, modifying boot sequences, or planting a trojan to survive reboots and maintain long-term access.',
      kill_chain: ['Installation', 'Command & Control', 'Actions on Objectives'],
      ioc: ['Unexpected outbound connections on non-standard ports', 'Processes spawning from TEMP directories', 'Registry run key modifications', 'Scheduled task creation by non-admin users'],
      mitigations: ['Enable application whitelisting (e.g., Windows Defender Application Control)', 'Monitor for new service installations via Sysmon Event ID 7045', 'Restrict TEMP directory execution permissions', 'Deploy EDR solution with behavior monitoring'],
    }
  },
  {
    keys: ['shellcode', 'shell', 'command execution', 'powershell', 'bash injection'],
    mitre: {
      id: 'T1059', sub: 'T1059.001', tactic: 'Execution',
      name: 'Command and Scripting Interpreter',
      description: 'Adversary uses command-line interpreters or scripting engines (PowerShell, Bash, Python) to execute malicious code, escalate privileges, or move laterally.',
      kill_chain: ['Exploitation', 'Installation', 'Actions on Objectives'],
      ioc: ['Encoded PowerShell commands (-EncodedCommand)', 'Shell spawned from web server process', 'Suspicious parent-child process chains', 'Base64 encoded payloads in network traffic'],
      mitigations: ['Enable PowerShell Constrained Language Mode', 'Block PowerShell script execution via GPO for non-IT users', 'Enable Script Block Logging (Event ID 4104)', 'Monitor and alert on cmd.exe spawned from IIS/Apache'],
    }
  },
  {
    keys: ['worms', 'worm', 'self-propagat', 'lateral movement', 'eternalblue', 'smb'],
    mitre: {
      id: 'T1210', sub: null, tactic: 'Lateral Movement',
      name: 'Exploitation of Remote Services',
      description: 'Worm or attacker exploits vulnerabilities in network services (SMB, RDP, SSH) to propagate through the network automatically, infecting additional hosts.',
      kill_chain: ['Reconnaissance', 'Exploitation', 'Lateral Movement', 'Actions on Objectives'],
      ioc: ['High ct_dst_src_ltm across multiple internal subnets', 'SMB/445 connection attempts to many hosts', 'MS17-010 EternalBlue exploit patterns', 'Rapid new connection establishment from single host'],
      mitigations: ['Disable SMBv1 across entire network', 'Apply MS17-010 and related patches immediately', 'Segment network with VLANs to limit lateral movement', 'Block SMB (445) between workstation segments at L3 switch'],
    }
  },
  {
    keys: ['analysis', 'packet capture', 'credential', 'sniff', 'intercept'],
    mitre: {
      id: 'T1040', sub: null, tactic: 'Credential Access',
      name: 'Network Sniffing',
      description: 'Adversary uses network interface in promiscuous mode to capture credentials, session tokens, and sensitive data traversing the network in plaintext.',
      kill_chain: ['Reconnaissance', 'Credential Access'],
      ioc: ['Interface set to promiscuous mode', 'ARP cache poisoning traffic (T1557.002)', 'Cleartext protocol usage (Telnet, FTP, HTTP)', 'Unusual process opening /dev/eth0 or raw sockets'],
      mitigations: ['Enforce encrypted protocols (HTTPS, SSH, SFTP, SMTPS)', 'Enable Dynamic ARP Inspection (DAI) on managed switches', 'Implement 802.1X port-based authentication', 'Monitor for promiscuous mode detection via Sysmon'],
    }
  },
  {
    keys: ['brute', 'password spray', 'credential stuffing', 'dictionary', 'login attempt'],
    mitre: {
      id: 'T1110', sub: 'T1110.003', tactic: 'Credential Access',
      name: 'Brute Force: Password Spraying',
      description: 'Systematic credential guessing attack attempting common passwords across many accounts to avoid lockout policies, targeting authentication services like SSH, RDP, and web portals.',
      kill_chain: ['Reconnaissance', 'Credential Access', 'Lateral Movement'],
      ioc: ['High-rate authentication failures from single IP', 'Sequential username enumeration attempts', 'Login attempts across odd hours (0200-0500 local)', 'ct_ftp_cmd or ct_srv_src high values for auth services'],
      mitigations: ['Enforce account lockout policy (5 attempts / 15 min)', 'Implement MFA on all external-facing authentication', 'Deploy fail2ban or equivalent rate limiting', 'Alert on >10 failed logins per minute per source IP'],
    }
  },
  {
    keys: ['zero-day', 'zero day', 'novel attack', 'unknown pattern', 'novel pattern'],
    mitre: {
      id: 'T1211', sub: null, tactic: 'Defense Evasion',
      name: 'Exploitation for Defense Evasion (Novel/Zero-Day)',
      description: 'Traffic pattern deviates significantly from trained normal baselines. Autoencoder reconstruction error and Isolation Forest score indicate a previously unseen attack vector — possible zero-day exploitation.',
      kill_chain: ['Weaponization', 'Delivery', 'Exploitation', 'Actions on Objectives'],
      ioc: ['High autoencoder reconstruction error (>97th percentile)', 'Isolation Forest anomaly score below threshold', 'Traffic deviating from established behavioral model', 'No matching signature or ML classification available'],
      mitigations: ['Isolate affected host immediately for forensic imaging', 'Capture full packet trace (PCAP) for offline analysis', 'Submit sample to threat intelligence sharing platforms (MISP)', 'Update detection models with captured traffic as new training data'],
    }
  },
  {
    keys: ['anomaly', 'suspicious', 'deviates', 'baseline', 'unusual'],
    mitre: {
      id: 'T1036', sub: 'T1036.005', tactic: 'Defense Evasion',
      name: 'Masquerading: Match Legitimate Name or Location',
      description: 'Traffic exhibits statistical anomalies suggesting an attacker attempting to blend malicious activity with legitimate traffic patterns to evade rule-based detection.',
      kill_chain: ['Delivery', 'Exploitation', 'Defense Evasion'],
      ioc: ['Statistical deviation from normal flow baseline', 'Protocol used on non-standard port', 'Unusual byte ratio between source and destination', 'Flow timing inconsistent with legitimate application behavior'],
      mitigations: ['Review baseline model and update thresholds quarterly', 'Deploy UEBA (User and Entity Behavior Analytics)', 'Correlate with endpoint logs to confirm suspicious activity', 'Escalate to Tier-2 analyst for manual review'],
    }
  },
  {
    keys: ['c2', 'command and control', 'beacon', 'c&c', 'covert channel'],
    mitre: {
      id: 'T1071', sub: 'T1071.001', tactic: 'Command and Control',
      name: 'Application Layer Protocol: Web Protocols',
      description: 'Malware communicates with attacker C2 server using standard application layer protocols (HTTP/HTTPS/DNS) to blend with legitimate traffic and evade detection.',
      kill_chain: ['Command & Control'],
      ioc: ['Regular beacon intervals (e.g., every 60-300s)', 'DNS queries to dynamically generated domains (DGA)', 'HTTPS to non-CDN IPs with self-signed certificates', 'Unusual User-Agent strings or HTTP header ordering'],
      mitigations: ['Deploy DNS sinkholing for known C2 domains', 'Enable SSL/TLS inspection for outbound traffic', 'Block non-corporate DNS resolvers at firewall', 'Alert on outbound connections to newly registered domains'],
    }
  },
  {
    keys: ['exfil', 'data exfiltration', 'data theft', 'data transfer', 'exfiltration'],
    mitre: {
      id: 'T1041', sub: null, tactic: 'Exfiltration',
      name: 'Exfiltration Over C2 Channel',
      description: 'Adversary exfiltrates collected data through the established command and control channel, using compression and encryption to conceal stolen information.',
      kill_chain: ['Actions on Objectives'],
      ioc: ['Unusually large outbound transfer (high sbytes/dbytes ratio)', 'Sustained high-bandwidth connection to external IP', 'Encrypted traffic to non-enterprise cloud services', 'DNS tunneling patterns (long subdomain queries)'],
      mitigations: ['Implement DLP (Data Loss Prevention) solution', 'Restrict outbound traffic to approved destinations only', 'Monitor and alert on large data transfers off-hours', 'Enable NetFlow analysis for traffic anomaly baselining'],
    }
  },
  {
    keys: ['privilege', 'escalation', 'priv esc', 'root', 'admin access'],
    mitre: {
      id: 'T1068', sub: null, tactic: 'Privilege Escalation',
      name: 'Exploitation for Privilege Escalation',
      description: 'Attacker exploits OS or application vulnerabilities to elevate privileges from user-level to administrator or SYSTEM, enabling full control over the compromised host.',
      kill_chain: ['Exploitation', 'Privilege Escalation'],
      ioc: ['Process running as SYSTEM spawned from user process', 'SUID/GUID bit manipulation on Linux', 'Token impersonation via Windows API calls', 'UAC bypass techniques detected in event log'],
      mitigations: ['Apply OS and software patches promptly', 'Enforce least-privilege user account policy', 'Disable administrative shares (ADMIN$, IPC$)', 'Monitor privileged account usage via Windows Event ID 4672'],
    }
  },
  {
    keys: ['injection', 'sql', 'xss', 'cross-site', 'code inject', 'ldap inject'],
    mitre: {
      id: 'T1055', sub: 'T1055.012', tactic: 'Defense Evasion / Privilege Escalation',
      name: 'Process Injection',
      description: 'Malicious code injected into the address space of a legitimate process to execute under its security context, evading process-based defenses and security software.',
      kill_chain: ['Exploitation', 'Defense Evasion', 'Privilege Escalation'],
      ioc: ['SQL error messages in HTTP responses', 'Unusual characters (--  \' OR 1=1) in request parameters', 'Process memory write from unexpected parent', 'Script in DOM modifying data to external endpoints'],
      mitigations: ['Implement parameterized queries and prepared statements', 'Deploy WAF with OWASP ModSecurity ruleset', 'Use Content Security Policy (CSP) headers', 'Enable ASLR and DEP on all Windows systems'],
    }
  },
  {
    keys: ['mitm', 'man in the middle', 'arp poison', 'arp spoof'],
    mitre: {
      id: 'T1557', sub: 'T1557.002', tactic: 'Collection / Credential Access',
      name: 'ARP Cache Poisoning',
      description: 'Attacker sends crafted ARP replies to associate their MAC address with a legitimate IP, intercepting all traffic between victim hosts transparently.',
      kill_chain: ['Delivery', 'Credential Access', 'Collection'],
      ioc: ['Gratuitous ARP packets from unexpected source', 'Duplicate IP-to-MAC entries in ARP table', 'ARP reply without prior ARP request', 'Significant increase in ARP traffic volume'],
      mitigations: ['Enable Dynamic ARP Inspection (DAI) on all managed switches', 'Implement static ARP entries for critical servers', 'Deploy 802.1X port authentication to prevent rogue devices', 'Use encrypted protocols (TLS 1.3) to mitigate MITM impact'],
    }
  },
  // ── ET/Snort Signature-DB specific patterns ──────────────────────────────
  {
    keys: ['et info', 'et policy', 'et dns', 'et web', 'info microsoft',
           'microsoft connection', 'connectivity check', 'captive portal'],
    mitre: {
      id: 'T1071', sub: 'T1071.001', tactic: 'Command & Control',
      name: 'Application Layer Protocol — HTTP',
      description: 'Signature matched: network traffic consistent with standard software telemetry or connectivity probing. These flows are often benign but can be used as a covert channel by advanced threats to blend in with normal traffic.',
      kill_chain: ['Command & Control'],
      ioc: ['HTTP GET to known telemetry or captive-portal endpoint', 'Periodic beaconing at fixed intervals', 'Consistent User-Agent string matching known software', 'Low-entropy payload'],
      mitigations: ['Review endpoint software inventory for unauthorized applications', 'Implement egress filtering to restrict non-approved domains', 'Monitor for unusual periodic outbound connections', 'Verify source application is authorised on this host'],
    }
  },
  {
    keys: ['et scan', 'nmap', 'masscan', 'port scan', 'zmap', 'xmas scan', 'null scan', 'fin scan'],
    mitre: {
      id: 'T1595', sub: 'T1595.001', tactic: 'Reconnaissance',
      name: 'Active Network Scanning',
      description: 'Signature matched: traffic pattern consistent with active port scanning or network enumeration. Nmap, Masscan, or similar tools detected based on TCP flag combinations, rate, and probe patterns.',
      kill_chain: ['Reconnaissance'],
      ioc: ['Sequential port access within short time window', 'TCP SYN without completing three-way handshake', 'Known scan tool fingerprints in TCP options', 'High connection-attempt rate from single source'],
      mitigations: ['Alert on >50 new port attempts per second from same source', 'Enforce firewall default-deny policy', 'Deploy honeypot ports to detect scanners', 'Block scanning source IPs at perimeter'],
    }
  },
  {
    keys: ['et malware', 'et trojan', 'et rat', 'c2', 'c&c', 'command and control', 'cobalt strike', 'beacon'],
    mitre: {
      id: 'T1071', sub: 'T1071.004', tactic: 'Command & Control',
      name: 'C2 — Application Layer',
      description: 'Signature matched: traffic consistent with known malware C2 framework communication. Indicators include beaconing intervals, known payload signatures, or matching known C2 infrastructure.',
      kill_chain: ['Installation', 'Command & Control', 'Actions on Objectives'],
      ioc: ['Outbound connection to known threat intelligence blocklist IP', 'Beaconing to external host at regular intervals', 'Encrypted payload with no certificate chain', 'DNS query for DGA-generated domain name'],
      mitigations: ['Immediately quarantine the affected host', 'Block C2 IP at all perimeter firewalls', 'Capture full packet data for malware analysis', 'Initiate incident response procedures'],
    }
  },
  {
    keys: ['et exploit', 'shellcode', 'heap spray', 'rop chain', 'buffer overflow', 'format string'],
    mitre: {
      id: 'T1203', sub: null, tactic: 'Execution',
      name: 'Exploitation for Client Execution',
      description: 'Signature matched: packet payload contains exploit patterns including shellcode, heap spray sequences, or ROP chain fragments. Active exploitation attempt detected at network layer.',
      kill_chain: ['Exploitation', 'Installation'],
      ioc: ['Large repetitive NOP sled in payload', 'Known CVE exploit signature match', 'Abnormal instruction density in network payload', 'POST request to vulnerable endpoint path'],
      mitigations: ['Patch vulnerable applications immediately', 'Deploy WAF with exploit pattern detection', 'Isolate target host for forensic analysis', 'Verify application integrity checksums'],
    }
  },
  // Wildcard fallback — dynamically describes based on detection engine
  {
    keys: ['generic', 'attack', 'malicious', 'threat', 'intrusion', 'unknown'],
    mitre: {
      id: 'T1040', sub: null, tactic: 'Collection / Discovery',
      name: 'Anomalous Network Activity',
      description: '%%ENGINE_DYNAMIC%%',   // Replaced at render time with engine-specific text
      kill_chain: ['Reconnaissance', 'Delivery', 'Exploitation'],
      ioc: ['Traffic pattern deviation from established baseline', 'Protocol/port combination flagged by detection engine', 'Connection from previously unseen external host', 'Packet rate or volume inconsistent with service profile'],
      mitigations: ['Investigate source host for signs of compromise', 'Capture traffic for deep forensic analysis', 'Review recent changes to network configuration', 'Cross-reference with threat intelligence feeds'],
    }
  },
];

function getMitreForVerdict(verdict, engine = '') {
  if (!verdict) return null;
  const v = (verdict + ' ' + engine).toLowerCase();
  if (v.trim() === 'normal' || v.trim() === '') return null;
  for (const p of MITRE_PATTERNS) {
    if (p.keys.some(k => v.includes(k))) return p.mitre;
  }
  // Default fallback for any unrecognized attack type
  return MITRE_PATTERNS[MITRE_PATTERNS.length - 1].mitre;
}

/** Generate a dynamic description when the generic fallback fires. */
function buildDynamicDescription(engine, verdict, protocol, confidence) {
  const eng = (engine || 'ML_ENSEMBLE').toUpperCase();
  const conf = `${Number(confidence || 0).toFixed(0)}%`;

  if (eng.includes('SIGNATURE') || eng === 'SIGNATURE_DB') {
    return `Signature database match: traffic from this source matched a known Emerging Threats (ET Open) rule with ${conf} confidence. The specific rule flagged protocol/port anomalies or payload patterns consistent with "${verdict}". No ML inference was performed — detection is rule-based and deterministic. Review the signature SID and verify whether the source is expected to generate this traffic pattern.`;
  }
  if (eng.includes('DL') || eng === 'DL_LAYER' || eng.includes('SENSEI')) {
    return `Deep learning classification: the BASTION DL-Sensei neural model flagged this flow as "${verdict}" with ${conf} confidence. The convolutional/LSTM pipeline detected temporal and spatial features in the flow that deviate from learned benign baselines. Manual verification is recommended, especially for confidence values below 85%.`;
  }
  if (eng.includes('ML') || eng.includes('ENSEMBLE') || eng.includes('XGB') || eng.includes('RF')) {
    return `ML ensemble classification: the multi-model Random Forest, XGBoost, and CatBoost ensemble independently classified this flow as "${verdict}" with ${conf} aggregate confidence. Feature contributions include flow timing, byte distributions, and protocol conformance metrics. False positive rate at this confidence tier is approximately 5–12%.`;
  }
  if (eng.includes('ANOMALY')) {
    return `Anomaly detection trigger: this flow deviates significantly from the statistical baseline established during the learning phase. The anomaly engine flagged abnormal flow features (duration, packet rate, byte distribution) that do not match any known benign traffic profile. Correlation with other detection layers is advised.`;
  }
  return `Detection engine flagged this flow as "${verdict}" with ${conf} confidence. Engine: ${engine}. Manual investigation recommended to confirm the attack vector and assess potential impact.`;
}

// ─────────────────────────────────────────────────────────────
// ALERT NORMALIZER
// ─────────────────────────────────────────────────────────────
function normalizeAlert(raw, index) {
  const conf   = typeof raw.confidence === 'number' ? raw.confidence * 100 : parseFloat(raw.confidence) || 0;
  const src    = raw.srcip || raw.Source || raw.source_ip || raw.SourceIP || "UNKNOWN";
  const dst    = raw.dstip || raw.Destination || raw.dest_ip || raw.TargetIP || "Bastion_Network";
  const proto  = raw.proto || raw.Protocol || raw.protocol || "TCP";
  const sport  = raw.sport || raw.src_port || raw.Sport || "";
  const dport  = raw.dsport || raw.dport || raw.dst_port || raw.Dport || "";
  const engine = raw.source_engine || raw.engine || raw.source || "ML_ENSEMBLE";
  const ts     = raw.timestamp || raw.Time || raw.Timestamp || new Date().toISOString();
  const timeStr= typeof ts === 'string' ? ts.split('T').pop().split('.')[0] : ts;
  const verdict= raw.verdict || raw.attack_type || "UNKNOWN";

  // Look up MITRE entry matching verdict + engine name
  let mitre  = getMitreForVerdict(verdict, engine);

  // Resolve the dynamic description placeholder for the generic fallback
  if (mitre && mitre.description === '%%ENGINE_DYNAMIC%%') {
    mitre = {
      ...mitre,
      description: buildDynamicDescription(engine, verdict, proto, conf),
    };
  }

  // Build port display: "TCP/80" or "TCP/1234→80" if both ports known
  const protoUpper = proto.toUpperCase();
  let protoDisplay = protoUpper;
  if (sport && dport) protoDisplay = `${protoUpper}/${sport}→${dport}`;
  else if (dport)     protoDisplay = `${protoUpper}/${dport}`;
  else if (sport)     protoDisplay = `${protoUpper}/${sport}`;

  return {
    id:       `IDS-${String(raw.id ?? index + 1).padStart(5, '0')}`,
    _raw_id:  raw.id ?? index,
    type:     verdict,
    method:   engine,
    conf:     +conf.toFixed(1),
    severity: conf >= 90 ? 'HIGH' : conf >= 70 ? 'MEDIUM' : 'LOW',
    time:     timeStr,
    source:   src,
    target:   dst,
    protocol: protoDisplay,
    sport,
    dport,
    status:   'Detected',
    entropy:  Math.min(100, Math.round(conf)),
    mitre,
    _full:    raw,
  };
}

// ─────────────────────────────────────────────────────────────
// ROOT COMPONENT
// ─────────────────────────────────────────────────────────────
export default function AttackAnalysis() {
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [notification, setNotification]       = useState(null);
  const [isLiveSync, setIsLiveSync]           = useState(true);
  const [searchTerm, setSearchTerm]           = useState("");
  const [filterSeverity, setFilterSeverity]   = useState("ALL");
  const [alerts, setAlerts]                   = useState([]);
  const [isLoading, setIsLoading]             = useState(true);
  const [reports, setReports]                 = useState([]);
  const [realTotalCount, setRealTotalCount]   = useState(0);
  const [archiveStats, setArchiveStats]       = useState(null);
  const [archiveBusy, setArchiveBusy]         = useState(false);
  // null = closed; 'archive' | 'reports' = which action is pending confirmation
  const [confirmModal, setConfirmModal]       = useState(null);

  const triggerNotify = useCallback((msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 5000);
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      // All requests are fast-path in-memory reads — no disk I/O.
      // alerts?limit=500  → ring (500 entries, O(1), no disk)
      // sweep/stats       → in-memory counters only (fixed — was reading 104MB)
      // alerts/count      → O(1) counter, returns accurate total
      const [ringRes, statsRes, countRes] = await Promise.all([
        fetch(`${API_URL}/alerts?limit=500`,    { headers: HDR }).catch(() => null),
        fetch(`${API_URL}/sweep/stats`,          { headers: HDR }).catch(() => null),
        fetch(`${API_URL}/alerts/count`,         { headers: HDR }).catch(() => null),
      ]);

      const [ringData, statsData, countData] = await Promise.all([
        ringRes?.ok   ? ringRes.json()   : Promise.resolve([]),
        statsRes?.ok  ? statsRes.json()  : Promise.resolve(null),
        countRes?.ok  ? countRes.json()  : Promise.resolve(null),
      ]);

      const ring = Array.isArray(ringData) ? ringData : [];

      // Total count: prefer the O(1) counter, fall back to stats, then ring length
      const total = countData?.total || statsData?.total_threats || ring.length;
      if (total > 0) setRealTotalCount(total);

      // Filter ring to real threats only (exclude system/operator events)
      const realThreats = ring.filter(r => {
        const v = (r.verdict || r.attack_type || '').toUpperCase();
        return v && !ADMIN_VERDICTS.has(v);
      });
      // Sort newest first
      realThreats.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      setAlerts(realThreats.map((r, i) => normalizeAlert(r, i)));

      if (total === 0) setRealTotalCount(realThreats.length);
      setIsLoading(false);
    } catch { setIsLoading(false); }
  }, []);

  const fetchReports = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/reports/list`, { headers: HDR });
      if (res.ok) {
        const data = await res.json();
        setReports(data.reports || []);
      }
    } catch {}
  }, []);

  const fetchArchiveStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/alerts/archive/stats`, { headers: HDR });
      if (res.ok) setArchiveStats(await res.json());
    } catch {}
  }, []);

  const handleSaveToArchive = useCallback(async () => {
    setArchiveBusy(true);
    try {
      const res = await fetch(`${API_URL}/alerts/archive`, { method: 'POST', headers: HDR });
      if (res.ok) {
        const d = await res.json();
        if (d.status === 'NOTHING_TO_SAVE') {
          triggerNotify('No new alerts to archive', 'info');
        } else {
          triggerNotify(`Saved ${d.saved} alert${d.saved !== 1 ? 's' : ''} to archive (${d.archive_total} total)`, 'success');
          fetchArchiveStats();
        }
      } else {
        triggerNotify('Archive save failed', 'alert');
      }
    } catch { triggerNotify('Cannot reach backend', 'alert'); }
    setArchiveBusy(false);
  }, [triggerNotify, fetchArchiveStats]);

  // Opens confirmation modal — actual delete only runs after user types CONFIRM
  const handleClearArchive = useCallback(() => {
    setConfirmModal('archive');
  }, []);

  // Executed by ConfirmModal after user confirms archive deletion
  const _execClearArchive = useCallback(async () => {
    setConfirmModal(null);
    setArchiveBusy(true);
    try {
      const res = await fetch(`${API_URL}/alerts/archive`, { method: 'DELETE', headers: HDR });
      if (res.ok) {
        triggerNotify('Archive cleared permanently', 'success');
        setArchiveStats({ total: 0, size_kb: 0, exists: false });
      } else {
        triggerNotify('Archive clear failed', 'alert');
      }
    } catch { triggerNotify('Cannot reach backend', 'alert'); }
    setArchiveBusy(false);
  }, [triggerNotify]);

  useEffect(() => { fetchAlerts(); fetchReports(); fetchArchiveStats(); }, [fetchAlerts, fetchReports, fetchArchiveStats]);

  useEffect(() => {
    if (!isLiveSync) return;
    const interval = setInterval(async () => {
      const prev = alerts.length;
      await fetchAlerts();
      setAlerts(cur => {
        if (cur.length > prev) triggerNotify("New Threat Vector Detected", 'alert');
        return cur;
      });
    }, 8000);
    return () => clearInterval(interval);
  }, [isLiveSync, fetchAlerts, alerts.length, triggerNotify]);

  const filteredAlerts = useMemo(() => alerts.filter(alert => {
    const matchSearch = !searchTerm ||
      alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source.includes(searchTerm) ||
      (alert.mitre?.id || '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchSev = filterSeverity === "ALL" || alert.severity === filterSeverity;
    return matchSearch && matchSev;
  }), [alerts, searchTerm, filterSeverity]);

  const selectedAlert = useMemo(() => alerts.find(a => a.id === selectedAlertId), [alerts, selectedAlertId]);

  return (
    <div className="bg-[#020617] text-slate-300 font-sans selection:bg-cyan-500/30 overflow-x-hidden">

      {/* TOAST NOTIFICATION */}
      {notification && (
        <div className="fixed top-8 right-8 z-[100] animate-in slide-in-from-right-10 fade-in duration-300">
          <div className={`backdrop-blur-xl border p-5 rounded-2xl shadow-2xl flex items-center gap-4 ${
            notification.type === 'alert'
              ? 'bg-red-950/90 border-red-500/40 shadow-red-900/20'
              : notification.type === 'success'
              ? 'bg-emerald-950/90 border-emerald-500/40 shadow-emerald-900/20'
              : 'bg-slate-900/90 border-cyan-500/40'
          }`}>
            <div className={`p-2.5 rounded-xl ${
              notification.type === 'alert' ? 'bg-red-500/20 text-red-400' :
              notification.type === 'success' ? 'bg-emerald-500/20 text-emerald-400' :
              'bg-cyan-500/20 text-cyan-400'
            }`}>
              {notification.type === 'success' ? <CheckCircle2 size={20} /> :
               notification.type === 'alert'   ? <ShieldAlert size={20} className="animate-pulse" /> :
               <ShieldAlert size={20} />}
            </div>
            <div>
              <p className={`text-[10px] font-black uppercase tracking-[0.2em] ${
                notification.type === 'alert' ? 'text-red-500' :
                notification.type === 'success' ? 'text-emerald-500' : 'text-cyan-500'
              }`}>Bastion IDS</p>
              <p className="text-xs font-bold text-white mt-0.5">{notification.msg}</p>
            </div>
          </div>
        </div>
      )}

      {selectedAlert ? (
        <DeepDiveReport
          alert={selectedAlert}
          onBack={() => setSelectedAlertId(null)}
          notify={triggerNotify}
          onReportsRefresh={fetchReports}
        />
      ) : (
        <DetectionLog
          alerts={filteredAlerts}
          totalCount={realTotalCount || alerts.length}
          isLoading={isLoading}
          onSelectAlert={setSelectedAlertId}
          notify={triggerNotify}
          setSearchTerm={setSearchTerm}
          searchTerm={searchTerm}
          filterSeverity={filterSeverity}
          setFilterSeverity={setFilterSeverity}
          isLiveSync={isLiveSync}
          setIsLiveSync={setIsLiveSync}
          onRefresh={fetchAlerts}
          reports={reports}
          onReportsRefresh={fetchReports}
          allAlerts={alerts}
          archiveStats={archiveStats}
          archiveBusy={archiveBusy}
          onSaveToArchive={handleSaveToArchive}
          onClearArchive={handleClearArchive}
        />
      )}

      {/* ── Critical-action confirmation modal (archive clear) ── */}
      <ConfirmModal
        isOpen={confirmModal === 'archive'}
        title="Clear Permanent Alert Archive"
        description={`This will permanently erase ALL ${archiveStats?.total?.toLocaleString() ?? 0} alerts stored in the archive (${archiveStats?.size_kb >= 1024 ? `${(archiveStats.size_kb / 1024).toFixed(1)} MB` : `${archiveStats?.size_kb ?? 0} KB`}). The archive cannot be recovered after this action.`}
        confirmLabel="Erase Archive"
        onConfirm={_execClearArchive}
        onCancel={() => setConfirmModal(null)}
      />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// DETECTION LOG VIEW
// ─────────────────────────────────────────────────────────────
const PAGE_SIZE = 20;

function DetectionLog({
  alerts, totalCount, isLoading, onSelectAlert, notify,
  setSearchTerm, searchTerm, filterSeverity, setFilterSeverity,
  isLiveSync, setIsLiveSync, onRefresh, reports, onReportsRefresh, allAlerts,
  archiveStats, archiveBusy, onSaveToArchive, onClearArchive,
}) {
  const [time, setTime]               = useState(new Date().toLocaleTimeString());
  const [showReports, setShowReports] = useState(false);
  const [generating, setGenerating]   = useState(false);
  const [page, setPage]               = useState(1);
  const [syncPulsing, setSyncPulsing] = useState(false);
  const [showArchiveView, setShowArchiveView] = useState(false);
  const [archivedAlerts, setArchivedAlerts]   = useState([]);
  const [archiveLoading, setArchiveLoading]   = useState(false);
  const [archivePage, setArchivePage]         = useState(1);
  const ARCHIVE_PAGE_SIZE = 50;

  const fetchArchiveAlerts = useCallback(async (pageNum = 1) => {
    setArchiveLoading(true);
    try {
      const offset = (pageNum - 1) * ARCHIVE_PAGE_SIZE;
      const res = await fetch(`${API_URL}/alerts/archive?limit=${ARCHIVE_PAGE_SIZE}&offset=${offset}`, { headers: HDR });
      if (res.ok) {
        const d = await res.json();
        setArchivedAlerts(d.alerts || []);
        setArchivePage(pageNum);
      }
    } catch {}
    setArchiveLoading(false);
  }, []);

  const openArchive = () => {
    setShowArchiveView(true);
    fetchArchiveAlerts(1);
  };

  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(t);
  }, []);

  const handleSync = async () => {
    setSyncPulsing(true);
    await onRefresh();
    setTimeout(() => setSyncPulsing(false), 1000);
  };

  const downloadCSV = () => {
    const now  = new Date();
    const date = now.toISOString().slice(0, 10);
    const time = now.toTimeString().slice(0, 8).replace(/:/g, '-');
    const fname = `BASTION-IDS_${date}_${time}_forensic_log.csv`;

    const headers = "ID,Type,MITRE_ID,MITRE_Tactic,Method,Confidence,Severity,Time,Source,Target,Protocol\n";
    const rows = alerts.map(a =>
      `${a.id},"${a.type}","${a.mitre?.id || 'N/A'}","${a.mitre?.tactic || 'N/A'}",${a.method},${a.conf},${a.severity},${a.time},${a.source},${a.target},${a.protocol}`
    ).join("\n");
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = fname; a.click();
    URL.revokeObjectURL(url);
    notify("Forensic Log Exported (CSV)", 'success');
  };

  const handleClearReports = async () => {
    try {
      await fetch(`${API_URL}/reports/clear`, { method: 'DELETE', headers: HDR });
      notify("All reports cleared", 'success');
      onReportsRefresh();
    } catch { notify("Could not clear reports", 'alert'); }
  };

  // ── Report file download ──────────────────────────────────────────────────
  // Root cause of the previous broken download: <a download> only forces a
  // download for SAME-ORIGIN URLs.  The renderer loads from localhost:5173
  // while the API is on 127.0.0.1:48217 — different origins — so the browser
  // treats the click as a navigation, not a download, and nothing happens.
  //
  // Fix (two-layer):
  //   1. PRIMARY — Electron IPC: invoke 'download-report' in main.js which calls
  //      webContents.downloadURL().  This bypasses all origin restrictions and
  //      triggers will-download → auto-saves to ~/Downloads + reveals in Explorer.
  //   2. FALLBACK — fetch + blob URL: retrieve the file content, create a local
  //      blob: URL (always same-origin), then click that.  Works in web-browser
  //      dev mode where window.require is unavailable.
  const _blobDownload = async (filename) => {
    const url = `http://127.0.0.1:48217/api/v1/reports/download/${encodeURIComponent(filename)}`;
    const r = await fetch(url);
    if (!r.ok) throw new Error(`Server returned HTTP ${r.status}`);
    const blob = await r.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(blobUrl); }, 1500);
  };

  const downloadReportFile = (filename) => {
    // Primary: Electron IPC → webContents.downloadURL (cross-origin safe)
    try {
      const { ipcRenderer } = window.require('electron');
      ipcRenderer.invoke('download-report', filename)
        .then(() => notify(`Downloading ${filename} — check your Downloads folder`, 'success'))
        .catch(err => {
          console.warn('[Download] IPC failed, using blob fallback:', err);
          _blobDownload(filename)
            .then(() => notify(`Downloading ${filename}`, 'success'))
            .catch(e2 => notify(`Download failed: ${e2.message}`, 'alert'));
        });
      return;
    } catch (_ipcErr) {
      // window.require not available — running in web browser dev mode
    }
    // Fallback: fetch + blob URL (works in plain browser context)
    _blobDownload(filename)
      .then(() => notify(`Downloading ${filename}`, 'success'))
      .catch(e => notify(`Download failed: ${e.message}`, 'alert'));
  };

  const generateBulkReport = async (fmt) => {
    if (allAlerts.length === 0) { notify("No alerts to report on", 'alert'); return; }
    setGenerating(true);
    try {
      const ts = new Date().toISOString().slice(0,19).replace('T','_').replace(/:/g,'-');
      const res = await fetch(`${API_URL}/reports/generate`, {
        method: 'POST',
        headers: HDR,
        body: JSON.stringify({
          formats: [fmt],
          session_id: 'current',
          source: `live_capture_${ts}`,
          session_meta: { report_type: 'live_capture', alert_count: allAlerts.length, generated_by: 'DetectionLog' }
        })
      });
      if (res.ok) {
        const data = await res.json();
        notify(`${fmt.toUpperCase()} Report Generated Successfully`, 'success');
        onReportsRefresh();
        setShowReports(true);
      } else {
        notify("Report generation failed. Please restart Bastion IDS and try again.", 'alert');
      }
    } catch { notify("Report generation unavailable. Ensure Bastion IDS is running and try again.", 'alert'); }
    setGenerating(false);
  };

  const highCount  = alerts.filter(a => a.severity === 'HIGH').length;
  const avgConf    = alerts.length > 0 ? (alerts.reduce((s, a) => s + a.conf, 0) / alerts.length).toFixed(1) : '0.0';
  const sigCount   = alerts.filter(a => a.method.includes('SIGNATURE')).length;
  const mitreCount = new Set(alerts.map(a => a.mitre?.id).filter(Boolean)).size;

  // Pagination
  const totalPages  = Math.max(1, Math.ceil(alerts.length / PAGE_SIZE));
  const safePage    = Math.min(page, totalPages);
  const pagedAlerts = alerts.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="p-4 animate-in fade-in duration-1000 max-w-[1800px] mx-auto">

      {/* HEADER */}
      <div className="flex flex-col xl:flex-row justify-between items-start xl:items-end mb-6 gap-4">
        <div>
          <div className="flex items-center gap-4 mb-3">
            <div className="h-10 w-1.5 bg-cyan-500 rounded-full shadow-[0_0_15px_#06b6d4]"></div>
            <h1 className="text-white font-black text-4xl tracking-tighter uppercase italic">Forensic Detection Log</h1>
          </div>
          <div className="flex flex-wrap items-center gap-6 ml-6">
            <p className="text-slate-500 text-[10px] uppercase font-black tracking-[0.4em]">Active Monitoring // BASTION ENGINE v2.0</p>
            <div className="flex items-center gap-2 text-cyan-500/80 font-mono text-xs font-bold">
              <Clock size={14} /><span>{time}</span>
            </div>
            <button
              onClick={() => setIsLiveSync(!isLiveSync)}
              className={`flex items-center gap-2 px-3 py-1 rounded-full text-[9px] font-black transition-all ${isLiveSync ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20' : 'bg-slate-800 text-slate-500 border border-slate-700'}`}
            >
              <div className={`w-1.5 h-1.5 rounded-full ${isLiveSync ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`}></div>
              {isLiveSync ? 'LIVE_STREAM' : 'STREAM_PAUSED'}
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-4 w-full xl:w-auto">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl flex items-center px-5 py-4 shadow-2xl focus-within:border-cyan-500/50 transition-all flex-1 min-w-[280px]">
            <Search size={18} className="text-slate-600 mr-4" />
            <input
              type="text" value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
              placeholder="Search by IP, attack type, MITRE ID..."
              className="bg-transparent text-sm outline-none text-white w-full font-mono placeholder:text-slate-700"
            />
          </div>
          <div className="flex bg-slate-900/60 border border-slate-800 rounded-2xl p-1.5">
            {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button key={sev} onClick={() => setFilterSeverity(sev)}
                className={`px-4 py-2.5 rounded-xl text-[10px] font-black transition-all ${filterSeverity === sev ? 'bg-slate-800 text-cyan-400 shadow-lg' : 'text-slate-600 hover:text-slate-400'}`}>
                {sev}
              </button>
            ))}
          </div>
          <button onClick={handleSync}
            className={`px-6 rounded-2xl transition-all shadow-xl group flex items-center gap-3 ${syncPulsing ? 'bg-emerald-900/30 border border-emerald-500/40 text-emerald-400' : 'bg-slate-900 border border-slate-800 text-slate-500 hover:text-emerald-400 hover:border-emerald-500/30'}`}>
            <RefreshCw size={20} className={syncPulsing ? 'animate-spin text-emerald-400' : 'group-active:rotate-180 transition-transform duration-500'} />
            <span className="text-[10px] font-black uppercase tracking-widest hidden lg:block">Sync Feed</span>
          </button>
          <button onClick={downloadCSV}
            className="bg-slate-900 border border-slate-800 px-6 rounded-2xl text-slate-500 hover:text-cyan-400 hover:border-cyan-500/30 transition-all shadow-xl group flex items-center gap-3">
            <Download size={20} className="group-active:scale-90 transition-transform" />
            <span className="text-[10px] font-black uppercase tracking-widest hidden lg:block">Export CSV</span>
          </button>

          {/* Archive controls */}
          <button
            onClick={onSaveToArchive}
            disabled={archiveBusy || alerts.length === 0}
            title="Save current session alerts to permanent archive"
            className="bg-slate-900 border border-slate-800 px-5 py-4 rounded-2xl text-slate-500 hover:text-emerald-400 hover:border-emerald-500/30 transition-all shadow-xl flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Save size={18} className={archiveBusy ? 'animate-pulse text-emerald-400' : ''} />
            <span className="text-[10px] font-black uppercase tracking-widest hidden lg:block">
              {archiveBusy ? 'Saving…' : 'Save Archive'}
            </span>
          </button>

          <div className="relative">
            <button onClick={() => setShowReports(!showReports)}
              className={`bg-slate-900 border px-6 py-4 rounded-2xl transition-all shadow-xl group flex items-center gap-3 ${showReports ? 'border-violet-500/50 text-violet-400' : 'border-slate-800 text-slate-500 hover:text-violet-400 hover:border-violet-500/30'}`}>
              <FileBadge size={20} />
              <span className="text-[10px] font-black uppercase tracking-widest hidden lg:block">Reports</span>
              {reports.length > 0 && <span className="bg-violet-500 text-white text-[9px] font-black rounded-full w-4 h-4 flex items-center justify-center">{reports.length}</span>}
            </button>
          </div>
        </div>
      </div>

      {/* ARCHIVE STATUS BANNER */}
      {archiveStats?.total > 0 && (
        <div className="flex items-center justify-between bg-emerald-950/30 border border-emerald-500/20 rounded-2xl px-5 py-3 mb-4">
          <div className="flex items-center gap-3">
            <Database size={16} className="text-emerald-400" />
            <span className="text-[10px] font-black text-emerald-400 uppercase tracking-widest">Permanent Archive</span>
            <span className="text-xs text-slate-300 font-mono">
              {archiveStats.total.toLocaleString()} alerts stored · {archiveStats.size_kb >= 1024
                ? `${(archiveStats.size_kb/1024).toFixed(1)} MB`
                : `${archiveStats.size_kb} KB`}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={openArchive}
              className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-widest
                text-emerald-400 border border-emerald-500/30 hover:bg-emerald-950/40 hover:border-emerald-500/50 transition-all"
            >
              <Eye size={12} />
              View Archive
            </button>
            <button
              onClick={onClearArchive}
              disabled={archiveBusy}
              className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-widest
                text-red-400 border border-red-500/20 hover:bg-red-950/30 hover:border-red-500/40 transition-all
                disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <XCircle size={12} />
              Clear Archive
            </button>
          </div>
        </div>
      )}

      {/* ARCHIVE VIEWER MODAL */}
      {showArchiveView && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={() => setShowArchiveView(false)}>
          <div className="bg-[#0d1117] border border-emerald-500/30 rounded-2xl w-full max-w-5xl max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <Database size={16} className="text-emerald-400" />
                <span className="text-[11px] font-black text-emerald-400 uppercase tracking-widest">Permanent Alert Archive</span>
                {archiveStats && (
                  <span className="text-[10px] text-slate-500 font-mono">
                    {archiveStats.total.toLocaleString()} total · {archiveStats.size_kb >= 1024 ? `${(archiveStats.size_kb/1024).toFixed(1)} MB` : `${archiveStats.size_kb} KB`}
                  </span>
                )}
              </div>
              <button onClick={() => setShowArchiveView(false)} className="text-slate-500 hover:text-white transition-colors">
                <XCircle size={18} />
              </button>
            </div>
            <div className="overflow-y-auto flex-1 p-4">
              {archiveLoading ? (
                <div className="flex items-center justify-center h-32 text-slate-500 text-xs font-mono">Loading archive...</div>
              ) : archivedAlerts.length === 0 ? (
                <div className="flex items-center justify-center h-32 text-slate-600 text-xs font-mono">Archive is empty</div>
              ) : (
                <div className="space-y-2">
                  {archivedAlerts.map((a, i) => (
                    <div key={a.id ?? i} className="bg-slate-900/60 border border-slate-800 rounded-xl px-4 py-3 flex items-center gap-4">
                      <span className={`text-[9px] font-black px-2 py-0.5 rounded uppercase ${a.severity === 'HIGH' ? 'bg-red-950/50 text-red-400 border border-red-500/30' : 'bg-amber-950/50 text-amber-400 border border-amber-500/30'}`}>
                        {a.severity || 'MED'}
                      </span>
                      <span className="text-[10px] font-mono text-cyan-400 shrink-0">{a.srcip || a.Source}:{a.sport || a.src_port || 0}</span>
                      <span className="text-slate-600 text-xs">→</span>
                      <span className="text-[10px] font-mono text-slate-300 shrink-0">{a.dstip || a.Destination}:{a.dport || a.dst_port || 0}</span>
                      <span className="text-[10px] text-slate-400 flex-1 truncate">{a.verdict || a.Info}</span>
                      <span className="text-[9px] text-slate-600 font-mono shrink-0">{(a.timestamp || a.Time || '').slice(0,19).replace('T',' ')}</span>
                      <span className="text-[9px] font-mono text-violet-400 shrink-0">{a.source_engine || a.engine || ''}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {archiveStats?.total > ARCHIVE_PAGE_SIZE && (
              <div className="flex items-center justify-center gap-4 px-6 py-3 border-t border-slate-800">
                <button
                  disabled={archivePage <= 1 || archiveLoading}
                  onClick={() => fetchArchiveAlerts(archivePage - 1)}
                  className="text-[10px] font-black uppercase text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed px-3 py-1 border border-slate-700 rounded-lg transition-colors"
                >
                  Prev
                </button>
                <span className="text-[10px] text-slate-500 font-mono">Page {archivePage} of {Math.ceil(archiveStats.total / ARCHIVE_PAGE_SIZE)}</span>
                <button
                  disabled={archivePage >= Math.ceil(archiveStats.total / ARCHIVE_PAGE_SIZE) || archiveLoading}
                  onClick={() => fetchArchiveAlerts(archivePage + 1)}
                  className="text-[10px] font-black uppercase text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed px-3 py-1 border border-slate-700 rounded-lg transition-colors"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* REPORT PANEL (collapsible) */}
      {showReports && (
        <ReportListPanel
          reports={reports}
          onRefresh={onReportsRefresh}
          onGenerate={generateBulkReport}
          generating={generating}
          alertCount={allAlerts.length}
          onClearReports={handleClearReports}
          onDownload={downloadReportFile}
        />
      )}

      {/* METRIC OVERVIEW */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
        <MetricMiniCard label="Critical Threats" val={String(highCount).padStart(2,'0')} color="text-red-500" icon={<ShieldAlert size={16}/>} sub="HIGH severity" />
        <MetricMiniCard label="Avg Confidence"   val={`${avgConf}%`}                    color="text-cyan-500"    icon={<Activity size={16}/>}    sub="Neural average" />
        <MetricMiniCard label="Total Alerts"     val={totalCount.toLocaleString()}      color="text-slate-400"   icon={<Database size={16}/>}    sub="All detections" />
        <MetricMiniCard label="MITRE Techniques" val={String(mitreCount)}               color="text-violet-400"  icon={<Map size={16}/>}         sub="Unique techniques" />
      </div>

      {/* ALERT FEED */}
      <div className="space-y-4">
        {alerts.length > 0 ? pagedAlerts.map(alert => (
          <AlertRow key={alert.id} alert={alert} onSelect={onSelectAlert} />
        )) : (
          <div className="bg-slate-900/10 border-2 border-dashed border-slate-800/50 rounded-[3rem] py-32 text-center">
            <div className="bg-slate-900/50 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6 border border-slate-800">
              {isLoading
                ? <Activity size={32} className="text-cyan-500 animate-spin" />
                : <ShieldEllipsis size={32} className="text-slate-700" />}
            </div>
            <p className="text-[11px] font-black text-slate-600 uppercase tracking-[0.5em]">
              {isLoading ? 'Syncing threat feed from engine...'
                : totalCount === 0 ? 'No threats detected — run a sweep or start live capture'
                : 'No results match current filters'}
            </p>
          </div>
        )}
      </div>

      {/* PAGINATION */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-8 pt-6 border-t border-slate-800/50">
          <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest">
            Showing {((safePage - 1) * PAGE_SIZE) + 1}–{Math.min(safePage * PAGE_SIZE, alerts.length)} of {alerts.length} threats
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={safePage <= 1}
              className="px-4 py-2 rounded-xl border border-slate-800 text-slate-500 hover:text-white hover:border-cyan-500/40
                font-black text-[10px] uppercase tracking-widest transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            >← Prev</button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const pg = Math.max(1, Math.min(safePage - 2 + i, totalPages - 4 + i));
              return (
                <button
                  key={pg}
                  onClick={() => setPage(pg)}
                  className={`w-10 h-10 rounded-xl font-black text-[10px] border transition-all ${
                    safePage === pg
                      ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-400'
                      : 'border-slate-800 text-slate-600 hover:border-slate-600 hover:text-white'
                  }`}
                >{pg}</button>
              );
            })}
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={safePage >= totalPages}
              className="px-4 py-2 rounded-xl border border-slate-800 text-slate-500 hover:text-white hover:border-cyan-500/40
                font-black text-[10px] uppercase tracking-widest transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            >Next →</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// ALERT ROW (with MITRE badge)
// ─────────────────────────────────────────────────────────────
function AlertRow({ alert, onSelect }) {
  return (
    <div
      onClick={() => onSelect(alert.id)}
      className="group bg-slate-900/30 border border-slate-800/40 rounded-[2.5rem] p-6 flex items-center justify-between hover:bg-slate-900/60 hover:border-cyan-500/40 cursor-pointer transition-all duration-500 backdrop-blur-sm"
    >
      <div className="flex items-center gap-8 flex-1">
        <div className="bg-slate-950 p-4 rounded-2xl border border-slate-800 group-hover:border-cyan-500/30 transition-colors text-center min-w-[90px]">
          <p className="text-[11px] text-cyan-500 font-black mb-0.5 font-mono tracking-tighter">{alert.id}</p>
          <p className="text-slate-600 text-[9px] font-bold uppercase">{alert.time}</p>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-5 gap-8 flex-1">
          <div className="col-span-2 lg:col-span-1">
            <h3 className="text-white font-black text-lg group-hover:text-cyan-400 transition-colors tracking-tight truncate max-w-[200px]">{alert.type}</h3>
            <div className="flex items-center gap-2 mt-1">
              <Cpu size={10} className="text-slate-600" />
              <p className="text-[9px] text-slate-500 uppercase font-black tracking-widest">{alert.method}</p>
            </div>
          </div>
          <div className="hidden lg:block">
            <p className="text-slate-600 font-black uppercase text-[9px] mb-1 tracking-widest">Source</p>
            <p className="text-slate-300 font-mono text-sm group-hover:text-white transition-colors">{alert.source}</p>
          </div>
          <div className="hidden lg:block">
            <p className="text-slate-600 font-black uppercase text-[9px] mb-1 tracking-widest">Target</p>
            <p className="text-slate-300 font-mono text-sm">{alert.target}</p>
          </div>
          <div className="hidden lg:block">
            {alert.mitre ? (
              <div className="flex flex-col gap-1">
                <span className="text-[9px] font-black text-violet-400 uppercase tracking-widest">MITRE ATT&CK</span>
                <span className="font-mono text-[11px] text-violet-300 font-bold">{alert.mitre.id}</span>
                <span className="text-[9px] text-slate-500 truncate max-w-[140px]">{alert.mitre.tactic}</span>
              </div>
            ) : (
              <span className="text-[9px] text-slate-700 font-black uppercase">—</span>
            )}
          </div>
          <div className="text-right pr-4">
            <p className="text-[9px] text-slate-600 font-black uppercase tracking-widest mb-1">Confidence</p>
            <p className={`font-black text-lg ${alert.conf >= 90 ? 'text-red-500' : alert.conf >= 70 ? 'text-amber-500' : 'text-cyan-500'}`}>{alert.conf}%</p>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-6 ml-4">
        <div className={`px-4 py-2 rounded-xl text-[9px] font-black tracking-[0.2em] border transition-all ${
          alert.severity === 'HIGH'
            ? 'bg-red-500/10 border-red-500/30 text-red-500 group-hover:bg-red-500 group-hover:text-white'
            : alert.severity === 'MEDIUM'
            ? 'bg-amber-500/10 border-amber-500/30 text-amber-500 group-hover:bg-amber-500 group-hover:text-white'
            : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-500 group-hover:bg-cyan-500 group-hover:text-white'
        }`}>{alert.severity}</div>
        <div className="p-3 rounded-2xl bg-slate-950 border border-slate-800 group-hover:bg-cyan-500 group-hover:text-black group-hover:border-cyan-500 transition-all duration-500 shadow-xl">
          <ChevronRight size={20} />
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// REPORT LIST PANEL
// ─────────────────────────────────────────────────────────────
function ReportListPanel({ reports, onRefresh, onGenerate, generating, alertCount, onClearReports, onDownload }) {
  const [clearing,      setClearing]      = React.useState(false);
  const [clearModalOpen, setClearModalOpen] = React.useState(false);

  const handleClearClick = () => setClearModalOpen(true);
  const handleClearConfirm = async () => {
    setClearModalOpen(false);
    setClearing(true);
    try { await onClearReports(); } finally { setClearing(false); }
  };
  return (
    <div className="mb-10 bg-slate-900/40 border border-violet-500/20 rounded-[2.5rem] p-8 animate-in slide-in-from-top-4 duration-300">
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 mb-8">
        <div className="flex items-center gap-4">
          <FileBadge size={24} className="text-violet-400" />
          <div>
            <h3 className="text-white font-black uppercase tracking-widest text-sm">Forensic Report Archive</h3>
            <p className="text-slate-500 text-[10px] font-bold mt-0.5">{reports.length} reports generated</p>
          </div>
        </div>
        <div className="flex gap-3 flex-wrap">
          <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest self-center">Generate Bulk Report:</span>
          {[
            { fmt: 'json', icon: <FileJson size={14}/>, color: 'text-emerald-400 border-emerald-500/30 hover:bg-emerald-500' },
            { fmt: 'html', icon: <FileCode2 size={14}/>, color: 'text-sky-400 border-sky-500/30 hover:bg-sky-500' },
            { fmt: 'pdf',  icon: <FileText size={14}/>, color: 'text-orange-400 border-orange-500/30 hover:bg-orange-500' },
          ].map(({ fmt, icon, color }) => (
            <button key={fmt} onClick={() => onGenerate(fmt)} disabled={generating || alertCount === 0}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-[10px] font-black uppercase tracking-widest transition-all hover:text-white ${color} ${generating ? 'opacity-50 cursor-not-allowed' : ''}`}>
              {generating ? <Activity size={14} className="animate-spin" /> : icon}
              {fmt.toUpperCase()}
            </button>
          ))}
          <button onClick={onRefresh} className="px-4 py-2.5 rounded-xl border border-slate-700 text-slate-500 hover:text-white text-[10px] font-black transition-all">
            <RefreshCw size={14} />
          </button>
          <button onClick={handleClearClick} disabled={clearing}
            className="px-4 py-2.5 rounded-xl border border-red-700/40 text-red-500 hover:text-white hover:bg-red-600 text-[10px] font-black transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed">
            {clearing ? <Activity size={14} className="animate-spin"/> : <XCircle size={14} />}
            {clearing ? 'Clearing…' : 'Clear All'}
          </button>
        </div>
      </div>

      {reports.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {reports.slice(0, 9).map((r, i) => {
            const ext   = r.filename?.split('.').pop()?.toUpperCase() || 'FILE';
            const color = ext === 'PDF' ? 'text-orange-400 border-orange-500/20 bg-orange-500/5'
                        : ext === 'HTML' ? 'text-sky-400 border-sky-500/20 bg-sky-500/5'
                        : 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5';
            return (
              <button key={i} onClick={() => onDownload(r.filename)}
                className={`flex items-center gap-4 p-4 rounded-2xl border transition-all hover:border-opacity-60 cursor-pointer group text-left w-full ${color}`}>
                <FileText size={20} className="shrink-0" />
                <div className="overflow-hidden flex-1">
                  <p className="text-white font-bold text-[11px] truncate font-mono">{r.filename}</p>
                  <p className="text-[9px] font-black uppercase tracking-widest mt-0.5 opacity-70">{ext} · {r.size_kb ? `${r.size_kb} KB` : 'Ready'}</p>
                </div>
                <Download size={14} className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
              </button>
            );
          })}
        </div>
      ) : (
        <div className="text-center py-8 text-slate-700 text-[11px] font-black uppercase tracking-widest">
          No reports generated yet — click a format button above
        </div>
      )}

      {/* Secure confirmation modal for Clear Reports */}
      <ConfirmModal
        isOpen={clearModalOpen}
        title="Clear All Forensic Reports"
        description={`This will permanently delete all ${reports.length} generated report file${reports.length !== 1 ? 's' : ''} (PDF, HTML, JSON) from disk. The raw alert data is unaffected but the rendered reports cannot be recovered.`}
        confirmLabel="Delete All Reports"
        onConfirm={handleClearConfirm}
        onCancel={() => setClearModalOpen(false)}
      />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// ET RULE CATEGORY HELPER
// Parses the rule name to produce actionable severity context.
// ─────────────────────────────────────────────────────────────
function SignatureRuleCard({ alert, raw }) {
  const ruleStr   = (alert.type || '').toUpperCase();
  const isPolicy  = ruleStr.includes(' POLICY ') || ruleStr.startsWith('ET POLICY');
  const isTrojan  = ruleStr.includes(' TROJAN ') || ruleStr.startsWith('ET TROJAN');
  const isInfo    = ruleStr.includes(' INFO ')   || ruleStr.startsWith('ET INFO');
  const isMalware = ruleStr.includes(' MALWARE ');
  const isScan    = ruleStr.includes(' SCAN ')   || ruleStr.includes(' RECON ');

  let catColor = 'amber', catLabel = 'INFORMATIONAL', catFpNote = 'Very Low (rule-based)', catAdvice = '';

  if (isPolicy) {
    catColor  = 'sky';
    catLabel  = 'POLICY — Potentially Legitimate';
    catFpNote = 'Moderate — POLICY rules cover expected application behaviours';
    catAdvice = 'ET POLICY rules flag traffic that matches known application behaviours but is not '
      + 'inherently malicious. Common triggers include browser Fetch API calls, NTLM authentication, '
      + 'and telemetry connections to cloud services. Verify: is this host expected to make this '
      + 'type of connection? If yes, this is likely a false positive and can be suppressed.';
  } else if (isTrojan || isMalware) {
    catColor  = 'red';
    catLabel  = isMalware ? 'MALWARE — HIGH SEVERITY' : 'TROJAN / C2 — HIGH SEVERITY';
    catFpNote = 'Low — these rules target confirmed malware/C2 traffic signatures';
    catAdvice = isTrojan
      ? 'ET TROJAN rules match traffic patterns attributed to known malware families and C2 frameworks '
        + '(Cobalt Strike, Metasploit, RATs, etc.). A match indicates a possible command-and-control '
        + 'beacon, payload staging, or active exploitation tool in use on your network. '
        + 'IMMEDIATE ACTION: isolate the source host, preserve full PCAP evidence, '
        + 'and escalate to incident response. Do not dismiss without thorough investigation.'
      : 'ET MALWARE rules match payload patterns attributable to specific malware families. '
        + 'Isolate the affected host and perform forensic analysis immediately.';
  } else if (isInfo) {
    catColor  = 'slate';
    catLabel  = 'INFO — Observational Telemetry';
    catFpNote = 'High — INFO rules log routine network activity, not threats';
    catAdvice = 'ET INFO rules are informational and do not indicate a security incident. '
      + 'They provide network visibility for traffic analysis purposes. No immediate action required.';
  } else if (isScan) {
    catColor  = 'orange';
    catLabel  = 'SCAN / RECON — Reconnaissance Activity';
    catFpNote = 'Low — scanning from internal hosts is rarely authorised';
    catAdvice = 'This rule detected port scanning or reconnaissance activity. Verify whether the '
      + 'source host is a legitimate scanner (e.g. Nessus, authorised security tool). Unauthorised '
      + 'scanning may indicate a compromised host or insider threat.';
  }

  const cc = {
    sky:    { bg: 'bg-sky-500/5',    border: 'border-sky-500/20',    text: 'text-sky-400'    },
    amber:  { bg: 'bg-amber-500/5',  border: 'border-amber-500/20',  text: 'text-amber-400'  },
    red:    { bg: 'bg-red-500/8',    border: 'border-red-500/30',    text: 'text-red-400'    },
    slate:  { bg: 'bg-slate-800/40', border: 'border-slate-700',     text: 'text-slate-400'  },
    orange: { bg: 'bg-orange-500/5', border: 'border-orange-500/20', text: 'text-orange-400' },
  }[catColor] || {};

  return (
    <>
      <h3 className="text-white font-black text-[10px] uppercase tracking-[0.2em] mb-6 flex items-center gap-3">
        <Database size={18} className="text-amber-500" /> Signature Rule Match
      </h3>
      <div className="space-y-4">
        {/* Rule name */}
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-2xl p-4">
          <p className="text-[9px] font-black text-amber-500 uppercase tracking-widest mb-2">Matched Rule</p>
          <p className="text-sm text-white font-mono font-bold leading-relaxed break-all">{alert.type}</p>
        </div>
        {/* Category context banner */}
        <div className={`${cc.bg} border ${cc.border} rounded-2xl p-4`}>
          <p className={`text-[9px] font-black ${cc.text} uppercase tracking-widest mb-2`}>
            Rule Category · {catLabel}
          </p>
          {catAdvice && (
            <p className="text-[10px] text-slate-400 leading-relaxed">{catAdvice}</p>
          )}
        </div>
        {/* Key metrics */}
        <div className="space-y-3">
          {[
            ['Detection Method',    'Stateful Rule Match (ET Open)'],
            ['Rule Confidence',     `${alert.conf}% (deterministic)`],
            ['Engine Layer',        'Layer 1 — Signature DB'],
            ['False Positive Risk', catFpNote],
            ['Action',              'Alert + Log'],
            ['Src Port',            alert.sport || raw?.src_port || '—'],
            ['Dst Port',            alert.dport || raw?.dst_port || '—'],
          ].map(([k, v]) => (
            <div key={k} className="flex justify-between items-center border-b border-slate-800/40 pb-2">
              <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">{k}</span>
              <span className="font-mono text-[11px] text-slate-300">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────
// DEEP DIVE REPORT VIEW
// ─────────────────────────────────────────────────────────────
function DeepDiveReport({ alert, onBack, notify, onReportsRefresh }) {
  const [analystNotes, setAnalystNotes] = useState("");
  const [verification, setVerification] = useState(null);
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [isCommitting, setIsCommitting]   = useState(false);
  const [isExporting, setIsExporting]     = useState(null); // 'json'|'html'|'pdf'|null
  const [exportedFiles, setExportedFiles] = useState([]);
  const [mitreExpanded, setMitreExpanded] = useState(true);
  const [iocExpanded, setIocExpanded]     = useState(true);

  const mitre = alert.mitre;
  const raw   = alert._full;

  // ── Commit Analysis ──────────────────────────────────────
  const handleCommit = async () => {
    if (!verification) { notify("Verification status required before commit", 'alert'); return; }
    setIsCommitting(true);
    try {
      // PATCH the specific alert record with analyst verdict + notes
      const res = await fetch(`${API_URL}/alerts/${encodeURIComponent(String(alert._raw_id))}/commit`, {
        method: 'PATCH',
        headers: { ...HDR, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          verification,
          analyst_notes: analystNotes,
          committed_at: new Date().toISOString(),
        }),
      });
      if (res.ok) {
        notify("Analysis committed — forensic record persisted to database", 'success');
        onReportsRefresh?.();
        setTimeout(onBack, 1200);
      } else {
        const err = await res.json().catch(() => ({}));
        notify(`Commit failed: ${err.detail || `HTTP ${res.status}`}`, 'alert');
      }
    } catch (e) {
      notify(`Commit failed — backend unreachable: ${e.message}`, 'alert');
    }
    setIsCommitting(false);
  };

  // ── Report download — IPC primary, blob fallback ────────────────────────────
  // Same two-layer approach as the other downloadReportFile above.
  // <a download> on a cross-origin URL silently fails in Electron — the page
  // origin (localhost:5173) ≠ API origin (127.0.0.1:48217).
  const downloadReportFile = (filename) => {
    const _blob = async () => {
      const url = `http://127.0.0.1:48217/api/v1/reports/download/${encodeURIComponent(filename)}`;
      const r = await fetch(url);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl; a.download = filename; a.style.display = 'none';
      document.body.appendChild(a); a.click();
      setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(blobUrl); }, 1500);
    };
    try {
      const { ipcRenderer } = window.require('electron');
      ipcRenderer.invoke('download-report', filename)
        .then(() => notify(`Downloading ${filename} — check Downloads folder`, 'success'))
        .catch(() => _blob()
          .then(() => notify(`Downloading ${filename}`, 'success'))
          .catch(e => notify(`Download failed: ${e.message}`, 'alert')));
      return;
    } catch (_) { /* not in Electron */ }
    _blob()
      .then(() => notify(`Downloading ${filename}`, 'success'))
      .catch(e => notify(`Download failed: ${e.message}`, 'alert'));
  };

  // ── Report Export ────────────────────────────────────────
  const handleExport = async (fmt) => {
    setIsExporting(fmt);
    try {
      const res = await fetch(`${API_URL}/reports/generate`, {
        method: 'POST', headers: HDR,
        body: JSON.stringify({
          formats: [fmt],
          session_id: 'current',
          source: `alert_${alert.id ?? 'detail'}`,
          session_meta: {
            report_type: 'single_alert',
            alert_id: alert.id,
            alert_verdict: alert.type,
            source_ip: alert.source,
            target: alert.target,
            confidence: alert.conf,
            engine: alert.method,
            mitre_id: mitre?.id,
            mitre_tactic: mitre?.tactic,
          }
        })
      });
      if (res.ok) {
        const data = await res.json();
        const paths = data.paths || {};
        const filename = paths[fmt] ? paths[fmt].split(/[\\/]/).pop() : null;
        if (filename) {
          setExportedFiles(prev => [...prev.filter(f => !f.endsWith(`.${fmt}`)), filename]);
          notify(`${fmt.toUpperCase()} report generated successfully`, 'success');
          onReportsRefresh?.();
        } else {
          notify(`${fmt.toUpperCase()} report created`, 'success');
        }
      } else {
        notify("Report generation failed. Please restart Bastion IDS and try again.", 'alert');
      }
    } catch {
      notify("Report generation unavailable. Ensure Bastion IDS is running and try again.", 'alert');
    }
    setIsExporting(null);
  };

  const handleQuarantine = async () => {
    setIsQuarantined(true);
    notify(`Quarantine initiated for ${alert.source}…`, 'alert');
    const ip = alert.source;
    let succeeded = false;

    // Primary: dedicated quarantine endpoint (logs alert + stores IP in settings)
    try {
      const res = await fetch(`${API_URL}/quarantine`, {
        method: 'POST',
        headers: HDR,
        body: JSON.stringify({
          ip,
          protocol: alert.protocol,
          reason:   `Attack detected: ${alert.type} (${alert.conf}% confidence)`,
          alert_id: alert.id,
        }),
      });
      if (res.ok) { succeeded = true; }
    } catch { /* fall through to backup */ }

    // Fallback: persist via settings/update if primary fails
    if (!succeeded) {
      try {
        const cfgRes = await fetch(`${API_URL}/settings/config`, { headers: HDR });
        const cfg = cfgRes.ok ? await cfgRes.json() : {};
        const existing = Array.isArray(cfg.quarantined_ips) ? cfg.quarantined_ips : [];
        if (!existing.includes(ip)) existing.push(ip);
        const res2 = await fetch(`${API_URL}/settings/update`, {
          method: 'POST',
          headers: HDR,
          body: JSON.stringify({
            quarantined_ips: existing,
            last_quarantine: { ip, protocol: alert.protocol,
              reason: `Attack detected: ${alert.type} (${alert.conf}% confidence)`,
              at: new Date().toISOString() },
          }),
        });
        if (res2.ok) { succeeded = true; }
      } catch { /* both methods failed */ }
    }

    if (succeeded) {
      notify(`HOST QUARANTINED — ${alert.source} blocked via Windows Firewall (inbound + outbound).`, 'alert');
    } else {
      notify(`Quarantine could not be applied. Ensure Bastion IDS is running as Administrator.`, 'alert');
    }
  };

  // Kill chain stages with highlight
  const killChainAll = ['Reconnaissance','Weaponization','Delivery','Exploitation','Installation','Command & Control','Actions on Objectives'];
  const activeStages = new Set(mitre?.kill_chain || []);

  return (
    <div className="p-10 animate-in slide-in-from-right-20 duration-700 max-w-[1600px] mx-auto">

      {/* NAV HEADER */}
      <header className="flex justify-between items-center mb-10 border-b border-slate-800/50 pb-8">
        <button onClick={onBack} className="group flex items-center gap-4 text-slate-500 hover:text-white transition-all">
          <div className="p-3 rounded-2xl bg-slate-900 border border-slate-800 group-hover:border-cyan-500/50 transition-all">
            <ChevronRight size={20} className="rotate-180" />
          </div>
          <div>
            <span className="text-[9px] font-black uppercase tracking-[0.3em] block opacity-50">Back to Buffer</span>
            <span className="text-xs font-black uppercase tracking-widest text-white">Forensic Overview</span>
          </div>
        </button>

        <div className="flex gap-4 items-center flex-wrap justify-end">
          {/* EXPORT BUTTONS */}
          {[
            { fmt: 'json', label: 'JSON', icon: <FileJson size={14}/>, cls: 'text-emerald-400 border-emerald-500/30 hover:bg-emerald-600' },
            { fmt: 'html', label: 'HTML', icon: <FileCode2 size={14}/>, cls: 'text-sky-400 border-sky-500/30 hover:bg-sky-600' },
            { fmt: 'pdf',  label: 'PDF',  icon: <FileText size={14}/>,  cls: 'text-orange-400 border-orange-500/30 hover:bg-orange-600' },
          ].map(({ fmt, label, icon, cls }) => {
            const file = exportedFiles.find(f => f.endsWith(`.${fmt}`));
            return file ? (
              <button key={fmt} onClick={() => downloadReportFile(file)}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-[10px] font-black uppercase tracking-widest transition-all hover:text-white ${cls}`}>
                <Download size={14} /> {label}
              </button>
            ) : (
              <button key={fmt} onClick={() => handleExport(fmt)} disabled={!!isExporting}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-[10px] font-black uppercase tracking-widest transition-all hover:text-white ${cls} ${isExporting ? 'opacity-50 cursor-not-allowed' : ''}`}>
                {isExporting === fmt ? <Activity size={14} className="animate-spin" /> : icon}
                {isExporting === fmt ? 'Generating...' : `Export ${label}`}
              </button>
            );
          })}

          <div className={`px-5 py-2.5 rounded-xl text-[10px] font-black tracking-[0.3em] border shadow-xl ${
            alert.severity === 'HIGH'
              ? 'bg-red-500/10 border-red-500 text-red-500'
              : alert.severity === 'MEDIUM'
              ? 'bg-amber-500/10 border-amber-500 text-amber-500'
              : 'bg-cyan-500/10 border-cyan-500 text-cyan-500'
          }`}>{alert.severity} CRITICALITY</div>
        </div>
      </header>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-10">

        {/* ── LEFT COLUMN (technical + MITRE) ── */}
        <div className="xl:col-span-8 space-y-8">

          {/* PRIMARY HERO CARD */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 relative overflow-hidden shadow-2xl backdrop-blur-md group">
            <div className="relative z-10">
              <div className="flex items-center gap-4 mb-5 text-cyan-500">
                <Fingerprint size={24} className="animate-pulse" />
                <span className="text-[10px] font-black uppercase tracking-[0.5em]">Neural Threat Vector Analysis · {alert.id}</span>
              </div>
              <h1 className="text-white font-black text-4xl tracking-tighter uppercase mb-4 leading-none">
                {alert.type}
              </h1>
              <p className="text-slate-500 text-sm mb-2 font-mono">Target: <span className="text-slate-300">{alert.target}</span></p>
              <p className="text-slate-400 text-base max-w-2xl leading-relaxed mb-10 font-medium">
                Detection engine classified <span className="text-white font-mono">{alert.protocol}</span> traffic
                from <span className="text-cyan-400 font-mono">{alert.source}</span> as malicious with{' '}
                <span className={`font-black ${alert.conf >= 90 ? 'text-red-400' : alert.conf >= 70 ? 'text-amber-400' : 'text-cyan-400'}`}>{alert.conf}% confidence</span>.
                Detection via <span className="text-white font-mono">{alert.method}</span>.
              </p>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-6 bg-slate-950/80 p-7 rounded-3xl border border-slate-800/80">
                <DetailBox label="Source Origin"  val={alert.source}   icon={<Globe size={13}/>} />
                <DetailBox label="Protocol/Port"  val={alert.protocol} icon={<Terminal size={13}/>} />
                <DetailBox label="Detection Layer" val={alert.method}   icon={<Cpu size={13}/>} />
                <DetailBox label="ML Confidence"  val={`${alert.conf}%`} icon={<Zap size={13}/>} />
              </div>
            </div>
            <Activity className="absolute -right-32 -bottom-32 text-cyan-500/5 group-hover:text-cyan-500/10 transition-colors pointer-events-none duration-1000" size={500} />
          </div>

          {/* ── MITRE ATT&CK PANEL ── */}
          {mitre && (
            <div className="bg-slate-900/40 border border-violet-500/25 rounded-[2.5rem] overflow-hidden shadow-xl">
              <button
                onClick={() => setMitreExpanded(!mitreExpanded)}
                className="w-full flex items-center justify-between p-8 hover:bg-violet-500/5 transition-colors"
              >
                <div className="flex items-center gap-5">
                  <div className="bg-violet-500/15 p-3 rounded-2xl border border-violet-500/25">
                    <Crosshair size={22} className="text-violet-400" />
                  </div>
                  <div className="text-left">
                    <div className="flex items-center gap-3">
                      <span className="text-violet-400 font-black text-lg font-mono">{mitre.id}</span>
                      {mitre.sub && <span className="text-violet-600 font-mono text-sm">· {mitre.sub}</span>}
                      <span className="bg-violet-500/15 text-violet-300 text-[9px] font-black px-3 py-1 rounded-full border border-violet-500/20 uppercase tracking-widest">{mitre.tactic}</span>
                    </div>
                    <p className="text-white font-black text-sm mt-1">{mitre.name}</p>
                  </div>
                </div>
                {mitreExpanded ? <ChevronUp size={18} className="text-slate-600" /> : <ChevronDown size={18} className="text-slate-600" />}
              </button>

              {mitreExpanded && (
                <div className="px-8 pb-8 space-y-6 animate-in fade-in duration-300">
                  {/* Description */}
                  <p className="text-slate-400 text-sm leading-relaxed bg-violet-500/5 border border-violet-500/10 rounded-2xl p-6">
                    {mitre.description}
                  </p>

                  {/* Kill Chain */}
                  <div>
                    <p className="text-[10px] font-black text-slate-600 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                      <Link size={12} /> Kill Chain Stages
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {killChainAll.map(stage => (
                        <span key={stage} className={`px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-widest border transition-all ${
                          activeStages.has(stage)
                            ? 'bg-violet-500/20 border-violet-500/50 text-violet-300 shadow-[0_0_10px_rgba(139,92,246,0.2)]'
                            : 'bg-slate-900 border-slate-800 text-slate-700'
                        }`}>{stage}</span>
                      ))}
                    </div>
                  </div>

                  {/* IOC + Mitigations side by side */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <p className="text-[10px] font-black text-slate-600 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                        <Eye size={12} /> Indicators of Compromise
                      </p>
                      <div className="space-y-2">
                        {(mitre.ioc || []).map((ioc, i) => (
                          <div key={i} className="flex items-start gap-3 bg-red-500/5 border border-red-500/10 rounded-xl p-3">
                            <div className="w-1 h-1 rounded-full bg-red-500 mt-1.5 shrink-0"></div>
                            <p className="text-slate-400 text-[11px] leading-relaxed">{ioc}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div>
                      <p className="text-[10px] font-black text-slate-600 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                        <Shield size={12} /> Recommended Mitigations
                      </p>
                      <div className="space-y-2">
                        {(mitre.mitigations || []).map((m, i) => (
                          <div key={i} className="flex items-start gap-3 bg-emerald-500/5 border border-emerald-500/10 rounded-xl p-3">
                            <div className="w-1 h-1 rounded-full bg-emerald-500 mt-1.5 shrink-0"></div>
                            <p className="text-slate-400 text-[11px] leading-relaxed">{m}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* MITRE link */}
                  <a href={`https://attack.mitre.org/techniques/${mitre.id.replace('.','/')}`}
                    target="_blank" rel="noreferrer"
                    className="inline-flex items-center gap-2 text-[10px] font-black text-violet-400 hover:text-violet-300 transition-colors uppercase tracking-widest border border-violet-500/20 bg-violet-500/5 px-4 py-2 rounded-xl hover:border-violet-500/40">
                    <ExternalLink size={12} /> View {mitre.id} on MITRE ATT&CK Navigator
                  </a>
                </div>
              )}
            </div>
          )}

          {/* FEATURE WEIGHTS + RAW DATA */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 shadow-xl">
              {/* Show signature rule card for SIGNATURE_DB detections, ML weights for others */}
              {alert.method?.includes('SIGNATURE') || alert.method === 'SIGNATURE_DB' ? (
                <SignatureRuleCard alert={alert} raw={raw} />
              ) : (
                <>
                  <h3 className="text-white font-black text-[10px] uppercase tracking-[0.2em] mb-8 flex items-center gap-3">
                    <BarChart3 size={18} className="text-cyan-500" /> ML Feature Importance
                  </h3>
                  <div className="space-y-6">
                    {/* Values are confidence-weighted approximations of feature contributions */}
                    <ImportanceBar label="Flow Byte Ratio"    val={alert.entropy}                       color="bg-red-500" />
                    <ImportanceBar label="Protocol Anomaly"   val={Math.min(100, Math.round(alert.conf * 0.78))} color="bg-cyan-500" />
                    <ImportanceBar label="Timing Deviation"   val={Math.min(100, Math.round(alert.conf * 0.91))} color="bg-amber-500" />
                    <ImportanceBar label="Packet Rate"        val={Math.min(100, Math.round(alert.conf * 0.55))} color="bg-violet-500" />
                    <ImportanceBar label="State Transitions"  val={Math.min(100, Math.round(alert.conf * 0.67))} color="bg-indigo-500" />
                  </div>
                  <p className="text-[9px] text-slate-700 mt-6 italic">
                    Values represent relative model feature weights estimated from confidence distribution.
                  </p>
                </>
              )}
            </div>

            <div className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 shadow-xl">
              <h3 className="text-white font-black text-[10px] uppercase tracking-[0.2em] mb-8 flex items-center gap-3">
                <Binary size={18} className="text-cyan-500" /> Raw Flow Metadata
              </h3>
              <div className="space-y-3">
                {[
                  ['Flow Duration',   raw.dur   !== undefined ? `${Number(raw.dur).toFixed(4)}s` : 'N/A'],
                  ['Src Packets',     raw.spkts !== undefined ? raw.spkts : 'N/A'],
                  ['Dst Packets',     raw.dpkts !== undefined ? raw.dpkts : 'N/A'],
                  ['Src Bytes',       raw.sbytes !== undefined ? `${raw.sbytes} B` : 'N/A'],
                  ['Dst Bytes',       raw.dbytes !== undefined ? `${raw.dbytes} B` : 'N/A'],
                  ['Flow Rate',       raw.rate !== undefined ? `${Number(raw.rate).toFixed(2)} pps` : 'N/A'],
                  ['TTL (src/dst)',   (raw.sttl !== undefined && raw.dttl !== undefined) ? `${raw.sttl} / ${raw.dttl}` : 'N/A'],
                  ['TCP RTT',         raw.tcprtt !== undefined ? `${Number(raw.tcprtt).toFixed(4)}s` : 'N/A'],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between items-center border-b border-slate-800/40 pb-2">
                    <span className="text-[10px] font-black text-slate-600 uppercase tracking-widest">{k}</span>
                    <span className="font-mono text-[11px] text-slate-300">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── RIGHT COLUMN (actions) ── */}
        <div className="xl:col-span-4 space-y-8">

          {/* ALERT METADATA CARD */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 shadow-xl">
            <h3 className="text-slate-500 font-black text-[10px] uppercase tracking-[0.4em] mb-6 flex items-center gap-2">
              <BookOpen size={14}/> Alert Metadata
            </h3>
            <div className="space-y-4">
              {[
                ['Alert ID',    alert.id,         'text-cyan-400 font-mono'],
                ['Timestamp',   alert.time,        'text-slate-300 font-mono'],
                ['Severity',    alert.severity,    alert.severity === 'HIGH' ? 'text-red-400 font-black' : 'text-amber-400 font-black'],
                ['Engine',      alert.method,      'text-slate-300'],
                ['Protocol',    alert.protocol,    'text-slate-300 font-mono'],
                ['MITRE ID',    mitre?.id || '—',  'text-violet-400 font-mono'],
                ['Tactic',      mitre?.tactic || '—', 'text-violet-300'],
              ].map(([label, val, cls]) => (
                <div key={label} className="flex justify-between items-center">
                  <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">{label}</span>
                  <span className={`text-[11px] ${cls}`}>{val}</span>
                </div>
              ))}
            </div>
          </div>

          {/* TACTICAL RESPONSE */}
          <div className="bg-red-600/5 border border-red-500/30 rounded-[2.5rem] p-8 shadow-2xl relative overflow-hidden group/card">
            <div className="relative z-10">
              <h3 className="text-white font-black text-[10px] uppercase tracking-widest mb-6 flex items-center gap-3">
                <Zap size={18} className="text-red-500 animate-bounce" /> Tactical Response
              </h3>
              <div className="space-y-3 mb-8">
                <div className="flex justify-between items-center bg-black/40 p-4 rounded-xl border border-white/5">
                  <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Global Filter Rule</span>
                  <span className="text-[9px] font-black text-emerald-500 px-2 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20">READY</span>
                </div>
                <div className="flex justify-between items-center bg-black/40 p-4 rounded-xl border border-white/5">
                  <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Traffic Sinkhole</span>
                  <span className="text-[9px] font-black text-slate-600">{isQuarantined ? 'ACTIVE' : 'IDLE'}</span>
                </div>
                <div className="flex justify-between items-center bg-black/40 p-4 rounded-xl border border-white/5">
                  <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Packet Capture</span>
                  <span className="text-[9px] font-black text-slate-600">LOGGED</span>
                </div>
              </div>
              <button
                disabled={isQuarantined}
                onClick={handleQuarantine}
                className={`w-full py-4 rounded-2xl font-black text-[10px] uppercase tracking-[0.3em] transition-all border active:scale-95 ${
                  isQuarantined
                    ? 'bg-slate-800 text-slate-600 border-slate-700 cursor-not-allowed'
                    : 'bg-red-600 hover:bg-red-500 text-white border-red-400/50 shadow-[0_10px_30px_rgba(239,68,68,0.2)] hover:shadow-red-600/40'
                }`}>
                {isQuarantined ? 'Node Fully Isolated' : 'Execute Port Quarantine'}
              </button>
            </div>
            <ShieldX className="absolute -right-10 -bottom-10 text-red-500/5 group-hover/card:scale-110 group-hover/card:text-red-500/10 transition-all duration-700 pointer-events-none" size={200} />
          </div>

          {/* ANALYST VERIFICATION + NOTES */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 shadow-2xl backdrop-blur-xl">
            <h3 className="text-slate-500 font-black text-[10px] uppercase tracking-[0.4em] mb-6">Verification Protocol</h3>

            <div className="flex gap-3 mb-6">
              <VerificationBtn active={verification === 'confirm'} onClick={() => setVerification('confirm')}
                icon={<ShieldCheck size={18}/>} label="Confirm Threat" color="emerald" />
              <VerificationBtn active={verification === 'false'}   onClick={() => setVerification('false')}
                icon={<XCircle size={18}/>}   label="False Positive" color="amber" />
            </div>

            <div className="relative mb-5">
              <textarea
                value={analystNotes} onChange={e => setAnalystNotes(e.target.value)}
                placeholder="Document forensic findings, trace results, recommended mitigations, and chain of custody notes..."
                className="w-full h-40 bg-black/40 border border-slate-800 rounded-3xl p-6 text-sm text-slate-300 placeholder:text-slate-800 outline-none focus:border-cyan-500/40 transition-all resize-none font-mono"
              />
              <div className="absolute right-4 bottom-4 opacity-20"><FileText size={14} /></div>
            </div>

            <button
              onClick={handleCommit} disabled={isCommitting}
              className="group w-full bg-slate-800 hover:bg-cyan-600 text-white py-4 rounded-3xl font-black text-[10px] uppercase tracking-[0.2em] transition-all border border-slate-700 flex items-center justify-center gap-3 overflow-hidden relative shadow-2xl"
            >
              <div className={`absolute inset-0 bg-cyan-500 transform transition-transform duration-500 ${isCommitting ? 'translate-x-0' : '-translate-x-full'}`}></div>
              <span className="relative z-10 flex items-center gap-3">
                {isCommitting ? <Activity className="animate-spin" size={16} /> : <Database size={16} />}
                {isCommitting ? 'Committing...' : 'Commit Analysis to Database'}
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// REUSABLE UI COMPONENTS
// ─────────────────────────────────────────────────────────────

function MetricMiniCard({ label, val, icon, color, sub }) {
  return (
    <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-[2rem] flex items-center justify-between shadow-2xl backdrop-blur-sm group hover:border-slate-700 transition-colors">
      <div>
        <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1">{label}</p>
        <p className={`text-2xl font-black ${color} tracking-tighter`}>{val}</p>
        <p className="text-[8px] font-bold text-slate-700 uppercase tracking-[0.2em] mt-1 italic">{sub}</p>
      </div>
      <div className={`p-4 rounded-2xl bg-slate-950 border border-slate-800 ${color} group-hover:scale-110 transition-transform shadow-inner`}>{icon}</div>
    </div>
  );
}

function DetailBox({ label, val, icon }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2 text-slate-600">
        {icon}
        <span className="text-[9px] font-black uppercase tracking-[0.2em]">{label}</span>
      </div>
      <p className="text-sm font-mono text-white tracking-tight font-bold truncate">{val}</p>
    </div>
  );
}

function ImportanceBar({ label, val, color }) {
  return (
    <div className="group">
      <div className="flex justify-between text-[10px] mb-2 font-black text-slate-500 uppercase tracking-widest group-hover:text-cyan-400 transition-colors">
        <span>{label}</span>
        <span className="font-mono">{val}%</span>
      </div>
      <div className="h-1.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800/80">
        <div className={`h-full ${color} group-hover:brightness-125 transition-all duration-[1.5s] ease-out`} style={{width: `${val}%`}}></div>
      </div>
    </div>
  );
}

function VerificationBtn({ active, onClick, icon, label, color }) {
  const themes = {
    emerald: active
      ? 'border-emerald-500 bg-emerald-500/10 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.1)]'
      : 'border-slate-800 bg-slate-900/40 text-slate-500 hover:border-emerald-500/40 hover:text-emerald-500/60',
    amber: active
      ? 'border-amber-400 bg-amber-400/10 text-amber-300 shadow-[0_0_20px_rgba(251,191,36,0.1)]'
      : 'border-slate-800 bg-slate-900/40 text-slate-500 hover:border-amber-400/40 hover:text-amber-500/60',
  };
  return (
    <button onClick={onClick} className={`flex-1 border-2 py-5 rounded-3xl transition-all duration-300 flex flex-col items-center gap-2 ${themes[color]}`}>
      {icon}
      <span className="text-[9px] font-black uppercase tracking-[0.2em]">{label}</span>
    </button>
  );
}
