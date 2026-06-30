"""
BASTION IDS — COMPREHENSIVE MITRE ATT&CK MAPPING DATABASE
===========================================================
Maps every known attack class, signature pattern, and anomaly type
to its full MITRE ATT&CK framework entry (Tactic + Technique + Sub-technique).

Coverage:
  - UNSW-NB15 attack categories
  - CICIDS 2018 attack categories
  - ET-Open signature classtypes
  - Common heuristic rule patterns
  - Zero-day / anomaly detections
  - All major MITRE ATT&CK v14 techniques

Reference: https://attack.mitre.org/
"""

from typing import Dict, Any

# ─────────────────────────────────────────────────────────────
# FULL MITRE ATT&CK TECHNIQUE CATALOG
# ─────────────────────────────────────────────────────────────
TECHNIQUES: Dict[str, Dict[str, Any]] = {

    # ── Reconnaissance ──────────────────────────────────────
    "T1595": {
        "id":"T1595","tactic":"Reconnaissance","name":"Active Scanning",
        "description":"Adversaries scan victim infrastructure to gather actionable information.",
        "mitigations":["M1056: Pre-compromise — monitor for unusual scan activity",
                       "Deploy honeypots to detect reconnaissance activity",
                       "Rate-limit inbound connections per source IP"],
        "severity":"MEDIUM"
    },
    "T1595.001": {
        "id":"T1595.001","tactic":"Reconnaissance","name":"Scanning IP Blocks",
        "description":"Scanning ranges of IP addresses to identify live hosts.",
        "mitigations":["Deploy IDS/IPS rules for sweep scan patterns",
                       "Use firewall geo-IP blocking for unexpected scan sources"],
        "severity":"MEDIUM"
    },
    "T1595.002": {
        "id":"T1595.002","tactic":"Reconnaissance","name":"Vulnerability Scanning",
        "description":"Scanning for vulnerabilities in services or software.",
        "mitigations":["Keep all services patched and up to date",
                       "Deploy a WAF to absorb vulnerability probe traffic"],
        "severity":"HIGH"
    },
    "T1592": {
        "id":"T1592","tactic":"Reconnaissance","name":"Gather Victim Host Information",
        "description":"Adversaries gather information about the victim's hosts.",
        "mitigations":["Limit public exposure of version banners and service headers"],
        "severity":"LOW"
    },
    "T1046": {
        "id":"T1046","tactic":"Discovery","name":"Network Service Discovery",
        "description":"Adversaries enumerate services running on remote hosts.",
        "mitigations":["Use host-based firewalls to restrict port exposure",
                       "Monitor for port scanning tools like Nmap"],
        "severity":"MEDIUM"
    },

    # ── Initial Access ───────────────────────────────────────
    "T1190": {
        "id":"T1190","tactic":"Initial Access","name":"Exploit Public-Facing Application",
        "description":"Exploiting a weakness in an internet-facing application.",
        "mitigations":["Patch vulnerable applications promptly",
                       "Deploy Web Application Firewall (WAF)",
                       "Perform regular vulnerability assessments"],
        "severity":"HIGH"
    },
    "T1133": {
        "id":"T1133","tactic":"Initial Access","name":"External Remote Services",
        "description":"Leveraging external remote services (VPN, RDP, SSH) to gain initial access.",
        "mitigations":["Use multi-factor authentication (MFA) on all remote access",
                       "Restrict RDP/SSH access to VPN-only",
                       "Monitor for login attempts from unusual geo-locations"],
        "severity":"HIGH"
    },
    "T1078": {
        "id":"T1078","tactic":"Initial Access","name":"Valid Accounts",
        "description":"Using valid credentials (stolen or compromised) for access.",
        "mitigations":["Enforce strong password policies",
                       "Enable MFA","Monitor for anomalous logon activity"],
        "severity":"HIGH"
    },
    "T1566": {
        "id":"T1566","tactic":"Initial Access","name":"Phishing",
        "description":"Phishing messages used to gain access to victim systems.",
        "mitigations":["Train users to identify phishing","Implement email filtering"],
        "severity":"HIGH"
    },

    # ── Execution ────────────────────────────────────────────
    "T1059": {
        "id":"T1059","tactic":"Execution","name":"Command and Scripting Interpreter",
        "description":"Abuse of scripting interpreters to execute malicious commands.",
        "mitigations":["Disable unnecessary scripting features",
                       "Use application whitelisting"],
        "severity":"HIGH"
    },
    "T1055": {
        "id":"T1055","tactic":"Execution","name":"Process Injection",
        "description":"Injecting code into processes to evade defenses.",
        "mitigations":["Use endpoint protection with behavior monitoring",
                       "Monitor for unusual memory operations"],
        "severity":"HIGH"
    },
    "T1203": {
        "id":"T1203","tactic":"Execution","name":"Exploitation for Client Execution",
        "description":"Exploiting software vulnerabilities to execute malicious code.",
        "mitigations":["Keep software and OS patched","Use exploit mitigation technologies"],
        "severity":"HIGH"
    },
    "T1204": {
        "id":"T1204","tactic":"Execution","name":"User Execution",
        "description":"Relying on user action to execute malicious code.",
        "mitigations":["User awareness training","Endpoint protection"],
        "severity":"MEDIUM"
    },

    # ── Persistence ──────────────────────────────────────────
    "T1543": {
        "id":"T1543","tactic":"Persistence","name":"Create or Modify System Process",
        "description":"Adversaries create or modify system processes to maintain persistence.",
        "mitigations":["Monitor for new or modified system services",
                       "Restrict service creation to admins",
                       "Use file integrity monitoring (FIM)"],
        "severity":"HIGH"
    },
    "T1547": {
        "id":"T1547","tactic":"Persistence","name":"Boot or Logon Autostart Execution",
        "description":"Gaining persistence by modifying autostart entries.",
        "mitigations":["Monitor autorun/startup registry keys",
                       "Audit scheduled tasks regularly"],
        "severity":"HIGH"
    },
    "T1136": {
        "id":"T1136","tactic":"Persistence","name":"Create Account",
        "description":"Creating accounts to maintain persistent access.",
        "mitigations":["Monitor for new account creation",
                       "Enforce account management policies"],
        "severity":"HIGH"
    },

    # ── Privilege Escalation ─────────────────────────────────
    "T1068": {
        "id":"T1068","tactic":"Privilege Escalation",
        "name":"Exploitation for Privilege Escalation",
        "description":"Exploiting vulnerabilities to gain elevated privileges.",
        "mitigations":["Patch privilege escalation vulnerabilities promptly",
                       "Limit administrator accounts"],
        "severity":"HIGH"
    },
    "T1548": {
        "id":"T1548","tactic":"Privilege Escalation",
        "name":"Abuse Elevation Control Mechanism",
        "description":"Abusing mechanisms like UAC to escalate privileges.",
        "mitigations":["Enforce UAC policies","Monitor privilege escalation events"],
        "severity":"HIGH"
    },

    # ── Defense Evasion ──────────────────────────────────────
    "T1036": {
        "id":"T1036","tactic":"Defense Evasion","name":"Masquerading",
        "description":"Manipulating name, location, or attributes of files/processes.",
        "mitigations":["Monitor for files/processes with unusual names",
                       "Use file integrity monitoring"],
        "severity":"MEDIUM"
    },
    "T1070": {
        "id":"T1070","tactic":"Defense Evasion","name":"Indicator Removal",
        "description":"Deleting or modifying indicators of compromise to evade detection.",
        "mitigations":["Centralize log storage","Monitor for log clearing events"],
        "severity":"MEDIUM"
    },
    "T1562": {
        "id":"T1562","tactic":"Defense Evasion","name":"Impair Defenses",
        "description":"Disabling security tools or altering detection configurations.",
        "mitigations":["Protect security tool configurations","Monitor for AV/FW disabling"],
        "severity":"HIGH"
    },
    "T1027": {
        "id":"T1027","tactic":"Defense Evasion","name":"Obfuscated Files or Information",
        "description":"Making files or information difficult to discover or analyze.",
        "mitigations":["Use deobfuscation tools in security pipeline",
                       "Monitor for encoded/encrypted payloads"],
        "severity":"MEDIUM"
    },

    # ── Credential Access ────────────────────────────────────
    "T1110": {
        "id":"T1110","tactic":"Credential Access","name":"Brute Force",
        "description":"Attempting to gain access through repeated login attempts.",
        "mitigations":["Account lockout policies","MFA","Monitor failed login attempts",
                       "Use CAPTCHA on login forms"],
        "severity":"HIGH"
    },
    "T1110.001": {
        "id":"T1110.001","tactic":"Credential Access","name":"Password Guessing",
        "description":"Systematically guessing user passwords.",
        "mitigations":["Enforce strong password policies","Account lockout"],
        "severity":"HIGH"
    },
    "T1110.003": {
        "id":"T1110.003","tactic":"Credential Access","name":"Password Spraying",
        "description":"Using a few common passwords against many accounts.",
        "mitigations":["Monitor for distributed failed logins","Enable MFA"],
        "severity":"HIGH"
    },
    "T1555": {
        "id":"T1555","tactic":"Credential Access","name":"Credentials from Password Stores",
        "description":"Accessing stored passwords from password managers or vaults.",
        "mitigations":["Protect credential stores","Monitor access to credential stores"],
        "severity":"HIGH"
    },

    # ── Discovery ────────────────────────────────────────────
    "T1016": {
        "id":"T1016","tactic":"Discovery","name":"System Network Configuration Discovery",
        "description":"Gathering information about the network configuration.",
        "mitigations":["Monitor for unusual execution of network config commands"],
        "severity":"LOW"
    },
    "T1018": {
        "id":"T1018","tactic":"Discovery","name":"Remote System Discovery",
        "description":"Discovering remote systems in the network.",
        "mitigations":["Monitor for network scanning activity"],
        "severity":"MEDIUM"
    },
    "T1049": {
        "id":"T1049","tactic":"Discovery","name":"System Network Connections Discovery",
        "description":"Enumerating active network connections.",
        "mitigations":["Monitor execution of networking commands"],
        "severity":"LOW"
    },
    "T1082": {
        "id":"T1082","tactic":"Discovery","name":"System Information Discovery",
        "description":"Gathering OS and hardware information.",
        "mitigations":["Monitor for system enumeration tools"],
        "severity":"LOW"
    },

    # ── Lateral Movement ─────────────────────────────────────
    "T1021": {
        "id":"T1021","tactic":"Lateral Movement","name":"Remote Services",
        "description":"Using legitimate remote services (RDP, SMB, SSH) to move laterally.",
        "mitigations":["Enforce MFA on remote services","Segment network",
                       "Monitor for unusual remote service activity"],
        "severity":"HIGH"
    },
    "T1021.001": {
        "id":"T1021.001","tactic":"Lateral Movement","name":"Remote Desktop Protocol",
        "description":"Using RDP to move laterally within a network.",
        "mitigations":["Disable RDP where not needed","Enforce MFA for RDP",
                       "Monitor RDP session logs"],
        "severity":"HIGH"
    },
    "T1021.002": {
        "id":"T1021.002","tactic":"Lateral Movement","name":"SMB/Windows Admin Shares",
        "description":"Using SMB to move laterally or access admin shares.",
        "mitigations":["Disable SMBv1","Restrict admin shares","Monitor SMB traffic"],
        "severity":"HIGH"
    },
    "T1210": {
        "id":"T1210","tactic":"Lateral Movement",
        "name":"Exploitation of Remote Services",
        "description":"Exploiting vulnerabilities in remote services to move laterally.",
        "mitigations":["Patch remote services promptly","Use network segmentation"],
        "severity":"HIGH"
    },

    # ── Collection ───────────────────────────────────────────
    "T1005": {
        "id":"T1005","tactic":"Collection","name":"Data from Local System",
        "description":"Searching and collecting data from local file system.",
        "mitigations":["Classify and protect sensitive data","Monitor bulk file access"],
        "severity":"MEDIUM"
    },
    "T1039": {
        "id":"T1039","tactic":"Collection","name":"Data from Network Shared Drive",
        "description":"Collecting data stored in shared network drives.",
        "mitigations":["Monitor for unusual access to network shares",
                       "Implement need-to-know access controls"],
        "severity":"MEDIUM"
    },

    # ── Command and Control (C2) ─────────────────────────────
    "T1071": {
        "id":"T1071","tactic":"Command and Control",
        "name":"Application Layer Protocol",
        "description":"Using application layer protocols (HTTP, DNS, SMTP) for C2.",
        "mitigations":["Monitor for unusual outbound connections",
                       "Deep packet inspection on C2 ports"],
        "severity":"HIGH"
    },
    "T1071.004": {
        "id":"T1071.004","tactic":"Command and Control","name":"DNS Tunneling",
        "description":"Using DNS queries and responses to encode C2 traffic.",
        "mitigations":["Monitor for unusually large or frequent DNS queries",
                       "Deploy DNS security solutions (e.g., DNS RPZ)",
                       "Block DNS over HTTPS (DoH) to untrusted resolvers"],
        "severity":"HIGH"
    },
    "T1095": {
        "id":"T1095","tactic":"Command and Control",
        "name":"Non-Application Layer Protocol",
        "description":"Using raw TCP/UDP/ICMP for C2 communication.",
        "mitigations":["Monitor for non-standard protocol usage",
                       "Block unexpected ICMP traffic"],
        "severity":"HIGH"
    },
    "T1571": {
        "id":"T1571","tactic":"Command and Control","name":"Non-Standard Port",
        "description":"Using non-standard ports to communicate with C2 server.",
        "mitigations":["Monitor for traffic on unusual/non-standard ports",
                       "Use egress filtering on firewall"],
        "severity":"HIGH"
    },
    "T1573": {
        "id":"T1573","tactic":"Command and Control","name":"Encrypted Channel",
        "description":"Encrypting C2 traffic to avoid detection.",
        "mitigations":["Deploy SSL/TLS inspection","Monitor certificate anomalies"],
        "severity":"MEDIUM"
    },

    # ── Exfiltration ─────────────────────────────────────────
    "T1041": {
        "id":"T1041","tactic":"Exfiltration","name":"Exfiltration Over C2 Channel",
        "description":"Stealing data over an existing C2 channel.",
        "mitigations":["Monitor for large outbound data transfers",
                       "Implement DLP (Data Loss Prevention) solutions"],
        "severity":"HIGH"
    },
    "T1048": {
        "id":"T1048","tactic":"Exfiltration",
        "name":"Exfiltration Over Alternative Protocol",
        "description":"Stealing data using a non-standard protocol (FTP, DNS, SMTP).",
        "mitigations":["Monitor FTP/DNS/SMTP for unusually large transfers",
                       "Egress data volume monitoring"],
        "severity":"HIGH"
    },
    "T1567": {
        "id":"T1567","tactic":"Exfiltration","name":"Exfiltration Over Web Service",
        "description":"Exfiltrating data to external web services.",
        "mitigations":["Monitor uploads to cloud storage services",
                       "Use CASB (Cloud Access Security Broker)"],
        "severity":"HIGH"
    },

    # ── Impact ───────────────────────────────────────────────
    "T1498": {
        "id":"T1498","tactic":"Impact","name":"Network Denial of Service",
        "description":"Flooding network infrastructure to cause service disruption.",
        "mitigations":["Use DDoS protection services (e.g., Cloudflare, AWS Shield)",
                       "Rate limit inbound connections","Deploy scrubbing centers"],
        "severity":"HIGH"
    },
    "T1498.001": {
        "id":"T1498.001","tactic":"Impact","name":"Direct Network Flood",
        "description":"Directly flooding a target with traffic (ICMP, UDP, SYN floods).",
        "mitigations":["Use rate limiting and traffic scrubbing",
                       "Deploy anti-DDoS hardware appliances"],
        "severity":"HIGH"
    },
    "T1499": {
        "id":"T1499","tactic":"Impact","name":"Endpoint Denial of Service",
        "description":"Exhausting resources on a target endpoint.",
        "mitigations":["Resource monitoring","Auto-scaling","Circuit breakers"],
        "severity":"HIGH"
    },
    "T1485": {
        "id":"T1485","tactic":"Impact","name":"Data Destruction",
        "description":"Destroying data to interrupt availability.",
        "mitigations":["Backup critical data","Monitor for mass file deletion"],
        "severity":"HIGH"
    },
    "T1486": {
        "id":"T1486","tactic":"Impact","name":"Data Encrypted for Impact",
        "description":"Encrypting data on target systems (ransomware).",
        "mitigations":["Maintain offline backups","Monitor for rapid file encryption",
                       "Deploy ransomware-aware endpoint protection"],
        "severity":"HIGH"
    },

    # ── Resource Development ─────────────────────────────────
    "T1583": {
        "id":"T1583","tactic":"Resource Development","name":"Acquire Infrastructure",
        "description":"Acquiring infrastructure for attack operations.",
        "mitigations":["Threat intelligence for known malicious infrastructure"],
        "severity":"LOW"
    },
    "T1588": {
        "id":"T1588","tactic":"Resource Development","name":"Obtain Capabilities",
        "description":"Obtaining tools or exploit code for attack campaigns.",
        "mitigations":["Monitor dark web for stolen credentials/tools"],
        "severity":"LOW"
    },
}

# ─────────────────────────────────────────────────────────────
# ATTACK CLASS → MITRE MAPPING
# ─────────────────────────────────────────────────────────────
# Maps every known attack category to primary + secondary MITRE techniques
ATTACK_CLASS_MAP: Dict[str, Dict[str, Any]] = {

    # ── UNSW-NB15 Classes ────────────────────────────────────
    "Analysis": {
        "primary": "T1595.002","secondary": ["T1046","T1595.001","T1592"],
        "description": "Network analysis and vulnerability scanning activity. "
                       "Adversary is profiling the network to identify exploitable services.",
        "kill_chain": "Reconnaissance → Weaponization",
        "ioc": ["Unusual port access patterns", "Service version probing",
                "Banner grabbing connections", "High connection rate to varied ports"]
    },
    "Backdoor": {
        "primary": "T1543","secondary": ["T1071","T1571","T1573","T1095"],
        "description": "Persistent unauthorized access mechanism installed on compromised host. "
                       "Allows remote control and continued access without re-exploitation.",
        "kill_chain": "Installation → Command & Control",
        "ioc": ["Unexpected outbound connections on unusual ports",
                "Processes listening on non-standard ports",
                "Periodic beaconing traffic patterns",
                "Encrypted traffic to unknown external IPs"]
    },
    "DoS": {
        "primary": "T1498","secondary": ["T1498.001","T1499"],
        "description": "Denial of Service attack overwhelming target resources or bandwidth. "
                       "Goal is to disrupt service availability.",
        "kill_chain": "Actions on Objectives",
        "ioc": ["Extremely high packet rate from single source",
                "Traffic volume spike (>10x baseline)",
                "Protocol anomalies (malformed packets)",
                "SYN flood: many SYN, few ACK responses"]
    },
    "Exploits": {
        "primary": "T1190","secondary": ["T1203","T1068","T1055","T1210"],
        "description": "Exploitation of vulnerability in a service or application to gain "
                       "unauthorized access or execute arbitrary code.",
        "kill_chain": "Exploitation → Installation",
        "ioc": ["Abnormal service response codes (500, crash)",
                "Buffer overflow traffic patterns (large payload to small service)",
                "Return-oriented programming patterns in payload",
                "Shellcode signatures in packet payload"]
    },
    "Fuzzers": {
        "primary": "T1595","secondary": ["T1046","T1595.002"],
        "description": "Automated input fuzzing to discover vulnerabilities in target services. "
                       "Generates malformed or unexpected inputs systematically.",
        "kill_chain": "Reconnaissance → Weaponization",
        "ioc": ["Rapid sequential connections with varied inputs",
                "Malformed protocol structures",
                "High error rate responses from target",
                "Payload entropy significantly above baseline"]
    },
    "Generic": {
        "primary": "T1036","secondary": ["T1027","T1070"],
        "description": "Generic attack traffic not fitting a specific known category. "
                       "May represent novel techniques or obfuscated known attacks.",
        "kill_chain": "Unknown / Multiple Stages",
        "ioc": ["Statistical deviation from baseline traffic profiles",
                "Protocol anomalies without clear attack signature",
                "Unusual feature combinations for traffic class"]
    },
    "Normal": {
        "primary": None,"secondary": [],
        "description": "Benign network traffic with no threat indicators detected.",
        "kill_chain": "N/A",
        "ioc": []
    },
    "Reconnaissance": {
        "primary": "T1595","secondary": ["T1046","T1018","T1592","T1595.001"],
        "description": "Active reconnaissance to map the network and identify targets. "
                       "Includes port scanning, host discovery, and service enumeration.",
        "kill_chain": "Reconnaissance",
        "ioc": ["Sequential port sweeps (Nmap-style)",
                "ICMP ping sweeps across subnets",
                "Service banner grabbing (small, quick connections)",
                "High distinct destination port count from single source"]
    },
    "Shellcode": {
        "primary": "T1055","secondary": ["T1203","T1059","T1068"],
        "description": "Shellcode injection or delivery in network traffic. "
                       "Binary code designed to exploit a vulnerability and spawn a shell.",
        "kill_chain": "Exploitation → Installation",
        "ioc": ["NOP sled patterns in payload (0x90 sequences)",
                "Known shellcode byte sequences",
                "Return address overwrite patterns",
                "Executable code in non-code areas of protocol"]
    },
    "Worms": {
        "primary": "T1210","secondary": ["T1543","T1190","T1021"],
        "description": "Self-propagating malware attempting to spread across the network "
                       "by exploiting vulnerabilities in remote services.",
        "kill_chain": "Lateral Movement → Persistence",
        "ioc": ["High connection rate to varied internal IPs",
                "Identical exploit payloads sent to multiple targets",
                "Unexpected SMB/RPC traffic across subnet",
                "Rapid replication pattern in new host connections"]
    },

    # ── CICIDS 2018 Classes ──────────────────────────────────
    "FTP-BruteForce": {
        "primary": "T1110","secondary": ["T1110.001","T1133"],
        "description": "Automated brute force attack against FTP service to guess credentials.",
        "kill_chain": "Exploitation",
        "ioc": ["High failed auth count to port 21",
                "Sequential password attempts","Short inter-request delay"]
    },
    "SSH-BruteForce": {
        "primary": "T1110","secondary": ["T1110.003","T1133"],
        "description": "Automated brute force attack against SSH service.",
        "kill_chain": "Exploitation",
        "ioc": ["High failed auth count to port 22","Multiple failed RSA handshakes",
                "Source IP not in authorized range"]
    },
    "DoS-Hulk": {
        "primary": "T1499","secondary": ["T1498"],
        "description": "HTTP DoS attack using the Hulk tool. Generates unique requests "
                       "to bypass caching and overwhelm web servers.",
        "kill_chain": "Actions on Objectives",
        "ioc": ["Extremely high HTTP request rate","Unique User-Agent per request",
                "No cache headers","Random URL parameters"]
    },
    "DoS-GoldenEye": {
        "primary": "T1499","secondary": ["T1498"],
        "description": "HTTP DoS attack using GoldenEye — focuses on HTTP layer exhaustion.",
        "kill_chain": "Actions on Objectives",
        "ioc": ["Keep-alive connections with slow data sending",
                "High connection count from few sources"]
    },
    "DoS-Slowloris": {
        "primary": "T1499","secondary": ["T1498"],
        "description": "Slow HTTP DoS attack — keeps connections open by sending partial headers.",
        "kill_chain": "Actions on Objectives",
        "ioc": ["Many incomplete HTTP requests","Long-duration low-bandwidth connections",
                "Connections that never fully close"]
    },
    "DDoS": {
        "primary": "T1498","secondary": ["T1498.001"],
        "description": "Distributed Denial of Service — multiple sources flooding target.",
        "kill_chain": "Actions on Objectives",
        "ioc": ["Traffic from geographically diverse sources",
                "Synchronized packet bursts","Spoofed source IPs"]
    },
    "Bot": {
        "primary": "T1543","secondary": ["T1071","T1573"],
        "description": "Botnet activity — compromised host communicating with C2 infrastructure.",
        "kill_chain": "Command & Control",
        "ioc": ["Periodic beaconing at fixed intervals","Encrypted traffic to known C2 IPs",
                "Low-volume persistent connections","Unusual DNS lookups (DGA patterns)"]
    },
    "Infiltration": {
        "primary": "T1190","secondary": ["T1210","T1068"],
        "description": "Successful intrusion into network — post-exploitation activity.",
        "kill_chain": "Actions on Objectives",
        "ioc": ["Traffic patterns inconsistent with normal user behavior",
                "Access to sensitive internal resources","Lateral movement indicators"]
    },
    "SQL-Injection": {
        "primary": "T1190","secondary": ["T1005"],
        "description": "SQL injection attack against a database-connected web application.",
        "kill_chain": "Exploitation → Collection",
        "ioc": ["SQL syntax in HTTP request parameters","Database error messages in response",
                "Unusual database query patterns","Large data returned from web endpoint"]
    },
    "XSS": {
        "primary": "T1059","secondary": ["T1566"],
        "description": "Cross-Site Scripting injection into web application.",
        "kill_chain": "Exploitation",
        "ioc": ["Script tags in HTTP parameters","Encoded JavaScript in URL parameters",
                "DOM manipulation patterns in HTTP body"]
    },
    "Heartbleed": {
        "primary": "T1190","secondary": ["T1555"],
        "description": "Exploitation of OpenSSL Heartbleed vulnerability (CVE-2014-0160) "
                       "to leak server memory contents.",
        "kill_chain": "Exploitation → Credential Access",
        "ioc": ["Malformed TLS heartbeat records","Oversized heartbeat requests",
                "Repeated small TLS sessions"]
    },

    # ── Signature Engine Verdicts ────────────────────────────
    "BLACKLISTED SOURCE IP": {
        "primary": "T1583","secondary": ["T1078"],
        "description": "Traffic originating from a known malicious IP in threat intelligence feeds.",
        "kill_chain": "Any",
        "ioc": ["Source IP matches threat intelligence blacklist"]
    },
    "BLACKLISTED DESTINATION IP": {
        "primary": "T1071","secondary": ["T1573"],
        "description": "Outbound connection to a known malicious or C2 IP address.",
        "kill_chain": "Command & Control",
        "ioc": ["Destination IP matches C2 infrastructure blacklist"]
    },
    "PORT SCAN": {
        "primary": "T1595.001","secondary": ["T1046"],
        "description": "Systematic scanning of target ports to enumerate open services.",
        "kill_chain": "Reconnaissance",
        "ioc": ["Sequential port access","High distinct port count from one source"]
    },
    "BRUTE FORCE": {
        "primary": "T1110","secondary": ["T1110.001","T1110.003"],
        "description": "Repeated authentication attempts to guess credentials.",
        "kill_chain": "Exploitation → Credential Access",
        "ioc": ["High failed login count","Short request intervals","Same source IP"]
    },
    "C2": {
        "primary": "T1571","secondary": ["T1095","T1573"],
        "description": "Command and Control communication on non-standard port.",
        "kill_chain": "Command & Control",
        "ioc": ["Non-standard destination port","Encrypted or obfuscated payload",
                "Regular/periodic connection pattern"]
    },
    "SMB": {
        "primary": "T1021.002","secondary": ["T1210","T1190"],
        "description": "Suspicious SMB protocol activity indicating possible exploitation "
                       "or lateral movement via Windows network shares.",
        "kill_chain": "Lateral Movement / Exploitation",
        "ioc": ["SMB traffic from unexpected sources","EternalBlue-style packet patterns",
                "Port 445 access with exploit-sized payloads"]
    },
    "RDP": {
        "primary": "T1021.001","secondary": ["T1110","T1133"],
        "description": "Suspicious RDP access attempt, possibly brute force or unauthorized access.",
        "kill_chain": "Initial Access / Lateral Movement",
        "ioc": ["Multiple RDP connections from external source","Failed RDP auth events"]
    },
    "DNS TUNNELING": {
        "primary": "T1071.004","secondary": ["T1041"],
        "description": "DNS used to encode and exfiltrate data or receive C2 commands.",
        "kill_chain": "Command & Control / Exfiltration",
        "ioc": ["Oversized DNS queries","High DNS query frequency","Base64 in DNS records",
                "Long subdomain chains (DGA-style)"]
    },
    "EXFILTRATION": {
        "primary": "T1041","secondary": ["T1048","T1567"],
        "description": "Large volume of data being transferred from internal to external hosts.",
        "kill_chain": "Exfiltration",
        "ioc": ["High outbound byte volume","Low inbound:outbound ratio",
                "Transfer to previously unseen external IP"]
    },
    "ICMP FLOOD": {
        "primary": "T1498.001","secondary": ["T1498"],
        "description": "ICMP flood attack overwhelming target with ping requests.",
        "kill_chain": "Actions on Objectives",
        "ioc": ["Very high ICMP packet rate","Packets from single or few sources",
                "Uniform ICMP packet sizes"]
    },
    "TELNET": {
        "primary": "T1021","secondary": ["T1078","T1133"],
        "description": "Telnet usage detected — plaintext protocol with no encryption.",
        "kill_chain": "Initial Access / Lateral Movement",
        "ioc": ["Telnet session on port 23","Credentials transmitted in plaintext"]
    },
    "NULL SCAN": {
        "primary": "T1595","secondary": ["T1046"],
        "description": "TCP Null scan — all flags cleared to probe for open ports.",
        "kill_chain": "Reconnaissance",
        "ioc": ["TCP segments with all flags cleared","Zero-byte probes"]
    },

    # ── Zero-Day / Anomaly Detections ────────────────────────
    "SUSPICIOUS": {
        "primary": "T1036","secondary": ["T1027","T1070"],
        "description": "Anomalous traffic detected by unsupervised anomaly sentinel. "
                       "Traffic significantly deviates from learned normal behavior. "
                       "May represent a novel attack, zero-day exploit, or evasion technique.",
        "kill_chain": "Unknown — possible novel/zero-day attack",
        "ioc": ["Statistical anomaly score above threshold",
                "Reconstruction error significantly above normal baseline",
                "Feature combination not observed in training data",
                "Possible zero-day exploit or advanced persistent threat (APT)"]
    },
    "ZERO-DAY": {
        "primary": "T1190","secondary": ["T1203","T1036"],
        "description": "High-confidence zero-day attack detection. Traffic exhibits characteristics "
                       "of an unknown exploit with no matching signature or learned pattern.",
        "kill_chain": "Exploitation (Novel Vector)",
        "ioc": ["No matching signature rule","Low ML classification confidence",
                "High anomaly reconstruction error","Never-before-seen traffic pattern"]
    },
    "ANOMALY": {
        "primary": "T1036","secondary": [],
        "description": "Statistical anomaly in network traffic deviating from the normal baseline.",
        "kill_chain": "Unknown",
        "ioc": ["Anomaly score above operational threshold"]
    },
}

# ─────────────────────────────────────────────────────────────
# ET-OPEN CLASSTYPE → MITRE MAPPING
# ─────────────────────────────────────────────────────────────
CLASSTYPE_MITRE_MAP: Dict[str, str] = {
    "attempted-admin":        "T1068",
    "successful-admin":       "T1068",
    "shellcode-detect":       "T1055",
    "trojan-activity":        "T1543",
    "web-application-attack": "T1190",
    "attempted-user":         "T1190",
    "denial-of-service":      "T1498",
    "network-scan":           "T1595",
    "policy-violation":       "T1036",
    "protocol-command-decode":"T1059",
    "bad-unknown":            "T1036",
    "misc-attack":            "T1036",
    "blacklist":              "T1583",
    "default":                "T1036",
}

# ─────────────────────────────────────────────────────────────
# LOOKUP FUNCTIONS
# ─────────────────────────────────────────────────────────────
_UNKNOWN_TECHNIQUE = TECHNIQUES["T1036"]
_UNKNOWN_CLASS = {
    "primary": "T1036", "secondary": [], "description": "Unknown attack pattern.",
    "kill_chain": "Unknown", "ioc": []
}

def get_attack_mapping(verdict: str) -> Dict[str, Any]:
    """
    Get full MITRE ATT&CK mapping for a given verdict/attack class.
    Performs fuzzy matching to handle signature engine verdicts.
    """
    v = verdict.strip().upper()

    # Direct lookup
    for key, val in ATTACK_CLASS_MAP.items():
        if key.upper() == v:
            return _enrich(val)

    # Partial keyword match (signature engine verdicts contain keywords)
    keywords = {
        "SCAN": "PORT SCAN","BRUTE": "BRUTE FORCE","FLOOD": "ICMP FLOOD",
        "EXFIL": "EXFILTRATION","BACKDOOR": "Backdoor","DOS": "DoS",
        "DDOS": "DDoS","EXPLOIT": "Exploits","RECON": "Reconnaissance",
        "SHELL": "Shellcode","WORM": "Worms","FUZZ": "Fuzzers",
        "ANALYSIS": "Analysis","GENERIC": "Generic","NORMAL": "Normal",
        "C2": "C2","RAT": "C2","TROJAN": "Backdoor","BOT": "Bot",
        "MALWARE": "Backdoor","BLACKLIST": "BLACKLISTED SOURCE IP",
        "SMB": "SMB","RDP": "RDP","TELNET": "TELNET","DNS": "DNS TUNNELING",
        "SQL": "SQL-Injection","XSS": "XSS","HEARTBLEED": "Heartbleed",
        "ZERO": "ZERO-DAY","NOVEL": "ZERO-DAY","ANOMAL": "ANOMALY",
        "SUSPICIOUS": "SUSPICIOUS","NULL": "NULL SCAN","XMAS": "NULL SCAN",
        "INFILTR": "Infiltration","FTP": "FTP-BruteForce",
    }
    for kw, mapped_class in keywords.items():
        if kw in v:
            entry = ATTACK_CLASS_MAP.get(mapped_class, _UNKNOWN_CLASS)
            return _enrich(entry)

    return _enrich(_UNKNOWN_CLASS)


def get_technique(technique_id: str) -> Dict[str, Any]:
    """Get a specific MITRE technique by ID."""
    return TECHNIQUES.get(technique_id, _UNKNOWN_TECHNIQUE)


def get_classtype_technique(classtype: str) -> str:
    """Map an ET-Open classtype to its primary MITRE technique ID."""
    return CLASSTYPE_MITRE_MAP.get(classtype, "T1036")


def _enrich(mapping: Dict) -> Dict:
    """Add full technique objects to a mapping entry."""
    result = dict(mapping)
    primary_id = result.get("primary")
    result["primary_technique"] = TECHNIQUES.get(primary_id, _UNKNOWN_TECHNIQUE) if primary_id else None
    result["secondary_techniques"] = [
        TECHNIQUES[t] for t in result.get("secondary", []) if t in TECHNIQUES
    ]
    return result


def build_mitre_summary(alerts: list) -> Dict[str, Any]:
    """
    Build a MITRE ATT&CK coverage summary from a list of alert dicts.
    Suitable for inclusion in forensic reports.
    """
    tactics_hit    = {}
    techniques_hit = {}
    severity_counts= {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for alert in alerts:
        verdict = alert.get("verdict","")
        mapping = get_attack_mapping(verdict)
        pt = mapping.get("primary_technique")
        if pt:
            tactic = pt.get("tactic","Unknown")
            tid    = pt.get("id","")
            tname  = pt.get("name","")
            tactics_hit[tactic]    = tactics_hit.get(tactic, 0) + 1
            techniques_hit[tid]    = {"name": tname, "tactic": tactic,
                                      "count": techniques_hit.get(tid,{}).get("count",0)+1}
        sev = alert.get("severity","MEDIUM")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "tactics_observed": tactics_hit,
        "techniques_observed": techniques_hit,
        "severity_distribution": severity_counts,
        "unique_tactics": len(tactics_hit),
        "unique_techniques": len(techniques_hit),
    }
