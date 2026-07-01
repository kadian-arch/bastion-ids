# Bastion IDS

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

A network intrusion detection system that combines signature matching, machine learning, deep learning, and behavioural anomaly detection into one pipeline. Built from scratch. Ships with a real-time SOC-style dashboard.

![Bastion IDS Dashboard](docs/screenshots/ops_center.png)

## What it does

Bastion IDS watches your network traffic and tells you when something is wrong. It runs four detection methods in sequence on every flow, each one catches a different class of threat.

When a packet hits the wire, Bastion checks it against 47,357 known attack signatures first (fast, no false positives on known threats), then runs it through three layers of trained AI models that pick up patterns the signatures miss, including attacks that have never been seen before.

Everything shows up in a live dashboard that looks like a real SOC packet table, threat log, network map, system health gauges, and a deep-dive forensic view for each alert.

## Detection pipeline

```
Network traffic
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 1 — Signature Engine                             │
│  47,357 Emerging Threats (ET-Open) rules + port/scan    │
│  heuristics. Instant verdict on known attacks.          │
└──────────────────────────┬──────────────────────────────┘
                           │ (if no signature match)
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 2 — ML Ensemble                                  │
│  Random Forest + XGBoost + CatBoost vote on the flow.   │
│  Consensus of 2+ models or single model at 92%+ fires.  │
└──────────────────────────┬──────────────────────────────┘
                           │ (if no consensus)
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 3 — Deep Neural Network Specialist               │
│  DNN trained on UNSW-NB15 takes a final look.           │
│  Fires at 85%+ confidence on any malicious category.    │
└──────────────────────────┬──────────────────────────────┘
                           │ (always runs in parallel)
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 4 — Behavioural Anomaly Engine                   │
│  Distribution-independent, threshold-gated detectors.   │
│  Catches ICMP covert channels and DNS tunnelling —      │
│  zero-day techniques with no existing signatures.       │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
                    Alert → Dashboard
```

**Trained on:** UNSW-NB15 (Australian Centre for Cyber Security) 49 features, 9 attack categories.

## Download

**[Download Bastion IDS Setup 2.0.0 for Windows →](https://github.com/kadian-arch/bastion-ids/releases/latest)**

The installer includes all trained models and everything needed to run. Requires Npcap for live packet capture (free download, the installer will prompt you).

## Running from source

**Requirements:** Python 3.12, Node.js 18+, Npcap (for live capture)

```bash
git clone https://github.com/kadian-arch/bastion-ids.git
cd bastion-ids
```

**Download models:**
The trained model files are large and not in the repo. Download them from the [latest release](https://github.com/kadian-arch/bastion-ids/releases/latest) → `models.zip`, then extract into the `models/` folder.

**Download ET-Open rules:**
```bash
curl -L https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz -o rules/emerging.rules.tar.gz
tar -xzf rules/emerging.rules.tar.gz -C rules/
```

**Install dependencies:**
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

cd app-desktop
npm install
```

**Start the system:**
```bash
# Terminal 1, backend (run as Administrator for live capture)
venv\Scripts\activate
python api_server.py

# Terminal 2 — frontend
cd app-desktop
npm run dev
# Open http://localhost:48218
```

---

## What Bastion is (and isn't)

Bastion is a **Network Intrusion Detection System (NIDS)**. It monitors traffic and raises alerts. It does not block anything on its own.

The dashboard includes response controls (port quarantine, IP blocking) that are designed to work alongside a firewall or network enforcement device. Without that integration they show intent — with it they trigger real action. This is the standard architecture: detection and enforcement are separate. Tools like Suricata and Zeek work the same way.


## Dashboard pages

**Operations Center**: Live stats (CPU, flows analyzed, threats detected, engine uptime) plus real-time resource graphs and network architecture overview. Shows all 4 detection layers with live status.

**Live Packet Capture**: Wireshark-style table streaming real packets off the wire. Filter by protocol (TCP, UDP, ICMP, DNS, HTTP, TLS, ARP, SSH). Threats highlighted in red. Click any row for the full forensic breakdown which engine flagged it, confidence, raw hex and BPF capabilty to narrow down to a particular traffic capture type.

**Data Ingest Portal**: Drop a `.csv`, `.pcap`, or `.log` file and run a full ML sweep across all flows. Good for post-incident analysis of captured traffic.

**Threat Intelligence**: Full alert log with severity filter, IP/type search, and CSV export. Click any alert for the deep-dive report: neural weight distribution chart, raw packet hex dump, and analyst verification (mark true/false positive, add notes). Forensic reports also generated in three different formats and downloadable in any desired of three, csv, html and pdf(which can be submitted in legal situations like court hearings).

**Network Topology**: Live ARP scan of the local subnet visualized as a node map. Classifies devices as server, gateway, or workstation, performs basic host info discovery such as OS.

**System Health**: CPU, RAM, storage, and network I/O gauges, updated every 3 seconds.

**Command & Control**: Admin panel for user management and access governance.


## Screenshots

| Operations Center | Live Packet Capture |
|---|---|
| ![Operations Center](docs/screenshots/ops_center.png) | ![Live Packet Capture](docs/screenshots/live_capture.png) |

| Threat Intelligence | Network Topology |
|---|---|
| ![Threat Intelligence](docs/screenshots/threat_intel.png) | ![Network Topology](docs/screenshots/network_topology.png) |

| System Health | Settings |
|---|---|
| ![System Health](docs/screenshots/system_health.png) | ![Settings](docs/screenshots/sys_config.png) |


## Tech stack

**Backend:** Python 3.12, FastAPI, Uvicorn, Scapy, TensorFlow/Keras, XGBoost, CatBoost, scikit-learn, pandas

**Frontend:** Electron, React 18, Vite, TailwindCSS, Chart.js

**Models trained on:** UNSW-NB15 dataset and tuned on CICIDS2017 to broaden attack categories in introduce variants detection capabilties.


## Project background

This started as a final year B.Tech project at the University of Buea (Network & Security, class of 2026). The goal was to go beyond simple signature matching and build something closer to how real enterprise IDS tools work layered detection, no single point of failure, and a UI that makes the data readable.

It's fully open source. If you're a researcher, a student, or someone who wants to understand how layered network detection works under the hood, everything is here.


## Troubleshooting

**Windows SmartScreen blocks the installer ("Windows protected your PC")**
This appears because the installer is not commercially code-signed. Click "More info" then "Run anyway." The installer is safe — you can verify the SHA-256 checksum against the release page.

**"Error decompressing data! Corrupted installer?" during installation**
Windows Defender is quarantining files mid-extraction. Before running the installer, go to Windows Security → Virus & threat protection → Manage settings → turn off Real-time protection temporarily, complete the installation, then turn it back on. Alternatively add `C:\Program Files\Bastion IDS` as a Defender exclusion before running the installer.

**"Engine failed to start" on the splash screen**
The detection engine (Python backend) did not launch in time. Check `%TEMP%\BastionIDS-launch.log` for the exact error. Common causes: the app was not run as Administrator (right-click → Run as administrator), or antivirus software blocked the engine process. If the log shows a missing module, uninstall and reinstall — a corrupted installation is the most likely cause.

**Live packet capture shows no traffic**
Npcap is required for live capture. If the installer did not install it automatically, download it from [npcap.com](https://npcap.com) and install it manually, then restart Bastion IDS. Also confirm the app is running as Administrator — without admin rights, raw packet capture is blocked by Windows.

**First launch takes 2-3 minutes**
Normal. The AI models (TensorFlow, XGBoost, CatBoost) load from disk on first launch. Subsequent launches are faster once Windows caches the files.

**The app installed but will not open at all**
Make sure you are on Windows 10 (build 1903 or later) or Windows 11. Windows 7/8 are not supported. Also confirm your machine has at least 4 GB of free RAM — the full model stack needs headroom to load.

If none of the above resolves your issue, open a GitHub issue with your `%TEMP%\BastionIDS-launch.log` attached, or email directly for one-on-one support: **donalsienkum@gmail.com**

---

## Commercial & deployment

If you need Bastion IDS deployed in your organization, want it customized for a specific environment, or need ongoing monitoring support, reach out:

**kadian.security@gmail.com**


## License

MIT — do what you want with it, attribution appreciated.

---

*Built by [Kum Donalsien Akwo](https://github.com/kadian-arch) · Kadian Inc · 2026*
