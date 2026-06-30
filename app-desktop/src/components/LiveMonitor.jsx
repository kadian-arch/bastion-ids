import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import axios from 'axios';
import {
  Play, Square, Pause, RotateCcw, Radio, ShieldAlert, Download,
  Search, Network, ChevronDown, X, Activity, Filter,
  CheckCircle, Layers, Database, FileDown, Save, AlertCircle,
} from 'lucide-react';

const AUTH_KEY    = 'BASTION-KADIAN-SEC-0x42';
const SOCKET_URL  = `ws://127.0.0.1:48217/api/v1/live-traffic?key=${AUTH_KEY}`;
const API_BASE    = 'http://127.0.0.1:48217/api/v1';
const AUTH_HDR    = { 'x-authority': AUTH_KEY };
const MAX_PACKETS = 5000;

// ── Protocol colour map (Wireshark-inspired) ─────────────────────────────────
const PROTO_PALETTE = {
  TCP:   { row: 'text-sky-300',     badge: 'bg-sky-900/40 text-sky-300 border-sky-700/50'     },
  UDP:   { row: 'text-violet-300',  badge: 'bg-violet-900/40 text-violet-300 border-violet-700/50' },
  ICMP:  { row: 'text-amber-300',   badge: 'bg-amber-900/40 text-amber-300 border-amber-700/50' },
  ICMPV6:{ row: 'text-amber-300',   badge: 'bg-amber-900/40 text-amber-300 border-amber-700/50' },
  DNS:   { row: 'text-teal-300',    badge: 'bg-teal-900/40 text-teal-300 border-teal-700/50'   },
  HTTP:  { row: 'text-emerald-300', badge: 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50' },
  HTTPS: { row: 'text-emerald-300', badge: 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50' },
  TLS:   { row: 'text-lime-300',    badge: 'bg-lime-900/40 text-lime-300 border-lime-700/50'   },
  ARP:   { row: 'text-yellow-300',  badge: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50' },
  SSH:   { row: 'text-pink-300',    badge: 'bg-pink-900/40 text-pink-300 border-pink-700/50'   },
  FTP:   { row: 'text-orange-300',  badge: 'bg-orange-900/40 text-orange-300 border-orange-700/50' },
  SMTP:  { row: 'text-red-300',     badge: 'bg-red-900/40 text-red-300 border-red-700/50'      },
  DHCP:  { row: 'text-fuchsia-300', badge: 'bg-fuchsia-900/40 text-fuchsia-300 border-fuchsia-700/50' },
  NTP:   { row: 'text-slate-300',   badge: 'bg-slate-800 text-slate-300 border-slate-700'      },
  IPV6:  { row: 'text-indigo-300', badge: 'bg-indigo-900/40 text-indigo-300 border-indigo-700/50' },
  THREAT:{ row: 'text-red-400',     badge: 'bg-red-900/60 text-red-400 border-red-700/80'      },
  DEFAULT:{ row: 'text-slate-400',  badge: 'bg-slate-800 text-slate-400 border-slate-700'      },
};

const PROTO_CHIPS = ['ALL', 'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS', 'ARP', 'SSH', 'IPv6'];

// ── BPF filter presets (Berkeley Packet Filter — network traffic scope) ────────
// BPF is a kernel-level filtering language used by packet capture tools (Wireshark,
// tcpdump, Scapy) to select which packets to inspect. These presets cover the most
// common use cases. "Custom Filter" lets you write a raw BPF expression.
const BPF_PRESETS = [
  { label: 'Any Traffic  (no filter)',     value: '' },
  { label: 'TCP Only',                     value: 'tcp' },
  { label: 'UDP Only',                     value: 'udp' },
  { label: 'ICMP Only',                    value: 'icmp' },
  { label: 'HTTP  (port 80)',              value: 'tcp port 80' },
  { label: 'HTTPS  (port 443)',            value: 'tcp port 443' },
  { label: 'DNS  (port 53)',               value: 'port 53' },
  { label: 'SSH  (port 22)',               value: 'tcp port 22' },
  { label: 'FTP  (ports 20-21)',           value: 'tcp port 20 or tcp port 21' },
  { label: 'SMTP  (port 25)',              value: 'tcp port 25' },
  { label: 'SMB / Windows Shares',         value: 'tcp port 445 or tcp port 139' },
  { label: 'ARP Only',                     value: 'arp' },
  { label: 'Broadcast Traffic',            value: 'broadcast' },
  { label: 'Exclude Loopback',             value: 'not host 127.0.0.1' },
  { label: 'Custom Filter…',              value: '__custom__' },
];

function protoPalette(proto, isThreat) {
  if (isThreat) return PROTO_PALETTE.THREAT;
  return PROTO_PALETTE[proto?.toUpperCase()] ?? PROTO_PALETTE.DEFAULT;
}

// ── Small helpers ─────────────────────────────────────────────────────────────
function ProtoBadge({ proto, isThreat }) {
  const p = protoPalette(proto, isThreat);
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-black uppercase tracking-wider border ${p.badge}`}>
      {proto ?? '???'}
    </span>
  );
}

function DetailRow({ label, val, accent }) {
  const cls = accent === 'cyan'   ? 'text-cyan-400'
            : accent === 'indigo' ? 'text-indigo-400'
            : accent === 'red'    ? 'text-red-400'
            : 'text-slate-300';
  return (
    <div className="flex gap-2 leading-snug">
      <span className="text-slate-600 w-28 shrink-0 text-[10px]">{label}:</span>
      <span className={`${cls} font-bold text-[11px] font-mono break-all`}>{String(val ?? '—')}</span>
    </div>
  );
}

function formatBytes(b) {
  if (b < 1024)        return `${b} B`;
  if (b < 1048576)     return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(2)} MB`;
}

// ── Wireshark-style Packet Inspector ─────────────────────────────────────────
// Collapsible layer tree (left 55%) + hex-dump pane (right 45%)
function PacketInspector({ pkt, iface, onClose }) {
  const [open, setOpen] = React.useState({ frame: true, eth: true, ip: true, transport: true, app: true });
  const toggle = (k) => setOpen(prev => ({ ...prev, [k]: !prev[k] }));
  const isThreat = pkt.verdict && pkt.verdict !== 'NORMAL';

  const proto = (pkt.proto || pkt.Protocol || '').toUpperCase();
  const isTCP  = proto === 'TCP';
  const isUDP  = proto === 'UDP';
  const isICMP = proto === 'ICMP';
  const isARP  = proto === 'ARP';

  // Build hex dump rows of 16 bytes each
  const hexBytes = (pkt.payload_hex || '').split(' ').filter(Boolean);
  const hexRows  = [];
  for (let i = 0; i < hexBytes.length; i += 16) {
    const chunk = hexBytes.slice(i, i + 16);
    const ascii = (pkt.payload_ascii || '').slice(i, i + 16);
    hexRows.push({ offset: i, hex: chunk, ascii });
  }

  // LayerRow — a collapsible tree header
  const LayerHeader = ({ id, label, color }) => (
    <button
      className={`w-full flex items-center gap-2 px-3 py-1.5 text-left hover:bg-slate-800/50 transition-colors ${color}`}
      onClick={() => toggle(id)}
    >
      <span className="text-slate-500 w-3 shrink-0 text-[9px]">{open[id] ? '▼' : '▶'}</span>
      <span className="text-[10px] font-black uppercase tracking-widest">{label}</span>
    </button>
  );

  // A single field row inside a layer
  const F = ({ label, val, accent }) => {
    const cls = accent === 'cyan'   ? 'text-cyan-400'
              : accent === 'red'    ? 'text-red-400'
              : accent === 'amber'  ? 'text-amber-400'
              : accent === 'indigo' ? 'text-indigo-400'
              : accent === 'emerald'? 'text-emerald-400'
              : 'text-slate-300';
    return (
      <div className="flex gap-2 px-6 py-0.5">
        <span className="text-slate-600 text-[9px] w-32 shrink-0">{label}</span>
        <span className={`${cls} text-[10px] font-mono break-all`}>{String(val ?? '—')}</span>
      </div>
    );
  };

  return (
    <div className="bg-slate-950 border border-cyan-500/25 rounded-lg overflow-hidden shadow-[0_0_24px_rgba(6,182,212,0.06)] flex flex-col">

      {/* ── Header bar ── */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-[#0a0f1a] shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <Layers size={13} className="text-cyan-400 shrink-0" />
          <span className="text-[10px] font-black uppercase tracking-widest text-cyan-400">
            Packet Inspector — #{pkt['No.']}
          </span>
          <ProtoBadge proto={pkt.Protocol} isThreat={isThreat} />
          {isThreat && (
            <span className="text-[9px] font-black uppercase tracking-widest text-red-400 animate-pulse ml-1">
              ⚠ THREAT DETECTED
            </span>
          )}
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-800 transition-colors shrink-0">
          <X size={14} className="text-slate-500 hover:text-white transition-colors" />
        </button>
      </div>

      {/* ── Two-pane body: Layer tree + Hex dump ── */}
      <div className="flex min-h-0 max-h-72 overflow-hidden">

        {/* LEFT: layer tree */}
        <div className="flex-1 overflow-y-auto border-r border-slate-800 custom-scrollbar py-1 font-mono">

          {/* Frame / Wire */}
          <LayerHeader id="frame" label="Frame" color="text-slate-400" />
          {open.frame && (
            <div className="py-1">
              <F label="Packet #"       val={pkt['No.']}                          />
              <F label="Capture time"   val={pkt.Time}                             />
              <F label="Interface"      val={iface || 'auto'}                      />
              <F label="Frame length"   val={`${pkt.Length ?? 0} bytes`}          />
              <F label="Protocol"       val={pkt.Protocol}                         />
              <F label="Info"           val={pkt.Info}                             />
            </div>
          )}

          {/* Ethernet II */}
          {(pkt.src_mac || pkt.dst_mac) && <>
            <LayerHeader id="eth" label="Ethernet II" color="text-yellow-400" />
            {open.eth && (
              <div className="py-1">
                <F label="Source MAC"    val={pkt.src_mac ? `${pkt.src_mac}${pkt.src_vendor ? ` (${pkt.src_vendor})` : ''}` : '—'} accent="cyan"   />
                <F label="Destination"   val={pkt.dst_mac} accent="indigo" />
                <F label="Type"          val={isARP ? '0x0806 (ARP)' : '0x0800 (IPv4)'}     />
              </div>
            )}
          </>}

          {/* IP / ARP layer */}
          {!isARP && (pkt.srcip || pkt.dstip) && <>
            <LayerHeader id="ip" label={`Internet Protocol ${pkt.proto === 'ipv6' ? 'v6' : 'v4'}`} color="text-sky-400" />
            {open.ip && (
              <div className="py-1">
                <F label="Source"        val={pkt.srcip}         accent="cyan"   />
                <F label="Destination"   val={pkt.dstip}         accent="indigo" />
                <F label="TTL / Hop lim" val={pkt.ttl ?? '—'}                    />
                {pkt.ip_id    !== undefined && <F label="ID"              val={`0x${(pkt.ip_id || 0).toString(16).padStart(4,'0')} (${pkt.ip_id})`} />}
                {pkt.ip_tos   !== undefined && <F label="TOS / DSCP"      val={`0x${(pkt.ip_tos || 0).toString(16).padStart(2,'0')}`}               />}
                {pkt.ip_df    !== undefined && <F label="Don't Fragment"  val={pkt.ip_df ? 'Set' : 'Not set'}                                        />}
                {pkt.ip_mf    !== undefined && <F label="More Fragments"  val={pkt.ip_mf ? 'Set' : 'Not set'}                                        />}
                {pkt.ip_frag  !== undefined && pkt.ip_frag > 0 && <F label="Frag offset"    val={pkt.ip_frag}                                        />}
              </div>
            )}
          </>}

          {/* Transport layer */}
          {(isTCP || isUDP || isICMP) && <>
            <LayerHeader id="transport" label={isTCP ? 'Transmission Control Protocol' : isUDP ? 'User Datagram Protocol' : 'ICMP'} color="text-violet-400" />
            {open.transport && (
              <div className="py-1">
                {(isTCP || isUDP) && <>
                  <F label="Source port"      val={pkt.src_port}   accent="cyan"   />
                  <F label="Destination port" val={pkt.dst_port}   accent="indigo" />
                </>}
                {isTCP && <>
                  <F label="Flags"            val={pkt.tcp_flags_detail || pkt.flags || '—'} accent="amber"   />
                  <F label="Sequence #"       val={pkt.tcp_seq  ?? '—'}                      />
                  <F label="Ack #"            val={pkt.tcp_ack  ?? '—'}                      />
                  <F label="Window size"      val={pkt.tcp_win  ?? '—'}                      />
                  {(pkt.tcp_urgent ?? 0) > 0 && <F label="Urgent pointer" val={pkt.tcp_urgent} accent="red" />}
                </>}
                {isUDP && pkt.udp_len != null && <F label="UDP length" val={`${pkt.udp_len} bytes`} />}
              </div>
            )}
          </>}

          {/* Application / Bastion AI telemetry */}
          <LayerHeader id="app" label="Bastion AI Telemetry" color={isThreat ? 'text-red-400' : 'text-emerald-400'} />
          {open.app && (
            <div className="py-1">
              {isThreat ? (
                <>
                  <F label="Verdict"       val={pkt.verdict}                                           accent="red"     />
                  <F label="Confidence"    val={`${((pkt.confidence ?? 0) * 100).toFixed(2)}%`}        accent="red"     />
                  <F label="Engine"        val={pkt.source_engine ?? '—'}                              accent="amber"   />
                  <F label="IDS Action"    val="FLAGGED / LOGGED TO ALERT STORE"                       accent="red"     />
                  {pkt.geo_flagged && <F label="Geo-Fence" val="⚠ Flagged — high-risk region"          accent="red"     />}
                </>
              ) : (
                <>
                  <F label="Verdict"       val="NORMAL — No threat detected"                           accent="emerald" />
                  <F label="Engine"        val={pkt.source_engine ?? 'BASTION_CLEAN'}                  accent="emerald" />
                  <F label="Coverage"      val="4/4 detection layers passed"                           accent="emerald" />
                </>
              )}
            </div>
          )}

        </div>

        {/* RIGHT: hex dump */}
        <div className="w-[42%] overflow-y-auto custom-scrollbar bg-black/40 py-2 px-2 font-mono shrink-0">
          <div className="text-[8px] text-slate-600 font-black uppercase tracking-widest px-1 pb-1 border-b border-slate-800 mb-1 flex gap-8">
            <span className="w-8">Offset</span>
            <span className="flex-1">Hexadecimal (16 bytes/row)</span>
            <span className="w-16 text-right">ASCII</span>
          </div>
          {hexRows.length === 0 ? (
            <div className="text-[9px] text-slate-700 text-center py-4">
              {pkt.payload_len != null
                ? pkt.payload_len === 0 ? 'No payload' : 'Payload truncated (capture limit)'
                : 'No payload data available'}
            </div>
          ) : (
            hexRows.map(({ offset, hex, ascii }) => (
              <div key={offset} className="flex gap-2 hover:bg-slate-800/30 px-1 rounded leading-5">
                <span className="text-slate-700 text-[9px] w-8 shrink-0">
                  {offset.toString(16).padStart(4, '0')}
                </span>
                <span className="flex-1 text-[9px] text-cyan-400/80 tracking-widest select-text">
                  {hex.join(' ').padEnd(47)}
                </span>
                <span className="text-[9px] text-emerald-400/70 select-text w-16 break-all text-right">
                  {ascii}
                </span>
              </div>
            ))
          )}
          {pkt.payload_len != null && pkt.payload_len > 256 && (
            <div className="text-[9px] text-slate-600 text-center pt-2">
              … {pkt.payload_len - 256} more bytes (truncated at 256 for display)
            </div>
          )}
        </div>

      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function LiveMonitor() {
  // Capture state machine: 'idle' | 'running' | 'stopped'
  const [captureState, setCaptureState] = useState('idle');
  const [packets,       setPackets]      = useState([]);
  const [interfaces,    setInterfaces]   = useState([]);
  // Persist selected interface across page navigations
  const [selIface, setSelIface] = useState(
    () => localStorage.getItem('bastion_sel_iface') ?? ''
  );
  const [bpfPreset,     setBpfPreset]    = useState('');       // selected preset value
  const [customBpf,     setCustomBpf]    = useState('');       // text when custom mode
  const [showCustom,    setShowCustom]   = useState(false);
  const [activeBpf,     setActiveBpf]    = useState('');
  const [protoFilter,   setProtoFilter]  = useState('ALL');
  const [searchTerm,    setSearchTerm]   = useState('');
  const [selPacket,     setSelPacket]    = useState(null);
  const [autoScroll,    setAutoScroll]   = useState(true);
  const [stats, setStats] = useState({ total: 0, threats: 0, pps: 0, bytes: 0 });
  const [captureError,  setCaptureError] = useState(null);   // sniffer error from backend
  const [ifaceWarning,  setIfaceWarning] = useState(null);   // ARP-only / wrong interface warning
  const [recIface,      setRecIface]     = useState(null);   // backend-recommended interface
  const [liveThreats,   setLiveThreats]  = useState([]);     // recent THREAT_DETECTED events (display only, capped at 20)
  const [sessionAlerts, setSessionAlerts] = useState(0);      // real session alert total (never capped)
  const [isolationToast, setIsolationToast] = useState(null); // auto-isolate notification
  const [exportingCSV,  setExportingCSV]  = useState(false);  // CSV export in-flight
  const [exportingPCAP, setExportingPCAP] = useState(false);  // PCAP export in-flight

  const wsRef          = useRef(null);
  const tableRef       = useRef(null);
  const pktCount       = useRef(0);
  const pktTimestamps  = useRef([]);   // sliding window timestamps for PPS
  const ppsTimer       = useRef(null);

  // Derived: the BPF string that will be applied on next start
  const pendingBpf = showCustom ? customBpf : bpfPreset;

  // ── Load network interfaces — fast retry until populated, then keep fresh ──
  useEffect(() => {
    let retryTimer = null;
    let refreshTimer = null;
    let populated = false;

    const isVirtual = n => {
      const nl = n.toLowerCase();
      return nl.includes('vmnet') || nl.includes('vmware') ||
             nl.includes('vethernet') || nl.includes('virtual') ||
             nl.includes('loopback') || nl.includes('bluetooth');
    };

    const loadIfaces = (isRefresh = false) => {
      // 10 s timeout — interface enumeration via psutil is fast, but if the backend
      // is still finishing model loading the request may queue for a few seconds.
      axios.get(`${API_BASE}/network/interfaces`, { headers: AUTH_HDR, timeout: 10000 })
        .then(({ data }) => {
          // Filter to real, up interfaces (exclude Loopback)
          const up = (data ?? []).filter(
            i => i.is_up && i.name && !i.name.toLowerCase().includes('loopback')
          );
          if (up.length > 0) {
            setInterfaces(up);
            if (!populated) {
              // Restore user's last selection; only auto-pick if nothing saved
              const saved = localStorage.getItem('bastion_sel_iface');
              const savedExists = saved && up.some(i => i.name === saved);
              if (!savedExists) {
                // Pre-select the best physical interface (Wi-Fi > Ethernet > other)
                const preferred =
                  up.find(i => /wi.?fi|wireless|wlan/i.test(i.name)) ||
                  up.find(i => /ethernet|lan|eth/i.test(i.name) && !isVirtual(i.name)) ||
                  up.find(i => !isVirtual(i.name)) ||
                  up[0];
                setSelIface(preferred.name);
                localStorage.setItem('bastion_sel_iface', preferred.name);
              }
              // else: saved interface is valid — already in state, no change needed
              populated = true;
            }
          } else if (!populated) {
            // Backend not ready yet — retry in 800 ms
            retryTimer = setTimeout(() => loadIfaces(false), 800);
          }
        })
        .catch(() => {
          if (!populated) {
            // Backend unreachable — retry in 800 ms
            retryTimer = setTimeout(() => loadIfaces(false), 800);
          }
          // If already populated but backend went away, keep existing list and
          // retry silently — the list refreshes once backend comes back.
        });
    };

    loadIfaces();

    // Keep interface list fresh every 30 s — detects new adapters and
    // recovers automatically if the backend crashed and restarted.
    refreshTimer = setInterval(() => loadIfaces(true), 30000);

    return () => {
      clearTimeout(retryTimer);
      clearInterval(refreshTimer);
      wsRef.current?.close();
      clearInterval(ppsTimer.current);
    };
  }, []);

  // ── Auto-scroll ─────────────────────────────────────────────────────────────
  useEffect(() => {
    if (autoScroll && tableRef.current) {
      tableRef.current.scrollTop = tableRef.current.scrollHeight;
    }
  }, [packets.length, autoScroll]);

  // ── PPS counter (sliding 1-second window for accurate real-time rate) ─────────
  function startPps() {
    clearInterval(ppsTimer.current);
    pktTimestamps.current = [];
    ppsTimer.current = setInterval(() => {
      const cutoff = Date.now() - 1000;
      // Drop timestamps older than 1 second
      pktTimestamps.current = pktTimestamps.current.filter(t => t >= cutoff);
      setStats(s => ({ ...s, pps: pktTimestamps.current.length }));
    }, 500);   // poll every 500ms for smooth display
  }
  function stopPps() {
    clearInterval(ppsTimer.current);
    setStats(s => ({ ...s, pps: 0 }));
  }

  // ── WebSocket connect ────────────────────────────────────────────────────────
  const openWs = useCallback((action, bpf) => {
    if (wsRef.current && wsRef.current.readyState !== WebSocket.CLOSED) {
      wsRef.current.close();
    }
    const ws = new WebSocket(SOCKET_URL);

    ws.onopen = () => {
      ws.send(JSON.stringify({ action, interface: selIface, bpf: bpf ?? '' }));
      setCaptureState('running');
      startPps();
    };

    ws.onmessage = ({ data }) => {
      try {
        const pkt = JSON.parse(data);

        // ── Backend error broadcast ──────────────────────────────────────
        if (pkt.type === 'CAPTURE_ERROR') {
          setCaptureError(pkt.error || 'Unknown capture error');
          setCaptureState('stopped');
          stopPps();
          return;
        }

        // ── Real-time threat detected event ──────────────────────────────
        // Backend broadcasts THREAT_DETECTED before the packet info so the
        // threat counter is always authoritative and never double-counted.
        if (pkt.type === 'THREAT_DETECTED') {
          const evt = {
            id:        pkt.No,
            verdict:   pkt.verdict,
            engine:    pkt.engine,
            src_ip:    pkt.src_ip,
            dst_ip:    pkt.dst_ip,
            ts:        pkt.timestamp,
            isolated:  pkt.auto_isolated,
          };
          setLiveThreats(prev => [evt, ...prev].slice(0, 20)); // keep last 20 for display
          setSessionAlerts(n => n + 1);                        // real running total
          setStats(s => ({ ...s, threats: pkt.total_threats ?? s.threats + 1 }));
          if (pkt.auto_isolated) {
            setIsolationToast({ ip: pkt.src_ip, ts: Date.now() });
            setTimeout(() => setIsolationToast(null), 6000);
          }
          return;  // don't add to packet ring
        }

        setCaptureError(null);  // clear any previous error on valid packet
        pktCount.current += 1;
        pktTimestamps.current.push(Date.now());   // record arrival for PPS calc
        setPackets(prev => {
          const next = prev.length >= MAX_PACKETS ? prev.slice(1) : prev;
          return [...next, pkt];
        });
        setStats(s => ({
          ...s,
          total: pktCount.current,
          bytes: s.bytes + (parseInt(pkt.Length) || 0),
          // threats updated authoritatively by THREAT_DETECTED events
        }));
      } catch {}
    };

    ws.onclose = () => {
      setCaptureState(prev => (prev === 'running' ? 'stopped' : prev));
      stopPps();
    };
    ws.onerror = () => { setCaptureState(prev => prev === 'running' ? 'stopped' : prev); stopPps(); };
    wsRef.current = ws;
  }, [selIface]);   // eslint-disable-line

  // ── Interface warning poll (every 8s while capturing) ───────────────────────
  // Checks /capture/stats for backend's analysis of whether the current interface
  // is only seeing ARP/broadcast traffic (wrong interface selected).
  useEffect(() => {
    if (captureState !== 'running') { setIfaceWarning(null); setRecIface(null); return; }
    const poll = () => {
      axios.get(`${API_BASE}/capture/stats`, { headers: AUTH_HDR, timeout: 5000 })
        .then(({ data }) => {
          setIfaceWarning(data.interface_warning || null);
          setRecIface(data.recommended_interface || null);
        })
        .catch(() => {});
    };
    poll(); // immediate first check
    const t = setInterval(poll, 8000);
    return () => clearInterval(t);
  }, [captureState]); // eslint-disable-line

  // ── Capture controls ─────────────────────────────────────────────────────────
  const handleStart = () => {
    setCaptureError(null);
    setIfaceWarning(null);
    setRecIface(null);
    setPackets([]);
    setLiveThreats([]);
    setSessionAlerts(0);
    setIsolationToast(null);
    pktCount.current      = 0;
    pktTimestamps.current = [];
    setStats({ total: 0, threats: 0, pps: 0, bytes: 0 });
    setSelPacket(null);
    setActiveBpf(pendingBpf);
    openWs('START', pendingBpf);
  };

  const handleStop = () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'STOP' }));
    }
    setCaptureState('stopped');
    stopPps();
  };

  const handleContinue = () => {
    setActiveBpf(pendingBpf);
    openWs('START', pendingBpf);   // resume on same packet list
  };

  const handleRestart = () => {
    setPackets([]);
    pktCount.current      = 0;
    pktTimestamps.current = [];
    setStats({ total: 0, threats: 0, pps: 0, bytes: 0 });
    setSelPacket(null);
    setActiveBpf(pendingBpf);
    openWs('RESTART', pendingBpf);
  };

  // ── Unique filename generator ─────────────────────────────────────────────
  function _bastionFileName(type, ext) {
    const now  = new Date();
    const date = now.toISOString().slice(0, 10);                  // YYYY-MM-DD
    const time = now.toTimeString().slice(0, 8).replace(/:/g, '-'); // HH-MM-SS
    const iface = (selIface || 'all').replace(/\s+/g, '_').slice(0, 20);
    return `BASTION-IDS_${date}_${time}_${iface}_${type}.${ext}`;
  }

  // ── Export CSV ───────────────────────────────────────────────────────────────
  const handleExportCSV = async () => {
    if (exportingCSV) return;
    setExportingCSV(true);
    try {
      const r = await axios.get(`${API_BASE}/capture/export-csv`, {
        responseType: 'blob',
        headers: AUTH_HDR,
        timeout: 30000,
      });
      _download(r.data, _bastionFileName('capture', 'csv'));
    } catch {
      // Fallback: build from local packet state
      if (packets.length) {
        const cols = ['No.','Time','Source','src_port','Destination','dst_port',
                      'Protocol','Length','Info','verdict','confidence','source_engine'];
        const rows = packets.map(p =>
          cols.map(c => `"${String(p[c] ?? '').replace(/"/g, '""')}"`).join(',')
        );
        _download(
          new Blob([cols.join(',') + '\n' + rows.join('\n')], { type: 'text/csv' }),
          _bastionFileName('capture', 'csv'),
        );
      }
    } finally {
      setExportingCSV(false);
    }
  };

  const handleExportPCAP = async () => {
    if (exportingPCAP) return;
    setExportingPCAP(true);
    try {
      const r = await axios.get(`${API_BASE}/capture/export-pcap`, {
        responseType: 'blob',
        headers: AUTH_HDR,
        timeout: 30000,
      });
      if (r.data.size === 0) throw new Error('Empty PCAP');
      _download(r.data, _bastionFileName('capture', 'pcap'));
    } catch (err) {
      console.error('PCAP export:', err?.message || err);
      setStats(s => ({ ...s, _pcapErr: true }));
      setTimeout(() => setStats(s => ({ ...s, _pcapErr: false })), 4000);
    } finally {
      setExportingPCAP(false);
    }
  };

  // ── Save session to disk ──────────────────────────────────────────────────
  const handleSaveSession = useCallback(async () => {
    if (!packets.length) return;
    // Save CSV locally (client-side fallback always works)
    const cols = ['No.','Time','Source','src_port','Destination','dst_port',
                  'Protocol','Length','Info','verdict','confidence','source_engine','ttl'];
    const rows = packets.map(p =>
      cols.map(c => `"${String(p[c] ?? '').replace(/"/g, '""')}"`).join(',')
    );
    _download(
      new Blob([cols.join(',') + '\n' + rows.join('\n')], { type: 'text/csv' }),
      _bastionFileName('session', 'csv'),
    );
    // Also try to save PCAP from backend
    try {
      const r = await axios.get(`${API_BASE}/capture/export-pcap`, {
        responseType: 'blob', headers: AUTH_HDR, timeout: 30000,
      });
      if (r.data.size > 0) {
        _download(r.data, _bastionFileName('session', 'pcap'));
      }
    } catch { /* CSV save always succeeds */ }
  }, [packets, selIface]);   // eslint-disable-line

  function _download(blob, name) {
    // In Electron, blob: URL anchor clicks trigger page navigation instead of
    // a file download.  Route through the IPC 'save-file-data' channel so the
    // main process writes the file via a native Save As dialog.
    try {
      const { ipcRenderer } = window.require('electron');
      const reader = new FileReader();
      reader.onload = () => {
        ipcRenderer.invoke('save-file-data', { buffer: reader.result, name });
      };
      reader.readAsArrayBuffer(blob);
      return;
    } catch (_e) {
      // Not in Electron — fall through to browser blob-URL approach
    }
    const url = URL.createObjectURL(blob);
    const a   = document.createElement('a');
    a.href     = url;
    a.download = name;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 3000);
  }

  // ── Filtered view ────────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    const q = searchTerm.toLowerCase();
    return packets.filter(p => {
      if (protoFilter !== 'ALL') {
        const pp = p.Protocol?.toUpperCase() ?? '';
        // IPv6 chip matches packets using IPv6 transport (proto field == 'ipv6' or 'tcp'/'udp' over v6)
        if (protoFilter === 'IPv6') {
          if (p.proto?.toLowerCase() !== 'ipv6' && pp !== 'IPV6') return false;
        } else if (pp !== protoFilter) return false;
      }
      if (q) {
        const vals = Object.values(p).map(v => String(v).toLowerCase());
        if (!vals.some(v => v.includes(q))) return false;
      }
      return true;
    });
  }, [packets, protoFilter, searchTerm]);

  const threats = useMemo(() => packets.filter(p => p.verdict && p.verdict !== 'NORMAL'), [packets]);

  // ── Button styles ─────────────────────────────────────────────────────────────
  const btn = (colour, disabled) =>
    `flex items-center gap-1.5 px-4 py-2 rounded text-[11px] font-black uppercase tracking-wider transition-all
     bg-${colour}-500/10 text-${colour}-400 border border-${colour}-500/40
     hover:bg-${colour}-500/20 hover:border-${colour}-400
     disabled:opacity-30 disabled:cursor-not-allowed`;

  // ─────────────────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col gap-3 pb-4 animate-in fade-in slide-in-from-bottom-4">

      {/* ══ CONTROL BAR ══════════════════════════════════════════════════════════ */}
      <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-wrap gap-3 items-center shadow-md">

        {/* Capture buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={handleStart}
            disabled={captureState === 'running'}
            className="flex items-center gap-1.5 px-4 py-2 rounded text-[11px] font-black uppercase tracking-wider transition-all
              bg-emerald-500/10 text-emerald-400 border border-emerald-500/40 hover:bg-emerald-500/20 hover:border-emerald-400
              disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <Play size={12} /> Start
          </button>
          <button
            onClick={handleStop}
            disabled={captureState !== 'running'}
            className="flex items-center gap-1.5 px-4 py-2 rounded text-[11px] font-black uppercase tracking-wider transition-all
              bg-red-500/10 text-red-400 border border-red-500/40 hover:bg-red-500/20 hover:border-red-400
              disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <Square size={12} /> Stop
          </button>
          <button
            onClick={handleContinue}
            disabled={captureState !== 'stopped'}
            className="flex items-center gap-1.5 px-4 py-2 rounded text-[11px] font-black uppercase tracking-wider transition-all
              bg-sky-500/10 text-sky-400 border border-sky-500/40 hover:bg-sky-500/20 hover:border-sky-400
              disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <Pause size={12} /> Continue
          </button>
          <button
            onClick={handleRestart}
            disabled={captureState === 'idle'}
            className="flex items-center gap-1.5 px-4 py-2 rounded text-[11px] font-black uppercase tracking-wider transition-all
              bg-amber-500/10 text-amber-400 border border-amber-500/40 hover:bg-amber-500/20 hover:border-amber-400
              disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <RotateCcw size={12} /> Restart
          </button>
        </div>

        <div className="w-px h-8 bg-slate-800 hidden lg:block" />

        {/* Interface selector */}
        <div className="flex items-center gap-2">
          <Network size={13} className="text-slate-500 shrink-0" />
          <select
            value={selIface}
            onChange={e => {
              setSelIface(e.target.value);
              localStorage.setItem('bastion_sel_iface', e.target.value);
            }}
            disabled={captureState === 'running'}
            className="bg-slate-900 border border-slate-800 text-slate-300 text-[10px] font-bold uppercase tracking-wider
              py-2 px-3 rounded outline-none w-52 disabled:opacity-40 cursor-pointer"
          >
            <option value="">Auto — All Interfaces</option>
            {interfaces.map(i => (
              <option key={i.name} value={i.name}>
                {i.name}{i.ip ? ` · ${i.ip}` : ''}{!i.is_up ? ' [DOWN]' : ''}
              </option>
            ))}
          </select>
        </div>

        {/* Traffic scope filter — Berkeley Packet Filter presets */}
        <div className="flex items-center gap-2 flex-1 min-w-[260px]">
          <Filter size={13} className="text-slate-500 shrink-0" />
          <div className="flex flex-col gap-1 flex-1">
            <select
              value={showCustom ? '__custom__' : bpfPreset}
              onChange={e => {
                const v = e.target.value;
                if (v === '__custom__') {
                  setShowCustom(true);
                } else {
                  setShowCustom(false);
                  setBpfPreset(v);
                }
              }}
              disabled={captureState === 'running'}
              className="bg-slate-900 border border-slate-800 text-slate-300 text-[11px] font-mono py-2 px-3
                rounded outline-none focus:border-cyan-500/50 transition-colors disabled:opacity-40 cursor-pointer"
            >
              {BPF_PRESETS.map((p, i) => (
                <option key={i} value={p.value}>{p.label}</option>
              ))}
            </select>
            {showCustom && (
              <input
                type="text"
                placeholder="e.g.  host 192.168.1.100  and  tcp port 80"
                value={customBpf}
                onChange={e => setCustomBpf(e.target.value)}
                disabled={captureState === 'running'}
                onKeyDown={e => e.key === 'Enter' && captureState === 'idle' && handleStart()}
                className="bg-slate-900 border border-cyan-500/30 text-slate-300 text-[11px] font-mono py-2 px-3
                  rounded outline-none focus:border-cyan-500/60 placeholder:text-slate-600 transition-colors"
              />
            )}
          </div>
        </div>

        {/* Export + Save buttons */}
        <div className="flex items-center gap-2 ml-auto flex-wrap">
          {/* PCAP error notification */}
          {stats._pcapErr && (
            <span className="flex items-center gap-1.5 text-[9px] font-black text-amber-400 bg-amber-950/20
              border border-amber-500/30 px-2 py-1 rounded animate-pulse">
              <AlertCircle size={10}/> PCAP unavailable — CSV saved
            </span>
          )}
          <button
            onClick={handleExportCSV}
            disabled={!packets.length || exportingCSV}
            className="flex items-center gap-1.5 px-3 py-2 rounded text-[10px] font-black uppercase tracking-wider
              bg-slate-900 text-slate-400 border border-slate-800 hover:border-cyan-500/40 hover:text-cyan-400
              transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            title="Export captured packets as CSV"
          >
            {exportingCSV
              ? <><RefreshCw size={12} className="animate-spin"/> Exporting…</>
              : <><FileDown size={12} /> CSV</>}
          </button>
          <button
            onClick={handleExportPCAP}
            disabled={!packets.length || exportingPCAP}
            className="flex items-center gap-1.5 px-3 py-2 rounded text-[10px] font-black uppercase tracking-wider
              bg-slate-900 text-slate-400 border border-slate-800 hover:border-violet-500/40 hover:text-violet-400
              transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            title="Export raw PCAP capture file"
          >
            {exportingPCAP
              ? <><RefreshCw size={12} className="animate-spin"/> Exporting…</>
              : <><Download size={12} /> PCAP</>}
          </button>
          <button
            onClick={handleSaveSession}
            disabled={!packets.length}
            className="flex items-center gap-1.5 px-3 py-2 rounded text-[10px] font-black uppercase tracking-wider
              bg-emerald-950/20 text-emerald-400 border border-emerald-500/30 hover:border-emerald-400 hover:bg-emerald-950/40
              transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            title="Save full session (CSV + PCAP) to disk with date/time identifier"
          >
            <Save size={12} /> Save Session
          </button>
        </div>
      </div>

      {/* ══ STATS STRIP ══════════════════════════════════════════════════════════ */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Packets Captured', val: stats.total.toLocaleString(),   icon: <Activity  size={15}/>, colour: 'text-cyan-400'   },
          { label: 'Threats Detected', val: stats.threats.toLocaleString(), icon: <ShieldAlert size={15}/>, colour: 'text-red-400' },
          { label: 'Throughput',       val: `${stats.pps} pkt/s`,           icon: <Radio     size={15}/>, colour: 'text-emerald-400' },
          { label: 'Data Volume',      val: formatBytes(stats.bytes),        icon: <Database  size={15}/>, colour: 'text-violet-400' },
        ].map(s => (
          <div key={s.label} className="bg-slate-950 border border-slate-800 rounded-lg px-4 py-3 flex items-center gap-3">
            <span className={s.colour}>{s.icon}</span>
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">{s.label}</p>
              <p className={`text-sm font-black font-mono ${s.colour}`}>{s.val}</p>
            </div>
          </div>
        ))}
      </div>

      {/* ══ AUTO-ISOLATION TOAST ════════════════════════════════════════════════ */}
      {isolationToast && (
        <div className="flex items-center gap-3 px-4 py-3 bg-amber-950/60 border border-amber-500/40 rounded-xl animate-in slide-in-from-top duration-300">
          <ShieldAlert size={16} className="text-amber-400 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-black uppercase tracking-widest text-amber-400">Auto-Isolate Fired</p>
            <p className="text-[9px] text-amber-300/80 font-mono">{isolationToast.ip} — Windows Firewall rule created. Release from Command &amp; Control.</p>
          </div>
          <button onClick={() => setIsolationToast(null)} className="text-amber-600 hover:text-amber-400 transition-colors">
            <X size={14} />
          </button>
        </div>
      )}

      {/* ══ LIVE THREAT FEED (shown during capture when threats exist) ══════════ */}
      {captureState === 'running' && liveThreats.length > 0 && (
        <div className="bg-red-950/20 border border-red-500/20 rounded-xl p-3">
          <p className="text-[9px] font-black uppercase tracking-widest text-red-400 mb-2 flex items-center gap-1.5">
            <ShieldAlert size={11}/> Live Threat Feed — {sessionAlerts.toLocaleString()} alert{sessionAlerts !== 1 ? 's' : ''} this session (showing latest {liveThreats.length})
          </p>
          <div className="space-y-1 max-h-40 overflow-y-auto scrollbar-thin">
            {liveThreats.map((t, i) => (
              <div key={i} className="flex items-center gap-2 text-[9px] font-mono">
                <span className="text-red-500">▶</span>
                <span className="text-red-300 font-black">{t.verdict}</span>
                <span className="text-slate-500">{t.src_ip} → {t.dst_ip}</span>
                <span className="text-slate-600">[{t.engine}]</span>
                {t.isolated && <span className="text-amber-400 font-black">ISOLATED</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ══ FILTER CHIPS + SEARCH BAR ════════════════════════════════════════════ */}
      <div className="flex flex-wrap gap-2 items-center">
        {/* Protocol chips */}
        {PROTO_CHIPS.map(p => (
          <button
            key={p}
            onClick={() => setProtoFilter(p)}
            className={`px-3 py-1 rounded text-[10px] font-black uppercase tracking-wider border transition-all ${
              protoFilter === p
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/60'
                : 'bg-slate-900 text-slate-600 border-slate-800 hover:border-slate-600 hover:text-slate-300'
            }`}
          >
            {p}
          </button>
        ))}

        {/* Search */}
        <div className="relative flex-1 min-w-[200px] ml-2">
          <input
            type="text"
            placeholder="Search IPs, ports, protocols, payloads..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 text-slate-300 text-[11px] font-mono py-2 pl-9 pr-8
              rounded outline-none focus:border-cyan-500/50 placeholder:text-slate-700 transition-colors"
          />
          <Search size={13} className="absolute left-3 top-2.5 text-slate-500 pointer-events-none" />
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} className="absolute right-3 top-2.5">
              <X size={13} className="text-slate-500 hover:text-slate-300 transition-colors" />
            </button>
          )}
        </div>

        {/* Auto-scroll toggle */}
        <button
          onClick={() => setAutoScroll(v => !v)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-black uppercase tracking-wider border transition-all ${
            autoScroll
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/40'
              : 'bg-slate-900 text-slate-600 border-slate-800 hover:text-slate-300'
          }`}
          title="Toggle auto-scroll to newest packets"
        >
          <ChevronDown size={12} /> Auto-Scroll
        </button>

        <span className="text-[10px] text-slate-700 font-mono pl-1">
          {filtered.length.toLocaleString()} / {packets.length.toLocaleString()} flows
        </span>
      </div>

      {/* ══ PACKET CAPTURE TABLE ═════════════════════════════════════════════════ */}
      <div className="bg-slate-950 border border-slate-800 rounded-lg flex flex-col shadow-lg"
           style={{ height: '400px' }}>

        {/* Table header bar */}
        <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-2">
            <Radio size={12} className={captureState === 'running' ? 'text-emerald-400 animate-pulse' : 'text-slate-700'} />
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Network Packet Stream</span>

            {captureState === 'running' && (
              <span className="text-[9px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded
                font-black uppercase tracking-widest animate-pulse ml-1">LIVE</span>
            )}
            {captureState === 'stopped' && (
              <span className="text-[9px] bg-amber-500/10 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded
                font-black uppercase tracking-widest ml-1">PAUSED</span>
            )}
            {activeBpf && (
              <span className="text-[9px] bg-violet-900/20 text-violet-400 border border-violet-700/30 px-2 py-0.5 rounded font-mono ml-1">
                bpf: {activeBpf}
              </span>
            )}
          </div>
          {threats.length > 0 && (
            <span className="text-[9px] bg-red-500/10 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-black uppercase tracking-widest">
              {threats.length} in view (of {sessionAlerts.toLocaleString()} total)
            </span>
          )}
        </div>

        {/* Interface warning banner — ARP-only / wrong adapter selected */}
        {ifaceWarning && captureState === 'running' && (
          <div className="mx-4 mb-2 flex items-start gap-3 bg-amber-500/10 border border-amber-500/30 rounded-xl px-4 py-3 animate-in slide-in-from-top-2 duration-300">
            <AlertCircle size={16} className="text-amber-400 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <p className="text-amber-300 text-[10px] font-black uppercase tracking-widest mb-1">Wrong Interface Detected</p>
              <p className="text-amber-400/80 text-[10px] font-bold leading-relaxed">{ifaceWarning}</p>
            </div>
            {recIface && (
              <button
                onClick={() => { setSelIface(recIface); setIfaceWarning(null); }}
                className="shrink-0 px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-black text-[9px] font-black uppercase tracking-widest rounded-lg transition-all"
              >
                Switch Now
              </button>
            )}
          </div>
        )}

        {/* Scrollable packet rows */}
        <div ref={tableRef} className="flex-1 overflow-y-auto overflow-x-auto custom-scrollbar">
          <table className="w-full whitespace-nowrap border-collapse text-[11px] font-mono">
            <thead className="sticky top-0 z-10 bg-[#060912] border-b border-slate-800">
              <tr className="text-[9px] text-slate-600 uppercase tracking-widest font-black">
                <th className="px-3 py-2 text-left w-12">#</th>
                <th className="px-3 py-2 text-left w-28">Time</th>
                <th className="px-3 py-2 text-left w-36">Source IP</th>
                <th className="px-3 py-2 text-left w-16">S.Port</th>
                <th className="px-3 py-2 text-left w-36">Dest IP</th>
                <th className="px-3 py-2 text-left w-16">D.Port</th>
                <th className="px-3 py-2 text-left w-28">Protocol</th>
                <th className="px-3 py-2 text-right w-16">Len</th>
                <th className="px-3 py-2 text-left">Payload / Info Summary</th>
                <th className="px-3 py-2 text-left w-28">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((pkt, idx) => {
                const isThreat  = pkt.verdict && pkt.verdict !== 'NORMAL';
                const isSelected = selPacket?.['No.'] === pkt['No.'];
                const palette   = protoPalette(pkt.Protocol, isThreat);
                return (
                  <tr
                    key={pkt['No.'] ?? idx}
                    onClick={() => setSelPacket(isSelected ? null : pkt)}
                    className={`border-b cursor-pointer transition-colors
                      ${isThreat
                        ? 'bg-red-950/15 hover:bg-red-950/40 border-red-900/20'
                        : 'hover:bg-slate-800/40 border-slate-800/40'}
                      ${isSelected ? 'ring-1 ring-inset ring-cyan-500/50 bg-cyan-950/10 hover:bg-cyan-950/20' : ''}`}
                  >
                    <td className="px-3 py-1 text-slate-700 font-black">{pkt['No.']}</td>
                    <td className="px-3 py-1 text-slate-600">{pkt.Time}</td>
                    <td className={`px-3 py-1 ${isThreat ? 'text-red-400' : 'text-cyan-400'}`}>{pkt.Source}</td>
                    <td className="px-3 py-1 text-slate-600">{pkt.src_port || '—'}</td>
                    <td className={`px-3 py-1 ${isThreat ? 'text-red-300' : 'text-indigo-400'}`}>{pkt.Destination}</td>
                    <td className="px-3 py-1 text-slate-600">{pkt.dst_port || '—'}</td>
                    <td className="px-3 py-1"><ProtoBadge proto={pkt.Protocol} isThreat={isThreat} /></td>
                    <td className="px-3 py-1 text-right text-slate-600">{pkt.Length}</td>
                    <td className="px-3 py-1 text-slate-500 max-w-xs truncate">{pkt.Info}</td>
                    <td className="px-3 py-1">
                      {isThreat
                        ? <span className="text-[9px] font-black text-red-400 uppercase tracking-wider">{pkt.verdict}</span>
                        : <span className="text-[9px] text-slate-800">—</span>
                      }
                    </td>
                  </tr>
                );
              })}

              {!filtered.length && (
                <tr>
                  <td colSpan={10} className="py-16 text-center">
                    {captureError ? (
                      <div className="flex flex-col items-center gap-3">
                        <AlertCircle size={28} className="text-red-500" />
                        <p className="text-red-400 text-[11px] font-black uppercase tracking-widest">Capture Failed</p>
                        <p className="text-amber-400/80 text-[10px] font-bold max-w-md leading-relaxed">{captureError}</p>
                        <p className="text-slate-600 text-[9px] mt-1">Double-click START_BASTION.bat → allow UAC → then restart capture</p>
                      </div>
                    ) : captureState === 'running' ? (
                      <div className="flex flex-col items-center gap-2">
                        <Activity size={22} className="text-cyan-500 animate-pulse" />
                        <p className="text-slate-600 text-[11px] uppercase font-bold tracking-widest">Capture interface bound — awaiting traffic frames...</p>
                        <p className="text-slate-700 text-[9px]">BPF filter active: ip or arp — only IPv4 and ARP packets shown</p>
                      </div>
                    ) : captureState === 'stopped' ? (
                      <p className="text-slate-700 text-[11px] uppercase font-bold tracking-widest">Capture paused — click Continue to resume or Restart to clear.</p>
                    ) : (
                      <div className="flex flex-col items-center gap-2">
                        <Radio size={22} className="text-slate-700" />
                        <p className="text-slate-700 text-[11px] uppercase font-bold tracking-widest">No active capture — select an interface and press Start.</p>
                        <p className="text-slate-800 text-[9px]">⚠ Requires Administrator — run via START_BASTION.bat for packet capture</p>
                      </div>
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ══ WIRESHARK-STYLE PACKET INSPECTOR (bottom pane) ══════════════════════ */}
      {selPacket && <PacketInspector pkt={selPacket} iface={selIface} onClose={() => setSelPacket(null)} />}


    </div>
  );
}
