import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import {
  Share2, Server as ServerIcon, Laptop, ShieldAlert, Activity, RefreshCw,
  Database, Radio, Terminal, Cpu, AlertTriangle, Zap, Info, Lock,
  ChevronRight, Search, Monitor, Network, Globe, Shield, Eye,
  Wifi, Router, Smartphone, Printer, ChevronDown, X
} from 'lucide-react';

const API_BASE_URL = 'http://127.0.0.1:48217/api/v1';
const AUTH_KEY     = "BASTION-KADIAN-SEC-0x42";

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'x-authority': AUTH_KEY }
});

/**
 * Derive OS display string from backend node data.
 * The backend already runs multi-factor fingerprinting (_fingerprint_os) —
 * prefer the `os` field from the node, fall back to TTL-based guess only
 * when no backend data is available.
 */
function inferOS(node) {
  // If backend already fingerprinted, use that result directly
  if (node?.os && node.os !== 'Unknown') {
    return { name: node.os, confidence: node.vendor ? `Vendor: ${node.vendor}` : `TTL=${node.ttl ?? 0}` };
  }
  const ttl = Number(node?.ttl ?? 0);
  if (!ttl) return { name: 'Unknown', confidence: 'No TTL' };
  if (ttl <= 64)  return { name: 'Linux / Unix', confidence: `TTL=${ttl}` };
  if (ttl <= 128) return { name: 'Windows',      confidence: `TTL=${ttl}` };
  if (ttl <= 255) return { name: 'Cisco / Network Device', confidence: `TTL=${ttl}` };
  return { name: 'Unknown', confidence: `TTL=${ttl}` };
}

/** OS icon colour helper */
function osColor(osName) {
  const n = (osName || '').toLowerCase();
  if (n.includes('windows'))    return 'text-sky-400';
  if (n.includes('apple') || n.includes('ios') || n.includes('macos')) return 'text-slate-300';
  if (n.includes('android'))    return 'text-emerald-400';
  if (n.includes('linux'))      return 'text-amber-400';
  if (n.includes('cisco') || n.includes('network')) return 'text-orange-400';
  if (n.includes('vmware') || n.includes('virtual')) return 'text-violet-400';
  return 'text-slate-500';
}

// Get icon for node type
function NodeIcon({ type, size = 16 }) {
  switch ((type || '').toLowerCase()) {
    case 'server':      return <ServerIcon size={size} />;
    case 'router':
    case 'gateway':     return <Radio size={size} />;
    case 'workstation': return <Monitor size={size} />;
    case 'mobile':      return <Smartphone size={size} />;
    case 'printer':     return <Printer size={size} />;
    default:            return <Laptop size={size} />;
  }
}

// Node type colour
function nodeColor(type) {
  switch ((type || '').toLowerCase()) {
    case 'server':      return { ring: 'stroke-violet-400', fill: 'fill-violet-900/30', text: 'text-violet-400' };
    case 'router':
    case 'gateway':     return { ring: 'stroke-amber-400',  fill: 'fill-amber-900/20',  text: 'text-amber-400'  };
    case 'workstation': return { ring: 'stroke-cyan-400',   fill: 'fill-cyan-900/20',   text: 'text-cyan-400'   };
    default:            return { ring: 'stroke-slate-500',  fill: 'fill-slate-800/40',  text: 'text-slate-400'  };
  }
}

export default function NetworkTopology({ status }) {
  const [nodes,          setNodes]          = useState([]);
  const [connections,    setConnections]    = useState([]);
  const [selectedNode,   setSelectedNode]   = useState(null);
  const [isLoading,      setIsLoading]      = useState(true);
  const [logs,           setLogs]           = useState([]);
  const [interfaces,     setInterfaces]     = useState([]);
  // Persist selected network interface across navigations (same key as LiveMonitor)
  const [selIface, setSelIface] = useState(
    () => localStorage.getItem('bastion_sel_iface') ?? ''
  );
  const [search,         setSearch]         = useState('');
  const [dpiStatus,      setDpiStatus]      = useState(null); // { nodeId, status }
  const [quarantined,    setQuarantined]    = useState(new Set());
  const [isRescanning,   setIsRescanning]   = useState(false);
  const [scanPulse,      setScanPulse]      = useState(0);   // increments to trigger CSS pulse
  const autoRefreshRef   = useRef(null);

  const addLog = useCallback((msg, level = 'INFO') => {
    const timestamp = new Date().toLocaleTimeString([], { hour12: false });
    const prefix    = level === 'ERR' ? '✗' : level === 'OK' ? '✓' : '›';
    setLogs(prev => [`[${timestamp}]  ${prefix}  ${msg}`, ...prev.slice(0, 59)]);
  }, []);

  // ── Load interfaces on mount — retry every 3 s until populated ──────────
  useEffect(() => {
    let retryTimer = null;
    const loadIfaces = () => {
      api.get('/network/interfaces')
        .then(({ data }) => {
          const up = (data || []).filter(
            i => i.is_up && i.name && !i.name.toLowerCase().includes('loopback')
          );
          if (up.length > 0) {
            setInterfaces(up);
            const saved = localStorage.getItem('bastion_sel_iface');
            const savedOk = saved && up.some(i => i.name === saved);
            if (!savedOk && !selIface) {
              // Auto-pick best interface only if nothing was saved
              const isVirtual = n => {
                const nl = n.toLowerCase();
                return nl.includes('vmnet') || nl.includes('vmware') ||
                       nl.includes('vethernet') || nl.includes('virtual') ||
                       nl.includes('loopback') || nl.includes('bluetooth');
              };
              const preferred =
                up.find(i => /wi.?fi|wireless|wlan/i.test(i.name)) ||
                up.find(i => /ethernet|lan|eth/i.test(i.name) && !isVirtual(i.name)) ||
                up.find(i => !isVirtual(i.name)) ||
                up[0];
              setSelIface(preferred.name);
              localStorage.setItem('bastion_sel_iface', preferred.name);
            }
          } else {
            retryTimer = setTimeout(loadIfaces, 3000);
          }
        })
        .catch(() => { retryTimer = setTimeout(loadIfaces, 3000); });
    };
    loadIfaces();
    return () => clearTimeout(retryTimer);
  }, []); // eslint-disable-line

  // ── Topology fetch — returns cached data immediately (non-blocking) ──────
  const fetchTopologyData = useCallback(async (iface) => {
    try {
      if (nodes.length === 0) setIsLoading(true);
      const params = iface ? { interface: iface } : {};
      const response = await api.get('/topology', { params });
      const newNodes = response.data.nodes || [];
      const newConns = response.data.connections || [];
      setNodes(newNodes);
      setConnections(newConns);
      // Don't log an error if the cache is still being populated (scanning state)
      if (response.data.scanning) {
        addLog('ARP scan in progress — topology will update shortly', 'INFO');
      } else {
        const devCount = (newNodes.length - 1);  // exclude CORE-IDS
        addLog(`Topology refreshed — ${devCount} device${devCount !== 1 ? 's' : ''} on network`, 'OK');
      }
    } catch {
      addLog('Network discovery failed — check engine connectivity', 'ERR');
    } finally {
      setIsLoading(false);
    }
  }, [addLog, nodes.length]);

  // ── Auto-refresh every 10 seconds ─────────────────────────
  useEffect(() => {
    fetchTopologyData(selIface);
    clearInterval(autoRefreshRef.current);
    autoRefreshRef.current = setInterval(() => fetchTopologyData(selIface), 10000);
    return () => clearInterval(autoRefreshRef.current);
  }, [selIface]); // re-bind when interface changes

  // ── Deep Packet Inspection on a node ─────────────────────
  const handleDPI = async (node) => {
    setDpiStatus({ nodeId: node.id, status: 'running' });
    addLog(`Deep Packet Inspection initiated on ${node.ip}`, 'INFO');
    try {
      // DPI: instruct engine to flag traffic to/from this IP for detailed analysis
      await api.post('/settings/update', { dpi_target: node.ip, dpi_enabled: true });
      addLog(`DPI active on ${node.ip} — layer-7 analysis enabled`, 'OK');
      setDpiStatus({ nodeId: node.id, status: 'active', ip: node.ip });
    } catch {
      addLog(`DPI could not be enabled — engine unreachable`, 'ERR');
      setDpiStatus(null);
    }
  };

  // ── Stop DPI (clears the engine-side target too) ──────────
  const handleStopDPI = async () => {
    const ip = dpiStatus?.ip;
    try {
      await api.post('/settings/update', { dpi_target: '', dpi_enabled: false });
      addLog(`DPI stopped${ip ? ` for ${ip}` : ''} — thresholds restored to normal`, 'OK');
    } catch {
      addLog(`DPI stop request failed — engine unreachable`, 'ERR');
    }
    setDpiStatus(null);
  };

  // ── Quarantine a node ─────────────────────────────────────
  const handleQuarantine = async (node) => {
    addLog(`Quarantine request issued for ${node.ip}`, 'INFO');
    setQuarantined(prev => new Set([...prev, node.id]));
    // Primary: dedicated quarantine endpoint (triggers Windows Firewall if Auto-Isolate enabled)
    try {
      await api.post('/quarantine', {
        ip: node.ip, protocol: 'ANY',
        reason: `Manual quarantine via Network Topology — ${node.os || 'Unknown OS'}`,
      });
      addLog(`Node ${node.ip} quarantined — Bastion isolation filter applied`, 'OK');
    } catch {
      // Fallback: settings update
      try {
        const cfg = await api.get('/settings/config');
        const existing = Array.isArray(cfg.data.quarantined_ips) ? cfg.data.quarantined_ips : [];
        if (!existing.includes(node.ip)) existing.push(node.ip);
        await api.post('/settings/update', { quarantined_ips: existing });
        addLog(`Node ${node.ip} flagged for quarantine (backend sync pending)`, 'OK');
      } catch {
        addLog(`Quarantine logged locally — backend unreachable`, 'ERR');
      }
    }
  };

  // ── Blocking rescan: calls POST /topology/scan with selected interface ───
  const handleRescan = useCallback(async () => {
    setIsRescanning(true);
    setScanPulse(p => p + 1);
    addLog(`Full ARP scan initiated on ${selIface || 'default interface'}...`, 'INFO');
    try {
      const response = await api.post('/topology/scan', { interface: selIface });
      const newNodes = response.data.nodes || [];
      const newConns = response.data.connections || [];
      setNodes(newNodes);
      setConnections(newConns);
      const devCount = newNodes.length - 1;
      const subnet   = response.data.target_subnet || selIface || 'network';
      addLog(`Rescan complete — ${devCount} host${devCount !== 1 ? 's' : ''} found on ${subnet}`, 'OK');
    } catch {
      addLog('Rescan failed — using cached topology', 'ERR');
      fetchTopologyData(selIface);
    } finally {
      setIsRescanning(false);
    }
  }, [selIface, addLog, fetchTopologyData]);

  // ── Quadratic bezier path between two topology nodes (curved links) ────
  function curvedPath(x1, y1, x2, y2) {
    const mx  = (x1 + x2) / 2;
    const my  = (y1 + y2) / 2;
    const dx  = x2 - x1;
    const dy  = y2 - y1;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    // Perpendicular deflection — scales with distance, capped at 35px
    const d   = Math.min(35, len * 0.18);
    const qx  = mx - (dy / len) * d;
    const qy  = my + (dx / len) * d;
    return `M ${x1} ${y1} Q ${qx} ${qy} ${x2} ${y2}`;
  }

  // ── Filter nodes by search ────────────────────────────────
  const visibleNodes = nodes.filter(n =>
    !search ||
    n.ip?.includes(search) ||
    n.id?.toLowerCase().includes(search.toLowerCase()) ||
    n.type?.toLowerCase().includes(search.toLowerCase()) ||
    n.mac?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="h-[calc(100vh-10rem)] flex flex-col font-mono text-slate-300">

      {/* ── HEADER ──────────────────────────────────────────── */}
      <div className="bg-slate-900 border-b border-slate-800 p-4 shrink-0 flex flex-wrap items-center justify-between gap-3 z-10 shadow-md">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-slate-950 rounded border border-slate-800">
            <Share2 className="text-cyan-500" size={20} />
          </div>
          <div>
            <h1 className="text-sm font-black text-white uppercase tracking-wider">Subnet Topology Mapper</h1>
            <p className="text-[10px] text-slate-500">
              {nodes.length} endpoint{nodes.length !== 1 ? 's' : ''} discovered
              {selIface ? ` · ${selIface}` : ''}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Interface selector */}
          <select
            value={selIface}
            onChange={e => {
              setSelIface(e.target.value);
              localStorage.setItem('bastion_sel_iface', e.target.value);
            }}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-[10px] font-bold py-1.5 px-3 rounded
              outline-none focus:border-cyan-500/50 cursor-pointer"
          >
            <option value="">All Interfaces</option>
            {interfaces.map(i => (
              <option key={i.name} value={i.name}>
                {i.name}{i.ip ? ` · ${i.ip}` : ''}
              </option>
            ))}
          </select>

          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-[10px] font-bold">
            <span className="text-slate-500 uppercase">Engine</span>
            <span className={status?.online ? 'text-emerald-500' : 'text-red-500'}>
              {status?.online ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>

          <div className="flex items-center gap-1.5 text-[9px] text-slate-600 font-black uppercase tracking-widest">
            <div className="w-1.5 h-1.5 bg-cyan-500 rounded-full animate-pulse" />
            Auto-refresh 10s
          </div>

          <button
            onClick={handleRescan}
            disabled={isRescanning}
            className="flex items-center gap-2 bg-cyan-900/30 hover:bg-cyan-900 text-cyan-400 px-4 py-1.5 rounded
              transition-colors text-[11px] font-bold disabled:opacity-60 disabled:cursor-wait"
          >
            <RefreshCw size={13} className={isRescanning ? 'animate-spin' : ''} />
            {isRescanning ? 'Scanning...' : 'Rescan Network'}
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">

        {/* ── LEFT PANEL: Asset List ──────────────────────── */}
        <div className="w-72 bg-slate-950 border-r border-slate-800 flex flex-col shrink-0">
          <div className="p-3 border-b border-slate-800">
            <div className="relative">
              <Search size={13} className="absolute left-3 top-2.5 text-slate-600" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Filter by IP, MAC, type..."
                className="w-full bg-slate-900 border border-slate-800 rounded px-9 py-2 text-[10px] outline-none
                  focus:border-cyan-500/50 placeholder:text-slate-700 text-slate-300 transition-colors"
              />
              {search && (
                <button onClick={() => setSearch('')} className="absolute right-3 top-2.5">
                  <X size={12} className="text-slate-600 hover:text-white" />
                </button>
              )}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar p-2">
            {visibleNodes.map(n => {
              const col      = nodeColor(n.type);
              const isQuaran = quarantined.has(n.id);
              const isDpiNode = dpiStatus?.nodeId === n.id && dpiStatus?.status === 'active';
              const isCore   = n.id === 'CORE-IDS';
              const isSelected = selectedNode?.id === n.id;
              const os       = inferOS(n);

              // Accent colour for the left stripe
              const accent = isCore     ? 'bg-violet-500'
                           : isQuaran   ? 'bg-red-500'
                           : isDpiNode  ? 'bg-violet-400'
                           : n.status === 'attack' ? 'bg-red-500'
                           : n.source === 'live_capture' ? 'bg-emerald-500'
                           : n.type === 'gateway'  ? 'bg-amber-500'
                           : n.type === 'server'   ? 'bg-violet-500'
                           : 'bg-cyan-500';

              return (
                <div
                  key={n.id}
                  onClick={() => setSelectedNode(n)}
                  className={`mb-2 rounded-lg cursor-pointer border transition-all overflow-hidden flex ${
                    isSelected
                      ? 'bg-cyan-900/20 border-cyan-500/40 shadow-lg shadow-cyan-900/20'
                      : 'bg-slate-900/50 border-slate-800 hover:border-slate-600 hover:bg-slate-900/80'
                  }`}
                >
                  {/* Left accent stripe */}
                  <div className={`w-1 shrink-0 ${accent} ${n.status === 'attack' ? 'animate-pulse' : ''}`} />

                  <div className="flex items-center gap-3 p-3 flex-1 min-w-0">
                    {/* Device icon with circular bg */}
                    <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 border ${
                      isSelected ? `${col.text} bg-slate-800 border-slate-600` : `${col.text} bg-slate-800/80 border-slate-700`
                    }`}>
                      <NodeIcon type={n.type} size={16} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <p className="text-[11px] font-black truncate text-white tracking-wider">{n.ip || n.id}</p>
                      <p className="text-[9px] text-slate-500 truncate font-bold uppercase tracking-wide mt-0.5">
                        {isCore ? 'Bastion IDS Core' : n.type || 'UNKNOWN'}
                      </p>
                      {os.name !== 'Unknown' && (
                        <p className={`text-[8px] truncate font-bold mt-0.5 ${osColor(os.name)}`}>{os.name}</p>
                      )}
                    </div>

                    {/* Status badges */}
                    <div className="flex flex-col items-end gap-1 shrink-0">
                      {n.status === 'attack' && (
                        <span className="text-[8px] font-black bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded border border-red-500/30 uppercase">
                          THREAT
                        </span>
                      )}
                      {isDpiNode && (
                        <span className="text-[8px] font-black bg-violet-500/20 text-violet-400 px-1.5 py-0.5 rounded border border-violet-500/30 uppercase animate-pulse">
                          DPI
                        </span>
                      )}
                      {isQuaran && (
                        <span className="text-[8px] font-black bg-red-900/40 text-red-500 px-1.5 py-0.5 rounded border border-red-700/40 uppercase">
                          QRN
                        </span>
                      )}
                      {!n.status || n.status === 'active' ? (
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1" title="Online" />
                      ) : null}
                    </div>
                  </div>
                </div>
              );
            })}

            {visibleNodes.length === 0 && !isLoading && (
              <div className="text-center py-12 text-slate-700 text-[10px] font-black uppercase tracking-widest">
                {search ? 'No endpoints match filter' : 'No endpoints discovered'}
              </div>
            )}
          </div>
        </div>

        {/* ── CENTER PANEL: SVG Topology Map ─────────────── */}
        <div className="flex-1 bg-slate-950 relative overflow-hidden flex flex-col">
          {/* Multi-layer tactical background */}
          <div className="absolute inset-0 pointer-events-none">
            {/* Base dot grid */}
            <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] bg-[size:24px_24px] opacity-30" />
            {/* Radial vignette */}
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_50%,transparent_40%,rgba(2,6,23,0.8)_100%)]" />
            {/* Subtle top-left corner glow (Bastion "sensor" effect) */}
            <div className="absolute top-0 left-0 w-96 h-96 bg-violet-900/5 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2" />
            <div className="absolute bottom-0 right-0 w-64 h-64 bg-cyan-900/5 rounded-full blur-3xl translate-x-1/4 translate-y-1/4" />
          </div>

          <div className="flex-1 relative cursor-crosshair">
            {isLoading && nodes.length === 0 ? (
              <div className="absolute inset-0 flex items-center justify-center text-cyan-500/50 flex-col gap-4">
                <Activity size={48} className="animate-pulse" />
                <span className="font-bold tracking-widest uppercase text-xs">
                  Scanning local network segment...
                </span>
              </div>
            ) : nodes.length === 0 ? (
              <div className="absolute inset-0 flex items-center justify-center flex-col gap-4 text-slate-700">
                <Network size={48} />
                <p className="text-[11px] font-black uppercase tracking-widest">No hosts discovered on selected interface</p>
              </div>
            ) : (
              <svg className="w-full h-full" viewBox="0 0 1000 560" preserveAspectRatio="xMidYMid meet">
                <defs>
                  {/* ── Glow filters ─────────────────────────────────────────── */}
                  <filter id="glow-xl" x="-60%" y="-60%" width="220%" height="220%">
                    <feGaussianBlur stdDeviation="6" result="b1"/>
                    <feGaussianBlur stdDeviation="3" result="b2"/>
                    <feMerge><feMergeNode in="b1"/><feMergeNode in="b2"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                  <filter id="glow-md" x="-40%" y="-40%" width="180%" height="180%">
                    <feGaussianBlur stdDeviation="3.5" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                  <filter id="glow-sm" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="2" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                  <filter id="glow-line" x="-10%" y="-200%" width="120%" height="500%">
                    <feGaussianBlur stdDeviation="1.5" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>

                  {/* ── Node fill radial gradients ─────────────────────────── */}
                  <radialGradient id="grad-core" cx="35%" cy="35%" r="65%">
                    <stop offset="0%" stopColor="#7c3aed" stopOpacity="0.9"/>
                    <stop offset="100%" stopColor="#1e1b4b" stopOpacity="0.5"/>
                  </radialGradient>
                  <radialGradient id="grad-gw" cx="35%" cy="35%" r="65%">
                    <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.85"/>
                    <stop offset="100%" stopColor="#1c1008" stopOpacity="0.4"/>
                  </radialGradient>
                  <radialGradient id="grad-ws" cx="35%" cy="35%" r="65%">
                    <stop offset="0%" stopColor="#0891b2" stopOpacity="0.8"/>
                    <stop offset="100%" stopColor="#082f49" stopOpacity="0.3"/>
                  </radialGradient>
                  <radialGradient id="grad-live" cx="35%" cy="35%" r="65%">
                    <stop offset="0%" stopColor="#10b981" stopOpacity="0.7"/>
                    <stop offset="100%" stopColor="#064e3b" stopOpacity="0.3"/>
                  </radialGradient>
                  {/* Highlight specular */}
                  <radialGradient id="grad-spec" cx="30%" cy="25%" r="55%">
                    <stop offset="0%" stopColor="#ffffff" stopOpacity="0.18"/>
                    <stop offset="100%" stopColor="#ffffff" stopOpacity="0"/>
                  </radialGradient>

                  {/* ── Connection gradients (per type) ───────────────────── */}
                  <linearGradient id="conn-cyan" gradientUnits="userSpaceOnUse" x1="500" y1="280" x2="500" y2="280">
                    <stop offset="0%"   stopColor="#06b6d4" stopOpacity="0.05"/>
                    <stop offset="45%"  stopColor="#06b6d4" stopOpacity="0.55"/>
                    <stop offset="55%"  stopColor="#06b6d4" stopOpacity="0.55"/>
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.05"/>
                  </linearGradient>
                  <linearGradient id="conn-green" gradientUnits="userSpaceOnUse" x1="500" y1="280" x2="500" y2="280">
                    <stop offset="0%"   stopColor="#10b981" stopOpacity="0.05"/>
                    <stop offset="45%"  stopColor="#10b981" stopOpacity="0.45"/>
                    <stop offset="55%"  stopColor="#10b981" stopOpacity="0.45"/>
                    <stop offset="100%" stopColor="#10b981" stopOpacity="0.05"/>
                  </linearGradient>
                </defs>

                {/* ── Radar grid: concentric rings + cross-hairs ─────────── */}
                {[70, 140, 210, 280].map(r => (
                  <circle key={r} cx="500" cy="280" r={r}
                    fill="none" stroke="#1e293b" strokeWidth="0.6" opacity="0.6"/>
                ))}
                <line x1="500" y1="0"   x2="500" y2="560" stroke="#1e293b" strokeWidth="0.4" opacity="0.4"/>
                <line x1="0"   y1="280" x2="1000" y2="280" stroke="#1e293b" strokeWidth="0.4" opacity="0.4"/>
                {/* Diagonal grid lines */}
                <line x1="205" y1="85"  x2="795" y2="475" stroke="#1e293b" strokeWidth="0.3" opacity="0.3"/>
                <line x1="795" y1="85"  x2="205" y2="475" stroke="#1e293b" strokeWidth="0.3" opacity="0.3"/>

                {/* ── Scan pulse rings (animated when rescanning) ──────────── */}
                {isRescanning && (() => {
                  const core = nodes.find(n => n.id === 'CORE-IDS');
                  const cx   = core?.x ?? 500;
                  const cy   = core?.y ?? 280;
                  return [0, 0.65, 1.3].map(delay => (
                    <circle key={delay} cx={cx} cy={cy} r="30" fill="none" stroke="#06b6d4" strokeWidth="1.5" opacity="0">
                      <animate attributeName="r"       values="30;290"  dur="2s" begin={`${delay}s`} repeatCount="indefinite"/>
                      <animate attributeName="opacity" values="0.7;0"   dur="2s" begin={`${delay}s`} repeatCount="indefinite"/>
                    </circle>
                  ));
                })()}

                {/* ── Connections (curved bezier paths) ─────────────────── */}
                {connections.map((c, i) => {
                  const src = nodes.find(n => n.id === c.from);
                  const tgt = nodes.find(n => n.id === c.to);
                  if (!src || !tgt) return null;
                  const isLive   = c.speed === 'live';
                  const pathD    = curvedPath(src.x, src.y, tgt.x, tgt.y);
                  const dotColor = isLive ? '#10b981' : '#06b6d4';
                  const dotSpeed = `${(1.8 + i * 0.25).toFixed(2)}s`;
                  return (
                    <g key={i}>
                      {/* Shadow / base line */}
                      <path d={pathD} fill="none" stroke="#0f172a" strokeWidth="3" opacity="0.8"/>
                      {/* Glowing connection line */}
                      <path d={pathD} fill="none"
                        stroke={isLive ? '#10b981' : '#06b6d4'}
                        strokeWidth="1.2" opacity={isLive ? 0.5 : 0.35}
                        filter="url(#glow-line)"
                      />
                      {/* Animated traffic dot */}
                      <circle r="2.5" fill={dotColor} opacity="0.85">
                        <animateMotion dur={dotSpeed} repeatCount="indefinite" path={pathD}/>
                      </circle>
                      {/* Second dot offset for busier look */}
                      {i % 2 === 0 && (
                        <circle r="1.5" fill={dotColor} opacity="0.5">
                          <animateMotion dur={dotSpeed} begin={`-${(parseFloat(dotSpeed) * 0.5).toFixed(2)}s`}
                            repeatCount="indefinite" path={pathD}/>
                        </circle>
                      )}
                    </g>
                  );
                })}

                {/* ── Nodes ─────────────────────────────────────────────── */}
                {nodes.map(n => {
                  const isCore     = n.id === 'CORE-IDS';
                  const isSelected = selectedNode?.id === n.id;
                  const isQuaran   = quarantined.has(n.id);
                  const isDpiNode  = dpiStatus?.nodeId === n.id && dpiStatus?.status === 'active';
                  const isLive     = n.source === 'live_capture';

                  // Size: CORE-IDS is larger
                  const R  = isCore ? 40 : 26;
                  const iR = isCore ? 36 : 22;   // inner fill radius

                  // Gradient & ring colour by type
                  let gradId   = 'grad-ws';
                  let ringCol  = '#06b6d4';
                  let textCol  = '#22d3ee';
                  if (isCore)                         { gradId = 'grad-core'; ringCol = '#7c3aed'; textCol = '#a78bfa'; }
                  else if (n.type === 'gateway')      { gradId = 'grad-gw';   ringCol = '#f59e0b'; textCol = '#fbbf24'; }
                  else if (isLive)                    { gradId = 'grad-live'; ringCol = '#10b981'; textCol = '#34d399'; }
                  if (isQuaran)                       { ringCol = '#ef4444';  textCol = '#f87171'; }

                  const glowF = isSelected ? 'url(#glow-xl)' : isCore ? 'url(#glow-md)' : undefined;
                  const osSuffix = n.os && n.os !== 'Unknown'
                    ? n.os.replace('Apple macOS','macOS').replace('Apple iOS','iOS')
                          .replace('Linux / Unix','Linux').replace('Cisco / Network Device','Cisco')
                          .split(' ').slice(0, 2).join(' ')
                    : null;

                  return (
                    <g key={n.id}
                      transform={`translate(${n.x ?? 300}, ${n.y ?? 200})`}
                      onClick={() => setSelectedNode(n)}
                      className="cursor-pointer"
                      style={{ filter: glowF }}
                    >
                      {/* Outer ambient glow ring (always on for selected / CORE) */}
                      {(isSelected || isCore) && (
                        <circle r={R + 14} fill="none" stroke={ringCol} strokeWidth="0.8" opacity="0.25"/>
                      )}

                      {/* Slow pulse ring for core node */}
                      {isCore && (
                        <circle r={R + 6} fill="none" stroke={ringCol} strokeWidth="1" opacity="0.4">
                          <animate attributeName="r"       values={`${R+6};${R+18};${R+6}`} dur="4s" repeatCount="indefinite"/>
                          <animate attributeName="opacity" values="0.4;0.1;0.4"             dur="4s" repeatCount="indefinite"/>
                        </circle>
                      )}

                      {/* Active / live node heartbeat */}
                      {!isCore && (n.status === 'active' || isLive) && (
                        <circle r={R + 4} fill="none" stroke={ringCol} strokeWidth="0.8" opacity="0.35">
                          <animate attributeName="r"       values={`${R+4};${R+10};${R+4}`} dur="3s" repeatCount="indefinite"/>
                          <animate attributeName="opacity" values="0.35;0.05;0.35"           dur="3s" repeatCount="indefinite"/>
                        </circle>
                      )}

                      {/* Quarantine dashed ring */}
                      {isQuaran && (
                        <circle r={R + 8} fill="none" stroke="#ef4444" strokeWidth="1.5"
                          strokeDasharray="5 3" opacity="0.7">
                          <animateTransform attributeName="transform" type="rotate"
                            from="0 0 0" to="360 0 0" dur="8s" repeatCount="indefinite"/>
                        </circle>
                      )}

                      {/* DPI spinning arc */}
                      {isDpiNode && (
                        <circle r={R + 8} fill="none" stroke="#a78bfa" strokeWidth="1.5"
                          strokeDasharray="12 4" opacity="0.8">
                          <animateTransform attributeName="transform" type="rotate"
                            from="0 0 0" to="360 0 0" dur="4s" repeatCount="indefinite"/>
                        </circle>
                      )}

                      {/* Main ring */}
                      <circle r={R} fill="none" stroke={ringCol}
                        strokeWidth={isSelected ? 2.5 : 1.5} opacity={isSelected ? 0.9 : 0.6}/>

                      {/* Fill */}
                      <circle r={iR} fill={`url(#${gradId})`}/>
                      {/* Specular highlight */}
                      <circle r={iR} fill="url(#grad-spec)"/>

                      {/* Icon via foreignObject */}
                      <foreignObject x={isCore ? -18 : -13} y={isCore ? -18 : -13}
                        width={isCore ? 36 : 26} height={isCore ? 36 : 26}>
                        <div style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          height: '100%', color: textCol, opacity: isSelected ? 1 : 0.85
                        }}>
                          <NodeIcon type={n.type} size={isCore ? 22 : 15}/>
                        </div>
                      </foreignObject>

                      {/* IP label below node */}
                      <text y={R + 13} textAnchor="middle" fontSize="8.5" fontFamily="monospace"
                        fill={isSelected ? '#e2e8f0' : '#64748b'} fontWeight="bold">
                        {n.ip || n.id}
                      </text>

                      {/* OS label (2nd line) */}
                      {osSuffix && (
                        <text y={R + 23} textAnchor="middle" fontSize="7" fontFamily="monospace"
                          fill={isSelected ? textCol : '#475569'}>
                          {osSuffix}
                        </text>
                      )}

                      {/* Status indicator dot (top-right) */}
                      <circle cx={R - 4} cy={-(R - 4)} r="5"
                        fill={n.status === 'attack' ? '#ef4444' : isQuaran ? '#f97316' :
                              isLive ? '#10b981' : isCore ? '#7c3aed' : '#22c55e'}
                        filter="url(#glow-sm)"/>
                      <circle cx={R - 4} cy={-(R - 4)} r="3"
                        fill={n.status === 'attack' ? '#fca5a5' : isQuaran ? '#fdba74' :
                              isLive ? '#6ee7b7' : isCore ? '#c4b5fd' : '#86efac'}/>
                    </g>
                  );
                })}

                {/* ── Map legend (bottom-left) ─────────────────────── */}
                <g transform="translate(18, 490)">
                  {/* Legend background */}
                  <rect x="0" y="0" width="210" height="60" rx="6"
                    fill="#0f172a" fillOpacity="0.85" stroke="#1e293b" strokeWidth="0.8"/>

                  {/* Title */}
                  <text x="10" y="14" fontSize="7" fontFamily="monospace" fontWeight="bold"
                    fill="#475569" letterSpacing="2">MAP LEGEND</text>

                  {/* Row 1 */}
                  <circle cx="18" cy="27" r="5" fill="url(#grad-core)"/>
                  <text x="28" y="31" fontSize="7.5" fontFamily="monospace" fill="#94a3b8">Bastion IDS (Core)</text>

                  <circle cx="108" cy="27" r="5" fill="url(#grad-gw)"/>
                  <text x="118" y="31" fontSize="7.5" fontFamily="monospace" fill="#94a3b8">Gateway / Router</text>

                  {/* Row 2 */}
                  <circle cx="18" cy="44" r="5" fill="url(#grad-ws)"/>
                  <text x="28" y="48" fontSize="7.5" fontFamily="monospace" fill="#94a3b8">Workstation / Host</text>

                  <circle cx="108" cy="44" r="4" fill="#ef4444" fillOpacity="0.7"/>
                  <text x="118" y="48" fontSize="7.5" fontFamily="monospace" fill="#94a3b8">Quarantined Node</text>
                </g>

                {/* ── Live-node counter badge (bottom-right) ─────────── */}
                <g transform="translate(820, 520)">
                  <rect x="0" y="0" width="160" height="28" rx="14"
                    fill="#0f172a" fillOpacity="0.9" stroke="#1e293b" strokeWidth="0.8"/>
                  <circle cx="16" cy="14" r="4" fill="#10b981">
                    <animate attributeName="opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite"/>
                  </circle>
                  <text x="26" y="18" fontSize="7.5" fontFamily="monospace" fill="#64748b">
                    {nodes.length} endpoint{nodes.length !== 1 ? 's' : ''} · live map
                  </text>
                </g>
              </svg>
            )}
          </div>

          {/* ── DISCOVERY LOG ─────────────────────────────── */}
          <div className="h-28 border-t border-slate-800 bg-slate-950 overflow-y-auto custom-scrollbar p-3">
            {logs.map((L, i) => (
              <div key={i} className={`text-[9px] mb-0.5 font-mono hover:text-slate-300 transition-colors ${
                L.includes('✗') ? 'text-red-400' :
                L.includes('✓') ? 'text-emerald-400' :
                'text-slate-600'
              }`}>{L}</div>
            ))}
            {logs.length === 0 && (
              <p className="text-[9px] text-slate-700 font-black uppercase tracking-widest">Waiting for discovery data...</p>
            )}
          </div>
        </div>

        {/* ── RIGHT PANEL: Node Inspector ─────────────────── */}
        {selectedNode && (
          <div className="w-80 bg-slate-950 border-l border-slate-800 shrink-0 flex flex-col animate-in slide-in-from-right-2 duration-200">
            {/* Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/80">
              <div className="flex items-center gap-2">
                <Network size={14} className="text-cyan-400" />
                <h3 className="font-black text-[10px] uppercase tracking-widest text-white">Node Inspector</h3>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded-full text-[8px] font-black uppercase tracking-widest ${
                  quarantined.has(selectedNode.id)
                    ? 'bg-red-900/50 text-red-400 border border-red-700/40'
                    : selectedNode.status === 'attack'
                    ? 'bg-red-900/50 text-red-400 border border-red-700/40 animate-pulse'
                    : 'bg-emerald-900/30 text-emerald-500 border border-emerald-700/30'
                }`}>
                  {quarantined.has(selectedNode.id) ? '⬤ Quarantined' : selectedNode.status === 'attack' ? '⬤ Under Attack' : '⬤ Active'}
                </span>
                <button onClick={() => setSelectedNode(null)}
                  className="p-1 rounded hover:bg-slate-800 transition-colors">
                  <X size={14} className="text-slate-600 hover:text-white transition-colors" />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-4">
              {/* Icon + identity */}
              <div className="text-center py-2">
                {/* Device icon with gradient ring */}
                <div className="relative inline-flex mb-4">
                  <div className={`w-20 h-20 rounded-2xl flex items-center justify-center border-2 ${
                    nodeColor(selectedNode.type).text
                  } bg-slate-900 ${
                    quarantined.has(selectedNode.id) ? 'border-red-500/60' :
                    selectedNode.id === 'CORE-IDS' ? 'border-violet-500/60' :
                    selectedNode.type === 'gateway' ? 'border-amber-500/50' :
                    'border-cyan-500/40'
                  } shadow-lg`}>
                    <NodeIcon type={selectedNode.type} size={36} />
                  </div>
                  {/* Status dot */}
                  <div className={`absolute -top-1 -right-1 w-4 h-4 rounded-full border-2 border-slate-950 ${
                    quarantined.has(selectedNode.id) ? 'bg-red-500' :
                    selectedNode.status === 'attack' ? 'bg-red-500 animate-pulse' :
                    'bg-emerald-500'
                  }`} />
                </div>
                <h2 className="text-base font-black text-white font-mono tracking-wider">
                  {selectedNode.ip || selectedNode.id}
                </h2>
                <p className="text-[9px] text-slate-500 uppercase font-black tracking-[0.2em] mt-1">
                  {selectedNode.id === 'CORE-IDS' ? 'Bastion IDS — Core Sensor' : selectedNode.type || 'Unknown Type'}
                </p>
                {selectedNode.vendor && (
                  <p className="text-[9px] text-slate-600 mt-0.5">{selectedNode.vendor}</p>
                )}
              </div>

              {/* Network properties */}
              <div className="space-y-2">
                <p className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Network Identity</p>
                <InspectorBlock label="IPv4 Address"  value={selectedNode.ip  || '—'} />
                <InspectorBlock label="Hardware MAC"  value={selectedNode.mac || '—'} />
                <InspectorBlock label="Hostname"      value={selectedNode.hostname || selectedNode.label || '—'} />
              </div>

              {/* OS fingerprint */}
              <div className="space-y-2">
                <p className="text-[9px] font-black text-slate-600 uppercase tracking-widest">OS Fingerprint</p>
                {(() => {
                  const os = inferOS(selectedNode);
                  return (
                    <>
                      <InspectorBlock
                        label="Operating System"
                        value={<span className={osColor(os.name)}>{os.name}</span>}
                      />
                      <InspectorBlock label="Detection Basis" value={os.confidence} />
                      {selectedNode.vendor && (
                        <InspectorBlock label="Hardware Vendor" value={selectedNode.vendor} />
                      )}
                      {selectedNode.hostname && (
                        <InspectorBlock label="Hostname" value={selectedNode.hostname} />
                      )}
                    </>
                  );
                })()}
                {selectedNode.open_ports?.length > 0 && (
                  <InspectorBlock label="Open Ports" value={selectedNode.open_ports.join(', ')} />
                )}
                {selectedNode.services?.length > 0 && (
                  <InspectorBlock label="Services" value={selectedNode.services.join(', ')} />
                )}
              </div>

              {/* Connection info */}
              {connections.filter(c => c.from === selectedNode.id || c.to === selectedNode.id).length > 0 && (
                <div className="space-y-2">
                  <p className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Connections</p>
                  <InspectorBlock
                    label="Active Links"
                    value={`${connections.filter(c => c.from === selectedNode.id || c.to === selectedNode.id).length} link${connections.filter(c => c.from === selectedNode.id || c.to === selectedNode.id).length !== 1 ? 's' : ''}`}
                  />
                </div>
              )}

              {/* DPI status */}
              {dpiStatus?.nodeId === selectedNode.id && dpiStatus?.status === 'active' && (
                <div className="p-3 bg-violet-900/20 border border-violet-500/30 rounded-xl">
                  <p className="text-[9px] font-black text-violet-400 uppercase tracking-widest mb-1">DPI Active</p>
                  <p className="text-[10px] text-slate-400 mb-2">
                    Full payload capture and a lowered alert threshold are applied to all
                    traffic to and from {dpiStatus.ip}. Stops automatically on engine restart.
                  </p>
                  <button
                    onClick={handleStopDPI}
                    className="w-full bg-violet-900/30 hover:bg-violet-900/60 border border-violet-500/40
                      py-2 rounded-lg text-[9px] font-black uppercase tracking-widest transition-all
                      text-violet-300"
                  >
                    Stop DPI
                  </button>
                </div>
              )}

              {/* Action buttons */}
              <div className="pt-2 space-y-2 border-t border-slate-800">
                <button
                  onClick={() => handleDPI(selectedNode)}
                  disabled={dpiStatus?.nodeId === selectedNode.id && dpiStatus?.status === 'running'}
                  className="w-full bg-slate-900 hover:bg-violet-900/30 border border-slate-700 hover:border-violet-500/40
                    py-3 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all text-slate-400
                    hover:text-violet-300 flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <Eye size={14} />
                  {dpiStatus?.nodeId === selectedNode.id && dpiStatus?.status === 'running'
                    ? 'Activating DPI...'
                    : dpiStatus?.nodeId === selectedNode.id && dpiStatus?.status === 'active'
                    ? 'DPI Active'
                    : 'Run Deep Packet Inspection'}
                </button>
                <button
                  onClick={() => handleQuarantine(selectedNode)}
                  disabled={quarantined.has(selectedNode.id)}
                  className={`w-full border py-3 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all
                    flex items-center justify-center gap-2 ${
                    quarantined.has(selectedNode.id)
                      ? 'bg-red-900/20 border-red-900/40 text-red-600 cursor-not-allowed'
                      : 'bg-red-900/10 hover:bg-red-900/40 border-red-900/40 hover:border-red-500/60 text-red-500'
                  }`}
                >
                  <ShieldAlert size={14} />
                  {quarantined.has(selectedNode.id) ? 'Node Quarantined' : 'Quarantine Node'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function InspectorBlock({ label, value, accent }) {
  return (
    <div className="bg-slate-900/60 p-3 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors group">
      <p className="text-[8px] text-slate-600 uppercase font-black tracking-[0.15em] mb-1.5 group-hover:text-slate-500 transition-colors">{label}</p>
      <div className={`text-[11px] font-mono font-bold break-all ${accent ?? 'text-white'}`}>{value}</div>
    </div>
  );
}
