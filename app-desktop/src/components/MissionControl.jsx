import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Database, ShieldCheck, ShieldAlert, Cpu, Activity,
  ArrowUpRight, ArrowDownRight, HardDrive, AlertTriangle,
  Network, Lock, Fingerprint, Layers, Brain, Eye,
  TrendingUp, Clock, Shield, CheckCircle, XCircle,
  Zap, BarChart3, Radio
} from 'lucide-react';
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, Title, Tooltip, Legend, Filler, ArcElement
} from 'chart.js';
import { Line, Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, Title, Tooltip, Legend, Filler, ArcElement
);

const API_URL  = 'http://127.0.0.1:48217/api/v1';
const AUTH_KEY = 'BASTION-KADIAN-SEC-0x42';

function formatBytes(b = 0) {
  if (!+b) return '0 B';
  const k = 1024, sizes = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(Math.abs(b)) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function elapsed(startTs) {
  const s = Math.floor((Date.now() - startTs) / 1000);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(ss).padStart(2,'0')}`;
}

// ── Chart shared config ──────────────────────────────────────────────────────
const lineOpts = (color) => ({
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 300 },
  scales: {
    y: { min: 0, max: 100, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#475569', font: { size: 9 } } },
    x: { grid: { display: false }, ticks: { display: false } }
  },
  plugins: { legend: { display: false }, tooltip: { enabled: false } },
  elements: { line: { tension: 0.4 }, point: { radius: 0 } }
});

// ── Main Dashboard ────────────────────────────────────────────────────────────
export default function MissionControl({ status }) {
  const [topologyNodes,     setTopologyNodes]     = useState([]);
  const [topoInterface,     setTopoInterface]     = useState(null); // last scanned interface
  const [recentAlerts,      setRecentAlerts]      = useState([]);
  const [globalStats,       setGlobalStats]       = useState({ analyzed: 0, threats: 0, blocked: 0, accuracy: '—' });
  const [layerStatus,       setLayerStatus]       = useState({});
  const [engineDiag,        setEngineDiag]        = useState({ sigs: 0, threshold: null });
  const [sweepLayerCounts,  setSweepLayerCounts]  = useState({ session: {} });
  const [uptime,         setUptime]         = useState(0);        // seconds
  const [startTs]        = useState(Date.now());
  const [uptimeStr,      setUptimeStr]      = useState('00:00:00');

  // Chart histories
  const [cpuHist, setCpuHist] = useState(Array(30).fill(0));
  const [ramHist, setRamHist] = useState(Array(30).fill(0));
  const [alertTimeline, setAlertTimeline] = useState(Array(12).fill(0)); // last 12 × 5-min buckets
  const timelineLabels = useMemo(() =>
    Array.from({ length: 12 }, (_, i) => {
      const d = new Date(Date.now() - (11 - i) * 5 * 60000);
      return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
    }), []); // eslint-disable-line

  const tickRef = useRef(null);

  // ── Uptime ticker ───────────────────────────────────────────────────────────
  useEffect(() => {
    const t = setInterval(() => setUptimeStr(elapsed(startTs)), 1000);
    return () => clearInterval(t);
  }, [startTs]);

  // ── Data fetcher ────────────────────────────────────────────────────────────
  useEffect(() => {
    const headers = { 'x-authority': AUTH_KEY };

    const fetchAll = async () => {
      // Topology
      try {
        const r = await fetch(`${API_URL}/topology`, { headers });
        const d = await r.json();
        setTopologyNodes(d.nodes ?? []);
        if (d.interface && d.interface !== 'all') setTopoInterface(d.interface);
      } catch {}

      // Health + layer status
      try {
        const r = await fetch(`${API_URL}/health`, { headers });
        const d = await r.json();
        setLayerStatus({
          signature: d.signature_engine ?? true,
          ml_rf:     d.ml_rf    ?? false,
          ml_xgb:    d.ml_xgb   ?? false,
          ml_cat:    d.ml_cat   ?? false,
          dl:        d.dl       ?? false,
          anomaly:   d.anomaly  ?? false,
        });
        setEngineDiag({
          sigs:      d.signatures_active ?? 0,
          threshold: typeof d.detection_threshold === 'number' ? d.detection_threshold : null,
        });
      } catch {}

      // Recent alerts + true total count
      try {
        const r = await fetch(`${API_URL}/alerts/recent?limit=20`, { headers });
        const d = await r.json();
        if (Array.isArray(d.alerts ?? d)) {
          const arr = d.alerts ?? d;
          setRecentAlerts(arr.slice(0, 20));
          if (arr.length) {
            setAlertTimeline(prev => {
              const next = [...prev];
              next[11] = arr.length;
              return next;
            });
          }
        }
      } catch {}

      // Real uncapped threat count
      try {
        const r = await fetch(`${API_URL}/alerts/count`, { headers });
        const d = await r.json();
        if (d.total != null) {
          setGlobalStats(prev => ({ ...prev, threats: d.total }));
        }
      } catch {}

      // Sweep / analysis stats
      try {
        const r = await fetch(`${API_URL}/sweep/stats`, { headers });
        const d = await r.json();
        setGlobalStats(prev => ({
          ...prev,
          analyzed: d.total_analyzed ?? prev.analyzed,
          threats:  d.total_threats  ?? prev.threats,
          accuracy: d.avg_confidence != null ? `${(d.avg_confidence * 100).toFixed(1)}%` : prev.accuracy,
        }));
        // layer_counts is a flat object — wrap it so the reducer works correctly
        if (d.layer_counts) {
          setSweepLayerCounts({ session: d.layer_counts });
        }
      } catch {}
    };

    fetchAll();
    tickRef.current = setInterval(fetchAll, 6000);
    return () => clearInterval(tickRef.current);
  }, []);

  // Update CPU/RAM chart on status change
  useEffect(() => {
    setCpuHist(p => [...p.slice(1), status.cpu ?? 0]);
    setRamHist(p => [...p.slice(1), status.ram ?? 0]);
  }, [status.cpu, status.ram]);

  // Slide alert timeline every 5 min
  useEffect(() => {
    const t = setInterval(() => {
      setAlertTimeline(p => [...p.slice(1), 0]);
    }, 5 * 60 * 1000);
    return () => clearInterval(t);
  }, []);

  // Chart datasets
  const timeLabels = useRef(Array(30).fill(''));
  const cpuChartData = {
    labels: timeLabels.current,
    datasets: [{ data: cpuHist, borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.08)', fill: true, borderWidth: 1.5 }]
  };
  const ramChartData = {
    labels: timeLabels.current,
    datasets: [{ data: ramHist, borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,0.08)', fill: true, borderWidth: 1.5 }]
  };

  const barMax = Math.max(...alertTimeline, 1);
  const alertBarData = {
    labels: timelineLabels,
    datasets: [{
      data: alertTimeline,
      backgroundColor: alertTimeline.map(v =>
        v === 0 ? 'rgba(239,68,68,0.1)' : v > barMax * 0.7 ? 'rgba(239,68,68,0.7)' : 'rgba(239,68,68,0.4)'
      ),
      borderColor: 'rgba(239,68,68,0.6)',
      borderWidth: 1,
      borderRadius: 3,
    }]
  };
  const barOpts = {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 300 },
    scales: {
      y: { min: 0, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#475569', font: { size: 9 } } },
      x: { grid: { display: false }, ticks: { color: '#334155', font: { size: 8 }, maxRotation: 0 } }
    },
    plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => ` ${c.raw} alerts` } } }
  };

  // Device distribution for doughnut
  const deviceCounts = topologyNodes.reduce((acc, n) => {
    const t = n.type || 'unknown';
    acc[t] = (acc[t] || 0) + 1;
    return acc;
  }, {});
  const doughnutData = {
    labels: Object.keys(deviceCounts),
    datasets: [{ data: Object.values(deviceCounts),
      backgroundColor: ['#06b6d4','#f59e0b','#10b981','#8b5cf6','#ef4444'],
      borderWidth: 0, cutout: '78%' }]
  };

  // ── 4-layer status definitions (static class strings — required for Tailwind JIT) ─
  const LAYER_PALETTE = {
    cyan:   {
      border:  'border-cyan-900/60',
      bg:      'bg-cyan-900/20',
      bdr:     'border-cyan-800/50',
      text:    'text-cyan-400',
      badge:   'text-cyan-700',
    },
    violet: {
      border:  'border-violet-900/60',
      bg:      'bg-violet-900/20',
      bdr:     'border-violet-800/50',
      text:    'text-violet-400',
      badge:   'text-violet-700',
    },
    indigo: {
      border:  'border-indigo-900/60',
      bg:      'bg-indigo-900/20',
      bdr:     'border-indigo-800/50',
      text:    'text-indigo-400',
      badge:   'text-indigo-700',
    },
    amber:  {
      border:  'border-amber-900/60',
      bg:      'bg-amber-900/20',
      bdr:     'border-amber-800/50',
      text:    'text-amber-400',
      badge:   'text-amber-700',
    },
  };

  const layers = [
    {
      key:   'signature',
      label: 'Signature Engine',
      sub:   'ET-Open 48k+ rules',
      icon:  <Shield size={18} />,
      on:    layerStatus.signature,
      pal:   LAYER_PALETTE.cyan,
    },
    {
      key:   'ml',
      label: 'ML Ensemble',
      sub:   'Random Forest + XGBoost + CatBoost',
      icon:  <Brain size={18} />,
      on:    layerStatus.ml_rf || layerStatus.ml_xgb || layerStatus.ml_cat,
      pal:   LAYER_PALETTE.violet,
    },
    {
      key:   'dl',
      label: 'Deep Neural Net',
      sub:   'Deep Neural Network Specialist',
      icon:  <Layers size={18} />,
      on:    layerStatus.dl,
      pal:   LAYER_PALETTE.indigo,
    },
    {
      key:   'anomaly',
      label: 'Anomaly Sentinel',
      sub:   'Behavioural Anomaly Detection',
      icon:  <Eye size={18} />,
      on:    layerStatus.anomaly,
      pal:   LAYER_PALETTE.amber,
    },
  ];

  const parseStorage = (v) => {
    const n = parseFloat(v);
    return isNaN(n) ? (v ?? '—') : `${n.toFixed(1)}%`;
  };

  return (
    <div className="space-y-5 font-mono text-slate-300 pb-12 animate-in fade-in slide-in-from-bottom-4">

      {/* ══ GLOBAL KPI STRIP ════════════════════════════════════════════════════ */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          icon={<Cpu size={18}/>}
          label="Host CPU Load"
          value={`${(status.cpu ?? 0).toFixed(1)}%`}
          sub={`RAM ${(status.ram ?? 0).toFixed(1)}%`}
          colour="cyan"
        />
        <KpiCard
          icon={<Database size={18}/>}
          label="Flows Analyzed"
          value={globalStats.analyzed.toLocaleString()}
          sub="Total this session"
          colour="violet"
        />
        <KpiCard
          icon={<ShieldAlert size={18}/>}
          label="Threats Detected"
          value={globalStats.threats.toLocaleString()}
          sub={globalStats.threats > 0 ? 'Action required' : 'All clear'}
          colour={globalStats.threats > 0 ? 'red' : 'emerald'}
          pulse={globalStats.threats > 0}
        />
        <KpiCard
          icon={<Clock size={18}/>}
          label="Engine Uptime"
          value={uptimeStr}
          sub={`Storage ${parseStorage(status.storage)}`}
          colour="emerald"
        />
      </div>

      {/* ══ LAYER STATUS CARDS ══════════════════════════════════════════════════ */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {layers.map((l, i) => (
          <div key={l.key}
            className={`relative bg-slate-950 border rounded-lg p-4 flex items-start gap-3 overflow-hidden
              ${l.on ? `${l.pal.border} shadow-[0_0_16px_rgba(0,0,0,0.4)]` : 'border-slate-800 opacity-60'}`}
          >
            {/* Layer number badge */}
            <span className={`absolute top-2 right-3 text-[9px] font-black uppercase tracking-widest
              ${l.on ? l.pal.badge : 'text-slate-800'}`}>
              Layer {i + 1}
            </span>

            <div className={`p-2 rounded border shrink-0
              ${l.on ? `${l.pal.bg} ${l.pal.bdr} ${l.pal.text}` : 'bg-slate-900 border-slate-800 text-slate-700'}`}>
              {l.icon}
            </div>

            <div className="min-w-0">
              <p className="text-[11px] font-black uppercase tracking-wider text-white leading-tight">{l.label}</p>
              <p className="text-[9px] text-slate-600 mt-0.5 font-mono leading-snug truncate">{l.sub}</p>
              <div className="flex items-center gap-1.5 mt-2">
                {l.on
                  ? <><CheckCircle size={11} className={l.pal.text} /><span className={`text-[9px] font-black uppercase tracking-wider ${l.pal.text}`}>Online</span></>
                  : <><XCircle size={11} className="text-slate-700" /><span className="text-[9px] font-black uppercase tracking-wider text-slate-700">Offline</span></>
                }
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ══ CHARTS ROW ══════════════════════════════════════════════════════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* CPU + RAM line charts */}
        <div className="lg:col-span-1 bg-slate-950 border border-slate-800 rounded-lg p-5 space-y-4 shadow">
          <p className="text-[10px] font-black uppercase tracking-widest text-slate-500">Resource Monitor</p>
          <div className="h-28 relative">
            <div className="absolute top-0 left-0 flex items-center gap-2 z-10">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse inline-block" />
              <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">CPU {(status.cpu ?? 0).toFixed(1)}%</span>
            </div>
            <Line data={cpuChartData} options={lineOpts('#06b6d4')} />
          </div>
          <div className="h-28 relative">
            <div className="absolute top-0 left-0 flex items-center gap-2 z-10">
              <span className="w-1.5 h-1.5 rounded-full bg-violet-500 animate-pulse inline-block" />
              <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">RAM {(status.ram ?? 0).toFixed(1)}%</span>
            </div>
            <Line data={ramChartData} options={lineOpts('#8b5cf6')} />
          </div>
          <div className="flex gap-4 pt-1 border-t border-slate-800">
            <div>
              <p className="text-[9px] text-slate-600 uppercase font-bold flex items-center gap-1">
                <ArrowDownRight size={10} className="text-emerald-500" /> RX
              </p>
              <p className="text-xs font-black text-white">{formatBytes(status.net_rx)}/s</p>
            </div>
            <div>
              <p className="text-[9px] text-slate-600 uppercase font-bold flex items-center gap-1">
                <ArrowUpRight size={10} className="text-cyan-500" /> TX
              </p>
              <p className="text-xs font-black text-white">{formatBytes(status.net_tx)}/s</p>
            </div>
          </div>
        </div>

        {/* Alert timeline bar chart */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-5 shadow flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <p className="text-[10px] font-black uppercase tracking-widest text-slate-500 flex items-center gap-2">
              <BarChart3 size={13} className="text-red-500" /> Alert Timeline (5-min buckets)
            </p>
            <span className="text-[9px] text-red-400 font-bold bg-red-950/20 border border-red-900/20 px-2 py-0.5 rounded">
              Last 60 min
            </span>
          </div>
          <div className="flex-1 min-h-[160px]">
            <Bar data={alertBarData} options={barOpts} />
          </div>
        </div>

        {/* Node topology doughnut */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-5 flex flex-col items-center justify-between shadow">
          <p className="text-[10px] font-black uppercase tracking-widest text-slate-500 self-start flex items-center gap-2 mb-3">
            <Fingerprint size={13} className="text-emerald-500" /> Network Architecture
          </p>
          <div className="relative w-36 h-36">
            <Doughnut
              data={doughnutData}
              options={{ cutout: '78%', plugins: { legend: { display: false }, tooltip: { enabled: false } }, animation: { duration: 400 } }}
            />
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-3xl font-black text-white">{topologyNodes.length}</span>
              <span className="text-[8px] uppercase text-cyan-400 font-black tracking-widest animate-pulse">Active Nodes</span>
            </div>
          </div>

          {/* Device type legend */}
          <div className="w-full mt-4 space-y-1.5">
            {Object.entries(deviceCounts).map(([type, count], i) => {
              const colors = ['#06b6d4','#f59e0b','#10b981','#8b5cf6','#ef4444'];
              return (
                <div key={type} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: colors[i % colors.length] }} />
                    <span className="text-[10px] text-slate-500 capitalize font-bold">{type}</span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-black">{count}</span>
                </div>
              );
            })}
            {!topologyNodes.length && (
              <p className="text-[9px] text-slate-700 text-center py-2 animate-pulse">Running ARP sweep...</p>
            )}
          </div>
        </div>
      </div>

      {/* ══ DETECTION LAYER ACTIVITY + ENGINE DIAGNOSTICS ═══════════════════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* Detection Layer Activity — per-engine hit counts */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Layers size={14} className="text-cyan-400" />
              <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Detection Layer Activity</span>
            </div>
            <span className="text-[9px] text-slate-600 font-mono">Session totals</span>
          </div>
          <div className="p-4 space-y-4">
            {[
              { label: 'L1 · Signature Engine', key: 'SIGNATURE_DB', col: 'bg-red-500',    text: 'text-red-400',    on: layerStatus.signature },
              { label: 'L2 · ML Ensemble',      key: 'ML_ENSEMBLE',  col: 'bg-violet-500', text: 'text-violet-400', on: layerStatus.ml_rf || layerStatus.ml_xgb || layerStatus.ml_cat },
              { label: 'L3 · Deep Neural Net',  key: 'DL_LAYER',     col: 'bg-indigo-500', text: 'text-indigo-400', on: layerStatus.dl },
              { label: 'L4 · Anomaly Sentinel', key: 'ANOMALY',      col: 'bg-amber-500',  text: 'text-amber-400',  on: layerStatus.anomaly },
            ].map(row => {
              const hits = Object.values(sweepLayerCounts).reduce((s, lc) =>
                s + (lc?.[row.key] ?? 0), 0);
              const total = globalStats.threats || 1;
              const pct   = Math.min(100, Math.round((hits / total) * 100));
              return (
                <div key={row.key}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-[10px] font-black uppercase tracking-wider ${row.on ? row.text : 'text-slate-700'}`}>
                      {row.label}
                    </span>
                    <span className={`text-[11px] font-black font-mono ${row.on ? row.text : 'text-slate-800'}`}>
                      {row.on ? hits.toLocaleString() : 'Offline'}
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    {row.on && hits > 0 && (
                      <div className={`h-full ${row.col} rounded-full transition-all`}
                           style={{ width: `${pct}%` }} />
                    )}
                  </div>
                </div>
              );
            })}
            <p className="text-[9px] text-slate-700 font-mono pt-2 border-t border-slate-900">
              Session threats: {globalStats.threats} · Flows analyzed: {globalStats.analyzed}
            </p>
          </div>
        </div>

        {/* Network & engine quick-stats */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800">
            <Zap size={14} className="text-amber-400" />
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Engine Diagnostics</span>
          </div>
          <div className="p-4 space-y-3">
            {[
              { label: 'Signature Database',  val: engineDiag.sigs > 0 ? `${engineDiag.sigs.toLocaleString()} active rules` : 'Loading…', icon: <Database size={13}/>, col: 'text-cyan-400' },
              { label: 'Detection Layers',    val: layers.filter(l => l.on).length + ' / 4 layers active', icon: <Brain size={13}/>, col: 'text-violet-400' },
              { label: 'Alert Confidence Floor', val: engineDiag.threshold != null ? `${Math.round(engineDiag.threshold * 100)}% minimum to alert` : '—', icon: <TrendingUp size={13}/>, col: 'text-emerald-400' },
              { label: 'Live Capture',        val: status?.is_capturing ? 'Active' : 'Standby', icon: <Radio size={13}/>,   col: 'text-sky-400'    },
              { label: 'System Mode',         val: status?.mode || 'OPERATIONAL',              icon: <Lock size={13}/>,       col: 'text-amber-400'  },
              { label: 'Network Nodes',       val: topologyNodes.length > 0 ? `${topologyNodes.length} endpoints mapped` : 'Pending discovery', icon: <Network size={13}/>, col: 'text-indigo-400' },
            ].map(row => (
              <div key={row.label} className="flex items-center justify-between py-1 border-b border-slate-900">
                <div className="flex items-center gap-2">
                  <span className={`${row.col} opacity-70`}>{row.icon}</span>
                  <span className="text-[11px] text-slate-500 font-bold">{row.label}</span>
                </div>
                <span className={`text-[11px] font-black font-mono ${row.col}`}>{row.val}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ══ SUBNET DEVICE CATALOG ════════════════════════════════════════════════ */}
      <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden shadow-lg">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Network size={14} className="text-emerald-500" />
            <h3 className="text-[10px] font-black uppercase tracking-widest text-white">Subnet Device Catalog</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse inline-block" />
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">
              {topologyNodes.length} synchronized nodes
            </span>
            {topoInterface
              ? <span className="text-[9px] text-emerald-600 font-mono ml-2">· {topoInterface}</span>
              : <span className="text-[9px] text-slate-700 font-mono ml-2">· Live ARP sweep</span>
            }
          </div>
        </div>

        <div className="overflow-x-auto max-h-72 overflow-y-auto custom-scrollbar">
          <table className="w-full text-left text-[11px] font-mono whitespace-nowrap">
            <thead className="sticky top-0 bg-[#060912] border-b border-slate-800
              text-[9px] uppercase font-black tracking-widest text-slate-600 z-10">
              <tr>
                <th className="px-5 py-3">Node Class</th>
                <th className="px-5 py-3">IP Address</th>
                <th className="px-5 py-3">MAC Address</th>
                <th className="px-5 py-3">Host Signature</th>
                <th className="px-5 py-3">OS Fingerprint</th>
                <th className="px-5 py-3 text-right">Link Status</th>
              </tr>
            </thead>
            <tbody>
              {topologyNodes.length > 0 ? topologyNodes.map((node, i) => {
                const typeColors = {
                  server:  'border-cyan-900/50 bg-cyan-900/20 text-cyan-400',
                  gateway: 'border-indigo-900/50 bg-indigo-900/20 text-indigo-400',
                  client:  'border-emerald-900/50 bg-emerald-900/20 text-emerald-400',
                  attacker:'border-red-900/50 bg-red-900/20 text-red-400',
                };
                const tc = typeColors[node.type] ?? 'border-slate-800 bg-slate-900 text-slate-500';
                return (
                  <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                    <td className="px-5 py-2.5">
                      <span className={`px-2 py-0.5 rounded border text-[9px] uppercase tracking-wider font-black ${tc}`}>
                        {node.type || 'Unknown'}
                      </span>
                    </td>
                    <td className="px-5 py-2.5 font-black text-white">{node.ip}</td>
                    <td className="px-5 py-2.5 text-slate-500">{node.mac || 'FF:FF:FF:FF:FF:FF'}</td>
                    <td className="px-5 py-2.5 text-slate-400">{node.label || '—'}</td>
                    <td className="px-5 py-2.5 text-slate-600 text-[10px]">{node.os || 'Unknown'}</td>
                    <td className="px-5 py-2.5 text-right">
                      {node.status === 'blocked'
                        ? <span className="text-red-400 font-black uppercase tracking-widest">Blocked</span>
                        : <span className="text-emerald-400 font-bold uppercase tracking-widest">Active</span>
                      }
                    </td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan={6} className="text-center py-16 text-slate-800 text-[11px] uppercase font-bold tracking-widest animate-pulse">
                    Executing ARP sweep across local subnets...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}

// ── KPI Card component ────────────────────────────────────────────────────────
// Static class maps — required for Tailwind JIT to include all classes
const KPI_PALETTE = {
  cyan:    { text: 'text-cyan-400',    box: 'text-cyan-400 bg-cyan-900/20 border-cyan-800/50'    },
  violet:  { text: 'text-violet-400',  box: 'text-violet-400 bg-violet-900/20 border-violet-800/50'  },
  emerald: { text: 'text-emerald-400', box: 'text-emerald-400 bg-emerald-900/20 border-emerald-800/50' },
  red:     { text: 'text-red-400',     box: 'text-red-400 bg-red-900/20 border-red-800/50'     },
  amber:   { text: 'text-amber-400',   box: 'text-amber-400 bg-amber-900/20 border-amber-800/50'   },
};

function KpiCard({ icon, label, value, sub, colour = 'cyan', pulse = false }) {
  const pal = KPI_PALETTE[colour] ?? KPI_PALETTE.cyan;
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex items-center justify-between shadow">
      <div>
        <p className="text-[9px] uppercase font-bold text-slate-600 tracking-widest mb-1">{label}</p>
        <p className={`text-xl font-black font-mono ${pal.text}`}>{value}</p>
        <p className="text-[9px] text-slate-700 mt-1 font-mono">{sub}</p>
      </div>
      <div className={`p-2.5 rounded border shrink-0 ${pal.box} ${pulse ? 'animate-pulse' : ''}`}>
        {icon}
      </div>
    </div>
  );
}
