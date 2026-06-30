import React, { useState, useEffect, useCallback } from 'react';
import {
  Database, Cpu, HardDrive, Zap, Lock, Filter, Search,
  Terminal, Activity, Server, ShieldCheck, ShieldAlert,
  RefreshCw, Layers, Shield, Eye, AlertTriangle
} from 'lucide-react';

/* ============================================================
   BASTION IDS — SYSTEM HEALTH DASHBOARD
   Pulls real metrics from /api/v1/health + /api/v1/alerts
   + /api/v1/startup-log for initialization messages.
   ============================================================ */

const API_BASE = "http://127.0.0.1:48217/api/v1";
const AUTH_HDR = { 'x-authority': 'BASTION-KADIAN-SEC-0x42' };

export default function SystemHealth({ status, liveHealth }) {
  const [logs, setLogs]               = useState([]);
  // Seed from parent's continuous poll so the first render is never null/red.
  // The component's own fetchHealth() keeps it fresh; the prop sync below
  // also updates state whenever the parent receives a new health payload.
  const [health, setHealth]           = useState(liveHealth ?? null);
  const [startupLog, setStartupLog]   = useState([]);
  const [activeAlerts, setActiveAlerts] = useState(0);
  const [avgConf, setAvgConf]         = useState(null);
  const [logFilter, setLogFilter]     = useState('ALL');
  const [logSearch, setLogSearch]     = useState('');
  const [lastRefresh, setLastRefresh] = useState(null);

  // ── Sync with parent health poll ────────────────────────
  // App.jsx polls /health every 4 s and passes the raw response as liveHealth.
  // Whenever that prop updates we mirror it here so the engine status rows
  // stay green even before this component's own fetchHealth() fires.
  useEffect(() => {
    if (liveHealth) setHealth(liveHealth);
  }, [liveHealth]);

  // ── Fetch health stats ──────────────────────────────────
  const fetchHealth = useCallback(async () => {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    try {
      const res = await fetch(`${API_BASE}/health`, { headers: AUTH_HDR, signal: ctrl.signal });
      clearTimeout(timer);
      if (res.ok) setHealth(await res.json());
    } catch { clearTimeout(timer); }
  }, []);

  // ── Fetch startup log ───────────────────────────────────
  const fetchStartupLog = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/startup-log`, { headers: AUTH_HDR });
      if (res.ok) {
        const data = await res.json();
        setStartupLog(data.log || []);
      }
    } catch {}
  }, []);

  // ── Fetch alerts for log feed ───────────────────────────
  // Uses /alerts?limit=200 — enough for the UI log display.
  // Previously fetched all 50 000 alerts on every 10 s poll, blocking the
  // backend event loop → health endpoint timeouts → "CONNECTING / 0 layers".
  const refreshLogs = useCallback(async () => {
    if (!status?.online) return;
    try {
      // Parallel fetch: recent alerts for display + count for stats
      const [alertsRes, countRes] = await Promise.all([
        fetch(`${API_BASE}/alerts?limit=200`, { headers: AUTH_HDR }),
        fetch(`${API_BASE}/alerts/count`,     { headers: AUTH_HDR }),
      ]);
      const ADMIN_V = new Set(['NORMAL', 'LOCKDOWN', 'BASTION_CLEAN', '', 'OPERATOR']);
      if (alertsRes.ok) {
        const data = await alertsRes.json();
        setLogs(data);
        const threats = data.filter(a => {
          const v = (a.verdict || '').toUpperCase();
          return v && !ADMIN_V.has(v);
        });
        if (threats.length > 0) {
          const avg = threats.reduce((s, a) => s + (Number(a.confidence) || 0), 0) / threats.length;
          setAvgConf((avg * 100).toFixed(1));
        } else {
          setAvgConf(null);
        }
      }
      if (countRes.ok) {
        const cd = await countRes.json();
        setActiveAlerts(cd.total ?? 0);
      }
      setLastRefresh(new Date().toLocaleTimeString());
    } catch (err) {
      console.error("LOG_UPLINK_ERROR", err);
    }
  }, [status?.online]);

  useEffect(() => {
    fetchHealth();
    fetchStartupLog();
    refreshLogs();
    // Poll health every 5 s so engine status recovers quickly after a backend restart.
    const healthTimer = setInterval(fetchHealth, 5000);
    const logsTimer   = setInterval(refreshLogs, 10000);
    return () => { clearInterval(healthTimer); clearInterval(logsTimer); };
  }, [fetchHealth, fetchStartupLog, refreshLogs]);

  // Real values from health endpoint
  const sigCount   = health?.signatures_active ?? status?.signatures ?? '—';
  const pktsProc   = health?.packets_processed ?? 0;
  const layersUp   = health?.layers_active ?? status?.layers ?? 0;
  const engineMode = health?.mode ?? status?.mode ?? 'OFFLINE';

  // Format packet count nicely
  const fmtPkts = (n) => {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
    if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
    return String(n);
  };

  // Model status flags from health endpoint
  const models = {
    rf:    health?.ml_rf   ?? false,
    xgb:   health?.ml_xgb  ?? false,
    cat:   health?.ml_cat  ?? false,
    dl:    health?.dl      ?? false,
    anomaly: health?.anomaly ?? false,
    sigs:  (health?.signatures_active ?? 0) > 0,
  };

  const ADMIN_VERDICTS = new Set(['NORMAL', 'LOCKDOWN', 'BASTION_CLEAN', '', 'OPERATOR']);

  // Threat feed: always shows only real threat detections (no NORMAL/admin rows).
  // Filter tabs: severity-based — ALL THREATS / HIGH / MEDIUM / LOW
  function _alertSeverity(conf) {
    const c = Number(conf || 0);
    if (c >= 0.90) return 'HIGH';
    if (c >= 0.70) return 'MEDIUM';
    return 'LOW';
  }

  const visibleLogs = logs.filter(log => {
    const v = (log.verdict || '').toUpperCase();
    // Threat feed only — skip NORMAL and operator actions
    if (ADMIN_VERDICTS.has(v) || !v) return false;
    // Severity filter
    if (logFilter !== 'ALL') {
      if (_alertSeverity(log.confidence) !== logFilter) return false;
    }
    // Search: IP address, verdict text, or engine name (case-insensitive)
    if (logSearch.trim()) {
      const q = logSearch.trim().toLowerCase();
      const src = (log.srcip || log.source_ip || '').toLowerCase();
      const dst = (log.dstip || log.dest_ip  || '').toLowerCase();
      const ver = (log.verdict || '').toLowerCase();
      const eng = (log.source_engine || log.engine || '').toLowerCase();
      const ts  = (log.timestamp || '').toLowerCase();
      if (!src.includes(q) && !dst.includes(q) && !ver.includes(q)
          && !eng.includes(q) && !ts.includes(q)) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 font-mono text-slate-300">

      {/* STATUS BANNERS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <BannerCard
          icon={<Activity />}
          title="Uplink Integrity"
          value={status?.online ? 'SECURE_LINK' : 'UPLINK_FAILURE'}
          color={status?.online ? 'text-emerald-500' : 'text-red-500'}
          sub={`Node: 127.0.0.1:48217${lastRefresh ? ` · ${lastRefresh}` : ''}`}
          border={status?.online ? 'border-emerald-900/50' : 'border-red-900/50'}
          bg={status?.online ? 'bg-emerald-900/10' : 'bg-red-900/10'}
        />
        <BannerCard
          icon={<ShieldAlert />}
          title="Active Threat Count"
          value={`${activeAlerts} DETECTED`}
          color={activeAlerts > 0 ? 'text-red-500' : 'text-emerald-500'}
          sub={avgConf ? `Avg Confidence: ${avgConf}%` : 'No active threats'}
          border="border-red-900/50"
          bg="bg-red-900/10"
        />
        <BannerCard
          icon={<Layers />}
          title="Detection Layers"
          value={`${layersUp} / 4 ONLINE`}
          color={layersUp >= 4 ? 'text-emerald-500' : layersUp >= 2 ? 'text-amber-500' : 'text-red-500'}
          sub={`Mode: ${engineMode}`}
          border="border-cyan-900/50"
          bg="bg-cyan-900/10"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* LEFT: RESOURCES + ENGINE STATS */}
        <div className="lg:col-span-4 space-y-4">

          {/* Resource bars */}
          <div className="bg-slate-950 border border-slate-800 p-4 rounded text-sm">
            <div className="flex items-center gap-2 mb-4 text-white">
              <Cpu size={16} className="text-cyan-500"/>
              <span className="font-bold uppercase tracking-wider">Host Resources</span>
            </div>
            <div className="space-y-4">
              <ResourceBar label="Processor Load"   value={status?.cpu ?? health?.cpu_percent ?? 0}  color="bg-cyan-500" />
              <ResourceBar label="Physical Memory"  value={status?.ram ?? health?.ram_percent ?? 0}  color="bg-indigo-500" />
              <ResourceBar label="Storage (Disk)"   value={Number(health?.storage_usage ?? status?.storage ?? 72)}  color="bg-slate-500" />
            </div>
          </div>

          {/* Engine stats — REAL values */}
          <div className="bg-slate-950 border border-slate-800 p-4 rounded">
            <h3 className="text-xs font-bold uppercase text-white mb-2 pb-2 border-b border-slate-800">Engine Statistics</h3>
            <div className="space-y-2 text-xs">
              <StatRow label="Active Signatures"  val={Number(sigCount).toLocaleString()} />
              <StatRow label="Packets Processed"  val={fmtPkts(pktsProc)} />
              <StatRow label="Threat Alerts"      val={String(activeAlerts)} />
              <StatRow label="Avg Threat Conf"    val={avgConf ? `${avgConf}%` : '—'} />
              <StatRow label="Uptime"             val={status?.uptime ?? health?.uptime ?? '—'} />
            </div>
          </div>

          {/* Model status checklist */}
          <div className="bg-slate-950 border border-slate-800 p-4 rounded">
            <h3 className="text-xs font-bold uppercase text-white mb-3 pb-2 border-b border-slate-800 flex items-center gap-2">
              <Shield size={14} className="text-cyan-500"/> Detection Layer Status
            </h3>
            <div className="space-y-2 text-xs">
              <ModelRow label="L1 · Signature Engine"  active={models.sigs}    detail={models.sigs    ? `${Number(sigCount).toLocaleString()} active rules` : (health ? 'Not loaded' : 'Initializing…')} />
              <ModelRow label="L2 · Random Forest"     active={models.rf}      detail={models.rf      ? 'ML Classifier — Random Forest'      : (health ? 'Not loaded' : 'Initializing…')} />
              <ModelRow label="L2 · Gradient Boost"    active={models.xgb}     detail={models.xgb     ? 'ML Classifier — Gradient Boost'      : (health ? 'Not loaded' : 'Initializing…')} />
              <ModelRow label="L2 · Category Boost"    active={models.cat}     detail={models.cat     ? 'ML Classifier — Category Boost'      : (health ? 'Not loaded' : 'Initializing…')} />
              <ModelRow label="L3 · Neural Specialist" active={models.dl}      detail={models.dl      ? 'Deep Neural Network Classifier'      : (health ? 'Not loaded' : 'Initializing…')} />
              <ModelRow label="L4 · Anomaly Sentinel"  active={models.anomaly} detail={models.anomaly ? 'Behavioral Anomaly Detection'         : (health ? 'Not loaded' : 'Initializing…')} />
            </div>
          </div>

          {/* Engine initialization status summary */}
          <div className="bg-slate-950 border border-slate-800 p-4 rounded">
            <h3 className="text-xs font-bold uppercase text-white mb-2 pb-2 border-b border-slate-800 flex items-center gap-2">
              <Terminal size={14} className="text-emerald-500"/> Engine Status
            </h3>
            <div className="space-y-1.5 text-[10px]">
              <div className="flex justify-between">
                <span className="text-slate-500">Signature Engine</span>
                <span className={models.sigs ? 'text-emerald-400 font-black' : 'text-red-400'}>{models.sigs ? 'ONLINE' : 'OFFLINE'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">ML Ensemble</span>
                <span className={models.rf ? 'text-emerald-400 font-black' : 'text-amber-400'}>{models.rf ? `ONLINE · ${[models.rf, models.xgb, models.cat].filter(Boolean).length}/3 models` : 'DEGRADED'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Neural Specialist</span>
                <span className={models.dl ? 'text-emerald-400 font-black' : 'text-amber-400'}>{models.dl ? 'ONLINE' : 'OFFLINE'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Anomaly Sentinel</span>
                <span className={models.anomaly ? 'text-emerald-400 font-black' : 'text-amber-400'}>{models.anomaly ? 'ONLINE' : 'INITIALIZING'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT: THREAT LOG FEED */}
        <div className="lg:col-span-8 bg-slate-950 border border-slate-800 rounded flex flex-col h-[700px]">
          <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-slate-900">
            <h3 className="text-xs font-bold uppercase flex items-center gap-2 text-white">
              <Terminal size={16} className="text-cyan-500" /> Threat_Log_Feed
              {visibleLogs.length > 0 && (
                <span className="bg-cyan-500/20 text-cyan-400 text-[9px] px-2 py-0.5 rounded-full border border-cyan-500/20">{visibleLogs.length}</span>
              )}
            </h3>
            <div className="flex gap-2 items-center">
              {/* Filter tabs — severity-based (threats only; normal traffic is not stored) */}
              <div className="flex bg-slate-800 rounded overflow-hidden border border-slate-700">
                {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
                  <button key={f} onClick={() => setLogFilter(f)}
                    className={`px-3 py-1.5 text-[9px] font-black uppercase tracking-widest transition-all ${
                      logFilter === f
                        ? f === 'HIGH'   ? 'bg-red-500/20 text-red-400'
                        : f === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400'
                        : f === 'LOW'    ? 'bg-slate-700 text-slate-300'
                        : 'bg-cyan-500/20 text-cyan-400'
                        : 'text-slate-500 hover:text-slate-300'
                    }`}>
                    {f === 'ALL' ? 'ALL THREATS' : f}
                  </button>
                ))}
              </div>
              {/* Search */}
              <div className="flex items-center gap-1 bg-slate-800 border border-slate-700 rounded px-2 py-1">
                <Search size={11} className="text-slate-600" />
                <input
                  value={logSearch} onChange={e => setLogSearch(e.target.value)}
                  placeholder="Filter..." className="bg-transparent text-[10px] outline-none text-white w-20 placeholder:text-slate-700"
                />
              </div>
              <button onClick={refreshLogs} title="Refresh"
                className="bg-slate-800 p-1.5 rounded hover:bg-slate-700 text-white border border-slate-700 transition-colors">
                <RefreshCw size={13} />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-auto p-2">
            <table className="w-full text-left text-xs whitespace-nowrap">
              <thead className="text-slate-500 sticky top-0 bg-slate-950 z-10">
                <tr>
                  <th className="py-2 px-3 border-b border-slate-800 text-[9px] uppercase tracking-widest">Time</th>
                  <th className="py-2 px-3 border-b border-slate-800 text-[9px] uppercase tracking-widest">Source IP</th>
                  <th className="py-2 px-3 border-b border-slate-800 text-[9px] uppercase tracking-widest">Verdict</th>
                  <th className="py-2 px-3 border-b border-slate-800 text-[9px] uppercase tracking-widest">Engine</th>
                  <th className="py-2 px-3 border-b border-slate-800 text-[9px] uppercase tracking-widest text-right">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {visibleLogs.length > 0 ? visibleLogs
                  .filter(log => {
                    // Always exclude LOCKDOWN and operator entries — those are admin actions
                    const v = (log.verdict || '').toUpperCase();
                    return !['LOCKDOWN', 'OPERATOR', 'BASTION_CLEAN'].includes(v);
                  })
                  .map((log, i) => {
                  const isThreeat = log.verdict && !['NORMAL', 'LOCKDOWN', 'BASTION_CLEAN', 'OPERATOR'].includes(log.verdict.toUpperCase());
                  const timeStr = log.timestamp
                    ? String(log.timestamp).split('T')[1]?.split('.')[0] || log.timestamp
                    : '—';
                  const conf = log.confidence != null ? (Number(log.confidence) * 100).toFixed(1) + '%' : '—';
                  return (
                    <tr key={i} className={`border-b border-slate-800/50 hover:bg-slate-900/60 transition-colors ${isThreeat ? 'bg-red-900/10' : ''}`}>
                      <td className="py-2 px-3 text-slate-500">{timeStr}</td>
                      <td className="py-2 px-3 text-slate-300 font-mono">{log.srcip || log.source_ip || '—'}</td>
                      <td className={`py-2 px-3 font-bold max-w-[180px] truncate ${isThreeat ? 'text-red-400' : 'text-emerald-500'}`}>
                        {log.verdict || 'UNKNOWN'}
                      </td>
                      <td className="py-2 px-3 text-slate-500 text-[10px]">{log.source_engine || log.engine || '—'}</td>
                      <td className={`py-2 px-3 text-right font-black ${isThreeat ? 'text-red-400' : 'text-slate-500'}`}>{conf}</td>
                    </tr>
                  );
                }) : (
                  <tr>
                    <td colSpan="5">
                      <div className="flex flex-col items-center justify-center p-12 opacity-30 text-center">
                        <Lock size={28} className="mb-4" />
                        <span className="font-bold text-xs tracking-widest uppercase">
                          {status?.online ? 'No Log Entries Match Filter' : 'Engine Offline — No Data'}
                        </span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// REUSABLE SUB-COMPONENTS
// ─────────────────────────────────────────────────────────────

function BannerCard({ icon, title, value, color, sub, border, bg }) {
  return (
    <div className={`${bg} ${border} border p-4 rounded flex items-center gap-4`}>
      <div className={`p-3 bg-slate-950 rounded border border-slate-800 ${color} shrink-0`}>{icon}</div>
      <div className="overflow-hidden">
        <p className="text-[10px] uppercase font-bold text-slate-400 mb-0.5 tracking-wider">{title}</p>
        <p className={`text-base font-black ${color} truncate`}>{value}</p>
        <p className="text-[9px] text-slate-500 mt-1 uppercase truncate">{sub}</p>
      </div>
    </div>
  );
}

function ResourceBar({ label, value, color }) {
  const clamped = Math.min(100, Math.max(0, Number(value) || 0));
  return (
    <div>
      <div className="flex justify-between text-[10px] font-bold mb-1 uppercase text-slate-400">
        <span>{label}</span>
        <span className={`${clamped > 80 ? 'text-red-400' : clamped > 60 ? 'text-amber-400' : 'text-white'}`}>{clamped}%</span>
      </div>
      <div className="h-1.5 bg-slate-900 border border-slate-800 rounded-full overflow-hidden">
        <div className={`h-full ${color} transition-all duration-700`} style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}

function StatRow({ label, val }) {
  return (
    <div className="flex justify-between items-center py-1 border-b border-slate-800/50 last:border-0 hover:bg-slate-900 rounded px-1 transition-colors">
      <span className="text-slate-500">{label}</span>
      <span className="text-white font-bold">{val}</span>
    </div>
  );
}

function ModelRow({ label, active, detail }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-slate-800/30 last:border-0">
      <div className="flex items-center gap-2">
        <div className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-emerald-500' : 'bg-red-500/50'}`}></div>
        <span className={`text-[10px] ${active ? 'text-slate-300' : 'text-slate-600'}`}>{label}</span>
      </div>
      <span className={`text-[9px] ${active ? 'text-slate-500' : 'text-slate-700'}`}>{detail}</span>
    </div>
  );
}
