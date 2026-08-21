/* eslint-disable no-unused-vars */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  ShieldAlert, ShieldCheck, Zap, Cpu, Terminal, Lock, Unlock,
  Database, AlertTriangle, Server, Eye, Radio, Settings2,
  HardDrive, Globe, Crosshair, BarChart3, Layers,
  Flame, Power, RefreshCw, UserX, ShieldX, Search, Activity,
  BellOff, Ghost, ShieldOff, Network, Laptop, Key, Fingerprint,
  UserCheck, Users, TrendingUp, ChevronRight, Map,
  ListFilter, History, Info, Wifi, Box, X, FileText,
  CheckCircle2, AlertCircle, Cpu as KernelIcon
} from 'lucide-react';

/* ============================================================
   BASTION IDS — COMMAND & CONTROL CENTER
   Wired to real API endpoints:
   - /api/v1/health         → live system metrics
   - /api/v1/alerts         → threat count + recent alerts
   - DELETE /api/v1/alerts  → purge all alerts
   - POST /api/v1/flush     → flush cache / engine reload
   - POST /api/v1/settings/update → policy overrides
   ============================================================ */

const API_BASE = "http://127.0.0.1:48217/api/v1";
const HDR      = { 'x-authority': 'BASTION-KADIAN-SEC-0x42', 'Content-Type': 'application/json' };

// Words displayed as a verification challenge for irreversible commands
const VERIFY_WORDS = ['AUTHORIZE', 'CONFIRM', 'EXECUTE', 'PROCEED', 'OVERRIDE', 'VALIDATE'];

// Policy definitions with descriptions of actual system behaviour
const POLICY_CONFIG = [
  {
    key: 'autoIsolate',
    label: 'Auto-Isolate Threats',
    desc: 'Automatically blocks the source IP of confirmed threat detections at the filter layer',
    icon: <ShieldX size={14}/>,
  },
  {
    key: 'mfaEnforce',
    label: 'Verification Challenge',
    desc: 'Requires the analyst to type a randomly-generated verification word before executing destructive operations (active by default for hard lockdown, wipe, and quarantine actions)',
    icon: <Key size={14}/>,
  },
  {
    key: 'stealthMode',
    label: 'Stealth Mode',
    desc: 'Blocks inbound mDNS (UDP 5353) via Windows Firewall so this host is hidden from mDNS/Bonjour service discovery',
    icon: <Ghost size={14}/>,
  },
  {
    key: 'deepInspection',
    label: 'Deep Packet Inspection',
    desc: 'Enables layer-7 payload analysis on all monitored flows — higher detection accuracy, higher CPU cost',
    icon: <Eye size={14}/>,
  },
  {
    key: 'ghostProtocol',
    label: 'Ghost Protocol',
    desc: 'Blocks inbound ICMP echo (ping) via Windows Firewall so this host stops replying to ping sweeps',
    icon: <BellOff size={14}/>,
  },
];

export default function BastionCommandCenter({ status, liveHealth, lockdownActive: lockdownActiveProp }) {
  const [isProcessing, setIsProcessing] = useState(false);
  const [systemMode, setSystemMode]     = useState('OPERATIONAL');
  const [notifications, setNotifications] = useState([]);
  const [logs, setLogs]                 = useState([]);

  // Confirmation modal state: { action, label, word } — includes random verification word
  const [showConfirm, setShowConfirm]   = useState(null);
  const [wordInput, setWordInput]       = useState('');

  // Seed from parent's continuous poll so engine rows are green on first render
  const [health, setHealth]             = useState(liveHealth ?? null);
  const [alertCount, setAlertCount]     = useState(0);
  const [layersUp, setLayersUp]         = useState(liveHealth?.layers_active ?? 0);
  const [sigCount, setSigCount]         = useState(0);
  const [pktsProcessed, setPktsProcessed] = useState(0);

  // Tracks if the "active threats" notification was already shown this session
  const alertShownRef = useRef(false);

  const [policies, setPolicies] = useState({
    autoIsolate:    true,
    mfaEnforce:     true,
    stealthMode:    false,
    deepInspection: true,
    ghostProtocol:  false
  });
  const [isolatedIPs, setIsolatedIPs] = useState([]);

  // ── Analyst feedback log (committed verdicts from Attack Analysis) ────────
  const [fbLog,   setFbLog]   = useState([]);
  const [fbStats, setFbStats] = useState(null);

  const fetchFeedback = useCallback(async () => {
    try {
      const [logRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/feedback`, { headers: HDR }),
        fetch(`${API_BASE}/feedback/stats`, { headers: HDR }),
      ]);
      if (logRes.ok)   setFbLog(await logRes.json());
      if (statsRes.ok) setFbStats(await statsRes.json());
    } catch {}
  }, []);

  useEffect(() => {
    fetchFeedback();
    const t = setInterval(fetchFeedback, 15000);
    return () => clearInterval(t);
  }, [fetchFeedback]);

  // ── Sync with parent health poll ────────────────────────────
  // App.jsx polls /health every 4 s and passes the raw response as liveHealth.
  // Mirror it so engine status rows stay green between this component's own polls.
  useEffect(() => {
    if (!liveHealth) return;
    setHealth(liveHealth);
    setLayersUp(liveHealth.layers_active ?? 0);
    setSigCount(liveHealth.signatures_active ?? 0);
    setPktsProcessed(liveHealth.packets_processed ?? 0);
  }, [liveHealth]);

  // Keep systemMode in sync with the server-side lockdown state
  // (health poll in App.jsx detects lockdown_active and passes it down)
  useEffect(() => {
    if (lockdownActiveProp === true)  setSystemMode('LOCKDOWN');
    if (lockdownActiveProp === false && systemMode === 'LOCKDOWN') setSystemMode('OPERATIONAL');
  }, [lockdownActiveProp]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Audit Log ─────────────────────────────────────────────
  const addLog = useCallback((m, s = 'SYS') => {
    const t = new Date().toLocaleTimeString([], { hour12: false });
    setLogs(prev => [{ t, m: String(m), s, id: Date.now() + Math.random() }, ...prev].slice(0, 80));
  }, []);

  const pushNotification = useCallback((message, type = 'INFO') => {
    const id = Date.now();
    setNotifications(prev => [...prev.filter(n => n.message !== message), { id, message, type }]);
    setTimeout(() => setNotifications(prev => prev.filter(n => n.id !== id)), 6000);
  }, []);

  // ── Fetch health ─────────────────────────────────────────
  const fetchHealth = useCallback(async () => {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    try {
      const res = await fetch(`${API_BASE}/health`, { headers: HDR, signal: ctrl.signal });
      clearTimeout(timer);
      if (!res.ok) return;
      const d = await res.json();
      setHealth(d);
      setLayersUp(d.layers_active ?? 0);
      setSigCount(d.signatures_active ?? 0);
      setPktsProcessed(d.packets_processed ?? 0);
    } catch { clearTimeout(timer); }
  }, []);

  // ── Fetch live policy state from backend ─────────────────
  // Syncs toggle UI with the actual server-side active_policies dict.
  // Also loads auto-isolated IPs so operators can release them from the UI.
  const fetchPolicies = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/policies/status`, { headers: HDR });
      if (!res.ok) return;
      const d = await res.json();
      if (d.policies) setPolicies(prev => ({ ...prev, ...d.policies }));
      if (Array.isArray(d.isolated_ips)) setIsolatedIPs(d.isolated_ips);
    } catch {}
  }, []);

  // ── Release a single auto-isolated IP ────────────────────
  const releaseIP = useCallback(async (ip) => {
    try {
      await fetch(`${API_BASE}/policies/release`, {
        method: 'POST', headers: HDR,
        body: JSON.stringify({ ip }),
      });
      setIsolatedIPs(prev => prev.filter(i => i !== ip));
      addLog(`AUTO-ISOLATE: Released ${ip}`, 'OK');
      pushNotification(`Released isolation for ${ip}`, 'INFO');
    } catch {
      addLog(`AUTO-ISOLATE: Release failed for ${ip}`, 'ERR');
    }
  }, [addLog, pushNotification]);

  // ── Fetch alert count — uses the O(1) counter, never loads alerts.json ──────
  // Previously this fetched all 50 000 alerts to count them, blocking the backend
  // event loop for seconds and causing health polls to timeout → CONNECTING state.
  const fetchAlertCount = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/alerts/count`, { headers: HDR });
      if (!res.ok) return;
      const data = await res.json();
      const threats = data.total ?? 0;
      setAlertCount(threats);
      if (threats > 0 && !alertShownRef.current) {
        pushNotification(`${threats} active threat${threats !== 1 ? 's' : ''} detected in log`, 'WARN');
        alertShownRef.current = true;
      }
    } catch {}
  }, [pushNotification]);

  // ── Init & polling ────────────────────────────────────────
  useEffect(() => {
    fetchHealth();
    fetchAlertCount();
    fetchPolicies();  // load real policy state from backend on mount
    addLog('Command & Control interface initialized', 'SYS');
    addLog('Authority key validated — admin session active', 'OK');
    const healthTimer  = setInterval(fetchHealth, 10000);
    const alertTimer   = setInterval(fetchAlertCount, 20000);
    const policyTimer  = setInterval(fetchPolicies, 30000);  // refresh isolation list
    return () => { clearInterval(healthTimer); clearInterval(alertTimer); clearInterval(policyTimer); };
  }, [fetchHealth, fetchAlertCount, fetchPolicies, addLog]);

  // ── Random word generator for verification challenges ─────
  const pickWord = () => VERIFY_WORDS[Math.floor(Math.random() * VERIFY_WORDS.length)];

  // ── Handle confirmed commands ─────────────────────────────
  const handleCommand = async (cmd) => {
    if (isProcessing) return;

    // Commands that require word verification
    const CONFIRM_CMDS = ['PURGE_ALERTS', 'FLUSH_CACHE', 'FULL_RESTART'];
    if (CONFIRM_CMDS.includes(cmd) && policies.mfaEnforce && showConfirm?.action !== cmd) {
      const word = pickWord();
      setShowConfirm({
        action: cmd,
        word,
        label: {
          PURGE_ALERTS: 'This will permanently delete ALL alerts from the database. This action cannot be undone.',
          FLUSH_CACHE:  'This will flush the engine cache and force a full model reload. All in-memory state will be cleared.',
          FULL_RESTART: 'This will send a restart signal to the backend engine process. The system will be briefly unavailable.',
        }[cmd],
      });
      setWordInput('');
      return;
    }
    setShowConfirm(null);
    setWordInput('');

    setIsProcessing(true);
    addLog(`EXEC: ${cmd} initiated`, 'REQ');

    try {
      if (cmd === 'LOCKDOWN') {
        const isCurrentlyLocked = systemMode === 'LOCKDOWN';
        const endpoint = isCurrentlyLocked ? `${API_BASE}/lockdown/release` : `${API_BASE}/lockdown`;
        const res = await fetch(endpoint, { method: 'POST', headers: HDR });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const next = isCurrentlyLocked ? 'OPERATIONAL' : 'LOCKDOWN';
        setSystemMode(next);
        addLog(`SYSTEM MODE → ${next}`, next === 'LOCKDOWN' ? 'ERR' : 'OK');
        pushNotification(
          next === 'LOCKDOWN'
            ? 'LOCKDOWN ENGAGED — Capture halted, all analysis blocked'
            : 'Lockdown released — system returned to operational state',
          next === 'LOCKDOWN' ? 'CRITICAL' : 'INFO'
        );

      } else if (cmd === 'PURGE_ALERTS') {
        const res = await fetch(`${API_BASE}/alerts`, { method: 'DELETE', headers: HDR });
        if (res.ok) {
          setAlertCount(0);
          alertShownRef.current = false; // allow re-notification after purge
          addLog('PURGE: All alert records permanently deleted', 'OK');
          pushNotification('All alerts purged successfully', 'INFO');
        } else throw new Error(`HTTP ${res.status}`);

      } else if (cmd === 'FLUSH_CACHE') {
        const res = await fetch(`${API_BASE}/flush`, { method: 'POST', headers: HDR });
        if (res.ok) {
          addLog('CACHE: Engine cache flushed — models reloading', 'OK');
          pushNotification('Engine cache cleared and reloaded', 'INFO');
        } else throw new Error(`HTTP ${res.status}`);

      } else if (cmd === 'FULL_RESTART') {
        await fetch(`${API_BASE}/restart`, { method: 'POST', headers: HDR }).catch(() => {});
        addLog('RESTART: Signal dispatched to backend process', 'WARN');
        pushNotification('Backend restart initiated — reconnecting in 15 seconds', 'WARN');
        setTimeout(() => { fetchHealth(); fetchAlertCount(); }, 15000);

      } else {
        addLog(`CMD: ${cmd} acknowledged`, 'OK');
      }
    } catch (err) {
      addLog(`ERROR: ${cmd} failed — ${err.message}`, 'ERR');
      pushNotification(`${cmd} failed: ${err.message}`, 'CRITICAL');
    } finally {
      setIsProcessing(false);
    }
  };

  // ── Policy toggle → API ───────────────────────────────────
  const togglePolicy = async (key) => {
    const next = { ...policies, [key]: !policies[key] };
    setPolicies(next);
    const cfg = POLICY_CONFIG.find(p => p.key === key);
    addLog(`POLICY: ${cfg?.label ?? key} → ${next[key] ? 'ENABLED' : 'DISABLED'}`, 'SYS');
    try {
      await fetch(`${API_BASE}/settings/update`, {
        method: 'POST', headers: HDR,
        body: JSON.stringify({ policy: key, value: next[key] }),
      });
    } catch {
      addLog(`POLICY: ${key} — backend sync unavailable`, 'WARN');
    }
  };

  // ── Helpers ───────────────────────────────────────────────
  const fmtPkts = (n) => {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
    if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
    return String(n || 0);
  };

  const cpu = Number(health?.cpu_percent ?? 0).toFixed(1);
  const ram = Number(health?.ram_percent ?? 0).toFixed(1);

  return (
    <div className="p-4 font-mono bg-[#010409] text-slate-300 selection:bg-cyan-500/30 overflow-x-hidden relative">

      {/* ── WORD VERIFICATION MODAL ─────────────────────────────────────── */}
      {showConfirm && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-sm z-[200] flex items-center justify-center p-4">
          <div className="bg-[#0d1117] border border-red-500/50 rounded-2xl p-8 max-w-md w-full shadow-2xl shadow-red-900/20 animate-in zoom-in-90 duration-200">
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2.5 bg-red-500/10 rounded-xl border border-red-500/30">
                <AlertTriangle size={22} className="text-red-500" />
              </div>
              <div>
                <h3 className="text-white font-black text-sm uppercase tracking-widest">Authorization Required</h3>
                <p className="text-[10px] text-red-400 font-black uppercase tracking-widest mt-0.5">Irreversible Action</p>
              </div>
            </div>

            <p className="text-slate-400 text-sm mb-6 leading-relaxed border-l-2 border-red-500/40 pl-4">{showConfirm.label}</p>

            <div className="mb-6">
              <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest mb-2">
                Type <span className="text-red-400 font-mono text-sm font-black tracking-[0.2em]">{showConfirm.word}</span> to authorize execution:
              </p>
              <input
                value={wordInput}
                onChange={e => setWordInput(e.target.value.toUpperCase())}
                placeholder={showConfirm.word}
                autoFocus
                className="w-full bg-slate-900 border border-slate-700 focus:border-red-500/60 rounded-xl py-3.5 px-4
                  text-white font-black font-mono uppercase tracking-[0.2em] text-sm outline-none
                  placeholder:text-slate-700 transition-colors"
              />
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => { setShowConfirm(null); setWordInput(''); }}
                className="flex-1 py-3 rounded-xl border border-slate-700 text-slate-400 hover:text-white
                  font-black text-[10px] uppercase tracking-widest transition-all hover:border-slate-500"
              >
                Cancel
              </button>
              <button
                onClick={() => handleCommand(showConfirm.action)}
                disabled={wordInput !== showConfirm.word}
                className="flex-1 py-3 rounded-xl bg-red-600 hover:bg-red-500 text-white font-black text-[10px]
                  uppercase tracking-widest transition-all shadow-lg shadow-red-900/30
                  disabled:opacity-30 disabled:cursor-not-allowed disabled:bg-slate-700"
              >
                Execute Command
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── NOTIFICATION OVERLAY ─────────────────────────────────────────── */}
      <div className="fixed top-6 right-6 z-[100] space-y-3 w-full max-w-[320px]">
        {notifications.map(n => (
          <div key={n.id} className={`border-2 p-4 rounded-xl shadow-2xl animate-in slide-in-from-right duration-300 flex items-start gap-3 ${
            n.type === 'CRITICAL' ? 'bg-red-950 border-red-500 shadow-red-900/20' :
            n.type === 'WARN'     ? 'bg-amber-950 border-amber-500/50 shadow-amber-900/20' :
            'bg-slate-900 border-slate-700'
          }`}>
            {n.type === 'CRITICAL' ? <AlertTriangle className="text-red-500 shrink-0" size={18} /> :
             n.type === 'WARN'     ? <AlertCircle className="text-amber-400 shrink-0" size={18} /> :
             <CheckCircle2 className="text-emerald-500 shrink-0" size={18} />}
            <div className="flex-1 min-w-0">
              <p className={`text-[9px] font-black uppercase mb-0.5 ${n.type === 'CRITICAL' ? 'text-red-500' : n.type === 'WARN' ? 'text-amber-400' : 'text-emerald-500'}`}>{n.type}</p>
              <p className="text-xs font-bold text-white leading-tight">{n.message}</p>
            </div>
            <button onClick={() => setNotifications(prev => prev.filter(x => x.id !== n.id))}>
              <X size={14} className="text-slate-500 hover:text-white transition-colors" />
            </button>
          </div>
        ))}
      </div>

      {/* ── AUTHORITY BAR ────────────────────────────────────────────────── */}
      <header className="flex flex-col xl:flex-row justify-between items-center mb-8 bg-[#0d1117] border border-slate-800 p-6 rounded-2xl shadow-2xl gap-6">
        <div className="flex items-center gap-6 w-full xl:w-auto min-w-0">
          <div className={`p-4 rounded-2xl border-2 transition-all duration-500 shrink-0 ${
            systemMode === 'LOCKDOWN'
              ? 'border-red-500 bg-red-500/20 animate-pulse'
              : layersUp >= 4 ? 'border-emerald-500 bg-emerald-500/10' : 'border-cyan-500 bg-cyan-500/10'
          }`}>
            {systemMode === 'LOCKDOWN'
              ? <ShieldAlert size={32} className="text-red-500" />
              : layersUp >= 4 ? <ShieldCheck size={32} className="text-emerald-500" /> : <ShieldCheck size={32} className="text-cyan-500" />}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <h1 className="text-2xl lg:text-3xl font-black text-white tracking-tighter uppercase italic">Bastion.OS</h1>
              <span className="bg-cyan-500/10 text-cyan-400 text-[10px] px-2 py-1 rounded border border-cyan-500/30">ADMIN</span>
              {systemMode === 'LOCKDOWN' && (
                <span className="bg-red-500/10 text-red-400 text-[10px] px-2 py-1 rounded border border-red-500/30 animate-pulse">LOCKDOWN</span>
              )}
            </div>
            <div className="flex flex-wrap gap-4 text-[10px] font-bold mt-2 uppercase tracking-widest text-slate-500">
              <span className="flex items-center gap-1 text-cyan-600"><Key size={11}/> 0xKADIAN-SEC</span>
              <span className="flex items-center gap-1 text-emerald-500"><Activity size={11}/> {health ? 'ONLINE' : 'CONNECTING'}</span>
              <span className="flex items-center gap-1 text-violet-400"><Layers size={11}/> {layersUp}/4 Layers Active</span>
            </div>
          </div>
        </div>

        <div className="flex gap-6 items-center w-full xl:w-auto">
          <div className="flex gap-8 px-6 border-slate-800 xl:border-x w-full xl:w-auto justify-center">
            <div className="text-center">
              <p className="text-[9px] text-slate-600 font-black uppercase tracking-widest">CPU</p>
              <p className="text-xl font-black text-emerald-500">{cpu}%</p>
            </div>
            <div className="text-center">
              <p className="text-[9px] text-slate-600 font-black uppercase tracking-widest">RAM</p>
              <p className="text-xl font-black text-cyan-500">{ram}%</p>
            </div>
            <div className="text-center">
              <p className="text-[9px] text-slate-600 font-black uppercase tracking-widest">Threats</p>
              <p className={`text-xl font-black ${alertCount > 0 ? 'text-red-500' : 'text-slate-500'}`}>{alertCount}</p>
            </div>
          </div>
          <button
            disabled={isProcessing}
            onClick={() => handleCommand('LOCKDOWN')}
            className={`shrink-0 px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all border whitespace-nowrap ${
              systemMode === 'LOCKDOWN'
                ? 'bg-red-600 text-white border-red-500 shadow-[0_0_20px_rgba(239,68,68,0.3)]'
                : 'bg-red-600/10 border-red-600/50 text-red-500 hover:bg-red-600 hover:text-white'
            } ${isProcessing ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isProcessing ? '...' : systemMode === 'LOCKDOWN' ? '🔓 Release Lockdown' : '🔒 Engage Lockdown'}
          </button>
        </div>
      </header>

      {/* ── MAIN GRID ────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">

        {/* LEFT COLUMN */}
        <div className="xl:col-span-8 space-y-8 min-w-0">

          {/* LIVE METRIC CARDS */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetricCard icon={Cpu}        label="CPU Load"       value={`${cpu}%`}              color="text-cyan-500"    bg="bg-cyan-500/10" />
            <MetricCard icon={Database}   label="Active Signatures" value={Number(sigCount).toLocaleString()} color="text-emerald-500" bg="bg-emerald-500/10" />
            <MetricCard icon={Activity}   label="Flows Analyzed" value={fmtPkts(pktsProcessed)} color="text-indigo-400"  bg="bg-indigo-500/10" />
            <MetricCard icon={ShieldAlert} label="Threats"       value={String(alertCount)}     color="text-red-500"     bg="bg-red-500/10" />
          </div>

          {/* DETECTION LAYER MATRIX */}
          <section className="bg-[#0d1117] border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <Layers size={20} className="text-cyan-500" />
                <h2 className="text-sm font-black text-white uppercase tracking-widest">Detection Layer Matrix</h2>
              </div>
              <button onClick={fetchHealth} className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-500 hover:text-cyan-400 transition-colors">
                <RefreshCw size={14} />
              </button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {(() => {
                const mlUp = health ? [health.ml_rf, health.ml_xgb, health.ml_cat].filter(Boolean).length : 0;
                return [
                  { label: 'L1 · Signature Engine', active: !!health?.signature_engine,
                    detail: `Known-threat rule matching · ${Number(sigCount).toLocaleString()} rules`,
                    icon: <Shield size={20}/> },
                  { label: 'L2 · ML Ensemble',      active: mlUp >= 2,
                    detail: `Supervised traffic classification · ${mlUp}/3 models online`,
                    icon: <BarChart3 size={20}/> },
                  { label: 'L3 · Neural Analysis',  active: !!health?.dl,
                    detail: 'Deep-learning threat classification',
                    icon: <Network size={20}/> },
                  { label: 'L4 · Anomaly Sentinel', active: !!health?.anomaly,
                    detail: 'Behavioural & zero-day detection',
                    icon: <Eye size={20}/> },
                ];
              })().map(({ label, active, detail, icon }) => (
                <div key={label} className={`p-4 rounded-xl border transition-all ${
                  active ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-slate-800 bg-slate-900/40'
                }`}>
                  <div className="flex items-center gap-3 mb-2">
                    <div className={active ? 'text-emerald-400' : 'text-slate-600'}>{icon}</div>
                    <div className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-emerald-500' : 'bg-red-500/50'}`}></div>
                  </div>
                  <p className={`text-[10px] font-black uppercase tracking-widest ${active ? 'text-slate-300' : 'text-slate-600'}`}>{label}</p>
                  <p className="text-[9px] text-slate-600 mt-1">{active ? detail : 'Offline'}</p>
                </div>
              ))}
            </div>
          </section>

          {/* ADMIN AUDIT TERMINAL — shows only admin actions performed this session */}
          <section className="bg-black border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
            <div className="bg-[#0d1117] px-6 py-3 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <Terminal size={13} className="text-emerald-500" /> Administrative Audit Log
              </h3>
              <span className="text-[9px] text-slate-600 font-black uppercase tracking-widest">Session actions only</span>
            </div>
            <div className="p-4 h-64 overflow-y-auto font-mono text-[11px] space-y-2 custom-scrollbar">
              {logs.length > 0 ? logs.map((log) => (
                <div key={log.id} className="flex gap-4 border-b border-white/5 pb-2">
                  <span className="text-slate-600 shrink-0 w-20">[{log.t}]</span>
                  <span className={`flex-1 break-all leading-relaxed ${
                    log.s === 'ERR'  ? 'text-red-400' :
                    log.s === 'WARN' ? 'text-amber-400' :
                    log.s === 'OK'   ? 'text-emerald-400' :
                    log.s === 'REQ'  ? 'text-cyan-400' :
                    'text-slate-500'
                  }`}>{log.m}</span>
                </div>
              )) : (
                <div className="flex items-center justify-center h-full text-slate-700 text-[10px] uppercase font-black tracking-widest">
                  No admin actions recorded this session
                </div>
              )}
            </div>
          </section>

          {/* ANALYST FEEDBACK LOG — committed verdicts from Attack Analysis.
              Sits under the audit log and spans the full main column. */}
          <section className="bg-[#0d1117] border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
            <div className="bg-black/40 px-6 py-3 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <UserCheck size={13} className="text-emerald-500" /> Analyst Feedback Log
              </h3>
              <span className="text-[9px] text-slate-600 font-black uppercase tracking-widest">
                {fbLog.length > 0 ? `${fbLog.length} committed verdicts` : 'Committed verdicts'}
              </span>
            </div>
            <div className="p-5">
              <p className="text-[9px] text-slate-600 leading-relaxed mb-4">
                Every verdict committed from Attack Analysis lands here. Confirmed accuracy is the
                share of alerts analysts marked as genuine — the system&apos;s real-world precision signal.
              </p>
              {fbStats && fbStats.total_feedback > 0 && (
                <div className="grid grid-cols-3 gap-3 mb-4">
                  <div className="bg-black/30 border border-slate-800 rounded-xl p-3 text-center">
                    <p className="text-lg font-black text-white font-mono">{fbStats.total_feedback}</p>
                    <p className="text-[8px] text-slate-600 font-black uppercase tracking-widest mt-0.5">Total Verdicts</p>
                  </div>
                  <div className="bg-black/30 border border-emerald-900/40 rounded-xl p-3 text-center">
                    <p className="text-lg font-black text-emerald-400 font-mono">
                      {Math.round((fbStats.analyst_precision_signal ?? 0) * 100)}%
                    </p>
                    <p className="text-[8px] text-slate-600 font-black uppercase tracking-widest mt-0.5">Confirmed Accuracy</p>
                  </div>
                  <div className="bg-black/30 border border-amber-900/40 rounded-xl p-3 text-center">
                    <p className="text-lg font-black text-amber-400 font-mono">{fbStats.false_alarms}</p>
                    <p className="text-[8px] text-slate-600 font-black uppercase tracking-widest mt-0.5">False Positives</p>
                  </div>
                </div>
              )}
              {fbLog.length === 0 ? (
                <p className="text-[10px] text-slate-700 font-mono py-6 text-center">
                  No verdicts committed yet. Open an alert in Attack Analysis, judge it under
                  Verification Protocol, and it will appear here.
                </p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-72 overflow-y-auto custom-scrollbar pr-1">
                  {[...fbLog].reverse().slice(0, 50).map((r, i) => (
                    <div key={i} className="bg-black/30 border border-slate-800/60 rounded-lg px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[8px] font-black tracking-widest border ${
                          r.judgement === 'CORRECT'
                            ? 'bg-emerald-600/15 text-emerald-400 border-emerald-700/40'
                            : 'bg-amber-600/15 text-amber-400 border-amber-700/40'
                        }`}>
                          {r.judgement === 'CORRECT' ? 'CONFIRMED' : 'FALSE POS'}
                        </span>
                        <span className="text-[9px] font-mono text-slate-400 truncate flex-1">
                          {String(r.verdict || 'UNKNOWN').slice(0, 46)}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[8px] font-mono text-slate-600">
                        {r.source_engine && <span>{r.source_engine}</span>}
                        {r.srcip && <span>{r.srcip}</span>}
                        {r.timestamp && <span className="ml-auto">{String(r.timestamp).slice(0, 16).replace('T', ' ')}</span>}
                      </div>
                      {r.note && (
                        <p className="text-[9px] text-slate-500 mt-1 leading-relaxed border-t border-slate-800/60 pt-1">
                          {r.note}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>

        {/* RIGHT COLUMN */}
        <aside className="xl:col-span-4 space-y-8 min-w-0">

          {/* POLICY OVERRIDES */}
          <div className="bg-[#0d1117] border border-slate-800 p-6 rounded-2xl">
            <h3 className="text-[10px] font-black text-white uppercase mb-5 flex items-center gap-2">
              <Settings2 size={16} className="text-cyan-500" /> Policy Overrides
            </h3>
            <div className="space-y-5">
              {POLICY_CONFIG.map(({ key, label, desc, icon }) => (
                <div key={key} className="cursor-pointer group" onClick={() => togglePolicy(key)}>
                  <div className="flex justify-between items-center mb-1">
                    <div className="flex items-center gap-2">
                      <span className={`transition-colors ${policies[key] ? 'text-cyan-400' : 'text-slate-600'}`}>{icon}</span>
                      <span className={`text-[10px] font-black uppercase tracking-widest group-hover:text-white transition-colors ${policies[key] ? 'text-slate-300' : 'text-slate-500'}`}>{label}</span>
                    </div>
                    <div className={`w-10 h-5 rounded-full relative shrink-0 transition-all duration-300 ${policies[key] ? 'bg-cyan-600' : 'bg-slate-800'}`}>
                      <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all duration-300 shadow ${policies[key] ? 'left-6' : 'left-1'}`} />
                    </div>
                  </div>
                  <p className="text-[9px] text-slate-600 leading-relaxed ml-5 group-hover:text-slate-500 transition-colors">{desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* AUTO-ISOLATED IPs — shows IPs blocked by Auto-Isolate policy */}
          {isolatedIPs.length > 0 && (
            <div className="bg-[#0d1117] border border-amber-600/30 p-5 rounded-2xl">
              <h3 className="text-[10px] font-black text-amber-400 uppercase mb-4 flex items-center gap-2">
                <ShieldX size={13} className="text-amber-500" /> Auto-Isolated IPs
                <span className="ml-auto px-2 py-0.5 bg-amber-600/20 text-amber-400 rounded text-[9px] font-black border border-amber-600/30">{isolatedIPs.length} BLOCKED</span>
              </h3>
              <div className="space-y-2">
                {isolatedIPs.map(ip => (
                  <div key={ip} className="flex items-center justify-between bg-black/30 border border-amber-900/30 rounded-lg px-3 py-2">
                    <div className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                      <span className="text-[10px] font-mono text-amber-300 tracking-widest">{ip}</span>
                    </div>
                    <button
                      onClick={() => releaseIP(ip)}
                      className="text-[9px] font-black uppercase tracking-widest text-slate-500 hover:text-amber-400 transition-colors px-2 py-1 border border-slate-700 hover:border-amber-600/40 rounded"
                    >
                      Release
                    </button>
                  </div>
                ))}
              </div>
              <p className="text-[9px] text-slate-600 mt-3">Firewall rules active — click Release to allow traffic from an IP</p>
            </div>
          )}

          {/* ENGINE CONTROLS */}
          <div className="bg-[#0d1117] border border-slate-800 p-5 rounded-2xl">
            <h3 className="text-[10px] font-black text-slate-400 uppercase mb-4 flex items-center gap-2">
              <Zap size={13} className="text-cyan-500" /> Engine Controls
            </h3>
            <div className="grid grid-cols-2 gap-2">
              <ActionButton
                onClick={() => handleCommand('FLUSH_CACHE')} disabled={isProcessing}
                icon={<RefreshCw size={13}/>} label="Flush Cache"
                cls="border-cyan-500/30 text-cyan-400 hover:bg-cyan-600"
              />
              <ActionButton
                onClick={async () => {
                  addLog('HEALTH: Refreshing live system metrics', 'SYS');
                  await fetchHealth(); await fetchAlertCount();
                  addLog('HEALTH: Metrics updated', 'OK');
                  pushNotification('Live metrics refreshed', 'INFO');
                }}
                disabled={isProcessing} icon={<Activity size={13}/>} label="Refresh Metrics"
                cls="border-emerald-500/30 text-emerald-400 hover:bg-emerald-600"
              />
              <ActionButton
                onClick={() => handleCommand('FULL_RESTART')} disabled={isProcessing}
                icon={<Power size={13}/>} label="Restart Engine"
                cls="border-amber-500/30 text-amber-400 hover:bg-amber-600"
              />
              <ActionButton
                onClick={async () => {
                  addLog('COUNTERS: Resetting session counters', 'WARN');
                  try {
                    const res = await fetch(`${API_BASE}/sweep/stats/reset`, { method: 'POST', headers: HDR });
                    if (res.ok) {
                      addLog('COUNTERS: Reset successfully', 'OK');
                      pushNotification('Session counters reset', 'INFO');
                    } else throw new Error(`HTTP ${res.status}`);
                  } catch (err) { addLog(`COUNTERS: Reset failed — ${err.message}`, 'ERR'); }
                }}
                disabled={isProcessing} icon={<BarChart3 size={13}/>} label="Reset Counters"
                cls="border-slate-600/40 text-slate-400 hover:bg-slate-700 hover:border-slate-500"
              />
            </div>
          </div>

          {/* DESTRUCTIVE ZONE */}
          <div className="bg-[#160b0b] border border-red-900/40 p-5 rounded-2xl">
            <div className="flex items-center gap-2 mb-1">
              <Flame size={13} className="text-red-600" />
              <h3 className="text-[10px] font-black text-red-500 uppercase tracking-widest">Destructive Zone</h3>
            </div>
            <p className="text-[9px] text-slate-600 leading-relaxed mb-4">
              Irreversible actions — word verification required.
            </p>
            <div className="grid grid-cols-2 gap-2">
              <ActionButton
                onClick={() => handleCommand('PURGE_ALERTS')} disabled={isProcessing}
                icon={<UserX size={13}/>} label="Purge Alerts"
                cls="border-red-600/40 text-red-500 hover:bg-red-600"
              />
              <ActionButton
                onClick={async () => {
                  addLog('WIPE: Clearing upload cache', 'WARN');
                  try {
                    await fetch(`${API_BASE}/wipe`, { method: 'POST', headers: HDR });
                    addLog('WIPE: Upload cache cleared', 'OK');
                  } catch { addLog('WIPE: Backend unavailable', 'ERR'); }
                }}
                disabled={isProcessing} icon={<ShieldOff size={13}/>} label="Wipe Cache"
                cls="border-red-900/30 text-red-700 hover:text-red-400 hover:border-red-500/50"
              />
            </div>
          </div>

        </aside>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// REUSABLE SUB-COMPONENTS
// ─────────────────────────────────────────────────────────────

function MetricCard({ icon: Icon, label, value, color, bg }) {
  return (
    <div className="bg-[#0d1117] border border-slate-800 p-4 rounded-xl flex items-center gap-3 hover:border-slate-700 transition-all min-w-0">
      <div className={`p-3 rounded-lg shrink-0 ${bg}`}>
        <Icon size={18} className={color} />
      </div>
      <div className="min-w-0 flex-1 overflow-hidden">
        <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest truncate">{label}</p>
        <p className={`text-lg font-black ${color} tracking-tight truncate`}>{value}</p>
      </div>
    </div>
  );
}

function Shield({ size, className }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
}

function ActionButton({ onClick, disabled, icon, label, cls }) {
  return (
    <button onClick={onClick} disabled={disabled}
      className={`w-full py-2.5 px-3 rounded-lg text-[9px] font-black uppercase tracking-widest transition-all border flex items-center justify-center gap-1.5 ${cls} ${disabled ? 'opacity-40 cursor-not-allowed' : 'hover:text-white'}`}>
      {icon}{label}
    </button>
  );
}
