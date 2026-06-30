import React, { useState, useEffect, useRef } from 'react';
import {
  Upload, BarChart3, Globe, Heart, Settings,
  LayoutDashboard, ShieldCheck, Radio, X, ChevronRight
} from 'lucide-react';

// ── BASTION™ Trademark Logo ───────────────────────────────────────────────────
// THE BASTION MARK — an all-seeing sentinel eye inside a precision targeting ring.
//
// Three interlocked elements:
//   1. Outer precision ring + four cardinal crosshair arms (perimeter surveillance)
//   2. Bold angular iris — a hexagonal aperture suggesting an optical sensor lens
//   3. Solid inner pupil dot — the detected threat, locked on target
//
// The mark reads instantly as: "nothing escapes this system."
// It draws on the visual language of military optics, satellite sensors, and
// enterprise-grade threat intelligence platforms — not generic shield clip-art.
function BastionLogo({ size = 24, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32"
      fill="none" xmlns="http://www.w3.org/2000/svg"
      className={className} aria-label="Bastion IDS"
    >
      {/* ── Outer surveillance ring ── */}
      <circle cx="16" cy="16" r="13" stroke="currentColor" strokeWidth="1.6" />

      {/* ── Four precision crosshair arms with inner gap (reticle) ── */}
      {/* Top arm */}
      <line x1="16" y1="3"  x2="16" y2="9.5"  stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/>
      {/* Bottom arm */}
      <line x1="16" y1="22.5" x2="16" y2="29" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/>
      {/* Left arm */}
      <line x1="3"  y1="16" x2="9.5"  y2="16" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/>
      {/* Right arm */}
      <line x1="22.5" y1="16" x2="29" y2="16" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/>

      {/* ── Hexagonal iris — angular sensor aperture ── */}
      {/* A regular hexagon centred at 16,16 with radius 6.4, flat-top orientation */}
      <polygon
        points="16,9.6 21.5,12.8 21.5,19.2 16,22.4 10.5,19.2 10.5,12.8"
        stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"
        fill="currentColor" fillOpacity="0.08"
      />

      {/* ── Inner diagonal tick-marks at 45° — depth / layering cues ── */}
      <line x1="19.5" y1="10.5" x2="21" y2="9"   stroke="currentColor" strokeWidth="1"   strokeLinecap="round" opacity="0.55"/>
      <line x1="12.5" y1="10.5" x2="11" y2="9"   stroke="currentColor" strokeWidth="1"   strokeLinecap="round" opacity="0.55"/>
      <line x1="19.5" y1="21.5" x2="21" y2="23"  stroke="currentColor" strokeWidth="1"   strokeLinecap="round" opacity="0.55"/>
      <line x1="12.5" y1="21.5" x2="11" y2="23"  stroke="currentColor" strokeWidth="1"   strokeLinecap="round" opacity="0.55"/>

      {/* ── Pupil — locked threat, dead-centre ── */}
      <circle cx="16" cy="16" r="2.4" fill="currentColor"/>
    </svg>
  );
}

import MissionControl   from './components/MissionControl';
import DataPortal       from './components/DataPortal';
import SystemHealth     from './components/SystemHealth';
import AttackAnalysis   from './components/AttackAnalysis';
import SystemSettings   from './components/settings/SystemSettings';
import AdminManagement  from './components/admin/AdminManagement';
import NetworkTopology  from './components/NetworkTopology';
import LiveMonitor      from './components/LiveMonitor';

// ── Navigation definition ────────────────────────────────────────────────────
// `id` matches render key; `keepAlive` = true means the component is never
// unmounted after first visit (CSS display:none when inactive).
const NAV = [
  {
    id:       'dashboard',
    name:     'Operations Center',
    icon:     <LayoutDashboard size={18}/>,
    sub:      'Global Overview',
    keepAlive: true,
  },
  {
    id:       'live',
    name:     'Live Packet Capture',
    icon:     <Radio size={18}/>,
    sub:      'Network Traffic Monitor',
    keepAlive: true,
    badge:    'LIVE',
  },
  {
    id:       'ingest',
    name:     'Data Ingest Portal',
    icon:     <Upload size={18}/>,
    sub:      'Batch Analysis Engine',
    keepAlive: true,
  },
  {
    id:       'analysis',
    name:     'Threat Intelligence',
    icon:     <BarChart3 size={18}/>,
    sub:      'Attack Analysis & Reports',
    keepAlive: true,
  },
  {
    id:       'topology',
    name:     'Network Topology',
    icon:     <Globe size={18}/>,
    sub:      'Infrastructure Discovery',
    keepAlive: false,
  },
  {
    id:       'health',
    name:     'System Health',
    icon:     <Heart size={18}/>,
    sub:      'Engine Vitality Metrics',
    keepAlive: true,
  },
  {
    id:       'admin',
    name:     'Command & Control',
    icon:     <ShieldCheck size={18}/>,
    sub:      'Administrative Operations',
    keepAlive: true,
  },
];

const API_URL  = 'http://127.0.0.1:48217/api/v1';
const AUTH_KEY = 'BASTION-KADIAN-SEC-0x42';
const ADMIN_VERDICTS = new Set(['NORMAL', 'LOCKDOWN', 'BASTION_CLEAN', '', 'OPERATOR']);

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [activeTab,      setActiveTab]      = useState('dashboard');
  const [visitedTabs,    setVisitedTabs]    = useState(new Set(['dashboard']));
  const [analysisData,   setAnalysisData]   = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  // Badge logic: badge = total real threats minus how many the admin has already seen.
  // seenThreats is updated to totalThreats when the user opens Threat Intelligence.
  // This way old threats never re-appear after the tab is visited — only genuinely
  // NEW alerts (count increase) will cause the badge to reappear.
  const [totalThreats,   setTotalThreats]   = useState(0);
  const [seenThreats,    setSeenThreats]    = useState(0);
  const threatBadge = Math.max(0, totalThreats - seenThreats);
  const [sysStatus,      setSysStatus]      = useState({
    online:  false,
    mode:    'OFFLINE',
    cpu:     0,
    ram:     0,
    uptime:  '00:00:00',
    storage: '0%',
    net_rx:  0,
    net_tx:  0,
  });
  // Full raw health response — passed as prop to SystemHealth and AdminManagement
  // so those components never show a null/red flash (they receive live data
  // immediately on first mount instead of waiting for their own fetch to complete).
  const [liveHealth, setLiveHealth] = useState(null);
  // Lockdown state — derived from health poll, shows system-wide red banner
  const [lockdownActive, setLockdownActive] = useState(false);

  // Track which tabs have been visited so we can lazy-mount them
  const handleNav = (id) => {
    setActiveTab(id);
    setVisitedTabs(prev => new Set([...prev, id]));
  };

  const handleAnalysisComplete = (data) => {
    setAnalysisData(data);
    handleNav('analysis');
  };

  // ── Threat badge polling ──────────────────────────────────────────────────────
  // Updates totalThreats from the server every 12 s.
  // threatBadge (derived above) = max(0, totalThreats - seenThreats).
  // seenThreats advances to match totalThreats when the admin visits
  // Threat Intelligence, so already-seen threats never re-appear on the badge.
  useEffect(() => {
    // Use /alerts/count (O(1) counter) — never loads the full alerts.json.
    // Loading all 50k alerts every 12 s was blocking the event loop and causing
    // the health endpoint to timeout → "CONNECTING / 0/4 Layers Active" in the UI.
    const poll = async () => {
      try {
        const res = await fetch(`${API_URL}/alerts/count`, { headers: { 'x-authority': AUTH_KEY } });
        if (!res.ok) return;
        const data = await res.json();
        setTotalThreats(data.total ?? 0);
      } catch {}
    };
    poll();
    const t = setInterval(poll, 12000);
    return () => clearInterval(t);
  }, []);

  // When the admin opens Threat Intelligence, mark all current threats as "seen"
  useEffect(() => {
    if (activeTab === 'analysis') {
      setSeenThreats(totalThreats);
    }
  }, [activeTab, totalThreats]);

  // ── Health polling ─────────────────────────────────────────────────────────
  // AbortController gives each poll a hard 4 s deadline.  A slow response can
  // never block a subsequent poll — if the backend is genuinely busy the abort
  // fires, the catch sets online=false momentarily, and the next poll succeeds.
  useEffect(() => {
    let activeController = null;
    const poll = async () => {
      if (activeController) activeController.abort();
      activeController = new AbortController();
      const signal = activeController.signal;
      const timer  = setTimeout(() => activeController.abort(), 4000);
      try {
        const res  = await fetch(`${API_URL}/health`,
          { headers: { 'x-authority': AUTH_KEY }, signal });
        clearTimeout(timer);
        if (!res.ok) throw new Error();
        const data = await res.json();
        setSysStatus({
          online:  true,
          mode:    data.mode          || 'ACTIVE',
          layers:  data.layers_active ?? 0,
          cpu:     Number(data.cpu_percent  ?? data.cpu_usage    ?? 0),
          ram:     Number(data.ram_percent  ?? data.ram_usage    ?? 0),
          uptime:  data.uptime        || '00:00:00',
          storage: data.storage_usage || '—',
          net_rx:  data.net_rx        || 0,
          net_tx:  data.net_tx        || 0,
        });
        // Push full payload to children so they have engine state immediately
        setLiveHealth(data);
        setLockdownActive(data.lockdown_active ?? false);
      } catch (e) {
        clearTimeout(timer);
        if (e.name !== 'AbortError') {
          setSysStatus(prev => ({ ...prev, online: false, mode: 'OFFLINE' }));
        }
      }
    };
    poll();
    const t = setInterval(poll, 4000);
    return () => { clearInterval(t); if (activeController) activeController.abort(); };
  }, []);

  const activeNav = NAV.find(n => n.id === activeTab);

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-screen bg-slate-950 text-slate-300 font-mono overflow-hidden">

      {/* ══ SIDEBAR ══════════════════════════════════════════════════════════ */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col z-20 shadow-2xl shrink-0">

        {/* Logo */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-1.5 bg-cyan-500/10 border border-cyan-800/50 rounded relative">
              <BastionLogo size={22} className="text-cyan-400" />
              {/* Animate the scan pulse when online */}
              {sysStatus.online && (
                <span className="absolute inset-0 rounded animate-ping opacity-20 bg-cyan-400 pointer-events-none" />
              )}
            </div>
            <div>
              <div className="flex items-baseline gap-1.5">
                <h1 className="font-black text-lg tracking-tighter text-white uppercase italic leading-none">BASTION</h1>
                <span className="text-[7px] text-cyan-600 font-black tracking-widest uppercase leading-none align-top">™</span>
              </div>
              <p className="text-[8px] text-slate-600 uppercase tracking-widest font-bold">Intrusion Detection System</p>
            </div>
          </div>
          <div className={`w-2 h-2 rounded-full shrink-0 ${sysStatus.online ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`} />
        </div>

        {/* Engine status strip */}
        <div className={`px-4 py-2 text-[9px] font-black uppercase tracking-widest flex items-center gap-2
          ${sysStatus.online
            ? 'text-emerald-500 bg-emerald-950/20 border-b border-emerald-900/20'
            : 'text-red-500 bg-red-950/20 border-b border-red-900/20'}`}>
          <span className={`w-1.5 h-1.5 rounded-full inline-block shrink-0
            ${sysStatus.online ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`} />
          {sysStatus.online ? `Engine ${sysStatus.mode}` : 'Backend Offline'}
          {sysStatus.online && (
            <span className="ml-auto text-slate-600 font-mono normal-case">
              CPU {sysStatus.cpu.toFixed(0)}%
            </span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto custom-scrollbar">
          {NAV.map(item => (
            <button
              key={item.id}
              onClick={() => handleNav(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all relative
                ${activeTab === item.id
                  ? 'bg-cyan-900/25 text-cyan-300 border border-cyan-800/40 shadow-[0_0_12px_rgba(6,182,212,0.06)]'
                  : 'text-slate-500 hover:bg-slate-800/70 hover:text-slate-300 border border-transparent'}`}
            >
              <span className={`shrink-0 transition-colors ${activeTab === item.id ? 'text-cyan-400' : ''}`}>
                {item.icon}
              </span>
              <div className="text-left min-w-0">
                <span className="text-[11px] font-black uppercase tracking-wide block leading-tight truncate">
                  {item.name}
                </span>
                <span className="text-[8px] text-slate-600 tracking-widest uppercase">{item.sub}</span>
              </div>

              {/* LIVE badge on Live Capture */}
              {item.badge && (
                <span className="ml-auto text-[8px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded
                  bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse shrink-0">
                  {item.badge}
                </span>
              )}

              {/* Threat count badge on Threat Intelligence */}
              {item.id === 'analysis' && threatBadge > 0 && activeTab !== 'analysis' && (
                <span className="ml-auto text-[9px] font-black rounded-full bg-red-500 text-white
                  min-w-[18px] h-[18px] flex items-center justify-center px-1 shrink-0
                  shadow-md shadow-red-500/30">
                  {threatBadge > 99 ? '99+' : threatBadge}
                </span>
              )}

              {/* Active chevron */}
              {activeTab === item.id && (
                <ChevronRight size={12} className="ml-auto text-cyan-600 shrink-0" />
              )}
            </button>
          ))}
        </nav>

        {/* Sidebar footer */}
        <div className="p-4 border-t border-slate-800 text-[9px] text-slate-700 font-mono space-y-0.5">
          <p className="font-black text-slate-600 uppercase tracking-widest">Bastion IDS v2.0</p>
          <p>Advanced Threat Detection & Analysis</p>
          <p>Hybrid Multi-Layer Neural Architecture</p>
          <p className="pt-1 text-slate-700">&copy; 2026 Kadian Inc &middot; by KING KAD</p>
        </div>
      </aside>

      {/* ══ MAIN CONTENT ═════════════════════════════════════════════════════ */}
      <main className="flex-1 flex flex-col min-w-0 relative">

        {/* Topbar */}
        <header className="h-14 border-b border-slate-800 flex items-center justify-between px-6 bg-slate-900 shrink-0">
          <div className="flex items-center gap-3">
            <span className="text-slate-700">/</span>
            <h2 className="text-sm font-black uppercase tracking-wider text-white">{activeNav?.name}</h2>
            <span className="text-[9px] text-slate-700 font-bold uppercase tracking-widest hidden md:inline">
              — {activeNav?.sub}
            </span>
          </div>

          <div className="flex items-center gap-4">
            {/* Live status pill */}
            <div className={`hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full border text-[9px] font-black uppercase tracking-widest
              ${sysStatus.online
                ? 'bg-emerald-950/30 border-emerald-900/40 text-emerald-400'
                : 'bg-red-950/30 border-red-900/40 text-red-500'}`}>
              <span className={`w-1.5 h-1.5 rounded-full inline-block ${sysStatus.online ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`} />
              {sysStatus.online ? 'All Systems Nominal' : 'Backend Unreachable'}
            </div>

            <div className="h-5 w-px bg-slate-800 hidden md:block" />

            {/* Settings gear */}
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white
                transition-colors border border-slate-700/50"
              title="System Configuration"
            >
              <Settings size={16} />
            </button>
          </div>
        </header>

        {/* ══ LOCKDOWN BANNER — visible on all pages when active ══════════════ */}
        {lockdownActive && (
          <div className="bg-red-950 border-b border-red-600/60 px-6 py-2.5 flex items-center gap-3 shrink-0
            animate-pulse shadow-[0_0_20px_rgba(239,68,68,0.25)]">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-none shrink-0" />
            <span className="text-red-400 text-[11px] font-black uppercase tracking-widest flex-1">
              ⚠ SYSTEM LOCKDOWN ACTIVE — All packet capture and threat analysis suspended.
              Go to Command &amp; Control to release.
            </span>
          </div>
        )}

        {/* Page content — lazy-mount keeps state alive across tab switches */}
        <section className="flex-1 overflow-y-auto p-4 lg:p-6 bg-slate-950 custom-scrollbar">

          {/* Always-rendered tabs (keepAlive=true) — hidden via CSS when inactive */}
          <div style={{ display: activeTab === 'dashboard' ? 'block' : 'none' }}>
            {visitedTabs.has('dashboard') && <MissionControl status={sysStatus} />}
          </div>

          <div style={{ display: activeTab === 'live' ? 'block' : 'none' }}>
            {visitedTabs.has('live') && <LiveMonitor />}
          </div>

          <div style={{ display: activeTab === 'ingest' ? 'block' : 'none' }}>
            {visitedTabs.has('ingest') && (
              <DataPortal
                status={sysStatus}
                onUploadSuccess={handleAnalysisComplete}
                lockdownActive={lockdownActive}
              />
            )}
          </div>

          <div style={{ display: activeTab === 'analysis' ? 'block' : 'none' }}>
            {visitedTabs.has('analysis') && (
              <AttackAnalysis status={sysStatus} data={analysisData} />
            )}
          </div>

          {/* keepAlive — never unmount so engine status never resets to red */}
          <div style={{ display: activeTab === 'health' ? 'block' : 'none' }}>
            {visitedTabs.has('health') && (
              <SystemHealth status={sysStatus} liveHealth={liveHealth} />
            )}
          </div>

          <div style={{ display: activeTab === 'admin' ? 'block' : 'none' }}>
            {visitedTabs.has('admin') && (
              <AdminManagement status={sysStatus} liveHealth={liveHealth} lockdownActive={lockdownActive} />
            )}
          </div>

          {/* Non-keepAlive tab (lightweight, no engine-status dependency) */}
          {activeTab === 'topology' && <NetworkTopology status={sysStatus} />}

        </section>
      </main>

      {/* ══ SETTINGS OVERLAY ═════════════════════════════════════════════════ */}
      {isSettingsOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-950 border border-slate-800 w-full max-w-6xl h-[90vh] rounded-xl shadow-2xl
            flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-4 relative">
            <button
              onClick={() => setIsSettingsOpen(false)}
              className="absolute top-4 right-4 z-50 p-2 bg-slate-900 border border-slate-800
                text-slate-400 hover:text-white rounded-lg transition-colors"
            >
              <X size={18} />
            </button>
            <div className="flex-1 overflow-y-auto custom-scrollbar">
              <SystemSettings />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
