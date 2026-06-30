import React, { useState, useRef, useEffect } from 'react';
import {
  UploadCloud, Play, RefreshCw, Activity,
  ShieldAlert, Database, Server, CheckCircle2,
  Terminal, ShieldCheck, AlertCircle,
  FileText, Download, Zap, Eye,
  ChevronLeft, ChevronRight, Clock, Info
} from 'lucide-react';

/* ============================================================
   BASTION IDS — TELEMETRY INGESTION PORTAL
   Handles file upload (CSV / PCAP / LOG) → full-dataset sweep
   → live threat results. No row cap. ETA tracking included.
   ============================================================ */

const API_BASE = "http://127.0.0.1:48217/api/v1";
const HDR      = { 'x-authority': 'BASTION-KADIAN-SEC-0x42' };

// Administrative / operator entries that should not appear as threats
const ADMIN_VERDICTS = new Set(["LOCKDOWN", "NORMAL", "BASTION_CLEAN", ""]);

function fmtEta(seconds) {
  if (!seconds || seconds <= 0) return null;
  if (seconds < 60)  return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds/60)}m ${Math.round(seconds%60)}s`;
  return `${Math.floor(seconds/3600)}h ${Math.floor((seconds%3600)/60)}m`;
}

export default function DataPortal({ lockdownActive }) {
  const [fileData,         setFileData]         = useState(null);
  const [detectedAttacks,  setDetectedAttacks]  = useState([]);
  const [loading,          setLoading]          = useState(false);
  const [sweepLoading,     setSweepLoading]     = useState(false);
  const [sweepProgress,    setSweepProgress]    = useState(null);
  const [sysStats,         setSysStats]         = useState({ cpu: 0, ram: 0, uptime: '—', status: 'OFFLINE' });
  const [dragOver,         setDragOver]         = useState(false);
  const [sweepError,       setSweepError]       = useState(null);
  const [previewPage,      setPreviewPage]      = useState(0);   // pagination
  const [reportStatus,     setReportStatus]     = useState(null);// {type:'ok'|'err', msg}
  const [reportFiles,      setReportFiles]      = useState(null);// {html,pdf,json} filenames
  const PREVIEW_PER_PAGE  = 25;

  const fileInputRef  = useRef(null);
  const sweepPollRef  = useRef(null);
  const timeoutRef    = useRef(null);

  // ── Health heartbeat ─────────────────────────────────────
  useEffect(() => {
    const sync = async () => {
      try {
        const d = await fetch(`${API_BASE}/health`, { headers: HDR }).then(r => r.json());
        setSysStats({
          cpu:    Number(d.cpu_percent ?? d.cpu_usage ?? 0).toFixed(1),
          ram:    Number(d.ram_percent ?? d.ram_usage ?? 0).toFixed(1),
          uptime: d.uptime ?? '—',
          status: 'ONLINE',
        });
      } catch { setSysStats(p => ({ ...p, status: 'OFFLINE' })); }
    };
    sync();
    const t = setInterval(sync, 8000);
    return () => clearInterval(t);
  }, []);

  // ── File processing ──────────────────────────────────────
  const processFile = async (file) => {
    if (!file) return;
    if (lockdownActive) {
      setSweepError('SYSTEM LOCKDOWN ACTIVE — release lockdown in Command & Control before uploading.');
      return;
    }
    setLoading(true); setFileData(null); setDetectedAttacks([]);
    setSweepProgress(null); setSweepError(null); setPreviewPage(0);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch(`${API_BASE}/ingest`, { method: 'POST', headers: HDR, body: fd });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setFileData(data);
    } catch (e) { setSweepError(`Upload failed: ${e.message}`); }
    finally { setLoading(false); }
  };

  const handleDrop       = e => { e.preventDefault(); setDragOver(false); processFile(e.dataTransfer.files[0]); };
  const handleDragOver   = e => { e.preventDefault(); setDragOver(true); };
  const handleDragLeave  = () => setDragOver(false);
  const handleFileInput  = e => processFile(e.target.files[0]);

  // ── Sweep execution + progress polling ──────────────────
  const executeSweep = async () => {
    if (!fileData?.filename || sweepLoading) return;
    setSweepLoading(true); setSweepError(null);
    setSweepProgress({ status: 'QUEUED', processed: 0, total: 0, hits: 0 });
    setDetectedAttacks([]);

    try {
      const kick = await fetch(`${API_BASE}/sweep/${encodeURIComponent(fileData.filename)}`,
        { method: 'POST', headers: HDR });
      if (!kick.ok) throw new Error(`HTTP ${kick.status}`);

      // Poll every 1.5 s
      if (sweepPollRef.current) clearInterval(sweepPollRef.current);
      sweepPollRef.current = setInterval(async () => {
        try {
          const prog = await fetch(
            `${API_BASE}/sweep/progress/${encodeURIComponent(fileData.filename)}`,
            { headers: HDR }
          ).then(r => r.json());
          setSweepProgress(prog);

          if (prog.status === 'COMPLETE' || String(prog.status).startsWith('ERROR')) {
            clearInterval(sweepPollRef.current);
            clearTimeout(timeoutRef.current);
            sweepPollRef.current = null;

            if (String(prog.status).startsWith('ERROR')) {
              setSweepError(`Analysis error: ${prog.status.replace('ERROR: ', '')}`);
            } else {
              // Load session-specific results — use ?session= to avoid reading
              // all 50 000 alerts; the backend filters on disk before returning.
              const session = fileData.filename;
              const sessionAlerts = await fetch(
                `${API_BASE}/alerts?session=${encodeURIComponent(session)}&limit=5000`,
                { headers: HDR }
              ).then(r => r.json());
              const filtered = sessionAlerts.filter(a =>
                a.verdict && !ADMIN_VERDICTS.has(a.verdict.toUpperCase())
              );
              setDetectedAttacks(filtered.length > 0 ? filtered : sessionAlerts.slice(-prog.hits));
            }
            setSweepLoading(false);
          }
        } catch {}
      }, 1500);

      // Extended timeout — 3 hours for very large datasets
      timeoutRef.current = setTimeout(() => {
        if (sweepPollRef.current) {
          clearInterval(sweepPollRef.current);
          sweepPollRef.current = null;
          setSweepLoading(false);
          setSweepError("Analysis timed out after 3 hours. The dataset may be too large for a single session — consider splitting it.");
        }
      }, 3 * 60 * 60 * 1000);

    } catch (err) {
      setSweepError(err.message);
      setSweepLoading(false);
    }
  };

  // ── Report generation ────────────────────────────────────
  const generateReport = async () => {
    setReportStatus({ type: 'loading', msg: 'Generating forensic report...' });
    setReportFiles(null);
    try {
      const res = await fetch(`${API_BASE}/reports/generate`, {
        method: 'POST',
        headers: { ...HDR, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          formats: ['html', 'pdf', 'json'],
          session_id: fileData?.filename ?? 'all',
          session_meta: {
            report_type:  'batch_analysis',
            source:       fileData?.filename ?? 'unknown',
            total_alerts: detectedAttacks.length,
          },
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      // data.paths = { html: "bastion_report_XXX.html", pdf: "...", json: "..." }
      setReportFiles(data.paths || {});
      setReportStatus({ type: 'ok', msg: `Forensic report ready — ID: ${data.report_id}` });
    } catch (e) {
      setReportStatus({ type: 'err', msg: `Report generation failed: ${e.message}` });
    }
  };

  // ── Report download ────────────────────────────────────────────────────────
  // ── Report download — IPC primary, blob fallback ────────────────────────────
  // ROOT FIX: <a download> on a cross-origin URL is silently ignored by Electron.
  // The renderer loads from localhost:5173 while the API is on 127.0.0.1:48217 —
  // different origins — so the <a> click triggers navigation, not a file save.
  //
  // Layer 1 (Electron): ipcRenderer.invoke('download-report') → main.js calls
  //   webContents.downloadURL() which is cross-origin-safe and triggers
  //   will-download → auto-saves to ~/Downloads and opens Explorer.
  // Layer 2 (fallback): fetch the file content → create blob: URL (same-origin)
  //   → click that URL.  Works in plain browser dev mode too.
  const downloadReport = (filename) => {
    setReportStatus(prev => ({ ...prev, msg: `Downloading ${filename}…` }));

    const _blob = async () => {
      const url = `http://127.0.0.1:48217/api/v1/reports/download/${encodeURIComponent(filename)}`;
      const r = await fetch(url);
      if (!r.ok) throw new Error(`Server returned HTTP ${r.status}`);
      const blob = await r.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl; a.download = filename; a.style.display = 'none';
      document.body.appendChild(a); a.click();
      setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(blobUrl); }, 1500);
    };

    // Primary: Electron IPC → webContents.downloadURL
    try {
      const { ipcRenderer } = window.require('electron');
      ipcRenderer.invoke('download-report', filename)
        .then(() => setReportStatus({ type: 'ok', msg: `${filename} saved to Downloads folder` }))
        .catch(() => _blob()
          .then(() => setReportStatus({ type: 'ok', msg: `${filename} downloading…` }))
          .catch(e => setReportStatus({ type: 'err', msg: `Download failed: ${e.message}` })));
      return;
    } catch (_) { /* window.require unavailable — browser dev mode */ }

    // Fallback: fetch + blob URL
    _blob()
      .then(() => setReportStatus({ type: 'ok', msg: `${filename} downloading…` }))
      .catch(e => setReportStatus({ type: 'err', msg: `Download failed: ${e.message}` }));
  };

  // ── Progress helpers ──────────────────────────────────────
  // ROOT FIX: during CSV loading the backend sets processed=rows_loaded AND
  // total=rows_loaded which makes processed/total = 1.0 = 100% → 99% instantly.
  // Only use the processed/total ratio when we're actually in the final collation
  // loop (stage starts with "collating"). All other stages use the backend's own
  // pct field (0 → 80%) which accurately reflects ML/DL inference progress.
  const isDone = sweepProgress?.status === 'COMPLETE';
  const stage  = sweepProgress?.stage ?? '';
  const isCollatingLoop = stage.startsWith('collating') &&
                          sweepProgress?.total > 0 &&
                          sweepProgress?.processed > 0;
  const pct = isDone ? 100
    : isCollatingLoop
      ? Math.min(99, Math.round((sweepProgress.processed / sweepProgress.total) * 100))
      : (sweepProgress?.pct ?? 0);

  // ── Stage → human-readable label ─────────────────────────
  const stageLabel = (() => {
    if (isDone) return 'Complete';
    const s = stage.toLowerCase();
    if (s.includes('loading'))               return 'Ingesting dataset…';
    if (s.includes('feature') || s.includes('bridge')) return 'Feature engineering…';
    if (s.includes('preprocess'))            return 'Preprocessing features…';
    if (s.includes('ml_inference:rf'))       return 'Random Forest inference…';
    if (s.includes('ml_inference:xgb'))      return 'XGBoost inference…';
    if (s.includes('ml_inference:cat'))      return 'CatBoost inference…';
    if (s.includes('ml_collation'))          return 'ML ensemble voting…';
    if (s.includes('dl_inference'))          return 'Deep Learning inference…';
    if (s.includes('anomaly'))               return 'Isolation Forest anomaly detection…';
    if (s.includes('collating'))             return 'Collating & writing alerts…';
    if (s.includes('queued') || sweepProgress?.status === 'QUEUED') return 'Queued — initializing…';
    return stage.replace(/_/g, ' ') || 'Processing…';
  })();

  // During ML inference phases, processed still holds the row count from loading
  // (backend only resets it at collation start). Show row progress only when meaningful.
  const showRowProgress = isCollatingLoop || isDone;

  // ── Preview pagination ────────────────────────────────────
  const totalPreviewPages = fileData ? Math.ceil(fileData.preview.length / PREVIEW_PER_PAGE) : 0;
  const previewRows       = fileData
    ? fileData.preview.slice(previewPage * PREVIEW_PER_PAGE, (previewPage + 1) * PREVIEW_PER_PAGE)
    : [];

  return (
    <div className="space-y-6 font-mono text-slate-300 pb-8 animate-in fade-in slide-in-from-bottom-4">

      {/* ── LOCKDOWN BLOCK ────────────────────────────────── */}
      {lockdownActive && (
        <div className="flex items-center gap-4 p-5 bg-red-950/60 border-2 border-red-500/50 rounded-xl shadow-lg shadow-red-900/20">
          <div className="p-3 bg-red-500/20 rounded-xl shrink-0">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-red-500"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <div>
            <p className="text-red-400 font-black text-sm uppercase tracking-widest">System Lockdown Active</p>
            <p className="text-red-300/70 text-[11px] mt-1">File upload and analysis are suspended. Go to Command &amp; Control → Release Lockdown to resume.</p>
          </div>
        </div>
      )}

      {/* ── HEADER ─────────────────────────────────────────── */}
      <header className="flex justify-between items-end border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Database className="text-cyan-500" size={24} />
            <h1 className="text-2xl font-black text-white uppercase tracking-tight">Telemetry Ingestion Portal</h1>
          </div>
          <p className="text-slate-500 text-xs font-semibold">
            UNSW · CICIDS · PCAP · Generic CSV — Universal Feature Bridge Active · No Dataset Cap
          </p>
        </div>
        <div className="flex gap-8">
          <div className="text-right">
            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Engine CPU</p>
            <div className="flex items-center gap-2">
              <Activity size={14} className="text-emerald-500" />
              <p className="text-lg font-black text-white">{sysStats.cpu}%</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">System RAM</p>
            <div className="flex items-center gap-2">
              <Server size={14} className="text-cyan-500" />
              <p className="text-lg font-black text-white">{sysStats.ram}%</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Detection Engine</p>
            <span className={`text-xs font-black px-2 py-1 rounded border ${
              sysStats.status === 'ONLINE'
                ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
                : 'text-red-400 border-red-500/30 bg-red-500/10'
            }`}>
              {sysStats.status}
            </span>
          </div>
        </div>
      </header>

      <div className="space-y-6">

        {/* ── ERROR / REPORT STATUS BANNERS ──────────────── */}
        {sweepError && (
          <div className="flex items-center gap-4 bg-red-950/50 border border-red-500/40 rounded-xl p-4">
            <AlertCircle size={18} className="text-red-500 shrink-0" />
            <p className="text-red-300 text-sm flex-1">{sweepError}</p>
            <button onClick={() => setSweepError(null)} className="text-red-500/50 hover:text-red-500 text-xs">✕</button>
          </div>
        )}

        {reportStatus && (
          <div className={`border rounded-xl p-4 ${
            reportStatus.type === 'ok'
              ? 'bg-emerald-950/40 border-emerald-600/40'
              : reportStatus.type === 'loading'
              ? 'bg-cyan-950/40 border-cyan-600/40'
              : 'bg-red-950/40 border-red-600/40'
          }`}>
            <div className="flex items-center gap-4">
              {reportStatus.type === 'ok'
                ? <CheckCircle2 size={18} className="text-emerald-400 shrink-0" />
                : reportStatus.type === 'loading'
                ? <RefreshCw size={18} className="text-cyan-400 animate-spin shrink-0" />
                : <AlertCircle  size={18} className="text-red-400 shrink-0" />
              }
              <p className={`text-sm flex-1 font-bold ${
                reportStatus.type === 'ok' ? 'text-emerald-300'
                : reportStatus.type === 'loading' ? 'text-cyan-300'
                : 'text-red-300'}`}>
                {reportStatus.msg}
              </p>
              <button
                onClick={() => { setReportStatus(null); setReportFiles(null); }}
                className="text-slate-600 hover:text-white text-xs"
              >✕</button>
            </div>

            {/* ── Direct download buttons ── */}
            {reportStatus.type === 'ok' && reportFiles && (
              <div className="mt-3 pt-3 border-t border-emerald-800/40 flex flex-wrap gap-2">
                <span className="text-[10px] text-slate-500 font-black uppercase tracking-widest self-center mr-1">
                  Download:
                </span>
                {reportFiles.html && (
                  <button
                    onClick={() => downloadReport(reportFiles.html)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-black uppercase tracking-widest border border-cyan-500/40 text-cyan-400 bg-cyan-950/40 hover:bg-cyan-600 hover:text-white transition-all"
                  >
                    <FileText size={11}/> HTML Report
                  </button>
                )}
                {reportFiles.pdf && (
                  <button
                    onClick={() => downloadReport(reportFiles.pdf)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-black uppercase tracking-widest border border-red-500/40 text-red-400 bg-red-950/40 hover:bg-red-600 hover:text-white transition-all"
                  >
                    <FileText size={11}/> PDF Report
                  </button>
                )}
                {reportFiles.json && (
                  <button
                    onClick={() => downloadReport(reportFiles.json)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-black uppercase tracking-widest border border-amber-500/40 text-amber-400 bg-amber-950/40 hover:bg-amber-600 hover:text-white transition-all"
                  >
                    <Download size={11}/> JSON Data
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── DROP ZONE ───────────────────────────────────── */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-6 shadow-md">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3 text-white">
              <div className="p-2 bg-slate-900 rounded"><UploadCloud size={18} className="text-cyan-500" /></div>
              <h3 className="font-bold uppercase tracking-widest text-sm">Target Dataset Selection</h3>
            </div>
            <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">
              Supports PCAP · CSV · LOG · Unlimited size
            </span>
          </div>

          <div
            onDrop={handleDrop} onDragOver={handleDragOver} onDragLeave={handleDragLeave}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed p-12 text-center rounded flex flex-col items-center justify-center transition-all cursor-pointer ${
              dragOver ? 'border-cyan-500 bg-cyan-500/5' : 'border-slate-800 bg-slate-900/50 hover:bg-slate-900 hover:border-slate-700'
            }`}
          >
            {loading ? (
              <div className="flex flex-col items-center gap-3 text-cyan-500">
                <RefreshCw className="animate-spin" size={32} />
                <span className="text-xs uppercase font-bold tracking-widest animate-pulse">Parsing & Bridging Feature Schema...</span>
              </div>
            ) : fileData ? (
              <div className="flex flex-col items-center gap-3 text-emerald-500">
                <CheckCircle2 size={40} />
                <p className="text-sm font-black text-white">{fileData.filename}</p>
                <p className="text-[11px] text-slate-500">
                  {fileData.total_rows != null
                    ? `${fileData.total_rows.toLocaleString()} total rows`
                    : `${fileData.preview.length} rows loaded for preview`
                  } · {fileData.columns.length} columns detected
                </p>
                <button
                  onClick={e => { e.stopPropagation(); setFileData(null); setDetectedAttacks([]); setSweepProgress(null); setSweepError(null); }}
                  className="text-[10px] text-slate-600 hover:text-red-400 transition-colors mt-2 font-black uppercase tracking-widest border border-slate-800 px-3 py-1.5 rounded-lg"
                >
                  Change File
                </button>
              </div>
            ) : (
              <>
                <UploadCloud size={48} className={`mb-4 ${dragOver ? 'text-cyan-500' : 'text-slate-700'}`} />
                <p className="text-sm font-semibold text-slate-300 mb-2">Drag & drop or click to select</p>
                <p className="text-xs text-slate-500 mb-4">Supports .PCAP · .CSV · .LOG — Any size</p>
                <span className="px-6 py-2 bg-slate-800 border border-slate-700 text-slate-200 hover:bg-cyan-600 hover:text-white transition-all rounded font-bold text-xs uppercase tracking-wider">
                  Browse Files
                </span>
              </>
            )}
          </div>
          <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileInput} accept=".pcap,.pcapng,.csv,.log" />
        </div>

        {/* ── DATASET PREVIEW + SWEEP ─────────────────────── */}
        {fileData && (
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-6 shadow-md animate-in fade-in">
            <div className="flex justify-between items-center mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-slate-900 rounded"><Database size={18} className="text-emerald-500" /></div>
                <div>
                  <h3 className="font-bold uppercase tracking-widest text-sm text-white">Dataset Preview</h3>
                  <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">
                    {fileData.filename} · {fileData.columns.length} columns
                    {fileData.total_rows != null ? ` · ${fileData.total_rows.toLocaleString()} rows` : ''}
                  </p>
                </div>
              </div>
              <button
                onClick={executeSweep} disabled={sweepLoading}
                className={`flex items-center gap-2 px-6 py-2.5 rounded text-xs font-black uppercase tracking-wider transition-all ${
                  sweepLoading
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-900/30'
                }`}
              >
                {sweepLoading
                  ? <><RefreshCw size={14} className="animate-spin" /> Analyzing...</>
                  : <><Play size={14}/> Execute Full Sweep</>
                }
              </button>
            </div>

            {/* Enhanced Progress Display */}
            {sweepProgress && (
              <div className="mb-6 bg-gradient-to-b from-slate-900 to-slate-950 border border-cyan-500/20 rounded-xl p-6 space-y-4 shadow-lg">
                {/* Title + Status */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${isDone ? 'bg-emerald-500' : 'bg-cyan-500 animate-pulse'}`} />
                    <h4 className="text-sm font-black text-cyan-300 uppercase tracking-widest">
                      {isDone ? '✓ Forensic Pipeline Complete' : 'Running Forensic Pipeline…'}
                    </h4>
                  </div>
                  {/* Stage badge */}
                  {!isDone && (
                    <span className="text-[9px] font-black uppercase tracking-widest text-slate-500 bg-slate-800 px-2 py-1 rounded border border-slate-700 animate-pulse">
                      {stageLabel}
                    </span>
                  )}
                </div>

                {/* Progress Metrics */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  {/* Rows Analyzed — only meaningful during collation/done */}
                  <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                    <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Rows Analyzed</p>
                    {showRowProgress ? (
                      <>
                        <p className="text-lg font-black text-cyan-400 mt-1">{sweepProgress.processed.toLocaleString()}</p>
                        <p className="text-[9px] text-slate-600 mt-1">of {sweepProgress.total.toLocaleString()}</p>
                      </>
                    ) : (
                      <>
                        <p className="text-lg font-black text-cyan-400 mt-1">{sweepProgress.total.toLocaleString()}</p>
                        <p className="text-[9px] text-slate-600 mt-1">loaded · ML running</p>
                      </>
                    )}
                  </div>

                  <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                    <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Progress</p>
                    <p className="text-lg font-black text-emerald-400 mt-1">{pct}%</p>
                    <p className="text-[9px] text-slate-600 mt-1">Complete</p>
                  </div>

                  {!isDone && sweepProgress.rate_rps > 0 && isCollatingLoop && (
                    <>
                      <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                        <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Throughput</p>
                        <p className="text-lg font-black text-amber-400 mt-1">{sweepProgress.rate_rps.toLocaleString()}</p>
                        <p className="text-[9px] text-slate-600 mt-1">rows/sec</p>
                      </div>
                      {sweepProgress.eta_seconds != null && (
                        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                          <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">ETA</p>
                          <p className="text-lg font-black text-violet-400 mt-1">{fmtEta(sweepProgress.eta_seconds)}</p>
                          <p className="text-[9px] text-slate-600 mt-1">Remaining</p>
                        </div>
                      )}
                    </>
                  )}

                  <div className={`rounded-lg p-3 border ${
                    isDone && sweepProgress.hits > 0
                      ? 'bg-red-950/40 border-red-700/50'
                      : 'bg-slate-800/50 border-slate-700'
                  }`}>
                    <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Threats Found</p>
                    {isDone || isCollatingLoop ? (
                      <>
                        <p className={`text-lg font-black mt-1 ${sweepProgress.hits > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                          {sweepProgress.hits.toLocaleString()}
                        </p>
                        <p className="text-[9px] text-slate-600 mt-1">
                          {isDone ? (sweepProgress.hits > 0 ? 'Threats Detected' : 'No Threats') : 'So far…'}
                        </p>
                      </>
                    ) : (
                      <>
                        <p className="text-lg font-black text-slate-500 mt-1 animate-pulse">—</p>
                        <p className="text-[9px] text-slate-600 mt-1">ML Inferring…</p>
                      </>
                    )}
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="space-y-2">
                  <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
                    <div
                      className={`h-full transition-all duration-700 ${isDone ? 'bg-gradient-to-r from-emerald-500 to-teal-500' : 'bg-gradient-to-r from-cyan-500 to-blue-500'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <p className="text-[9px] text-slate-500 text-center font-bold">
                    {isDone
                      ? `100% · ${sweepProgress.total.toLocaleString()} rows — Pipeline complete`
                      : isCollatingLoop
                        ? `${pct}% · ${sweepProgress.processed.toLocaleString()} / ${sweepProgress.total.toLocaleString()} rows`
                        : `${pct}% · ${stageLabel}`}
                  </p>
                </div>

                {/* Pipeline Stages — thresholds match backend pct milestones */}
                <div className="space-y-2 pt-2 border-t border-slate-700">
                  {[
                    { name: 'Ingesting & normalising traffic data',   active: sweepProgress?.pct >= 5  },
                    { name: 'Feature bridge & preprocessing',          active: sweepProgress?.pct >= 12 },
                    { name: 'ML ensemble inference (RF / XGB / CAT)', active: sweepProgress?.pct >= 35 },
                    { name: 'Deep Learning & anomaly detection',       active: sweepProgress?.pct >= 62 },
                    { name: 'Collating alerts & building evidence',    active: sweepProgress?.pct >= 80 },
                    { name: 'Complete — forensic pipeline done',       active: isDone },
                  ].map((ps, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${ps.active ? 'bg-emerald-500' : 'bg-slate-600'}`} />
                      <span className={`text-[9px] font-bold uppercase tracking-widest ${ps.active ? 'text-emerald-300' : 'text-slate-600'}`}>
                        {ps.name}
                      </span>
                    </div>
                  ))}
                </div>

                {isDone && (
                  <p className="text-[10px] text-emerald-300 font-bold text-center uppercase tracking-widest bg-emerald-950/30 rounded-lg py-2 border border-emerald-500/30">
                    ✓ {sweepProgress.total.toLocaleString()} flows analyzed • {sweepProgress.hits} threats extracted
                  </p>
                )}
              </div>
            )}

            {/* Preview table with pagination */}
            <div className="border border-slate-800 rounded bg-slate-900 overflow-x-auto custom-scrollbar">
              <div className="overflow-x-auto max-h-[300px]">
                <table className="w-full text-left whitespace-nowrap text-xs">
                  <thead className="bg-[#050505] border-b border-slate-800 sticky top-0 z-20 text-slate-500 shadow-md">
                    <tr>
                      {fileData.columns.map(c => (
                        <th key={c} className="px-4 py-3 border-r border-slate-800 font-black uppercase tracking-widest text-[9px]">{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="text-[11px] text-slate-300 font-mono">
                    {previewRows.map((row, idx) => (
                      <tr key={idx} className="border-b border-slate-800/50 hover:bg-slate-800/80 transition-colors">
                        {fileData.columns.map((c, i) => (
                          <td key={i} className={`px-4 py-2 border-r border-slate-800 max-w-[200px] truncate ${i < 2 ? 'font-black text-cyan-500/80' : ''}`}>
                            {String(row[c] ?? '—')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination controls */}
              {totalPreviewPages > 1 && (
                <div className="flex items-center justify-between px-4 py-2 border-t border-slate-800 bg-slate-900">
                  <span className="text-[9px] text-slate-600 font-mono">
                    Page {previewPage + 1} of {totalPreviewPages} · {fileData.preview.length} preview rows
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setPreviewPage(p => Math.max(0, p - 1))}
                      disabled={previewPage === 0}
                      className="p-1 rounded border border-slate-700 text-slate-500 hover:text-white disabled:opacity-30 transition-colors"
                    >
                      <ChevronLeft size={12} />
                    </button>
                    {Array.from({ length: Math.min(5, totalPreviewPages) }, (_, i) => {
                      const pg = Math.min(Math.max(0, previewPage - 2) + i, totalPreviewPages - 1);
                      return (
                        <button key={pg}
                          onClick={() => setPreviewPage(pg)}
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border transition-colors ${
                            pg === previewPage
                              ? 'bg-cyan-600 border-cyan-500 text-white'
                              : 'border-slate-700 text-slate-600 hover:text-white'
                          }`}
                        >
                          {pg + 1}
                        </button>
                      );
                    })}
                    <button
                      onClick={() => setPreviewPage(p => Math.min(totalPreviewPages - 1, p + 1))}
                      disabled={previewPage >= totalPreviewPages - 1}
                      className="p-1 rounded border border-slate-700 text-slate-500 hover:text-white disabled:opacity-30 transition-colors"
                    >
                      <ChevronRight size={12} />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Generate Forensic Report button (no threat matrix) */}
        {detectedAttacks.length > 0 && sweepProgress?.status === 'COMPLETE' && (
          <div className="flex justify-center">
            <button
              onClick={generateReport}
              className="flex items-center gap-2 px-6 py-3 rounded text-sm font-black uppercase tracking-widest border border-violet-500/40 text-violet-400 bg-violet-500/10 hover:bg-violet-500 hover:text-white transition-all"
            >
              <FileText size={16}/> Generate Forensic Report
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
