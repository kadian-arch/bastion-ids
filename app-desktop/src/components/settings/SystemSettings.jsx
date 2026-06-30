import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Settings, Save, Terminal, CpuIcon, Layers, ShieldAlert, Key,
  Database, Zap, Loader2, RotateCcw, CheckCircle, XCircle,
  AlertTriangle, RefreshCw, Trash2, Shield, Lock
} from 'lucide-react';

const API = 'http://localhost:48217/api/v1';
const HDR = { 'x-authority': 'BASTION-KADIAN-SEC-0x42' };

// ── Inline toast ─────────────────────────────────────────────────────────────
function useToast() {
  const [toast, setToast] = useState(null); // { type: 'ok'|'err'|'warn', msg: '' }
  const show = useCallback((type, msg) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 4500);
  }, []);
  return { toast, ok: (m) => show('ok', m), err: (m) => show('err', m), warn: (m) => show('warn', m) };
}

function Toast({ toast }) {
  if (!toast) return null;
  const styles = {
    ok:   'bg-emerald-950 border-emerald-700 text-emerald-300',
    err:  'bg-red-950 border-red-700 text-red-300',
    warn: 'bg-amber-950 border-amber-700 text-amber-300',
  };
  const icons = {
    ok:   <CheckCircle size={14} />,
    err:  <XCircle size={14} />,
    warn: <AlertTriangle size={14} />,
  };
  return (
    <div className={`fixed bottom-6 right-6 z-[200] flex items-center gap-3 px-4 py-3
      border rounded-lg shadow-2xl text-xs font-bold font-mono max-w-xs
      animate-in fade-in slide-in-from-bottom-4 ${styles[toast.type]}`}>
      {icons[toast.type]}
      <span>{toast.msg}</span>
    </div>
  );
}

// ── Main ─────────────────────────────────────────────────────────────────────
export default function SystemSettings() {
  const [isLoading,    setIsLoading]    = useState(true);
  const [isCommitting, setIsCommitting] = useState(false);
  const [config,       setConfig]       = useState({});
  const [initialConfig,setInitialConfig]= useState({});
  const [hasChanges,   setHasChanges]   = useState(false);
  const [busy,         setBusy]         = useState({});  // { [actionKey]: true }
  const [lockdownMode, setLockdownMode] = useState(false);
  const { toast, ok, err, warn } = useToast();

  // ── Load settings ──────────────────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        setIsLoading(true);
        const { data } = await axios.get(`${API}/settings/config`, { headers: HDR });
        setConfig(data);
        setInitialConfig(data);
      } catch {
        err('Backend unreachable — settings could not be loaded.');
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  const handleUpdate = (key, value) => {
    const next = { ...config, [key]: value };
    setConfig(next);
    setHasChanges(JSON.stringify(next) !== JSON.stringify(initialConfig));
  };

  // ── Commit config changes ──────────────────────────────────────────────────
  const handleCommit = async () => {
    setIsCommitting(true);
    try {
      await axios.post(`${API}/settings/update`, config, { headers: HDR });
      setInitialConfig(config);
      setHasChanges(false);
      ok('Configuration committed to backend.');
    } catch {
      err('Failed to commit settings — check backend connection.');
    } finally {
      setIsCommitting(false);
    }
  };

  // ── Generic action runner with per-button busy state ──────────────────────
  const runAction = async (key, endpoint, method = 'post', successMsg, opts = {}) => {
    if (busy[key]) return;
    setBusy(b => ({ ...b, [key]: true }));
    try {
      const fn  = method === 'delete' ? axios.delete : axios.post;
      const res = await fn(`${API}${endpoint}`, opts.body ?? {}, { headers: HDR });
      if (opts.onSuccess) opts.onSuccess(res.data);
      ok(successMsg ?? res.data?.message ?? 'Action completed.');
    } catch (e) {
      const detail = e?.response?.data?.detail ?? e?.message ?? 'Unknown error';
      err(`Failed: ${detail}`);
    } finally {
      setBusy(b => ({ ...b, [key]: false }));
    }
  };

  if (isLoading) return (
    <div className="p-8 text-slate-500 font-mono text-sm flex items-center gap-3">
      <Loader2 size={18} className="animate-spin text-cyan-500" />
      Loading Configuration Matrix...
    </div>
  );

  return (
    <div className="space-y-6 font-mono text-slate-300 pb-12">
      <Toast toast={toast} />

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex justify-between items-center bg-slate-900 border-b border-slate-800 p-4 sticky top-0 z-20">
        <div className="flex items-center gap-3">
          <Settings className="text-cyan-500" size={20} />
          <h1 className="text-lg font-black text-white uppercase tracking-wider">System Configuration</h1>
          {lockdownMode && (
            <span className="ml-3 px-2 py-0.5 bg-red-900/50 border border-red-700 text-red-400
              text-[9px] font-black uppercase tracking-widest rounded animate-pulse">
              LOCKDOWN ACTIVE
            </span>
          )}
        </div>

        <div className="flex gap-3">
          <button
            disabled={!hasChanges}
            onClick={() => { setConfig(initialConfig); setHasChanges(false); }}
            className="px-4 py-1.5 bg-slate-800 text-slate-400 rounded hover:bg-slate-700 transition-colors
              text-xs font-bold uppercase disabled:opacity-30 flex items-center gap-2 border border-slate-700"
          >
            <RotateCcw size={13} /> Revert
          </button>
          <button
            disabled={!hasChanges || isCommitting}
            onClick={handleCommit}
            className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded transition-colors
              text-xs font-bold uppercase disabled:opacity-30 shadow flex items-center gap-2"
          >
            {isCommitting ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
            Commit Changes
          </button>
        </div>
      </div>

      {/* ── Grid ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 px-6">

        {/* ── COL 1: Identity + Resources ─────────────────────────────────── */}
        <div className="space-y-6">
          <ConfigBlock icon={<Terminal size={16}/>} title="Node Identity" color="text-cyan-500">
            <InputField
              label="System Hostname"
              value={config.systemName || ''}
              onChange={v => handleUpdate('systemName', v)}
            />
            <div className="grid grid-cols-2 gap-4 mt-4">
              <InputField
                label="Sniff Interface"
                value={config.interface || ''}
                onChange={v => handleUpdate('interface', v)}
              />
              <InputField
                label="Log Retention (d)"
                type="number"
                value={config.retentionDays || 0}
                onChange={v => handleUpdate('retentionDays', parseInt(v) || 0)}
              />
            </div>
          </ConfigBlock>

          <ConfigBlock icon={<CpuIcon size={16}/>} title="Resource Governance" color="text-emerald-500">
            <WeightSlider
              label="Max CPU Utilization"
              value={config.cpuLimit || 0}
              onChange={v => handleUpdate('cpuLimit', v)}
            />
            <WeightSlider
              label="Memory Cap (MB)"
              value={config.ramLimit || 4096}
              max={16384}
              onChange={v => handleUpdate('ramLimit', v)}
            />
            <p className="text-[9px] text-slate-700 mt-2 leading-relaxed">
              These limits are advisory — the backend will log a warning when thresholds are exceeded.
            </p>
          </ConfigBlock>
        </div>

        {/* ── COL 2: ML + Mitigation ──────────────────────────────────────── */}
        <div className="space-y-6">
          <ConfigBlock icon={<Layers size={16}/>} title="Detection Sensitivity" color="text-indigo-500">
            <WeightSlider
              label="Signature Confidence Floor"
              value={config.sigWeight ?? 70}
              onChange={v => handleUpdate('sigWeight', v)}
            />
            <WeightSlider
              label="ML Ensemble Vote Threshold"
              value={config.mlThreshold ?? 60}
              onChange={v => handleUpdate('mlThreshold', v)}
            />
            <WeightSlider
              label="Anomaly Sensitivity"
              value={config.anomalyWeight ?? 50}
              onChange={v => handleUpdate('anomalyWeight', v)}
            />
            <ActionButton
              label="Flush ML Buffer"
              icon={<RefreshCw size={13}/>}
              loading={busy['mlreset']}
              onClick={() => runAction('mlreset', '/neural/reset', 'post',
                'ML buffer flushed — models will reinitialise on next inference.')}
              color="default"
            />
          </ConfigBlock>

          <ConfigBlock icon={<ShieldAlert size={16}/>} title="Mitigation Policies" color="text-amber-500">
            <ToggleRow
              label="Auto-Quarantine Hosts"
              desc="Block flagged IPs via Windows Firewall"
              active={config.autoQuarantine}
              onClick={() => handleUpdate('autoQuarantine', !config.autoQuarantine)}
            />
            <ToggleRow
              label="Geo-IP Blocking"
              desc="Deny traffic from high-risk ASNs"
              active={config.geoBlock}
              onClick={() => handleUpdate('geoBlock', !config.geoBlock)}
            />
            <ToggleRow
              label="Engine Stealth Mode"
              desc="Suppress ICMP responses from this host"
              active={config.engineStealthMode}
              onClick={() => handleUpdate('engineStealthMode', !config.engineStealthMode)}
            />
            <p className="text-[9px] text-slate-700 mt-1">
              Toggle changes are staged — hit Commit to push to backend.
            </p>
          </ConfigBlock>
        </div>

        {/* ── COL 3: Keys + Storage + Urgent ──────────────────────────────── */}
        <div className="space-y-6">

          <ConfigBlock icon={<Key size={16}/>} title="Access Control" color="text-pink-500">
            <div className="mb-4">
              <label className="text-[10px] text-slate-500 uppercase font-bold tracking-widest block mb-2">
                Master API Key
              </label>
              <input
                readOnly
                value={config.apiKey || ''}
                className="w-full bg-slate-950 border border-slate-800 p-2 rounded text-[10px]
                  text-slate-500 font-mono select-all cursor-text"
              />
            </div>
            <ActionButton
              label="Rotate API Key"
              icon={<Key size={13}/>}
              loading={busy['rollkey']}
              onClick={() => runAction(
                'rollkey', '/roll-key', 'post',
                'API key rotated — copy the new key from the field above.',
                {
                  onSuccess: (data) => {
                    if (data?.new_key) {
                      handleUpdate('apiKey', data.new_key);
                    }
                  }
                }
              )}
              color="pink"
            />
          </ConfigBlock>

          <ConfigBlock icon={<Database size={16}/>} title="Storage Operations" color="text-slate-400">
            <div className="grid grid-cols-2 gap-3 mb-3">
              <ActionButton
                label="Optimize DB"
                icon={<Database size={13}/>}
                loading={busy['maint']}
                onClick={() => runAction('maint', '/maint', 'post',
                  'Database maintenance pass initiated.')}
                color="default"
              />
              <ActionButton
                label="Clear Alert Logs"
                icon={<Trash2 size={13}/>}
                loading={busy['flush']}
                onClick={() => runAction('flush', '/flush', 'post',
                  'Alert log cleared — session history reset to zero.')}
                color="amber"
              />
            </div>
            <ActionButton
              label="Wipe Forensic Disk"
              icon={<XCircle size={13}/>}
              loading={busy['wipe']}
              onClick={() => runAction('wipe', '/wipe', 'post',
                'Volatile forensic data wiped. Persistent logs unaffected.')}
              color="red"
              full
            />
          </ConfigBlock>

          {/* ── Urgent Directives ──────────────────────────────────────────── */}
          <div className="bg-slate-950 border border-red-900/50 p-5 rounded">
            <h4 className="flex items-center gap-2 text-xs font-bold text-red-400 uppercase tracking-widest mb-1">
              <Zap size={15} /> Urgent Directives
            </h4>
            <p className="text-[9px] text-slate-700 mb-4">
              Irreversible commands — confirm before executing.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <ActionButton
                label="Restart Node"
                icon={<RefreshCw size={13}/>}
                loading={busy['restart']}
                onClick={() => runAction('restart', '/restart', 'post',
                  'Restart acknowledged — close and reopen the launcher BAT to restart.')}
                color="default"
              />
              <ActionButton
                label="Hard Lockdown"
                icon={<Lock size={13}/>}
                loading={busy['lockdown']}
                onClick={() => runAction(
                  'lockdown', '/lockdown', 'post',
                  'LOCKDOWN EXECUTED — capture halted, buffers flushed, counters reset.',
                  { onSuccess: () => setLockdownMode(true) }
                )}
                color="lockdown"
              />
            </div>
            {lockdownMode && (
              <div className="mt-3 p-2 bg-red-950/30 border border-red-900/40 rounded text-[9px]
                text-red-400 font-mono">
                System is in lockdown state. Restart the engine to resume normal operations.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────
function ConfigBlock({ icon, title, children, color }) {
  return (
    <div className="bg-slate-950 border border-slate-800 rounded p-5">
      <div className="flex items-center gap-3 mb-5">
        <div className={`p-2 bg-slate-900 rounded border border-slate-800 ${color}`}>{icon}</div>
        <h3 className="text-white text-sm font-bold uppercase tracking-wider">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function InputField({ label, value, onChange, type = 'text' }) {
  return (
    <div>
      <label className="text-[10px] text-slate-500 font-bold uppercase tracking-widest block mb-1.5">
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-slate-900 border border-slate-800 p-2 text-xs text-white rounded
          outline-none focus:border-cyan-500 transition-colors"
      />
    </div>
  );
}

function WeightSlider({ label, value, onChange, max = 100 }) {
  return (
    <div className="mb-4">
      <div className="flex justify-between items-center mb-1.5">
        <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">{label}</span>
        <span className="text-xs font-black text-white font-mono">{value}{max === 100 ? '%' : ''}</span>
      </div>
      <input
        type="range" min="0" max={max} value={value}
        onChange={(e) => onChange(parseInt(e.target.value))}
        className="w-full accent-cyan-500 h-1 bg-slate-800 rounded outline-none cursor-pointer"
      />
    </div>
  );
}

function ToggleRow({ label, desc, active, onClick }) {
  return (
    <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded mb-2.5">
      <div>
        <p className="text-[10px] text-slate-300 font-bold uppercase tracking-wider">{label}</p>
        {desc && <p className="text-[9px] text-slate-700 mt-0.5">{desc}</p>}
      </div>
      <button
        onClick={onClick}
        className={`w-9 h-5 rounded-full relative transition-colors shrink-0 ml-3
          ${active ? 'bg-cyan-500' : 'bg-slate-700'}`}
      >
        <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all
          ${active ? 'left-5' : 'left-1'}`} />
      </button>
    </div>
  );
}

// colour variants — all static strings for Tailwind JIT
const BTN_STYLES = {
  default:  'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200',
  amber:    'bg-amber-900/30 hover:bg-amber-900/60 border-amber-800/50 text-amber-300',
  red:      'bg-red-900/30 hover:bg-red-900/60 border-red-800/50 text-red-400',
  pink:     'bg-pink-900/30 hover:bg-pink-800/40 border-pink-800/50 text-pink-300',
  lockdown: 'bg-red-600 hover:bg-red-500 border-red-500 text-white shadow-lg',
};

function ActionButton({ label, icon, onClick, loading, color = 'default', full = false }) {
  const cls = BTN_STYLES[color] ?? BTN_STYLES.default;
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`${full ? 'w-full' : ''} flex items-center justify-center gap-2
        py-2 px-3 rounded border text-[10px] font-bold uppercase tracking-wider
        transition-colors disabled:opacity-50 ${cls}`}
    >
      {loading ? <Loader2 size={13} className="animate-spin" /> : icon}
      {label}
    </button>
  );
}
