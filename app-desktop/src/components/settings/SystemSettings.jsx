import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Settings, Save, Terminal, CpuIcon, Layers, Key,
  Database, Loader2, RotateCcw, CheckCircle, XCircle,
  AlertTriangle, RefreshCw, Trash2
} from 'lucide-react';

const API = 'http://localhost:48217/api/v1';
const HDR = { 'x-authority': 'BASTION-KADIAN-SEC-0x42' };

const VERIFY_WORDS = ['CONFIRM','EXECUTE','PROCEED','AUTHORIZE','VALIDATE','APPROVE'];

function useToast() {
  const [toast, setToast] = useState(null);
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

// ── Word-verification dialog for destructive commands ─────────────────────────
function ConfirmDialog({ action, word, onConfirm, onCancel }) {
  const [input, setInput] = useState('');
  return (
    <div className="fixed inset-0 z-[300] flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-950 border border-red-800 rounded-lg p-6 w-80 shadow-2xl font-mono">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle size={16} className="text-red-400" />
          <span className="text-red-400 text-xs font-black uppercase tracking-widest">Confirm Destructive Action</span>
        </div>
        <p className="text-slate-400 text-[10px] mb-4 leading-relaxed">
          This action is irreversible. Type <span className="text-white font-black">{word}</span> to confirm.
        </p>
        <input
          autoFocus
          value={input}
          onChange={e => setInput(e.target.value.toUpperCase())}
          placeholder={`Type ${word}`}
          className="w-full bg-slate-900 border border-slate-700 p-2 rounded text-xs text-white font-mono
            outline-none focus:border-red-500 mb-4 tracking-widest"
        />
        <div className="flex gap-2">
          <button
            onClick={onCancel}
            className="flex-1 py-2 bg-slate-800 text-slate-300 rounded text-[10px] font-bold uppercase
              hover:bg-slate-700 transition-colors border border-slate-700"
          >
            Cancel
          </button>
          <button
            disabled={input !== word}
            onClick={onConfirm}
            className="flex-1 py-2 bg-red-700 text-white rounded text-[10px] font-bold uppercase
              hover:bg-red-600 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
          >
            Execute
          </button>
        </div>
      </div>
    </div>
  );
}

export default function SystemSettings() {
  const [isLoading,    setIsLoading]    = useState(true);
  const [isCommitting, setIsCommitting] = useState(false);
  const [config,       setConfig]       = useState({});
  const [initialConfig,setInitialConfig]= useState({});
  const [hasChanges,   setHasChanges]   = useState(false);
  const [busy,         setBusy]         = useState({});
  const [confirm,      setConfirm]      = useState(null); // { key, word, action }
  const { toast, ok, err, warn } = useToast();

  useEffect(() => {
    (async () => {
      try {
        setIsLoading(true);
        const { data } = await axios.get(`${API}/settings/config`, { headers: HDR });
        setConfig(data);
        setInitialConfig(data);
      } catch {
        err('Settings could not be loaded. Ensure Bastion IDS is running.');
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

  const handleCommit = async () => {
    setIsCommitting(true);
    try {
      await axios.post(`${API}/settings/update`, config, { headers: HDR });
      setInitialConfig(config);
      setHasChanges(false);
      ok('Configuration saved successfully.');
    } catch {
      err('Failed to save settings. Please try again.');
    } finally {
      setIsCommitting(false);
    }
  };

  const runAction = async (key, endpoint, method = 'post', successMsg, opts = {}) => {
    if (busy[key]) return;
    setBusy(b => ({ ...b, [key]: true }));
    try {
      const fn  = method === 'delete' ? axios.delete : axios.post;
      const res = await fn(`${API}${endpoint}`, opts.body ?? {}, { headers: HDR });
      if (opts.onSuccess) opts.onSuccess(res.data);
      ok(successMsg ?? res.data?.message ?? 'Action completed.');
    } catch {
      err('Action could not be completed. Please try again.');
    } finally {
      setBusy(b => ({ ...b, [key]: false }));
    }
  };

  // ── Wrap destructive actions with word-verification challenge ─────────────
  const runDestructive = (key, endpoint, method, successMsg, opts = {}) => {
    const word = VERIFY_WORDS[Math.floor(Math.random() * VERIFY_WORDS.length)];
    setConfirm({
      word,
      action: () => {
        setConfirm(null);
        runAction(key, endpoint, method, successMsg, opts);
      },
    });
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
      {confirm && (
        <ConfirmDialog
          word={confirm.word}
          onConfirm={confirm.action}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex justify-between items-center bg-slate-900 border-b border-slate-800 p-4 sticky top-0 z-20">
        <div className="flex items-center gap-3">
          <Settings className="text-cyan-500" size={20} />
          <h1 className="text-lg font-black text-white uppercase tracking-wider">System Configuration</h1>
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
                label="Log Retention (days)"
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
            <p className="text-[9px] text-slate-600 mt-2 leading-relaxed">
              Resource limits are advisory — the engine logs a warning when thresholds are exceeded.
            </p>
          </ConfigBlock>
        </div>

        {/* ── COL 2: ML + Mitigation ──────────────────────────────────────── */}
        <div className="space-y-6">
          <ConfigBlock icon={<Layers size={16}/>} title="Detection Sensitivity" color="text-indigo-500">
            <WeightSlider
              label="Signature Confidence Floor"
              value={config.sigConfFloor ?? 70}
              onChange={v => handleUpdate('sigConfFloor', v)}
            />
            <WeightSlider
              label="ML Ensemble Vote Threshold"
              value={config.mlVoteThreshold ?? 60}
              onChange={v => handleUpdate('mlVoteThreshold', v)}
            />
            <WeightSlider
              label="Anomaly Sensitivity"
              value={config.anomalySensitivity ?? 50}
              onChange={v => handleUpdate('anomalySensitivity', v)}
            />
            <ActionButton
              label="Flush Inference Cache"
              icon={<RefreshCw size={13}/>}
              loading={busy['mlreset']}
              onClick={() => runAction('mlreset', '/neural/reset', 'post',
                'Inference cache cleared. Models remain loaded.')}
              color="default"
            />
          </ConfigBlock>

          {/* Mitigation policies live in Command & Control — single source of
              truth for operational toggles. Settings covers configuration only. */}
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
                'API key rotated. Copy the new key from the field above.',
                { onSuccess: (data) => { if (data?.new_key) handleUpdate('apiKey', data.new_key); } }
              )}
              color="pink"
            />
          </ConfigBlock>

          <ConfigBlock icon={<Database size={16}/>} title="Log Maintenance" color="text-slate-400">
            <div className="grid grid-cols-2 gap-3">
              <ActionButton
                label="Compact Logs"
                icon={<Database size={13}/>}
                loading={busy['maint']}
                onClick={() => runAction('maint', '/maint', 'post', null)}
                color="default"
              />
              <ActionButton
                label="Clear Alert History"
                icon={<Trash2 size={13}/>}
                loading={busy['flush']}
                onClick={() => runDestructive('flush', '/flush', 'post',
                  'Alert history cleared — current session log reset.')}
                color="amber"
              />
            </div>
            <p className="text-[9px] text-slate-600 mt-3 leading-relaxed">
              Compact Logs removes duplicate alert entries. Clear Alert History erases the
              current session's alert log; saved detection logs and the permanent archive
              are not affected. Operational commands (restart, lockdown, purge) live in
              Command &amp; Control.
            </p>
          </ConfigBlock>
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

const BTN_STYLES = {
  default:  'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200',
  amber:    'bg-amber-900/30 hover:bg-amber-900/60 border-amber-800/50 text-amber-300',
  pink:     'bg-pink-900/30 hover:bg-pink-800/40 border-pink-800/50 text-pink-300',
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
