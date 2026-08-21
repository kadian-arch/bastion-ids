import React, { useState, useEffect, useRef } from 'react';
import { AlertTriangle, Trash2, X, ShieldAlert } from 'lucide-react';

/**
 * ConfirmModal — secure confirmation dialog for critical / irreversible actions.
 *
 * The user must manually type the word CONFIRM (case-insensitive) before the
 * action button activates.  This prevents single-click accidents on destructive
 * operations such as clearing the permanent archive or deleting all reports.
 *
 * Props
 * ─────
 *  isOpen        {bool}    — whether the modal is visible
 *  title         {string}  — short action title ("Clear Alert Archive")
 *  description   {string}  — human-readable explanation of what will be deleted
 *  onConfirm     {fn}      — called when user types CONFIRM and clicks execute
 *  onCancel      {fn}      — called when user cancels (or clicks backdrop)
 *  confirmLabel  {string}  — label on the execute button  (default: "Delete Permanently")
 *  icon          {node}    — optional icon to replace the default AlertTriangle
 */
export default function ConfirmModal({
  isOpen,
  title,
  description,
  onConfirm,
  onCancel,
  confirmLabel = 'Delete Permanently',
  icon,
}) {
  const [typed, setTyped]   = useState('');
  const inputRef            = useRef(null);

  // Reset input and focus every time the modal opens
  useEffect(() => {
    if (isOpen) {
      setTyped('');
      const t = setTimeout(() => inputRef.current?.focus(), 120);
      return () => clearTimeout(t);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const ready = typed.trim().toUpperCase() === 'CONFIRM';

  function handleConfirm() {
    if (!ready) return;
    onConfirm();
  }

  return (
    /* Portal-style overlay — sits above everything at z-[200] */
    <div className="fixed inset-0 z-[200] flex items-center justify-center font-mono">

      {/* ── Backdrop ─────────────────────────────────────────── */}
      <div
        className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm"
        onClick={onCancel}
      />

      {/* ── Modal card ───────────────────────────────────────── */}
      <div className="relative w-full max-w-[420px] mx-4 bg-slate-900 border border-red-500/30 rounded-2xl shadow-2xl shadow-red-900/25 overflow-hidden animate-in zoom-in-95 fade-in duration-200">

        {/* Danger accent bar at top */}
        <div className="h-[3px] bg-gradient-to-r from-red-700 via-red-500 to-orange-400 w-full" />

        {/* ── Header ─────────────────────────────────────────── */}
        <div className="flex items-start justify-between p-5 border-b border-slate-800">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-red-950/60 rounded-xl border border-red-500/30 shrink-0 mt-0.5">
              {icon ?? <AlertTriangle size={18} className="text-red-400" />}
            </div>
            <div>
              <p className="text-[9px] font-black text-red-500 uppercase tracking-[0.2em] mb-1">
                ⚠ Critical Destructive Action
              </p>
              <h2 className="text-white font-black text-sm leading-tight">{title}</h2>
            </div>
          </div>
          <button
            onClick={onCancel}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-600 hover:text-white transition-colors shrink-0"
          >
            <X size={15} />
          </button>
        </div>

        {/* ── Body ───────────────────────────────────────────── */}
        <div className="p-5 space-y-4">

          {/* Warning description */}
          <div className="bg-red-950/25 border border-red-500/20 rounded-xl p-4 space-y-2">
            <p className="text-[11px] text-slate-300 leading-relaxed">{description}</p>
            <div className="flex items-center gap-2 pt-1">
              <ShieldAlert size={12} className="text-red-500 shrink-0" />
              <p className="text-[10px] font-black text-red-400 uppercase tracking-widest">
                This action is permanent and cannot be undone.
              </p>
            </div>
          </div>

          {/* Confirmation input */}
          <div>
            <label className="block text-[9px] font-black text-slate-500 uppercase tracking-widest mb-2">
              Type{' '}
              <span className="text-cyan-400 font-mono text-[10px] bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">
                CONFIRM
              </span>
              {' '}to unlock the action:
            </label>
            <input
              ref={inputRef}
              value={typed}
              onChange={e => setTyped(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter')  handleConfirm();
                if (e.key === 'Escape') onCancel();
              }}
              placeholder="Type CONFIRM here..."
              spellCheck={false}
              autoComplete="off"
              className={`w-full bg-slate-950 border rounded-xl px-4 py-3 text-sm font-mono outline-none
                placeholder:text-slate-700 text-white caret-cyan-400 transition-colors
                ${ready
                  ? 'border-red-500/60 focus:border-red-400 shadow-inner shadow-red-900/20'
                  : 'border-slate-700 focus:border-slate-500'
                }`}
            />
            {/* Live hint */}
            <p className={`text-[9px] mt-1.5 transition-colors ${
              ready ? 'text-red-400 font-black' : 'text-slate-700'
            }`}>
              {ready ? '✓ Confirmation accepted — action is now unlocked.' : 'Action is locked until confirmation is typed.'}
            </p>
          </div>
        </div>

        {/* ── Actions ────────────────────────────────────────── */}
        <div className="flex gap-3 p-5 pt-0">
          <button
            onClick={onCancel}
            className="flex-1 py-3 rounded-xl text-[10px] font-black uppercase tracking-widest
              bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white
              transition-all border border-slate-700"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!ready}
            className={`flex-1 py-3 rounded-xl text-[10px] font-black uppercase tracking-widest
              flex items-center justify-center gap-2 transition-all
              ${ready
                ? 'bg-red-600 hover:bg-red-500 text-white border border-red-500 shadow-lg shadow-red-900/30 cursor-pointer'
                : 'bg-slate-800/50 text-slate-700 border border-slate-800 cursor-not-allowed'
              }`}
          >
            <Trash2 size={13} />
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
