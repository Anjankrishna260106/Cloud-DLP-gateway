import React from 'react';

export function ActionBadge({ action }) {
  const styles = {
    ALLOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    MASK: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    QUARANTINE: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    BLOCK: 'bg-red-500/15 text-red-400 border-red-500/30',
  };
  return (
    <span className={`px-2.5 py-0.5 text-xs font-semibold rounded-full border ${styles[action] || 'bg-slate-800 text-slate-300 border-slate-700'}`}>
      {action}
    </span>
  );
}

export function RiskBadge({ risk }) {
  const styles = {
    PUBLIC: 'bg-slate-700/40 text-slate-300 border-slate-600/40',
    SENSITIVE_LOW: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
    MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  };
  return (
    <span className={`px-2.5 py-0.5 text-xs font-semibold rounded-md border ${styles[risk] || 'bg-slate-800 text-slate-300'}`}>
      {risk}
    </span>
  );
}
