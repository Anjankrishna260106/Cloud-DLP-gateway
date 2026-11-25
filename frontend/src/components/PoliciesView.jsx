import React, { useEffect, useState } from 'react';
import { Sliders, CheckCircle2, AlertCircle } from 'lucide-react';
import { api } from '../api';
import { ActionBadge } from './BadgeHelpers';

export default function PoliciesView({ user }) {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState('');

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const res = await api.getPolicies();
      setPolicies(res.policies || []);
    } catch (err) {
      setMsg(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleToggle = async (pol) => {
    try {
      await api.updatePolicy(pol.id, {
        action: pol.action,
        is_active: !pol.is_active,
        description: pol.description,
      });
      await fetchPolicies();
    } catch (err) {
      setMsg(err.message);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">DLP Governance Policy Matrix</h1>
        <p className="text-sm text-slate-400">
          Pre-storage rules mapping risk classifications to AWS S3 routing actions.
        </p>
      </div>

      {msg && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400 flex items-center gap-2">
          <AlertCircle className="w-4 h-4" />
          {msg}
        </div>
      )}

      {loading ? (
        <div className="text-slate-400 text-sm">Loading policies...</div>
      ) : (
        <div className="grid gap-4">
          {policies.map((p) => (
            <div key={p.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-3">
                  <Sliders className="w-4 h-4 text-cyan-400" />
                  <span className="font-mono text-sm font-bold text-white">{p.name}</span>
                  <ActionBadge action={p.action} />
                </div>
                <p className="text-xs text-slate-400">{p.description}</p>
                <div className="text-xs text-slate-500">Trigger Tier: <span className="text-slate-300 font-medium">{p.risk_threshold}</span></div>
              </div>
              <button
                onClick={() => handleToggle(p)}
                disabled={user?.role !== 'admin'}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold border transition ${
                  p.is_active
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                } disabled:opacity-50`}
              >
                {p.is_active ? 'Active' : 'Disabled'}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
