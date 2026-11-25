import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert, EyeOff, Ban, FileCheck, RefreshCw, ChevronRight } from 'lucide-react';
import { api } from '../api';
import { ActionBadge, RiskBadge } from './BadgeHelpers';
import EventDetailModal from './EventDetailModal';

export default function DashboardView() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [detailError, setDetailError] = useState('');

  const loadStats = async () => {
    setLoading(true);
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  const handleInspectEvent = async (eventId) => {
    setDetailError('');
    try {
      const res = await api.getEventDetail(eventId);
      setSelectedEvent(res.event);
    } catch (err) {
      setDetailError(err.message);
    }
  };

  if (loading && !stats) {
    return <div className="p-8 text-slate-400">Loading Cloud DLP Telemetry...</div>;
  }

  const actions = stats?.action_breakdown || { ALLOW: 0, MASK: 0, QUARANTINE: 0, BLOCK: 0 };
  const entityTypes = Object.entries(stats?.entity_type_breakdown || {});
  const total = stats?.total_files_scanned || 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Pre-Storage DLP Security Dashboard</h1>
          <p className="text-sm text-slate-400">
            Real-time telemetry of inbound file inspection prior to AWS S3 persistence
          </p>
        </div>
        <button
          onClick={loadStats}
          className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 px-3.5 py-2 rounded-lg text-sm transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
            <span>FILES SCANNED</span>
            <FileCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold text-white">{total}</div>
          <div className="text-xs text-slate-500 mt-1">{stats?.total_sensitive_findings || 0} total findings</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-emerald-400 text-xs font-medium mb-2">
            <span>ALLOWED (SAFE)</span>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="text-3xl font-bold text-white">{actions.ALLOW || 0}</div>
          <div className="text-xs text-slate-500 mt-1">Routed to Safe Bucket</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-amber-400 text-xs font-medium mb-2">
            <span>MASKED (SANITIZED)</span>
            <EyeOff className="w-4 h-4" />
          </div>
          <div className="text-3xl font-bold text-white">{actions.MASK || 0}</div>
          <div className="text-xs text-slate-500 mt-1">Redacted → Safe Bucket</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-orange-400 text-xs font-medium mb-2">
            <span>QUARANTINED</span>
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div className="text-3xl font-bold text-white">{actions.QUARANTINE || 0}</div>
          <div className="text-xs text-slate-500 mt-1">Isolated Quarantine Bucket</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-red-400 text-xs font-medium mb-2">
            <span>BLOCKED (REJECTED)</span>
            <Ban className="w-4 h-4" />
          </div>
          <div className="text-3xl font-bold text-white">{actions.BLOCK || 0}</div>
          <div className="text-xs text-slate-500 mt-1">Zero S3 Persistence</div>
        </div>
      </div>

      {/* Breakdown Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Action Breakdown */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Policy Action Distribution</h3>
          <div className="space-y-3.5">
            {[
              { label: 'ALLOW', count: actions.ALLOW || 0, color: 'bg-emerald-500' },
              { label: 'MASK', count: actions.MASK || 0, color: 'bg-amber-500' },
              { label: 'QUARANTINE', count: actions.QUARANTINE || 0, color: 'bg-orange-500' },
              { label: 'BLOCK', count: actions.BLOCK || 0, color: 'bg-red-500' },
            ].map((item) => {
              const pct = total > 0 ? Math.round((item.count / total) * 100) : 0;
              return (
                <div key={item.label}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-medium text-slate-300">{item.label}</span>
                    <span className="text-slate-400">{item.count} files ({pct}%)</span>
                  </div>
                  <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800">
                    <div className={`${item.color} h-full transition-all duration-500`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Sensitive Data Type Breakdown */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Detected Sensitive Data Types</h3>
          {entityTypes.length > 0 ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {entityTypes.map(([etype, count]) => (
                <div key={etype} className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <div className="text-xs font-mono text-cyan-400 truncate">{etype}</div>
                  <div className="text-2xl font-bold text-white mt-1">{count}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-36 flex items-center justify-center text-sm text-slate-500 border border-dashed border-slate-800 rounded-lg">
              Upload test files to populate sensitive entity analytics.
            </div>
          )}
        </div>
      </div>

      {/* Recent Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">Recent Pre-Storage Scan Events</h3>
          <span className="text-xs text-slate-400">Click any row for full forensic detection details</span>
        </div>
        {detailError && (
          <div className="m-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
            {detailError}
          </div>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 text-xs uppercase text-slate-400">
              <tr>
                <th className="px-5 py-3">Scan ID</th>
                <th className="px-5 py-3">Filename</th>
                <th className="px-5 py-3">Risk Level</th>
                <th className="px-5 py-3">Action</th>
                <th className="px-5 py-3">Findings</th>
                <th className="px-5 py-3">S3 Bucket Route</th>
                <th className="px-5 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {stats?.recent_events?.length > 0 ? (
                stats.recent_events.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => handleInspectEvent(ev.id)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="px-5 py-3.5 font-mono text-xs text-cyan-400">{ev.id}</td>
                    <td className="px-5 py-3.5 font-medium text-white">{ev.filename}</td>
                    <td className="px-5 py-3.5"><RiskBadge risk={ev.risk_level} /></td>
                    <td className="px-5 py-3.5"><ActionBadge action={ev.policy_action} /></td>
                    <td className="px-5 py-3.5 text-slate-300">{ev.findings_count}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-slate-400">
                      {ev.destination_bucket || '— (Rejected)'}
                    </td>
                    <td className="px-5 py-3.5 text-right text-slate-500">
                      <ChevronRight className="w-4 h-4 inline" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" className="px-5 py-8 text-center text-slate-500">
                    No files scanned yet. Go to Upload & Scan to run the demo scenarios!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
}
