import React from 'react';
import { X, ShieldAlert, Database, Clock, FileText, Download, CheckCircle2, AlertTriangle } from 'lucide-react';
import { ActionBadge, RiskBadge } from './BadgeHelpers';
import { api } from '../api';

export default function EventDetailModal({ event, onClose }) {
  if (!event) return null;

  const handleDownload = async () => {
    try {
      await api.downloadFileBlob(event.id, event.sanitized_filename || event.filename);
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <FileText className="w-5 h-5 text-cyan-400" />
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-lg font-bold text-white">{event.filename}</h2>
                <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">{event.id}</span>
              </div>
              <p className="text-xs text-slate-400">Uploaded by {event.user_email} • {new Date(event.timestamp).toLocaleString()}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Summary Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5">
              <div className="text-xs text-slate-400 mb-1">DLP Policy Action</div>
              <ActionBadge action={event.policy_action} />
            </div>
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5">
              <div className="text-xs text-slate-400 mb-1">Risk Classification</div>
              <div className="flex items-center gap-2">
                <RiskBadge risk={event.risk_level} />
                <span className="text-sm font-bold text-white">{event.risk_score}/100</span>
              </div>
            </div>
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5">
              <div className="text-xs text-slate-400 mb-1">Cloud S3 Destination</div>
              <div className="text-xs font-mono text-cyan-300 truncate">
                {event.destination_bucket ? `s3://${event.destination_bucket}` : 'REJECTED (No S3 Write)'}
              </div>
            </div>
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5">
              <div className="text-xs text-slate-400 mb-1">Inspection Latency</div>
              <div className="text-sm font-semibold text-white flex items-center gap-1.5">
                <Clock className="w-4 h-4 text-slate-400" />
                {event.processing_time_ms} ms
              </div>
            </div>
          </div>

          {/* Decision Reason & S3 Metadata */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Policy Triggered: {event.policy_name}
              </span>
              {event.stored_in_s3 && (
                <button
                  onClick={handleDownload}
                  className="text-xs flex items-center gap-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 px-3 py-1.5 rounded-lg transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download Stored File
                </button>
              )}
            </div>
            <p className="text-sm text-slate-200">{event.decision_reason}</p>
            {event.s3_metadata && (
              <div className="pt-2 border-t border-slate-800/80 flex flex-wrap gap-4 text-xs text-slate-400 font-mono">
                <span>Provider: {event.s3_metadata.provider}</span>
                <span>Encryption: {event.s3_metadata.encryption}</span>
                <span>ACL: {event.s3_metadata.acl}</span>
                <span className="truncate max-w-md">Key: {event.s3_key}</span>
              </div>
            )}
          </div>

          {/* Findings List */}
          <div>
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Detected Sensitive Entities ({event.findings_count})
            </h3>
            {event.findings && event.findings.length > 0 ? (
              <div className="border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase">
                    <tr>
                      <th className="px-4 py-3">Entity Type</th>
                      <th className="px-4 py-3">Redacted Value</th>
                      <th className="px-4 py-3">Validation</th>
                      <th className="px-4 py-3">Confidence</th>
                      <th className="px-4 py-3">Context Snippet</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {event.findings.map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="px-4 py-3 font-semibold text-cyan-300">{f.entity_type}</td>
                        <td className="px-4 py-3 font-mono text-amber-300">{f.value_preview}</td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {f.validation_status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-300">{Math.round(f.confidence * 100)}%</td>
                        <td className="px-4 py-3 font-mono text-slate-400 max-w-xs truncate">{f.context_snippet}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-4 text-sm text-emerald-300 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                Zero sensitive data patterns detected in this file.
              </div>
            )}
          </div>

          {/* Masked Preview */}
          {event.masked_preview && (
            <div>
              <h3 className="text-sm font-semibold text-white mb-2">Sanitized Output Preview (Stored in Safe Bucket)</h3>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-emerald-300 whitespace-pre-wrap overflow-x-auto">
                {event.masked_preview}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
