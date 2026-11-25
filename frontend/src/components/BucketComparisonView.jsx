import React, { useEffect, useState } from 'react';
import { Database, ShieldCheck, ShieldAlert, Lock, CheckCircle2, XCircle, FileText, ArrowRight, RefreshCw, Code } from 'lucide-react';
import { api } from '../api';

export default function BucketComparisonView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('matrix'); // 'matrix', 'files', 'policies'
  const [policyView, setPolicyView] = useState('both'); // 'safe', 'quarantine', 'both'

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await api.getBucketsComparison();
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading && !data) {
    return <div className="p-8 text-slate-400">Loading S3 Bucket Permissions & Architecture Telemetry...</div>;
  }

  const safe = data?.safe_bucket;
  const quar = data?.quarantine_bucket;

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Database className="w-6 h-6 text-cyan-400" />
            S3 Dual-Bucket Isolation & Permissions Architecture
          </h1>
          <p className="text-sm text-slate-400">
            Compare the operational Safe Bucket against the Zero-Trust Quarantine Vault to demonstrate pre-storage DLP routing.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 px-3.5 py-2 rounded-lg text-xs transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Buckets
        </button>
      </div>

      {/* Top 2 Architectural Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Safe Bucket Card */}
        <div className="bg-gradient-to-br from-slate-900 via-slate-900 to-emerald-950/20 border border-emerald-500/30 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-3">
            <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              Operational Tier
            </span>
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
          </div>
          <h2 className="text-lg font-bold text-white font-mono">{safe?.name}</h2>
          <p className="text-xs text-slate-300 mt-2">{safe?.purpose}</p>

          <div className="grid grid-cols-2 gap-3 mt-5 pt-4 border-t border-slate-800 text-xs">
            <div>
              <div className="text-slate-400">Stored Objects</div>
              <div className="text-xl font-bold text-emerald-400 mt-0.5">{safe?.total_files} files</div>
            </div>
            <div>
              <div className="text-slate-400">Default Encryption</div>
              <div className="font-semibold text-white mt-0.5">{safe?.default_encryption?.ServerSideEncryption}</div>
            </div>
            <div>
              <div className="text-slate-400">Standard App Access</div>
              <div className="font-semibold text-emerald-400 flex items-center gap-1 mt-0.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> Allowed
              </div>
            </div>
            <div>
              <div className="text-slate-400">Compliance Lockdown</div>
              <div className="font-semibold text-slate-400 mt-0.5">Standard Lifecycle</div>
            </div>
          </div>
        </div>

        {/* Quarantine Bucket Card */}
        <div className="bg-gradient-to-br from-slate-900 via-slate-900 to-orange-950/20 border border-orange-500/30 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-3">
            <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-orange-500/10 text-orange-400 border border-orange-500/30">
              Zero-Trust Regulatory Vault
            </span>
            <Lock className="w-6 h-6 text-orange-400" />
          </div>
          <h2 className="text-lg font-bold text-white font-mono">{quar?.name}</h2>
          <p className="text-xs text-slate-300 mt-2">{quar?.purpose}</p>

          <div className="grid grid-cols-2 gap-3 mt-5 pt-4 border-t border-slate-800 text-xs">
            <div>
              <div className="text-slate-400">Isolated Objects</div>
              <div className="text-xl font-bold text-orange-400 mt-0.5">{quar?.total_files} files</div>
            </div>
            <div>
              <div className="text-slate-400">Default Encryption</div>
              <div className="font-semibold text-white mt-0.5">{quar?.default_encryption?.ServerSideEncryption}</div>
            </div>
            <div>
              <div className="text-slate-400">Standard App Access</div>
              <div className="font-semibold text-red-400 flex items-center gap-1 mt-0.5">
                <XCircle className="w-3.5 h-3.5" /> Explicitly Denied
              </div>
            </div>
            <div>
              <div className="text-slate-400">Access Restriction</div>
              <div className="font-semibold text-orange-300 mt-0.5">Auditor Role Only</div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800">
        <button
          onClick={() => setActiveTab('matrix')}
          className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
            activeTab === 'matrix' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
          }`}
        >
          Security Controls & Permissions Matrix
        </button>
        <button
          onClick={() => setActiveTab('files')}
          className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
            activeTab === 'files' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
          }`}
        >
          Live Bucket File Browser ({safe?.total_files + quar?.total_files} total objects)
        </button>
        <button
          onClick={() => setActiveTab('policies')}
          className={`flex-1 py-2 text-xs font-bold rounded-lg transition ${
            activeTab === 'policies' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
          }`}
        >
          AWS IAM Bucket Policies (JSON)
        </button>
      </div>

      {/* Sub-Tab 1: Security Matrix */}
      {activeTab === 'matrix' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white">Cloud Storage Policy & Access Matrix</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Side-by-side comparison of IAM statements, transport security, and data governance controls.
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase">
                <tr>
                  <th className="px-6 py-3.5">Security Control</th>
                  <th className="px-6 py-3.5 text-emerald-400">Safe Bucket (ALLOW / MASK)</th>
                  <th className="px-6 py-3.5 text-orange-400">Quarantine Bucket (ISOLATION)</th>
                  <th className="px-6 py-3.5">Why This Difference Matters</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">Intended Ingestion</td>
                  <td className="px-6 py-3.5 font-medium text-emerald-300">Clean Files & In-Flight Sanitized PII</td>
                  <td className="px-6 py-3.5 font-medium text-orange-300">PAN, Credit Cards, Aadhaar Records</td>
                  <td className="px-6 py-3.5 text-slate-400">Prevents unredacted financial records from mixing with operational data.</td>
                </tr>
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">Read Access Principals</td>
                  <td className="px-6 py-3.5 font-mono text-slate-200">AppRole, AnalyticsService</td>
                  <td className="px-6 py-3.5 font-mono text-orange-300">ComplianceAuditorRole ONLY</td>
                  <td className="px-6 py-3.5 text-slate-400">Standard business microservices are air-gapped from quarantine files.</td>
                </tr>
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">Standard App Access</td>
                  <td className="px-6 py-3.5">
                    <span className="inline-flex items-center gap-1 font-bold text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Permitted
                    </span>
                  </td>
                  <td className="px-6 py-3.5">
                    <span className="inline-flex items-center gap-1 font-bold text-red-400">
                      <XCircle className="w-3.5 h-3.5" /> Explicitly Denied
                    </span>
                  </td>
                  <td className="px-6 py-3.5 text-slate-400">Eliminates horizontal privilege escalation or accidental public leaks.</td>
                </tr>
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">DLP Gateway Permissions</td>
                  <td className="px-6 py-3.5 font-mono text-slate-200">s3:PutObject, s3:GetObject</td>
                  <td className="px-6 py-3.5 font-mono text-orange-300">s3:PutObject ONLY (Write-Once)</td>
                  <td className="px-6 py-3.5 text-slate-400">Least-privilege: gateway can only deposit quarantined files, never read them back.</td>
                </tr>
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">Encryption at Rest</td>
                  <td className="px-6 py-3.5 font-mono text-slate-200">SSE-S3 (AES-256)</td>
                  <td className="px-6 py-3.5 font-mono text-orange-300">SSE-KMS / SSE-S3 (AES-256)</td>
                  <td className="px-6 py-3.5 text-slate-400">Cryptographic protection against raw disk or storage exfiltration.</td>
                </tr>
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">Transport Security</td>
                  <td className="px-6 py-3.5 text-emerald-400">TLS 1.3 Enforced (Deny HTTP)</td>
                  <td className="px-6 py-3.5 text-emerald-400">TLS 1.3 Enforced (Deny HTTP)</td>
                  <td className="px-6 py-3.5 text-slate-400">Denies any request where aws:SecureTransport is false.</td>
                </tr>
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">S3 Object Lock (WORM)</td>
                  <td className="px-6 py-3.5 text-slate-400">Disabled (Standard lifecycle)</td>
                  <td className="px-6 py-3.5 font-bold text-amber-300">Compliance Mode (7 Years)</td>
                  <td className="px-6 py-3.5 text-slate-400">Anti-tamper: quarantined regulatory evidence cannot be overwritten or deleted.</td>
                </tr>
                <tr>
                  <td className="px-6 py-3.5 font-semibold text-white">CloudTrail SIEM Logging</td>
                  <td className="px-6 py-3.5 text-slate-400">Management Events</td>
                  <td className="px-6 py-3.5 font-bold text-cyan-300">Data Events (Read/Write Alerts)</td>
                  <td className="px-6 py-3.5 text-slate-400">Every inspection of a quarantined object triggers an immediate SIEM audit alert.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sub-Tab 2: Live Files Browser */}
      {activeTab === 'files' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Safe Bucket Files */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" />
                Safe Bucket: s3://{safe?.name}
              </h3>
              <span className="text-xs bg-slate-950 px-2 py-0.5 rounded text-slate-400 font-mono">
                {safe?.files?.length || 0} objects
              </span>
            </div>
            <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
              {safe?.files?.map((f, i) => (
                <div key={i} className="bg-slate-950 border border-slate-800 p-3 rounded-xl text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white truncate max-w-xs">{f.filename}</span>
                    <span className="text-slate-400">{(f.size_bytes / 1024).toFixed(1)} KB</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-500 font-mono text-[11px]">
                    <span className="truncate max-w-xs text-slate-400">{f.key}</span>
                    <span className="text-emerald-400">{f.encryption}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Quarantine Bucket Files */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-orange-400 flex items-center gap-2">
                <Lock className="w-4 h-4" />
                Quarantine Bucket: s3://{quar?.name}
              </h3>
              <span className="text-xs bg-slate-950 px-2 py-0.5 rounded text-orange-400 font-mono">
                {quar?.files?.length || 0} isolated objects
              </span>
            </div>
            <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
              {quar?.files?.map((f, i) => (
                <div key={i} className="bg-slate-950 border border-orange-500/20 p-3 rounded-xl text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-orange-300 truncate max-w-xs">{f.filename}</span>
                    <span className="text-slate-400">{(f.size_bytes / 1024).toFixed(1)} KB</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-500 font-mono text-[11px]">
                    <span className="truncate max-w-xs text-slate-400">{f.key}</span>
                    <span className="text-orange-400 font-semibold">{f.encryption}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab 3: IAM Policies Viewer */}
      {activeTab === 'policies' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-emerald-400">
              Safe Bucket Policy: {safe?.name}
            </h3>
            <p className="text-xs text-slate-400">
              Grants read/write permissions to operational microservices while strictly enforcing TLS encryption in transit.
            </p>
            <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-emerald-300 overflow-x-auto">
              {JSON.stringify(safe?.bucket_policy, null, 2)}
            </pre>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-orange-400">
              Quarantine Bucket Policy (Zero-Trust Lockdown): {quar?.name}
            </h3>
            <p className="text-xs text-slate-400">
              Notice the <span className="text-red-400 font-semibold font-mono">ExplicitDenyStandardAppAccess</span> statement denying normal app roles, and restricting read access solely to <span className="text-orange-300 font-mono">CloudGuardComplianceAuditorRole</span>.
            </p>
            <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-orange-300 overflow-x-auto">
              {JSON.stringify(quar?.bucket_policy, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
