import React, { useEffect, useState } from 'react';
import { ShieldAlert, ShieldCheck, Terminal, RefreshCw, Zap } from 'lucide-react';
import { api } from '../api';

export default function SecurityLabView({ securityMode, onModeChange }) {
  const [s3Posture, setS3Posture] = useState(null);
  const [redosInput, setRedosInput] = useState('aaaaaaaaaaaaaaaaaaaaaaaa!');
  const [redosResult, setRedosResult] = useState(null);
  const [switching, setSwitching] = useState(false);

  const loadPosture = async () => {
    try {
      const data = await api.getS3Audit();
      setS3Posture(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadPosture();
  }, [securityMode]);

  const toggleMode = async (newMode) => {
    setSwitching(true);
    try {
      await api.setSecurityMode(newMode);
      onModeChange(newMode);
    } catch (err) {
      alert(err.message);
    } finally {
      setSwitching(false);
    }
  };

  const runRedos = async () => {
    try {
      const res = await api.runReDoSTest(redosInput);
      setRedosResult(res);
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Cloud Security Seminar Lab</h1>
          <p className="text-sm text-slate-400">
            Toggle between Vulnerable Demo and Remediated modes to inspect live posture differences.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 p-1.5 rounded-xl">
          <button
            disabled={switching}
            onClick={() => toggleMode('vulnerable')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
              securityMode === 'vulnerable'
                ? 'bg-red-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            Vulnerable Demo
          </button>
          <button
            disabled={switching}
            onClick={() => toggleMode('remediated')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-1.5 ${
              securityMode === 'remediated'
                ? 'bg-emerald-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            Remediated (Secure)
          </button>
        </div>
      </div>

      {/* S3 Bucket Posture Panel */}
      {s3Posture && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              AWS S3 Quarantine Bucket Security Posture
            </h2>
            <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${
              s3Posture.mode === 'vulnerable' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
            }`}>
              {s3Posture.mode.toUpperCase()}
            </span>
          </div>
          <p className={`text-xs p-3 rounded-lg border ${
            s3Posture.mode === 'vulnerable'
              ? 'bg-red-950/30 border-red-500/30 text-red-300'
              : 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
          }`}>
            {s3Posture.risk_finding}
          </p>
          <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-300 overflow-x-auto">
            {JSON.stringify(s3Posture.bucket_policy, null, 2)}
          </pre>
        </div>
      )}

      {/* ReDoS Benchmark Tester */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" />
          ReDoS Regex Engine Latency Test
        </h2>
        <div className="flex gap-3">
          <input
            type="text"
            value={redosInput}
            onChange={(e) => setRedosInput(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-xs font-mono text-white"
          />
          <button
            onClick={runRedos}
            className="bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition"
          >
            Run Regex Benchmark
          </button>
        </div>
        {redosResult && (
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono space-y-1">
            <div>Mode: <span className="text-cyan-400">{redosResult.security_mode}</span></div>
            <div>Pattern: <span className="text-slate-300">{redosResult.regex_pattern}</span></div>
            <div>
              Execution Time:{' '}
              <span className={redosResult.backtracking_warning ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>
                {redosResult.execution_time_ms} ms
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
