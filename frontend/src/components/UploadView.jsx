import React, { useState } from 'react';
import { UploadCloud, FileText, ShieldCheck, ShieldAlert, Ban, EyeOff, Download, AlertCircle, ArrowRight } from 'lucide-react';
import { api } from '../api';
import { ActionBadge, RiskBadge } from './BadgeHelpers';

export default function UploadView() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setResult(null);
      setError('');
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) return;
    setScanning(true);
    setError('');
    setResult(null);
    try {
      const res = await api.uploadFile(selectedFile);
      setResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  const handleDownload = async () => {
    if (!result?.event) return;
    try {
      await api.downloadFileBlob(
        result.event.id,
        result.event.sanitized_filename || result.event.filename
      );
    } catch (err) {
      alert(err.message);
    }
  };

  const ev = result?.event;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Pre-Storage DLP Upload & Inspection Gateway</h1>
        <p className="text-sm text-slate-400">
          Files are extracted, analyzed, classified, and sanitized or blocked BEFORE touching AWS S3 storage.
        </p>
      </div>

      {/* Pipeline Diagram Banner */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-300">
        {['1. Ingest File', '2. Extract Text', '3. Detect Entities', '4. Risk Classification', '5. Policy Enforcement', '6. S3 Routing / Reject'].map((step, i, arr) => (
          <React.Fragment key={step}>
            <span className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg font-medium text-cyan-300">
              {step}
            </span>
            {i < arr.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-slate-600 hidden sm:block" />}
          </React.Fragment>
        ))}
      </div>

      {/* Upload Dropzone */}
      <form onSubmit={handleUpload} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
        <label className="flex flex-col items-center justify-center border-2 border-dashed border-slate-700 hover:border-cyan-500/70 rounded-xl p-10 cursor-pointer bg-slate-950/60 transition">
          <UploadCloud className="w-12 h-12 text-cyan-400 mb-3" />
          <span className="text-sm font-medium text-white">
            {selectedFile ? selectedFile.name : 'Click to select a file (.txt, .csv, .pdf, .docx, .xlsx)'}
          </span>
          <span className="text-xs text-slate-500 mt-1">
            {selectedFile ? `${(selectedFile.size / 1024).toFixed(2)} KB` : 'Max size: 10 MB'}
          </span>
          <input
            type="file"
            onChange={handleFileChange}
            className="hidden"
          />
        </label>

        {error && (
          <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!selectedFile || scanning}
            className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium px-6 py-2.5 rounded-xl transition flex items-center gap-2"
          >
            {scanning ? 'Running Pre-Storage DLP Inspection...' : 'Scan & Route to Cloud Storage'}
          </button>
        </div>
      </form>

      {/* Instant Inspection Result */}
      {ev && (
        <div className={`border rounded-2xl p-6 space-y-5 ${
          ev.policy_action === 'BLOCK' ? 'bg-red-950/20 border-red-500/40' :
          ev.policy_action === 'QUARANTINE' ? 'bg-orange-950/20 border-orange-500/40' :
          ev.policy_action === 'MASK' ? 'bg-amber-950/20 border-amber-500/40' :
          'bg-emerald-950/20 border-emerald-500/40'
        }`}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              {ev.policy_action === 'ALLOW' && <ShieldCheck className="w-8 h-8 text-emerald-400" />}
              {ev.policy_action === 'MASK' && <EyeOff className="w-8 h-8 text-amber-400" />}
              {ev.policy_action === 'QUARANTINE' && <ShieldAlert className="w-8 h-8 text-orange-400" />}
              {ev.policy_action === 'BLOCK' && <Ban className="w-8 h-8 text-red-400" />}
              <div>
                <div className="flex items-center gap-2.5">
                  <h2 className="text-lg font-bold text-white">
                    {ev.policy_action === 'BLOCK' ? 'UPLOAD REJECTED BY DLP GATEWAY' : `ROUTED: ${ev.destination_bucket}`}
                  </h2>
                  <ActionBadge action={ev.policy_action} />
                  <RiskBadge risk={ev.risk_level} />
                </div>
                <p className="text-xs text-slate-300 mt-1">{ev.decision_reason}</p>
              </div>
            </div>

            {result.stored_in_s3 && (
              <button
                onClick={handleDownload}
                className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 px-4 py-2 rounded-lg text-xs font-medium transition"
              >
                <Download className="w-4 h-4" />
                Download {ev.is_masked ? 'Sanitized' : 'Stored'} File
              </button>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
              <div className="text-slate-400">Scan ID</div>
              <div className="font-mono text-cyan-300 mt-0.5">{ev.id}</div>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
              <div className="text-slate-400">Risk Score</div>
              <div className="font-bold text-white mt-0.5">{ev.risk_score} / 100</div>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
              <div className="text-slate-400">Extractor Used</div>
              <div className="font-mono text-slate-200 mt-0.5">{ev.extractor_used}</div>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
              <div className="text-slate-400">Inspection Time</div>
              <div className="font-semibold text-white mt-0.5">{ev.processing_time_ms} ms</div>
            </div>
          </div>

          {ev.findings && ev.findings.length > 0 && (
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
              <h3 className="text-xs font-semibold uppercase text-slate-400 mb-3">
                Detected Entities ({ev.findings_count})
              </h3>
              <div className="space-y-2">
                {ev.findings.map((f, idx) => (
                  <div key={idx} className="flex flex-wrap items-center justify-between gap-2 text-xs bg-slate-900 border border-slate-800 px-3 py-2 rounded-lg">
                    <div className="flex items-center gap-2.5">
                      <span className="font-bold text-cyan-400">{f.entity_type}</span>
                      <span className="font-mono text-amber-300">{f.value_preview}</span>
                    </div>
                    <div className="text-slate-400">
                      Confidence: <span className="text-white">{Math.round(f.confidence * 100)}%</span> ({f.validation_status})
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {ev.masked_preview && (
            <div>
              <h3 className="text-xs font-semibold uppercase text-emerald-400 mb-2">
                Sanitized Content Preview (Persisted to Safe Bucket)
              </h3>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-emerald-300 whitespace-pre-wrap">
                {ev.masked_preview}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
