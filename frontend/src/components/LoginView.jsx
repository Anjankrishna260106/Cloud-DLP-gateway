import React, { useState } from 'react';
import { Shield, Lock, Mail, User, AlertCircle, ArrowRight } from 'lucide-react';
import { api, setToken } from '../api';

export default function LoginView({ onAuthSuccess }) {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('admin@dlp-gateway.local');
  const [password, setPassword] = useState('Admin@12345');
  const [fullName, setFullName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = isRegister
        ? await api.register(email, password, fullName || 'Seminar User')
        : await api.login(email, password);
      setToken(data.access_token);
      onAuthSuccess(data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fillDemo = (demoEmail, demoPass) => {
    setIsRegister(false);
    setEmail(demoEmail);
    setPassword(demoPass);
    setError('');
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-950/30 via-slate-950 to-slate-950">
      <div className="max-w-md w-full bg-slate-900/90 border border-slate-800 rounded-2xl p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Shield className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">CloudGuard DLP Gateway</h1>
            <p className="text-xs text-slate-400">Pre-Storage Cloud Data Loss Prevention</p>
          </div>
        </div>

        <div className="flex rounded-lg bg-slate-950 p-1 mb-6 border border-slate-800">
          <button
            type="button"
            onClick={() => setIsRegister(false)}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition ${
              !isRegister ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => setIsRegister(true)}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition ${
              isRegister ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            Register
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Jane Doe"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium py-2.5 rounded-lg transition flex items-center justify-center gap-2"
          >
            {loading ? 'Authenticating...' : isRegister ? 'Create Account' : 'Access DLP Gateway'}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-slate-800">
          <p className="text-xs text-slate-400 mb-2.5 font-medium">Quick Demo Accounts:</p>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => fillDemo('admin@dlp-gateway.local', 'Admin@12345')}
              className="text-xs bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg p-2 text-left transition"
            >
              <div className="font-semibold text-cyan-400">Admin Role</div>
              <div className="text-slate-500 truncate">admin@dlp-gateway.local</div>
            </button>
            <button
              type="button"
              onClick={() => fillDemo('demo@dlp-gateway.local', 'User@12345')}
              className="text-xs bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg p-2 text-left transition"
            >
              <div className="font-semibold text-emerald-400">Standard User</div>
              <div className="text-slate-500 truncate">demo@dlp-gateway.local</div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
