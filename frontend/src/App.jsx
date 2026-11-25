import React, { useEffect, useState } from 'react';
import {
  Shield, LayoutDashboard, UploadCloud, Sliders, FlaskConical,
  LogOut, ShieldAlert, ShieldCheck, FileText, Database
} from 'lucide-react';
import { api, setToken } from './api';
import LoginView from './components/LoginView';
import DashboardView from './components/DashboardView';
import UploadView from './components/UploadView';
import PoliciesView from './components/PoliciesView';
import SecurityLabView from './components/SecurityLabView';
import BucketComparisonView from './components/BucketComparisonView';

export default function App() {
  const [user, setUser] = useState(null);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [securityMode, setSecurityMode] = useState('remediated');

  useEffect(() => {
    const verify = async () => {
      try {
        const res = await api.getMe();
        setUser(res.user);
        setSecurityMode(res.security_mode || 'remediated');
      } catch {
        setToken(null);
      } finally {
        setCheckingAuth(false);
      }
    };
    verify();
  }, []);

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {
      // ignore
    }
    setToken(null);
    setUser(null);
  };

  if (checkingAuth) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400 text-sm">
        Initializing CloudGuard DLP Gateway...
      </div>
    );
  }

  if (!user) {
    return <LoginView onAuthSuccess={(u) => setUser(u)} />;
  }

  const navItems = [
    { id: 'dashboard', label: 'Security Dashboard', icon: LayoutDashboard },
    { id: 'upload', label: 'Upload & Inspect', icon: UploadCloud },
    { id: 'buckets', label: 'S3 Dual-Bucket Posture', icon: Database },
    { id: 'policies', label: 'Policy Engine', icon: Sliders },
    { id: 'lab', label: 'Security Seminar Lab', icon: FlaskConical },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col md:flex-row">
      {/* Sidebar */}
      <aside className="w-full md:w-64 bg-slate-900 border-b md:border-b-0 md:border-r border-slate-800 flex flex-col justify-between p-4">
        <div>
          <div className="flex items-center gap-2.5 px-2 py-3 mb-6">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-sm text-white">CloudGuard DLP</div>
              <div className="text-[11px] text-slate-400">Pre-Storage S3 Gateway</div>
            </div>
          </div>

          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition ${
                    active
                      ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="pt-4 border-t border-slate-800 space-y-3 mt-6">
          <div className={`px-3 py-2 rounded-lg border text-xs flex items-center gap-2 ${
            securityMode === 'vulnerable'
              ? 'bg-red-950/40 border-red-500/40 text-red-300'
              : 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
          }`}>
            {securityMode === 'vulnerable' ? <ShieldAlert className="w-4 h-4 shrink-0" /> : <ShieldCheck className="w-4 h-4 shrink-0" />}
            <div>
              <div className="font-bold uppercase">{securityMode} Mode</div>
            </div>
          </div>

          <div className="px-2">
            <div className="text-xs font-semibold text-white truncate">{user.full_name}</div>
            <div className="text-[11px] text-slate-400 truncate">{user.email}</div>
            <span className="inline-block mt-1 text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
              {user.role}
            </span>
          </div>

          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-slate-800 transition"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-6 md:p-8 overflow-y-auto">
        {activeTab === 'dashboard' && <DashboardView />}
        {activeTab === 'upload' && <UploadView />}
        {activeTab === 'buckets' && <BucketComparisonView />}
        {activeTab === 'policies' && <PoliciesView user={user} />}
        {activeTab === 'lab' && (
          <SecurityLabView
            securityMode={securityMode}
            onModeChange={(m) => setSecurityMode(m)}
          />
        )}
      </main>
    </div>
  );
}
