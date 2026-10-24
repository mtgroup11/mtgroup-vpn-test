// @ts-nocheck
/* eslint-disable */
'use client';
import React, { useCallback, useEffect, useState } from 'react';
import TrafficGraph from '@/components/TrafficGraph';

// Every number on this page comes from GET /api/metrics/dashboard (via the
// server-side proxy in app/api/metrics/dashboard/route.ts). There is
// deliberately no simulated fallback: the previous version filled the
// screen with Math.random() numbers whenever the API was unreachable, so an
// operator could be looking at an invented "Low risk" during an outage.
// If the data is unavailable, the page says so.

const TOKEN_KEY = 'mtg_admin_token';

function loadToken() {
  try { return window.sessionStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}
function saveToken(token) {
  try {
    if (token) window.sessionStorage.setItem(TOKEN_KEY, token);
    else window.sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* storage unavailable — keep the token in memory only */ }
}

function LoginForm({ onLogin, message }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(message || '');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.access_token) {
        setError(data.error || `Login failed (${res.status})`);
      } else {
        onLogin(data.access_token);
      }
    } catch {
      setError('Panel backend unreachable');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white font-mono flex items-center justify-center p-6">
      <form onSubmit={submit} className="w-full max-w-sm bg-zinc-900/60 border border-emerald-500/30 rounded-2xl p-6 flex flex-col gap-4">
        <h1 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-500">MTGroup NOC</h1>
        <input className="bg-black/50 border border-zinc-700 rounded px-3 py-2" placeholder="Admin username"
               autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <input className="bg-black/50 border border-zinc-700 rounded px-3 py-2" placeholder="Password" type="password"
               autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <div className="text-rose-400 text-sm">{error}</div>}
        <button disabled={busy || !username || !password}
                className="py-2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 hover:bg-emerald-500/40 disabled:opacity-40">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}

const Stat = ({ label, value, hint }) => (
  <div className="flex flex-col p-3 bg-black/40 border border-zinc-800 rounded-lg">
    <span className="text-xs text-zinc-500 uppercase tracking-widest">{label}</span>
    <span className="text-2xl font-bold text-zinc-100">{value}</span>
    {hint && <span className="text-xs text-zinc-500">{hint}</span>}
  </div>
);

export default function NOCDashboard() {
  const [token, setToken] = useState('');
  const [ready, setReady] = useState(false);
  const [metrics, setMetrics] = useState(null);
  const [error, setError] = useState('');
  const [loginMessage, setLoginMessage] = useState('');

  useEffect(() => { setToken(loadToken()); setReady(true); }, []);

  const logout = useCallback((message = '') => {
    saveToken('');
    setToken('');
    setMetrics(null);
    setLoginMessage(message);
  }, []);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    const fetchMetrics = async () => {
      try {
        const res = await fetch('/api/metrics/dashboard', {
          headers: { Authorization: `Bearer ${token}` },
          cache: 'no-store',
        });
        if (res.status === 401 || res.status === 403) {
          if (!cancelled) logout('Session expired or revoked — please sign in again.');
          return;
        }
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.error || `backend returned ${res.status}`);
        }
        const data = await res.json();
        if (!cancelled) { setMetrics(data); setError(''); }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'backend unreachable');
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [token, logout]);

  if (!ready) return null;
  if (!token) {
    return <LoginForm message={loginMessage} onLogin={(t) => { saveToken(t); setLoginMessage(''); setToken(t); }} />;
  }

  const m = metrics;
  const risk = m?.risk_score ?? null;
  const critical = risk !== null && risk > 75;

  const BentoBox = ({ children, className = '' }) => (
    <div className={`bg-zinc-900/60 backdrop-blur-md border rounded-2xl p-6 shadow-2xl overflow-hidden flex flex-col ${critical ? 'border-rose-500/40' : 'border-emerald-500/30'} ${className}`}>
      {children}
    </div>
  );

  return (
    <div className="min-h-screen bg-black text-white font-mono p-6">
      <header className="mb-8 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-500 mb-2">MTGroup Ultimate NOC</h1>
          <p className="text-zinc-400 text-sm uppercase tracking-widest">
            {m ? `Updated ${new Date(m.generated_at).toLocaleTimeString()}` : 'Waiting for first telemetry…'}
          </p>
        </div>
        <button onClick={() => logout()} className="px-4 py-2 text-xs uppercase tracking-widest rounded border border-zinc-700 text-zinc-400 hover:text-white">
          Sign out
        </button>
      </header>

      {error && (
        <div className="max-w-7xl mx-auto mb-6 p-3 rounded-lg border border-rose-500/50 bg-rose-500/10 text-rose-300 text-sm">
          Telemetry unavailable: {error}{m ? ' — showing the last successful reading.' : ''}
        </div>
      )}

      <main className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 max-w-7xl mx-auto">
        <BentoBox className="items-center justify-center text-center">
          <h2 className="text-xl font-semibold text-zinc-100 mb-2 w-full text-left border-b border-zinc-800 pb-2">Risk Radar</h2>
          <div className={`text-7xl font-black my-4 ${critical ? 'text-rose-500' : risk !== null && risk > 30 ? 'text-yellow-500' : 'text-emerald-500'}`}>
            {risk ?? '—'}
          </div>
          <div className="text-zinc-500 text-sm tracking-widest uppercase">{m?.risk_status ?? 'No data'}</div>
        </BentoBox>

        <BentoBox className="xl:col-span-2">
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Fleet</h2>
          <div className="flex flex-col md:flex-row gap-6">
            <div className="flex flex-col items-center justify-center p-4 bg-black/40 rounded-xl border border-zinc-800 flex-1">
              <div className="text-6xl font-black text-emerald-400">{m ? `${m.connection_quality}%` : '—'}</div>
              <div className="text-xs text-zinc-500 uppercase tracking-widest">Nodes answering health checks</div>
              {m && <div className="text-xs text-zinc-500 mt-1">{m.healthy_nodes} / {m.total_active_nodes} healthy</div>}
            </div>
            <div className="w-full md:w-2/3">
              <TrafficGraph nodes={m?.nodes ?? []} />
            </div>
          </div>
        </BentoBox>

        <BentoBox>
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Users</h2>
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Active" value={m?.active_users ?? '—'} />
            <Stat label="Total" value={m?.total_users ?? '—'} />
          </div>
        </BentoBox>

        <BentoBox>
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Defense</h2>
          <div className="grid grid-cols-2 gap-3">
            <Stat label="eBPF" value={m?.ebpf_status ?? '—'} />
            <Stat label="XDP bans" value={m?.ebpf_active_bans ?? '—'} />
            <Stat label="Honeypot hits" value={m?.honeypot_triggers ?? '—'} hint="since panel start" />
          </div>
        </BentoBox>

        <BentoBox>
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Host</h2>
          <div className="grid grid-cols-2 gap-3">
            <Stat label="CPU" value={m ? `${m.system.cpu_percent}%` : '—'} />
            <Stat label="RAM" value={m ? `${m.system.ram_percent}%` : '—'} />
          </div>
        </BentoBox>

        <BentoBox className="xl:col-span-3">
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Incident Timeline</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            {(m?.incident_timeline ?? []).map((inc, i) => (
              <div key={i} className="p-3 bg-black/50 border border-zinc-800 rounded-lg">
                <div className="text-xs font-bold mb-1 text-emerald-400">{inc.time} - {inc.action}</div>
                <div className="text-xs text-zinc-400">{inc.details}</div>
              </div>
            ))}
            {(!m || m.incident_timeline.length === 0) && <div className="text-zinc-500 text-sm">No recent incidents.</div>}
          </div>
        </BentoBox>
      </main>
    </div>
  );
}
