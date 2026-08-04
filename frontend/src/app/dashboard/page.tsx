// @ts-nocheck
/* eslint-disable */
'use client';
import React, { useState, useEffect } from 'react';

// Utilities
const generateIP = () => `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

export default function NOCDashboard() {
  // 🎚️ Master Combat Switch
  const [combatMode, setCombatMode] = useState(false);

  // Live Metrics State
  const [metrics, setMetrics] = useState({
    risk_score: 18,
    risk_status: "Low",
    connection_quality: 94,
    incident_timeline: [
      { time: "10:42", action: "XDP_BLACKLIST", details: "Dropped 1400 packets" },
      { time: "10:39", action: "HONEYPOT_TRIGGER", details: "Active probe blocked" },
    ],
    ebpf_status: "Online",
    active_users: 142
  });

  // Toggles state
  const [dpiToggles, setDpiToggles] = useState({
    tlsFragment: true,
    noiseInjection: false,
    warpCoreBypass: false
  });

  // Fetch API / Simulation
  useEffect(() => {
    let intervalTime = combatMode ? 1000 : 3000;
    
    const fetchMetrics = async () => {
      try {
        // Try to fetch real API
        const res = await fetch('/api/metrics/dashboard');
        if (res.ok) {
          const data = await res.json();
          setMetrics(data);
        } else {
          throw new Error("API not ready");
        }
      } catch (err) {
        // Simulated Fallback
        setMetrics(prev => {
          let newRisk = combatMode ? Math.min(100, prev.risk_score + Math.floor(Math.random() * 15)) : Math.max(0, prev.risk_score - Math.floor(Math.random() * 5));
          let status = newRisk <= 25 ? "Low" : newRisk <= 60 ? "Medium" : "Critical";
          
          let newQuality = combatMode ? Math.max(0, prev.connection_quality - Math.floor(Math.random() * 5)) : Math.min(100, prev.connection_quality + Math.floor(Math.random() * 2));

          const newTimeline = [...prev.incident_timeline];
          if (combatMode && Math.random() > 0.5) {
            newTimeline.unshift({
              time: new Date().toLocaleTimeString('en-US', { hour12: false }).slice(0, 5),
              action: Math.random() > 0.5 ? "DPI_THREAT_DETECTED" : "eBPF_BLOCK",
              details: `Auto-mitigated IP ${generateIP()}`
            });
          }

          return {
            ...prev,
            risk_score: newRisk,
            risk_status: status,
            connection_quality: newQuality,
            incident_timeline: newTimeline.slice(0, 5)
          };
        });
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, intervalTime);
    return () => clearInterval(interval);
  }, [combatMode]);

  // Dynamic Theme Classes
  const themeColor = combatMode ? 'rose' : 'emerald';
  const borderClass = combatMode 
    ? 'border-rose-500/40 hover:border-rose-500/70' 
    : 'border-emerald-500/30 hover:border-emerald-500/60';
  const textGradient = combatMode
    ? 'from-rose-500 to-red-600'
    : 'from-emerald-400 to-cyan-500';

  const BentoBox = ({ children, className = '' }: { children: React.ReactNode, className?: string }) => (
    <div className={`bg-zinc-900/60 backdrop-blur-md border rounded-2xl p-6 transition-all duration-300 shadow-2xl overflow-hidden flex flex-col ${borderClass} ${className} ${combatMode ? 'shadow-[0_0_20px_rgba(244,63,94,0.15)]' : 'shadow-black/50'}`}>
      {children}
    </div>
  );

  return (
    <div className={`min-h-screen bg-black text-white font-mono p-6 transition-colors duration-500 ${combatMode ? 'glitch-bg' : ''}`}>
      {/* Glitch style simulation for combat mode */}
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes glitch {
          0% { transform: translate(0) }
          20% { transform: translate(-1px, 1px) }
          40% { transform: translate(-1px, -1px) }
          60% { transform: translate(1px, 1px) }
          80% { transform: translate(1px, -1px) }
          100% { transform: translate(0) }
        }
        .glitch-bg { animation: glitch 0.3s ease-in-out infinite alternate; }
      `}} />

      <header className="mb-8 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-zinc-800 pb-4">
        <div>
          <h1 className={`text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r ${textGradient} mb-2 transition-all duration-300`}>
            MTGroup Ultimate NOC
          </h1>
          <p className="text-zinc-400 text-sm uppercase tracking-widest">Enterprise SaaS & Autonomous Cyber Defense</p>
        </div>
        
        {/* 🎚️ Master Combat Switch */}
        <div className="flex items-center gap-4 bg-zinc-900/80 p-3 rounded-xl border border-zinc-800">
          <span className={`text-sm font-bold uppercase tracking-widest ${combatMode ? 'text-rose-500 animate-pulse' : 'text-zinc-500'}`}>
            ⚔️ Savaş Modu
          </span>
          <button 
            onClick={() => setCombatMode(!combatMode)}
            className={`w-16 h-8 rounded-full p-1 transition-colors duration-300 shadow-inner ${combatMode ? 'bg-rose-600' : 'bg-zinc-700'}`}
          >
            <div className={`w-6 h-6 bg-white rounded-full transition-transform duration-300 shadow-md ${combatMode ? 'translate-x-8' : 'translate-x-0'}`} />
          </button>
        </div>
      </header>

      <main className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 max-w-7xl mx-auto">
        
        {/* 🧩 Hücre 1: Risk Radar */}
        <BentoBox className="xl:col-span-1 flex flex-col items-center justify-center text-center">
          <h2 className="text-xl font-semibold text-zinc-100 mb-2 w-full text-left border-b border-zinc-800 pb-2">Risk Radar</h2>
          <div className="flex-1 flex flex-col items-center justify-center w-full py-4">
            <div className={`text-7xl font-black mb-2 transition-colors duration-500 ${metrics.risk_score > 75 ? 'text-rose-500 drop-shadow-[0_0_15px_rgba(244,63,94,0.5)]' : metrics.risk_score > 30 ? 'text-yellow-500' : 'text-emerald-500'}`}>
              {metrics.risk_score}
            </div>
            <div className="text-zinc-500 text-sm tracking-widest uppercase mb-6">System Risk Score</div>
            
            <div className={`px-4 py-2 rounded-lg text-xs uppercase tracking-widest border transition-all duration-300 ${metrics.risk_score > 75 ? 'bg-rose-500/20 text-rose-400 border-rose-500/50 animate-pulse' : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30'}`}>
              Autonomous Engine: {metrics.risk_score > 75 ? 'ACTIVE (SHIELD ON)' : 'STANDBY'}
            </div>
          </div>
        </BentoBox>

        {/* 🧩 Hücre 2: Quality Index & Nodes */}
        <BentoBox className="xl:col-span-2">
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Connection Quality Index</h2>
          <div className="flex flex-col md:flex-row gap-6">
            <div className="flex flex-col items-center justify-center p-4 bg-black/40 rounded-xl border border-zinc-800 flex-1">
               <div className={`text-6xl font-black mb-2 transition-colors duration-500 ${combatMode ? 'text-rose-400' : 'text-emerald-400'}`}>{metrics.connection_quality}</div>
               <div className="text-xs text-zinc-500 uppercase tracking-widest">Excellence Score</div>
            </div>
            <div className="flex-2 flex flex-col justify-between w-full md:w-2/3 gap-2">
              {[
                { name: 'Germany-Core', status: combatMode ? 'Degraded' : 'Optimal', ping: combatMode ? '85ms' : '24ms' },
                { name: 'Netherlands-Relay', status: 'Optimal', ping: '31ms' },
                { name: 'TR-Edge', status: combatMode ? 'Under Attack' : 'Optimal', ping: combatMode ? '142ms' : '15ms' }
              ].map((node, i) => (
                <div key={i} className="flex justify-between items-center p-3 bg-zinc-800/30 rounded-lg text-sm transition-colors duration-300">
                  <span className="font-semibold text-zinc-300">{node.name}</span>
                  <div className="flex gap-4">
                    <span className={node.status === 'Optimal' ? 'text-emerald-400' : 'text-rose-400'}>{node.status}</span>
                    <span className="text-zinc-500 font-mono">{node.ping}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </BentoBox>

        {/* 🧩 Hücre 3: Config Time Machine */}
        <BentoBox className="xl:col-span-1">
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Config Time Machine</h2>
          <div className="flex flex-col gap-3">
            {[
              { id: "snap_94a2", time: "10 min ago", tag: "Stable" },
              { id: "snap_81f0", time: "2 hours ago", tag: "DPI-Resistant" },
              { id: "snap_77b1", time: "Yesterday", tag: "Performance" }
            ].map((snap, i) => (
              <div key={i} className="p-3 bg-black/40 border border-zinc-800 rounded-lg flex flex-col gap-3 transition-colors duration-300 hover:bg-zinc-900">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-zinc-400 font-mono">{snap.id}</span>
                  <span className="text-zinc-500">{snap.time}</span>
                </div>
                <div className="flex gap-2">
                  <button className="flex-1 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs rounded transition-colors">Rollback</button>
                  <button className={`flex-1 py-1.5 text-xs rounded transition-colors ${combatMode ? 'bg-rose-500/20 text-rose-400 hover:bg-rose-500/40' : 'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/40'}`}>Safe Apply</button>
                </div>
              </div>
            ))}
          </div>
        </BentoBox>

        {/* 🧩 Hücre 4: Smart Preset Advisor */}
        <BentoBox className="xl:col-span-1 flex flex-col">
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Smart Preset Advisor</h2>
          <div className="flex-1 flex flex-col justify-between bg-black/40 p-4 rounded-xl border border-zinc-800">
            <div className="mb-4">
              <span className={`text-xs uppercase tracking-widest font-bold mb-2 block ${combatMode ? 'text-rose-400' : 'text-blue-400'}`}>AI Analysis</span>
              <p className="text-sm text-zinc-300 leading-relaxed transition-opacity duration-300">
                {combatMode 
                  ? "CRITICAL: Heavy deep packet inspection detected. Immediate switch to 'War Mode' playbook recommended to evade GFQ active probes."
                  : "Suggestion: Minor latency detected on TR-Edge. Switching to 'DPI Resistant' mode could optimize throughput by 12%."}
              </p>
            </div>
            <button className={`w-full py-3 rounded-lg font-bold uppercase tracking-widest text-xs transition-colors border shadow-lg ${combatMode ? 'bg-rose-500/20 text-rose-400 border-rose-500/50 hover:bg-rose-500 hover:text-white shadow-rose-500/20' : 'bg-blue-500/20 text-blue-400 border-blue-500/50 hover:bg-blue-500 hover:text-white shadow-blue-500/20'}`}>
              ▶ Playbook'u Çalıştır
            </button>
          </div>
        </BentoBox>

        {/* 🧩 Hücre 5: Spiritus DPI Toggles */}
        <BentoBox className="xl:col-span-1">
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Spiritus DPI Engine</h2>
          <div className="flex flex-col gap-4 mt-2">
            
            <div className="flex justify-between items-center p-3 bg-zinc-800/30 rounded-lg">
              <div>
                <div className="text-sm font-semibold text-zinc-200">TLS Fragment</div>
                <div className="text-xs text-zinc-500">Evade SNI detection</div>
              </div>
              <button onClick={() => setDpiToggles(p => ({...p, tlsFragment: !p.tlsFragment}))} className={`w-12 h-6 rounded-full p-1 transition-colors duration-300 ${dpiToggles.tlsFragment ? (combatMode ? 'bg-rose-500' : 'bg-emerald-500') : 'bg-zinc-700'}`}>
                <div className={`w-4 h-4 bg-white rounded-full transition-transform duration-300 ${dpiToggles.tlsFragment ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>

            <div className="flex justify-between items-center p-3 bg-zinc-800/30 rounded-lg">
              <div>
                <div className="text-sm font-semibold text-zinc-200">Noise Injection</div>
                <div className="text-xs text-zinc-500">Obfuscate packet length</div>
              </div>
              <button onClick={() => setDpiToggles(p => ({...p, noiseInjection: !p.noiseInjection}))} className={`w-12 h-6 rounded-full p-1 transition-colors duration-300 ${dpiToggles.noiseInjection ? (combatMode ? 'bg-rose-500' : 'bg-emerald-500') : 'bg-zinc-700'}`}>
                <div className={`w-4 h-4 bg-white rounded-full transition-transform duration-300 ${dpiToggles.noiseInjection ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>

            <div className="flex justify-between items-center p-3 bg-zinc-800/30 rounded-lg">
              <div>
                <div className="text-sm font-semibold text-zinc-200">Warp Core Bypass</div>
                <div className="text-xs text-zinc-500">Quantum-resistant tunnel</div>
              </div>
              <button onClick={() => setDpiToggles(p => ({...p, warpCoreBypass: !p.warpCoreBypass}))} className={`w-12 h-6 rounded-full p-1 transition-colors duration-300 ${dpiToggles.warpCoreBypass ? (combatMode ? 'bg-rose-500' : 'bg-emerald-500') : 'bg-zinc-700'}`}>
                <div className={`w-4 h-4 bg-white rounded-full transition-transform duration-300 ${dpiToggles.warpCoreBypass ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>

          </div>
        </BentoBox>

        {/* Bonus Hücre: Live Incident Timeline (Görsel Zenginlik) */}
        <BentoBox className="xl:col-span-3">
          <h2 className="text-xl font-semibold text-zinc-100 mb-4 border-b border-zinc-800 pb-2">Live Incident Timeline</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
             {metrics.incident_timeline.map((inc, i) => (
                <div key={i} className="p-3 bg-black/50 border border-zinc-800 rounded-lg shadow-inner">
                   <div className={`text-xs font-bold mb-1 transition-colors duration-300 ${combatMode ? 'text-rose-400' : 'text-emerald-400'}`}>{inc.time} - {inc.action}</div>
                   <div className="text-xs text-zinc-400">{inc.details}</div>
                </div>
             ))}
             {metrics.incident_timeline.length === 0 && <div className="text-zinc-500 text-sm">No recent incidents.</div>}
          </div>
        </BentoBox>

      </main>
    </div>
  );
}
