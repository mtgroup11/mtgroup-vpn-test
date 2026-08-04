// @ts-nocheck
/* eslint-disable */
import React from 'react';

export default function RadarChart({ anomalies = [] }) {
  return (
    <section className="bg-gray-900 border border-green-900/50 p-4 rounded shadow-lg h-full flex flex-col">
      <h2 className="text-xl mb-4 border-b border-green-900/30 pb-2 text-green-500">{'AI Anomaly Radar'}</h2>
      <div className="flex-1 flex bg-gray-950 rounded border border-gray-800 relative overflow-hidden">
        
        {/* Radar Animation (Left Side) */}
        <div className="w-1/2 relative flex items-center justify-center border-r border-gray-800">
          <div className="absolute w-[80%] h-[80%] rounded-full border border-green-900/30"></div>
          <div className="absolute w-[60%] h-[60%] rounded-full border border-green-900/50"></div>
          <div className="absolute w-[40%] h-[40%] rounded-full border border-green-800/80"></div>
          <div className="absolute w-1 h-[80%] bg-green-500/20 origin-center animate-spin" style={{ animationDuration: '3s' }}></div>
        </div>
        
        {/* Anomaly Log (Right Side) */}
        <div className="w-1/2 p-2 overflow-y-auto">
          <p className="text-xs text-green-700 mb-2 font-bold uppercase tracking-wider">{'Recent Intercepts'}</p>
          <ul className="space-y-2">
            {anomalies.map((anom, i) => (
              <li key={i} className="text-xs border-l-2 border-red-500 pl-2">
                <div className="text-red-400 font-bold">{anom.ip}</div>
                <div className="text-gray-400 flex justify-between">
                  <span>Score: {anom.score}</span>
                  <span className="text-red-500">[{anom.action}]</span>
                </div>
              </li>
            ))}
            {anomalies.length === 0 && <p className="text-xs text-gray-500 italic">{'No anomalies detected.'}</p>}
          </ul>
        </div>

      </div>
    </section>
  );
}
