// @ts-nocheck
/* eslint-disable */
import React from 'react';

export default function TrafficGraph({ nodes = [] }) {
  return (
    <section className="bg-gray-900 border border-green-900/50 p-4 rounded shadow-lg h-full overflow-y-auto">
      <h2 className="text-xl mb-4 border-b border-green-900/30 pb-2 text-green-500">{'Active Node Traffic'}</h2>
      <ul className="space-y-4 text-sm font-mono text-gray-300">
        {nodes.map((node, i) => (
          <li key={i} className="flex flex-col border-b border-gray-800 pb-2">
            <div className="flex justify-between mb-1">
              <span>{node.name}</span> 
              <span className={`text-${node.color}-400`}>{node.traffic}</span>
            </div>
            <div className="w-full bg-gray-800 h-1.5 rounded">
              <div 
                className={`bg-${node.color}-500 h-1.5 rounded ${node.percent > 80 ? 'animate-pulse' : 'transition-all duration-500'}`} 
                style={{width: `${node.percent}%`}}
              ></div>
            </div>
          </li>
        ))}
        {nodes.length === 0 && <p className="text-gray-500 italic">{'Waiting for telemetry...'}</p>}
      </ul>
    </section>
  );
}
