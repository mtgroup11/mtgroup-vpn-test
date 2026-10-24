// @ts-nocheck
/* eslint-disable */
import React from 'react';

// Full class names, spelled out: Tailwind only ships classes it can find
// verbatim in the source, so the old `text-${node.color}-400` template
// produced classes that were never generated (no colour at all).
const COLORS = {
  emerald: { text: 'text-emerald-400', bar: 'bg-emerald-500' },
  amber: { text: 'text-amber-400', bar: 'bg-amber-500' },
  gray: { text: 'text-gray-400', bar: 'bg-gray-500' },
};

export default function TrafficGraph({ nodes = [] }) {
  return (
    <section className="bg-gray-900 border border-green-900/50 p-4 rounded shadow-lg h-full overflow-y-auto">
      <h2 className="text-xl mb-4 border-b border-green-900/30 pb-2 text-green-500">{'Active Nodes'}</h2>
      <ul className="space-y-4 text-sm font-mono text-gray-300">
        {nodes.map((node) => {
          const color = COLORS[node.color] || COLORS.gray;
          return (
            <li key={node.id ?? node.name} className="flex flex-col border-b border-gray-800 pb-2">
              <div className="flex justify-between mb-1">
                <span>{node.name}</span>
                <span className={color.text}>{node.health_status ? `${node.health_status} · ` : ''}{node.traffic}</span>
              </div>
              <div className="w-full bg-gray-800 h-1.5 rounded">
                <div
                  className={`${color.bar} h-1.5 rounded ${node.percent > 80 ? 'animate-pulse' : 'transition-all duration-500'}`}
                  style={{ width: `${node.percent}%` }}
                ></div>
              </div>
            </li>
          );
        })}
        {nodes.length === 0 && <p className="text-gray-500 italic">{'No active nodes.'}</p>}
      </ul>
    </section>
  );
}
