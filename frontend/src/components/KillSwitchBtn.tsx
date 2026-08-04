// @ts-nocheck
/* eslint-disable */
import React from 'react';

interface KillSwitchBtnProps {
  isActive: boolean;
  onToggle: () => void;
}

export default function KillSwitchBtn({ isActive, onToggle }: KillSwitchBtnProps) {
  return (
    <section className="bg-gray-900 border border-red-900/50 p-4 rounded shadow-lg flex flex-col justify-between h-full">
      <div>
        <h2 className="text-xl text-red-500 mb-4 border-b border-red-900/30 pb-2">{'Command Center'}</h2>
        <p className="text-xs text-gray-400 mb-4">{'Immediate tactical actions. Use with caution. Bypasses normal routing.'}</p>
      </div>
      <button 
        onClick={onToggle}
        className={`w-full py-4 font-bold text-lg rounded transition-all duration-300 ${isActive ? 'bg-gray-950 text-red-600 border border-red-800 shadow-[0_0_15px_rgba(220,38,38,0.5)]' : 'bg-red-900 hover:bg-red-800 text-white'}`}
      >
        {isActive ? 'RELEASE KERNEL LOCKDOWN' : 'TRIGGER KERNEL KILL SWITCH'}
      </button>
    </section>
  );
}
