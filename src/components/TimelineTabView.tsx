import React from 'react';
import { Activity, Calendar, ShieldAlert, TrendingUp, TrendingDown, Clock, CheckCircle } from 'lucide-react';
import { ScanReport } from '../types';

interface TimelineTabProps {
  report: ScanReport;
  history: ScanReport[];
  loadingHistory: boolean;
  computeMetrics: (reports: ScanReport[]) => any;
  getGrade: (score: number) => { char: string; desc: string; color: string; stroke: string };
}

export function TimelineTabView({ report, history, loadingHistory, computeMetrics, getGrade }: TimelineTabProps) {
  const tMetrics = computeMetrics(history);

  // Compile sorted checkpoints chronologically
  const sortedHistory = [...history].sort((a, b) => new Date(a.scannedAt).getTime() - new Date(b.scannedAt).getTime());
  
  // Custom High-Tech SVG Progress Coordinates
  const points = sortedHistory.map((h, idx) => {
    const x = sortedHistory.length > 1 ? (idx / (sortedHistory.length - 1)) * 400 + 50 : 250;
    const y = 135 - (h.score / 100) * 95; // Map score 0-100 to y inside viewBox heights
    return {
      x,
      y,
      score: h.score,
      id: h.id,
      label: new Date(h.scannedAt).toLocaleDateString([], { month: 'short', day: 'numeric' })
    };
  });

  let linePath = '';
  let areaPath = '';
  if (points.length === 1) {
    const p = points[0];
    linePath = `M 50 ${p.y} L 450 ${p.y}`;
    areaPath = `M 50 ${p.y} L 450 ${p.y} L 450 140 L 50 140 Z`;
  } else if (points.length > 1) {
    linePath = points.map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
    areaPath = `${linePath} L ${points[points.length - 1].x} 140 L ${points[0].x} 140 Z`;
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* 1. Progression Metrics Grid (PROMINENT OVERVIEW) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Metric A: Score progression delta */}
        <div className="p-4 bg-white/[0.015] border border-white/[0.04] rounded-2xl flex flex-col justify-between hover:bg-white/[0.025] transition-colors duration-300">
          <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest flex items-center gap-1.5">
            <Activity size={10} className="text-[#00FF88]" />
            Score Progression
          </span>
          <div className="my-2">
            <span className="font-tech text-3.5xl font-black text-white">{report.score}%</span>
            <span className={`inline-flex items-center gap-1 ml-2 text-xs font-bold leading-none ${tMetrics.scoreDelta >= 0 ? 'text-[#00FF88]' : 'text-red-400'}`}>
              {tMetrics.scoreDelta >= 0 ? '+' : ''}{tMetrics.scoreDelta}
            </span>
          </div>
          <span className="font-condensed text-[9px] uppercase tracking-wider text-[#484F58] font-bold">
            Compared to initial ingestion
          </span>
        </div>

        {/* Metric B: Improvement % */}
        <div className="p-4 bg-white/[0.015] border border-white/[0.04] rounded-2xl flex flex-col justify-between hover:bg-white/[0.025] transition-colors duration-300">
          <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest flex items-center gap-1.5">
            <TrendingUp size={10} className="text-[#00FF88]" />
            Security Improvement
          </span>
          <div className="my-2 flex items-baseline">
            <span className="font-tech text-3.5xl font-black text-[#00FF88]">
              {tMetrics.improvementPercent >= 0 ? '+' : ''}{tMetrics.improvementPercent}%
            </span>
          </div>
          <span className="font-condensed text-[9px] uppercase tracking-wider text-[#484F58] font-bold flex items-center gap-1">
            {tMetrics.scoreDelta >= 0 ? (
              <span className="text-[#00FF88]">▲ Upward progress</span>
            ) : (
              <span className="text-red-400">▼ System degradation</span>
            )}
          </span>
        </div>

        {/* Metric C: Resolved findings */}
        <div className="p-4 bg-white/[0.015] border border-white/[0.04] rounded-2xl flex flex-col justify-between hover:bg-white/[0.025] transition-colors duration-300">
          <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest flex items-center gap-1.5">
            <CheckCircle size={10} className="text-[#00FF88]" />
            Vulnerabilities Repaired
          </span>
          <div className="my-2">
            <span className="font-tech text-3.5xl font-black text-white">{tMetrics.findingsResolved}</span>
            <span className="font-sans text-xs text-[#8B949E] ml-1.5">instances</span>
          </div>
          <span className="font-condensed text-[9px] uppercase tracking-wider text-[#484F58] font-bold">
            Automatically patched in sandbox
          </span>
        </div>

        {/* Metric D: New findings */}
        <div className="p-4 bg-white/[0.015] border border-white/[0.04] rounded-2xl flex flex-col justify-between hover:bg-white/[0.025] transition-colors duration-300">
          <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest flex items-center gap-1.5">
            <ShieldAlert size={10} className="text-[#FF8C00]" />
            New Infiltrations
          </span>
          <div className="my-2">
            <span className="font-tech text-3.5xl font-black text-white">+{tMetrics.newFindings}</span>
            <span className="font-sans text-xs text-[#8B949E] ml-1.5">unverified</span>
          </div>
          <span className="font-condensed text-[9px] uppercase tracking-wider text-[#484F58] font-bold">
            Discovered since baseline audit
          </span>
        </div>
      </div>

      {/* 2. Interactive SVG Score Progress Chart */}
      <section className="glass-card hover:border-white/[0.05] border border-white/[0.02] rounded-2xl overflow-hidden p-4 md:p-5.5 bg-[#03060a]/20">
        <div className="flex flex-wrap items-center justify-between border-b border-white/[0.03] pb-3 mb-4 gap-4">
          <div>
            <h4 className="font-display text-sm font-black text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="text-[#00FF88]" size={16} />
              Vulnerability Score Line Progression
            </h4>
            <p className="font-condensed text-[11px] text-[#8B949E] uppercase tracking-wider mt-0.5">
              // Continuous compliance security score trace mapped with Postgres events
            </p>
          </div>
          <span className="font-condensed text-[10px] text-[#00FF88] border border-[#00FF88]/20 bg-[#00FF88]/5 px-2.5 py-1 rounded-lg font-bold tracking-widest uppercase">
            {tMetrics.trend}
          </span>
        </div>

        {points.length === 0 ? (
          <div className="text-center py-10 font-sans text-xs text-[#8B949E]">
            Establishing sequence baseline, running background telemetry...
          </div>
        ) : (
          <div className="relative">
            <svg viewBox="0 0 500 160" className="w-full h-48 md:h-56 overflow-visible">
              <defs>
                <linearGradient id="timelineGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00FF88" stopOpacity="0.18" />
                  <stop offset="100%" stopColor="#00FF88" stopOpacity="0.0" />
                </linearGradient>
              </defs>
              {/* Grid Lines */}
              <line x1="40" y1="40" x2="460" y2="40" stroke="rgba(255,255,255,0.02)" strokeDasharray="3" />
              <line x1="40" y1="90" x2="460" y2="90" stroke="rgba(255,255,255,0.02)" strokeDasharray="3" />
              <line x1="40" y1="135" x2="460" y2="135" stroke="rgba(255,255,255,0.02)" strokeDasharray="3" />

              {/* Y axis text */}
              <text x="15" y="44" className="font-mono text-[8.5px] fill-[#484F58] font-bold">100</text>
              <text x="15" y="94" className="font-mono text-[8.5px] fill-[#484F58] font-bold">50</text>
              <text x="15" y="139" className="font-mono text-[8.5px] fill-[#484F58] font-bold">0</text>

              {/* Neon Glow Shaded Area Under Line */}
              {areaPath && <path d={areaPath} fill="url(#timelineGrad)" />}

              {/* Main Glowing Line Path */}
              {linePath && (
                <path
                  d={linePath}
                  fill="none"
                  stroke="#00FF88"
                  strokeWidth="2"
                  strokeLinecap="round"
                  style={{ filter: 'drop-shadow(0px 0px 6px rgba(0, 255, 136, 0.45))' }}
                />
              )}

              {/* Grid interactive checkpoint dots */}
              {points.map((p, idx) => (
                <g key={p.id} className="group cursor-pointer">
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r="4"
                    fill="#040810"
                    stroke="#00FF88"
                    strokeWidth="2"
                    style={{ filter: 'drop-shadow(0px 0px 4px rgba(0, 255, 136, 0.6))' }}
                  />
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r="8"
                    fill="#00FF88"
                    fillOpacity="0"
                    className="hover:fill-opacity-10 transition-all duration-200"
                  />
                  
                  {/* Floating interactive tooltip */}
                  <g className="opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none">
                    <rect
                      x={p.x - 22}
                      y={p.y - 30}
                      width="44"
                      height="18"
                      rx="4"
                      fill="#0d1117"
                      stroke="rgba(0, 255, 136, 0.35)"
                      strokeWidth="1"
                    />
                    <text
                      x={p.x}
                      y={p.y - 18}
                      textAnchor="middle"
                      className="font-tech text-[9px] fill-white font-extrabold"
                    >
                      {p.score}%
                    </text>
                  </g>

                  {/* X axis descriptions */}
                  <text
                    x={p.x}
                    y="155"
                    textAnchor="middle"
                    className="font-mono text-[8px] fill-[#8B949E] group-hover:fill-[#00FF88] transition-colors"
                  >
                    {p.label}
                  </text>
                </g>
              ))}
            </svg>
          </div>
        )}
      </section>

      {/* 3. Repository Health Summary Cards */}
      <section className="bg-white/[0.005] border border-white/[0.03] rounded-2xl p-4 md:p-5.5">
        <h4 className="font-display text-[10px] text-[#484F58] uppercase tracking-[0.2em] mb-4 font-black border-b border-white/[0.03] pb-2.5 flex items-center gap-1.5 leading-none">
          REPOSITORY HEALTH PARAMETER ASSESSING REPORT
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Trend Card */}
          <div className="p-4 bg-white/[0.01] border border-white/[0.03] rounded-xl">
            <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest block leading-none mb-2">Security Trend</span>
            <div className="flex items-center gap-2 mt-1.5">
              {tMetrics.scoreDelta >= 0 ? (
                <div className="p-1 px-1.5 rounded bg-[#00FF88]/10 text-[#00FF88] inline-flex items-center gap-1 font-condensed font-black text-[10px] tracking-wider uppercase border border-[#00FF88]/20">
                  ▲ {tMetrics.trend}
                </div>
              ) : (
                <div className="p-1 px-1.5 rounded bg-red-400/10 text-red-400 inline-flex items-center gap-1 font-condensed font-black text-[10px] tracking-wider uppercase border border-red-400/20">
                  ▼ {tMetrics.trend}
                </div>
              )}
            </div>
            <p className="font-sans text-[11px] text-[#8B949E] mt-3 leading-relaxed">
              Based on {history.length} iterations over scanned git tags.
            </p>
          </div>

          {/* Most Improved Area Card */}
          <div className="p-4 bg-white/[0.01] border border-white/[0.03] rounded-xl">
            <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest block leading-none mb-2">Most Improved Area</span>
            <div className="font-display text-xs text-white uppercase font-black mt-2 tracking-normal truncate">
              {tMetrics.mostImproved}
            </div>
            <p className="font-sans text-[11px] text-[#8B949E] mt-3 leading-relaxed">
              Taint tracking indicators report highest remediation rates inside this domain.
            </p>
          </div>

          {/* Highest Risk Area Card */}
          <div className="p-4 bg-white/[0.01] border border-white/[0.03] rounded-xl">
            <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest block leading-none mb-2 text-rose-400 flex items-center gap-1">
              <ShieldAlert size={10} />
              Highest Operating Risk
            </span>
            <div className="font-display text-xs text-rose-400 uppercase font-black mt-2 tracking-normal truncate">
              {tMetrics.highestRisk}
            </div>
            <p className="font-sans text-[11px] text-[#8B949E] mt-3 leading-relaxed">
              Active pathways match unvalidated, unauthenticated software rules.
            </p>
          </div>

          {/* Fix Velocity Card */}
          <div className="p-4 bg-white/[0.01] border border-white/[0.03] rounded-xl">
            <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest block leading-none mb-2">Refactoring Velocity</span>
            <div className="font-sans text-xs text-white font-extrabold mt-2">
              {tMetrics.fixVelocity}
            </div>
            <p className="font-sans text-[11px] text-[#8B949E] mt-3 leading-relaxed">
              Calculates how rapidly codebase repairs register in the system.
            </p>
          </div>

          {/* Technical Debt Card */}
          <div className="p-4 bg-[#0A0505]/30 border border-[#FF4444]/15 rounded-xl">
            <span className="font-condensed text-[9px] text-[#FF4444] uppercase font-black tracking-widest block leading-none mb-2">Technical Security Debt</span>
            <div className="font-display text-xs text-[#FF4444] uppercase font-black mt-2 leading-snug">
              {tMetrics.techDebt}
            </div>
            <p className="font-sans text-[11px] text-[#8B949E] mt-3 leading-relaxed">
              Consolidated effort required to resolve all open critical/high flaws.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Chronological Raw Database Scan History Listings */}
      <section className="bg-white/[0.005] border border-white/[0.03] rounded-2xl p-4 md:p-5.5">
        <h4 className="font-display text-[10px] text-[#484F58] uppercase tracking-[0.2em] mb-4 font-black border-b border-white/[0.03] pb-2.5 flex items-center gap-1.5 leading-none">
          HISTORICAL SECURE REGISTRY LOGS ({history.length} RECORDS)
        </h4>

        {loadingHistory ? (
          <div className="text-center py-10 font-sans text-xs text-[#8B949E]">
            Syncing timeline database streams with Supabase...
          </div>
        ) : history.length === 0 ? (
          <div className="text-center py-10 font-sans text-xs text-[#484F58]">
            No previous records exist in PostgreSQL. Registering this scan as baseline.
          </div>
        ) : (
          <div className="space-y-2.5">
            {history.map((h, logIdx) => {
              const hGrade = getGrade(h.score);
              const isCurrent = h.id === report.id;
              const hTotalFindings = h.counts.critical + h.counts.high + h.counts.medium + h.counts.low;
              
              return (
                <div
                  key={h.id || logIdx}
                  className={`p-3 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-3 transition-all duration-300 ${
                    isCurrent 
                      ? 'border-[#00FF88]/30 bg-[#00FF88]/[0.015] shadow-[0_0_15px_rgba(0,255,136,0.02)]' 
                      : 'border-white/[0.03] bg-white/[0.005] hover:border-white/[0.08] hover:bg-white/[0.01]'
                  }`}
                >
                  <div className="flex items-center gap-3.5 min-w-0">
                    {/* Tiny Grade Dial indicator */}
                    <div className="w-10 h-10 rounded-xl bg-white/[0.01] border border-white/[0.04] flex items-center justify-center flex-shrink-0 relative">
                      <span className={`font-display text-sm font-black ${hGrade.color}`}>
                        {hGrade.char}
                      </span>
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-sans text-xs font-bold text-white uppercase">{h.repositoryOwner}/{h.repositoryName}</span>
                        {isCurrent && (
                          <span className="px-1.5 py-0.5 rounded bg-[#00FF88]/10 text-[#00FF88] text-[7.5px] font-mono font-bold uppercase tracking-wider">
                            Active Report
                          </span>
                        )}
                      </div>
                      <span className="font-mono text-[9px] text-[#8B949E] mt-1 block flex items-center gap-1.5 uppercase tracking-wider">
                        <Calendar size={10} />
                        Scanned At: {new Date(h.scannedAt).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 flex-wrap shrink-0">
                    {/* Findings Counts Badge list */}
                    <div className="flex items-center gap-1 text-[8.5px] font-mono leading-none">
                      <span className="px-2 py-1 rounded bg-red-500/10 text-red-500 border border-red-500/10 font-bold">CRIT {h.counts.critical}</span>
                      <span className="px-2 py-1 rounded bg-orange-500/10 text-orange-400 border border-orange-500/10 font-bold">HIGH {h.counts.high}</span>
                      <span className="px-2 py-1 rounded bg-yellow-500/10 text-yellow-500 border border-[#484f58]/30 text-[#8B949E]">MED {h.counts.medium}</span>
                    </div>

                    {/* Attack Chains Indicator */}
                    {h.attackChains && h.attackChains.length > 0 && (
                      <span className="px-2 py-1 rounded bg-red-500/15 border border-red-500/25 text-red-400 text-[8.5px] font-mono font-black animate-scale-up">
                        {h.attackChains.length} CHAINS
                      </span>
                    )}

                    {/* Secure Score badge indicator */}
                    <div className="text-right shrink-0">
                      <span className="font-condensed text-[9px] text-[#484F58] uppercase font-bold tracking-widest block leading-none">Security Score</span>
                      <span className={`font-tech text-base font-black ${hGrade.color} block mt-1`}>
                        {h.score}/100
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
