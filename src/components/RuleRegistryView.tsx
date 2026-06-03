import React, { useState } from 'react';
import { ruleRegistry } from '../rules';
import { Rule, RuleCategory, RuleSeverity } from '../types';
import { Shield, Sparkles, Search, Code, CheckCircle, Info, ExternalLink, HelpCircle } from 'lucide-react';

export function RuleRegistryView() {
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);

  const categories: { key: string; label: string }[] = [
    { key: 'all', label: 'All Categories' },
    { key: 'secrets', label: 'Secrets' },
    { key: 'authentication', label: 'Authentication' },
    { key: 'authorization', label: 'Authorization' },
    { key: 'xss', label: 'XSS' },
    { key: 'api-security', label: 'API Security' },
    { key: 'supabase', label: 'Supabase' },
    { key: 'ai-security', label: 'AI Security' },
    { key: 'vercel', label: 'Vercel' }
  ];

  const getSeverityStyles = (severity: RuleSeverity) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'info':
        return 'bg-neutral-500/15 text-neutral-400 border-neutral-500/30';
    }
  };

  const getCategoryTheme = (category: RuleCategory) => {
    switch (category) {
      case 'secrets': return 'text-red-400 border-red-400/25 bg-red-400/5';
      case 'authentication': return 'text-sky-400 border-sky-400/25 bg-sky-400/5';
      case 'authorization': return 'text-purple-400 border-purple-400/25 bg-purple-400/5';
      case 'xss': return 'text-amber-400 border-amber-400/25 bg-amber-400/5';
      case 'api-security': return 'text-emerald-400 border-emerald-400/25 bg-emerald-400/5';
      case 'supabase': return 'text-teal-400 border-teal-400/25 bg-teal-400/5';
      case 'ai-security': return 'text-pink-400 border-pink-400/25 bg-pink-400/5';
      case 'vercel': return 'text-blue-400 border-blue-400/25 bg-blue-400/5';
    }
  };

  // Filter and search rules
  const filteredRules = ruleRegistry.filter(rule => {
    const matchesCategory = activeCategory === 'all' || rule.category === activeCategory;
    const matchesSearch = 
      rule.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <section className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-2xl mb-8 animate-fade-in relative">
      <div className="absolute top-0 right-0 p-6 opacity-[0.01] pointer-events-none text-[#00FFFF]">
        <Shield size={100} />
      </div>

      <div className="border-b border-white/[0.04] pb-4 mb-6">
        <span className="text-[10px] text-[#00FFFF] uppercase tracking-[0.2em] font-extrabold font-mono">// RULE REGISTRY CENTRAL MATRIX</span>
        <h2 className="text-xl font-black text-white uppercase tracking-wider flex items-center gap-2 mt-1">
          <Code className="text-[#00FFFF]" size={20} />
          AudiCode Core Rule Registry
        </h2>
        <p className="text-xs text-neutral-400 mt-1 leading-relaxed">
          Index of 20+ active, high-signal deterministic security rules. Fully compliance-aligned to locate leakages, misconfigurations, injection channels, or administrative bypasses.
        </p>
      </div>

      {/* Categories Toolbar switcher */}
      <div className="flex flex-wrap gap-1.5 mb-6">
        {categories.map((cat) => {
          const isActive = activeCategory === cat.key;
          const count = cat.key === 'all' 
            ? ruleRegistry.length 
            : ruleRegistry.filter(r => r.category === cat.key).length;

          return (
            <button
              key={cat.key}
              onClick={() => setActiveCategory(cat.key)}
              className={`px-3 py-1.5 rounded-lg text-[10px] uppercase font-bold tracking-wider border select-none transition-all cursor-pointer flex items-center gap-1.5 ${
                isActive
                  ? 'bg-[#00FFFF]/10 border-[#00FFFF]/40 text-[#00FFFF] shadow-[0_0_10px_rgba(0,255,255,0.05)]'
                  : 'bg-[#03060a]/20 border-white/[0.03] text-neutral-400 hover:text-neutral-300 hover:border-white/[0.08]'
              }`}
            >
              {cat.label}
              <span className={`text-[9px] px-1 rounded font-mono ${isActive ? 'bg-[#00FFFF]/20' : 'bg-white/[0.03] text-neutral-500'}`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Dynamic Search queries */}
      <div className="relative mb-6">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-500" size={15} />
        <input 
          type="text"
          placeholder="Filter core database rule IDs, titles, or descriptions..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full bg-[#03060a]/45 border border-white/[0.04] focus:border-[#00FFFF]/40 focus:ring-0 rounded-xl px-4 py-2.5 pl-10 text-xs text-white placeholder-neutral-500 outline-none transition-all"
        />
      </div>

      {/* Master/Detail Rule View Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-[420px]">
        
        {/* Left pane: Rule list panel (col-span-5) */}
        <div className="lg:col-span-6 border border-white/[0.03] bg-[#03060a]/30 rounded-xl overflow-hidden flex flex-col max-h-[480px]">
          <div className="bg-white/[0.01] border-b border-white/[0.04] px-4 py-2 flex justify-between items-center text-[9px] uppercase tracking-wider font-mono font-bold text-neutral-500">
            <span>REGISTERED ENGINE DEFINITIONS</span>
            <span>{filteredRules.length} matches</span>
          </div>

          <div className="divide-y divide-white/[0.02] overflow-y-auto flex-1 select-none">
            {filteredRules.length === 0 ? (
              <div className="py-20 text-center text-xs text-neutral-500 font-mono">
                // No rules registered under selected criteria.
              </div>
            ) : (
              filteredRules.map((r) => {
                const isSelected = selectedRuleId === r.id;
                return (
                  <button
                    key={r.id}
                    onClick={() => setSelectedRuleId(r.id)}
                    className={`w-full text-left px-4 py-3.5 transition-all outline-none border-l-2 cursor-pointer flex flex-col gap-1.5 group select-none ${
                      isSelected
                        ? 'bg-[#00FFFF]/5 border-[#00FFFF] text-[#00FFFF]'
                        : 'border-transparent hover:bg-white/[0.01] text-neutral-400 hover:text-neutral-300'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2.5 w-full">
                      <div className="flex items-center gap-2 overflow-hidden">
                        <span className="font-mono text-[10px] font-bold text-[#8B949E] group-hover:text-white transition-colors">
                          {r.id}
                        </span>
                        <span className={`text-[9px] px-1.5 py-0.2 border rounded select-none uppercase font-mono font-bold ${getCategoryTheme(r.category)}`}>
                          {r.category}
                        </span>
                      </div>
                      
                      <span className={`text-[8px] px-2 py-0.5 border rounded-lg font-sans font-bold uppercase tracking-wider select-none ${getSeverityStyles(r.severity)}`}>
                        {r.severity}
                      </span>
                    </div>

                    <h4 className="font-extrabold text-xs text-white truncate w-full group-hover:text-[#00FFFF] transition-colors leading-snug">
                      {r.title}
                    </h4>

                    <div className="flex items-center justify-between mt-0.5 text-[9px] text-neutral-500 font-mono">
                      <span>TYPE: <span className="text-neutral-400 font-bold uppercase">{r.detectionType}</span></span>
                      {r.aiEligible && (
                        <span className="text-pink-400 flex items-center gap-0.5 text-[8px] font-bold">
                          <Sparkles size={8} /> AI
                        </span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right pane: Selected rule detail board (col-span-7) */}
        <div className="lg:col-span-6 bg-[#000000]/60 border border-white/[0.03] rounded-xl overflow-hidden flex flex-col min-h-[300px]">
          {selectedRuleId ? (() => {
            const rule = ruleRegistry.find(r => r.id === selectedRuleId);
            if (!rule) return null;

            return (
              <div className="flex flex-col h-full animate-fade-in text-neutral-300">
                {/* Header row */}
                <div className="bg-[#070b11] border-b border-white/[0.04] p-4 flex justify-between items-start gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-black text-[#00FFFF]">{rule.id}</span>
                      <span className={`text-[9px] px-1.5 py-0.5 border rounded-md uppercase font-mono font-bold ${getCategoryTheme(rule.category)}`}>
                        {rule.category}
                      </span>
                    </div>
                    <h3 className="font-black text-sm text-white mt-1 leading-relaxed uppercase">{rule.title}</h3>
                  </div>

                  <span className={`text-[9px] px-2.5 py-1 border rounded-lg font-bold uppercase tracking-widest ${getSeverityStyles(rule.severity)}`}>
                    {rule.severity}
                  </span>
                </div>

                {/* Main scrollable grid information */}
                <div className="p-5 space-y-5 overflow-y-auto max-h-[380px] text-xs">
                  
                  {/* Scope metadata parameters */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-[#03060a]/40 border border-white/[0.02] p-3 rounded-lg">
                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider">// Base Confidence Metric</span>
                      <span className="block font-mono font-semibold text-white mt-1">{(rule.confidenceBase * 100).toFixed(0)}% Accuracy</span>
                    </div>
                    <div className="bg-[#03060a]/40 border border-white/[0.02] p-3 rounded-lg">
                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider">// AI Verification Ready</span>
                      <span className="block font-mono font-semibold text-white mt-1">
                        {rule.aiEligible ? (
                          <span className="text-pink-400 flex items-center gap-1">
                            <Sparkles size={11} /> Eligible
                          </span>
                        ) : 'Not Eligible'}
                      </span>
                    </div>
                    <div className="bg-[#03060a]/40 border border-white/[0.02] p-3 rounded-lg">
                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider">// Match Architecture Type</span>
                      <span className="block font-mono font-semibold text-[#00FFFF] mt-1 uppercase">{rule.detectionType} Detection</span>
                    </div>
                    <div className="bg-[#03060a]/40 border border-white/[0.02] p-3 rounded-lg">
                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider">// Target Extensions</span>
                      <span className="block font-mono font-semibold text-neutral-300 mt-1 truncate" title={rule.appliesTo.join(', ')}>
                        {rule.appliesTo.join(', ')}
                      </span>
                    </div>
                  </div>

                  {/* Core description segment */}
                  <div>
                    <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider mb-1.5">// Exposure Description</span>
                    <p className="text-neutral-300 leading-relaxed font-sans text-xs bg-[#03060a]/20 p-3 border border-white/[0.02] rounded-lg">
                      {rule.description}
                    </p>
                  </div>

                  {/* Remediation template block */}
                  <div>
                    <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider mb-1.5">// Compliant Remediation</span>
                    <div className="bg-emerald-950/20 border border-emerald-500/20 text-emerald-300 p-3.5 rounded-lg font-sans leading-relaxed text-xs">
                      <div className="flex gap-2 items-start">
                        <CheckCircle className="text-emerald-400 flex-shrink-0 mt-0.5" size={13} />
                        <span>{rule.remediationTemplate}</span>
                      </div>
                    </div>
                  </div>

                  {/* Active Regex pattern visualization if type is regex */}
                  {rule.detectionType === 'regex' && (
                    <div>
                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider mb-1.5">// Underlying Match Regex Pattern</span>
                      <div className="bg-[#03060a]/80 border border-white/[0.04] p-3 rounded-lg font-mono text-[10px] text-amber-300 break-all select-all">
                        /{rule.patternString}/gi
                      </div>
                    </div>
                  )}

                </div>
              </div>
            );
          })() : (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-center text-xs text-neutral-500 font-mono">
              <Code className="text-neutral-700 animate-pulse mb-3" size={24} />
              <span>// SELECT A RULE FROM DEFINITIONS PANEL TO AUDIT LOGIC</span>
            </div>
          )}
        </div>

      </div>
    </section>
  );
}
