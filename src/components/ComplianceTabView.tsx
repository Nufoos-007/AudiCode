import React from 'react';
import { Cpu, CheckCircle, ShieldAlert, BadgeCheck, Network, Brain, Database, FileText, Blocks, Terminal } from 'lucide-react';
import { ScanReport } from '../types';

interface ComplianceTabProps {
  report: ScanReport;
}

export function ComplianceTabView({ report }: ComplianceTabProps) {
  const frameworks = report.frameworksDetected || [];
  const aiProbability = report.aiGeneratedProbability !== undefined ? report.aiGeneratedProbability : 15;
  const aiRisk = report.aiRiskLevel || 'LOW';
  const aiQuality = report.aiArchitectureQuality || 'EXCELLENT';
  const aiFactors = report.aiFactorsText || [];

  // Technology framework specifications definitions mapping
  const FRAMEWORK_DESCRIPTIONS: Record<string, { label: string; icon: React.ReactNode; color: string; desc: string; audits: string[] }> = {
    'Next.js': {
      label: 'Next.js Stack',
      icon: <Blocks className="text-white" size={16} />,
      color: 'bg-black text-white hover:border-white/30',
      desc: 'Static routing, SSR APIs, dynamic server action contexts, and React Server Components (RSC).',
      audits: [
        'Secure NextJS middleware context tokens and verify path authorization.',
        'Validate data cache purging states inside Next fetch variables.',
        'Avoid exporting server-side action hooks with unrestricted arguments.'
      ]
    },
    'React': {
      label: 'React Engine',
      icon: <Blocks className="text-sky-400" size={16} />,
      color: 'bg-sky-500/10 text-sky-400 hover:border-sky-500/30 border border-sky-500/15',
      desc: 'Standard client rendering flows, stateful DOM node lifecycles, and context-flow variables.',
      audits: [
        'Ensure direct component renders sanitize user-supplied dynamic structures.',
        'Apply state memoization values strictly to prevent race propagation renders.',
        'Wrap asynchronous effects cleanups in dedicated abort states.'
      ]
    },
    'Vite': {
      label: 'Vite Compiler',
      icon: <Blocks className="text-yellow-400" size={16} />,
      color: 'bg-yellow-500/10 text-yellow-400 hover:border-yellow-500/30 border border-yellow-500/15',
      desc: 'Lightweight asset bundling, environment configuration mapping, and client HMR modules.',
      audits: [
        'Prevent baking sensitive API tokens inside client environment parameters (e.g. VITE_ keys).',
        'Analyze generated client asset chunks to ensure secrets are cleared during compilation.',
        'Maintain strictly clean dependencies configurations.'
      ]
    },
    'Express': {
      label: 'Express Node API',
      icon: <Blocks className="text-[#00FF88]" size={16} />,
      color: 'bg-[#00FF88]/10 text-[#00FF88] hover:border-[#00FF88]/30 border border-[#00FF88]/15',
      desc: 'NodeJS routing framework, REST endpoints, and custom middleware pipeline structures.',
      audits: [
        'Apply helmet security headers to prevent framing leaks and scripting bypasses.',
        'Incorporate express-rate-limit middleware to prevent request starvation (DoS).',
        'Verify express.json() payload parameter sizes strictly to avoid memory crashes.'
      ]
    },
    'Supabase': {
      label: 'Supabase Cloud',
      icon: <Database className="text-emerald-400" size={16} />,
      color: 'bg-emerald-500/10 text-emerald-400 hover:border-emerald-500/30 border border-emerald-500/15',
      desc: 'PostgreSQL virtualization layer, Row-Level-Security rules, and Realtime db listening endpoints.',
      audits: [
        'Enforce Row-Level Security (RLS) on all user-facing tables.',
        'Avoid committing the service_role master credential key inside repository files.',
        'Verify security policies on public channels strictly before open listening.'
      ]
    },
    'Firebase': {
      label: 'Firebase Platform',
      icon: <Database className="text-[#FF8C00]" size={16} />,
      color: 'bg-[#FF8C00]/10 text-[#FF8C00] hover:border-[#FF8C00]/30 border border-[#FF8C00]/15',
      desc: 'NoSQL Firestore structures, serverless cloud functions, and standard client authentication.',
      audits: [
        'Configure Firestore Security Rules to restrict access solely to verified owners.',
        'Prevent committing sensitive private key service credential JSON blocks on git tags.',
        'Enforce security validation checks inside functions parameters triggers.'
      ]
    },
    'Stripe': {
      label: 'Stripe Gateway',
      icon: <Blocks className="text-indigo-400" size={16} />,
      color: 'bg-indigo-500/10 text-indigo-400 hover:border-indigo-500/30 border border-indigo-500/15',
      desc: 'Instant charge APIs, checkout flow managers, and incoming payment webhook routing paths.',
      audits: [
        'Validate incoming webhook signatures via stripe.webhooks.constructEvent().',
        'Ensure secret API keys are accessed lazily via server-oriented process.env.',
        'Audit client views to prove private transaction codes never propagate in JS.'
      ]
    },
    'OpenAI': {
      label: 'OpenAI Services',
      icon: <Brain className="text-[#00FF88]" size={16} />,
      color: 'bg-[#00FF88]/10 text-[#00FF88] hover:border-[#00FF88]/35 border border-[#00FF88]/15',
      desc: 'Large language foundation interfaces, embedding generators, and server completion routines.',
      audits: [
        'Enforce token parameters limits to protect endpoints against expensive LLM billing runs.',
        'Proxy OpenAI network commands strictly across server API pipelines.',
        'Implement prompt injection scrubbing before embedding parameters models.'
      ]
    }
  };

  // Heuristics lists matching prompt requirements
  const AI_HEURISTIC_FACTORS = [
    { id: 'GIANT-FILE', label: 'Monolithic Module Bloat (Over 800 lines)', category: 'Single module containing thousands of unmodularized statements.' },
    { id: 'REPETITIVE-NAME', label: 'Repetitive Automated Variable naming (Robot code)', category: 'Automatic generators using iterative variables naming (obj1, helperA, dataB, loops).' },
    { id: 'EXPLODED-COMMENTS', label: 'Over-documentation explaining simple syntax details', category: 'Copious scholastic inline instructions explaining standard language calls (loops, assigns).' },
    { id: 'BLOATED-COMPONENTS', label: 'Oversized React components with giant nested layouts', category: 'Massive layouts rendered from a single component block.' },
    { id: 'SILENT-CATCH', label: 'Silenced exception catch wrappers (Catch swallow)', category: 'Suppressed code traps bypassing crash telemetry.' },
    { id: 'SANDBOX-BYPASS', label: 'Validation bypass flags for demo/sandbox testing', category: 'Hardcoded indicators bypassing oauth authentication tokens for verification testing.' },
    { id: 'MIXED-RESPONSIBILITY', label: 'Mixed domains of responsibility (Spaghetti code)', category: 'Single modules importing database, UI, system routing simultaneously.' }
  ];

  return (
    <div className="space-y-5 animate-fade-in">
      {/* SECTION A: TECHNOLOGY STACK INTELLIGENCE badges */}
      <section className="bg-white/[0.005] border border-white/[0.03] rounded-2xl p-4 md:p-5.5">
        <div className="flex items-center gap-3 border-b border-white/[0.03] pb-3 mb-4">
          <div className="p-2.5 rounded-xl bg-[#00FF88]/10 text-[#00FF88] shadow-inner font-extrabold pb-2 mb-2 pt-0 md:p-2 flex gap-1.5 leading-none">
            <Blocks size={18} />
          </div>
          <div>
            <h4 className="font-display text-sm font-black text-white uppercase tracking-wider">
              Detected Stack Intelligence & Findings
            </h4>
            <p className="font-condensed text-[11px] text-[#8B949E] uppercase tracking-wider mt-0.5">
              // Framework Audit parameters for active technology components
            </p>
          </div>
        </div>

        {frameworks.length === 0 ? (
          <div className="text-center py-8 font-sans text-xs text-[#8B949E]">
            No complex frame stack components registered. Standard lightweight JS modules found.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {frameworks.map((fw) => {
              const info = FRAMEWORK_DESCRIPTIONS[fw] || {
                label: `${fw} Framework`,
                icon: <Blocks size={16} />,
                color: 'bg-white/5 text-white',
                desc: 'Generic technology module detected inside the scanned workspace paths.',
                audits: ['Ensure credential parameters are stored outside code paths.', 'Audit dependencies recursively.']
              };

              return (
                <div 
                  key={fw}
                  className="p-3.5 rounded-xl border border-white/[0.03] bg-white/[0.01] hover:border-white/[0.08] transition-all duration-300"
                >
                  <div className="flex items-center justify-between gap-3 mb-2.5">
                    <span className={`px-2.5 py-1 rounded-xl text-[10px] font-display font-black uppercase flex items-center gap-2 ${info.color}`}>
                      {info.icon}
                      {info.label}
                    </span>
                    <span className="font-condensed text-[9px] text-[#00FF88] uppercase font-bold tracking-widest">// SECURE AUDIT</span>
                  </div>
                  <p className="font-sans text-[11.5px] text-[#8B949E] leading-relaxed">
                    {info.desc}
                  </p>

                  <div className="mt-3.5 space-y-2">
                    <span className="font-condensed text-[9px] text-[#484F58] uppercase font-bold tracking-widest block">// Framework Specific Recommendations:</span>
                    {info.audits.map((aud, index) => (
                      <div key={index} className="flex items-start gap-2 text-xs text-[#8B949E]">
                        <span className="text-[#00FF88] shrink-0 font-bold mt-0.5">✓</span>
                        <span className="font-sans text-[11px] leading-normal">{aud}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* SECTION B: AI GENERATED CODE COMPLIANCE ANALYSIS */}
      <section className="glass-card hover:border-white/[0.05] border border-white/[0.02] rounded-2xl p-4 md:p-5.5 bg-[#03060a]/20">
        <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-white/[0.03] pb-3 mb-4 gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-xl bg-[#00FF88]/10 text-[#00FF88] shadow-inner shrink-0 mt-0.5">
              <Brain size={18} />
            </div>
            <div>
              <h4 className="font-display text-sm font-black text-white uppercase tracking-wider">
                AI Generated Code Structural Analyzer
              </h4>
              <p className="font-condensed text-[11px] text-[#8B949E] uppercase tracking-wider mt-0.5">
                // Heuristic mapping of automatic coding automation patterns
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 shrink-0">
            {/* Probability indicator ring */}
            <div className="flex items-center gap-2.5 p-2.5 border border-white/[0.03] bg-white/[0.01] rounded-2xl">
              <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-bold tracking-widest text-right shrink-0">
                Probability<br/>Score
              </span>
              <div className="font-tech text-2xl font-black text-[#00FF88] animate-pulse">
                {aiProbability}%
              </div>
            </div>

            {/* Quality badge descriptors */}
            <div className="text-right">
              <span className="font-condensed text-[9px] text-[#484F58] uppercase font-bold tracking-widest block leading-none">Security Status</span>
              <span className={`inline-block font-display text-xs uppercase font-black tracking-wider mt-1 ${
                aiRisk === 'HIGH' ? 'text-red-400' : aiRisk === 'MEDIUM' ? 'text-[#FF8C00]' : 'text-[#00FF88]'
              }`}>
                {aiRisk} AI RISK
              </span>
            </div>
          </div>
        </div>

        {/* AI Structural Heuristics Analysis Details */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
          <div className="p-4 bg-white/[0.01] border border-white/[0.03] rounded-xl text-center">
            <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest block">AI Probability Level</span>
            <div className="text-2xl font-tech font-bold text-white mt-2">
              {aiProbability > 70 ? 'High Automation' : aiProbability > 40 ? 'Moderate Co-Author' : 'Pre-dominantly human'}
            </div>
          </div>

          <div className="p-4 bg-white/[0.01] border border-white/[0.03] rounded-xl text-center">
            <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest block">Architecture Quality</span>
            <div className="text-2xl font-tech font-bold text-[#00FF88] mt-2">
              {aiQuality}
            </div>
          </div>

          <div className="p-4 bg-white/[0.01] border border-white/[0.03] rounded-xl text-center">
            <span className="font-condensed text-[9px] text-[#8B949E] uppercase font-black tracking-widest block">Active Rule Count</span>
            <div className="text-2xl font-tech font-bold text-white mt-2">
              {aiFactors.length} Indicators Found
            </div>
          </div>
        </div>

        {/* Detailed factors checklist displaying structural indicators */}
        <div className="bg-[#03060a]/30 border border-white/[0.03] rounded-xl p-4">
          <h5 className="font-display text-[10px] text-[#484F58] uppercase tracking-[0.2em] mb-3 font-black">
            AI structural indicators heuristics scorecard
          </h5>

          <div className="space-y-2.5 font-sans text-xs">
            {AI_HEURISTIC_FACTORS.map((fact) => {
              // Checks if the active factor is registered in aiFactors lists
              const isFound = aiFactors.some(f => f.toUpperCase().includes(fact.id) || fact.label.toUpperCase().includes(f.toUpperCase()));
              
              return (
                <div 
                  key={fact.id}
                  className={`p-2.5 rounded-lg border flex items-start gap-2.5 transition-colors duration-200 ${
                    isFound 
                      ? 'border-yellow-500/20 bg-yellow-500/[0.01] hover:bg-yellow-500/[0.02]' 
                      : 'border-white/[0.01] bg-transparent hover:bg-white/[0.005]'
                  }`}
                >
                  {isFound ? (
                    <span className="w-5 h-5 flex items-center justify-center rounded-full bg-yellow-500/15 text-yellow-500 text-xs font-bold leading-none shrink-0 mt-0.5 animate-pulse">
                      !
                    </span>
                  ) : (
                    <span className="w-5 h-5 flex items-center justify-center rounded-full bg-[#00FF88]/10 text-[#00FF88] text-xs font-bold leading-none shrink-0 mt-0.5">
                      ✓
                    </span>
                  )}

                  <div className="min-w-0">
                    <span className={`block font-bold truncate ${isFound ? 'text-yellow-400' : 'text-[#8B949E]'}`}>
                      {fact.label}
                    </span>
                    <span className="text-[#8B949E]/70 block mt-0.5 font-sans leading-relaxed text-[11px]">
                      {fact.category}
                    </span>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-widest shrink-0 ml-auto ${
                    isFound ? 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20' : 'bg-white/[0.01] text-[#484F58]'
                  }`}>
                    {isFound ? 'Identified' : 'Clean'}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
}
