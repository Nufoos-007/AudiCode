import React, { useState, useEffect } from 'react';
import { Database, Key, ShieldAlert, ShieldCheck, RefreshCw, AlertTriangle, User, Shield } from 'lucide-react';
import { getSupabase } from '../supabase';

interface DiagnosticData {
  supabase: {
    urlConfigured: boolean;
    anonKeyConfigured: boolean;
    databaseUrlConfigured: boolean;
    initialized: boolean;
    liveConnected: boolean;
    connectionError: string | null;
    tableVerified: boolean;
  };
  session: {
    isAuthenticated: boolean;
    activeUser: {
      id: string;
      login: string;
      name?: string;
      avatarUrl: string;
    } | null;
  };
  missingEnvVars: string[];
}

export function AuthDiagnostics() {
  const [data, setData] = useState<DiagnosticData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Client-side session stats
  const [clientUserId, setClientUserId] = useState<string | null>(null);
  const [clientGithubUsername, setClientGithubUsername] = useState<string | null>(null);
  const [hasProviderToken, setHasProviderToken] = useState<boolean>(false);
  const [clientSessionStatus, setClientSessionStatus] = useState<string>('Checking...');

  const fetchDiagnostics = async () => {
    setLoading(true);
    setError(null);

    try {
      // 1. Resolve client-side session factors
      const supabase = await getSupabase();
      const { data: { session } } = await supabase.auth.getSession();

      if (session) {
        setClientUserId(session.user.id);
        const metadata = session.user.user_metadata || {};
        setClientGithubUsername(metadata.preferred_username || metadata.user_name || session.user.email?.split('@')[0] || null);
        setHasProviderToken(!!session.provider_token || !!window.localStorage.getItem('audi_sb_provider_token'));
        setClientSessionStatus('Active Supabase JWT Session');
      } else {
        // Check for sandbox guest token
        const activeToken = window.localStorage.getItem('audi_sb_access_token');
        if (activeToken === 'demo_token_sandbox_bypass_true') {
          setClientUserId('guest-dev');
          setClientGithubUsername('demo-auditor');
          setHasProviderToken(true);
          setClientSessionStatus('Active Sandbox Demo Mode');
        } else {
          setClientUserId(null);
          setClientGithubUsername(null);
          setHasProviderToken(false);
          setClientSessionStatus('No Client Session');
        }
      }

      // 2. Fetch server-side status
      const sbAccessToken = window.localStorage.getItem('audi_sb_access_token') || '';
      const sbProviderToken = window.localStorage.getItem('audi_sb_provider_token') || '';
      
      const headers: Record<string, string> = {};
      if (sbAccessToken) headers['Authorization'] = `Bearer ${sbAccessToken}`;
      if (sbProviderToken) headers['x-provider-token'] = sbProviderToken;

      const res = await fetch('/api/auth/diagnostics', { headers });
      if (!res.ok) {
        throw new Error('Failed to retrieve system diagnostics payload.');
      }
      const payload = await res.json();
      setData(payload);
    } catch (err: any) {
      setError(err.message || 'Connecting to diagnostics server endpoints failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDiagnostics();
  }, []);

  if (loading) {
    return (
      <div className="w-full bg-[#0D1117] border border-[#21262D] rounded-xl p-6 flex flex-col items-center justify-center min-h-[250px] font-mono text-xs text-[#7D8590]">
        <RefreshCw className="animate-spin text-[#00FF88] mb-3" size={24} />
        <span>Loading secure auth diagnostics query...</span>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="w-full bg-[#0D1117] border border-[#FF4444]/20 rounded-xl p-6 text-center">
        <ShieldAlert className="text-[#FF4444] mx-auto mb-3" size={32} />
        <h3 className="font-sans text-sm font-bold text-[#E6EDF3] mb-1">Diagnostics Offline</h3>
        <p className="font-mono text-xs text-[#7D8590] mb-4">{error || 'Unable to retrieve diagnostics'}</p>
        <button
          onClick={fetchDiagnostics}
          className="px-4 py-2 rounded bg-transparent border border-[#21262D] text-[#E6EDF3] hover:bg-[#161B22] font-mono text-xs cursor-pointer transition-all duration-150"
        >
          Retry Diagnostic Scan
        </button>
      </div>
    );
  }

  const hasMissingCritical = data.missingEnvVars.length > 0;

  return (
    <div className="w-full bg-[#0D1117] border border-[#21262D] rounded-xl p-6 shadow-2xl animate-fade-in text-[#E6EDF3]">
      {/* Title Header */}
      <div className="flex items-center justify-between border-b border-[#21262D] pb-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#21262D] flex items-center justify-center text-[#00FF88]">
            <Key size={16} />
          </div>
          <div>
            <h3 className="font-sans text-sm font-bold text-[#E6EDF3]">Authentication Status & Server Diagnostics</h3>
            <p className="font-mono text-[10px] text-[#7D8590]">Real-time system environment state analyzer</p>
          </div>
        </div>

        <button
          onClick={fetchDiagnostics}
          className="p-1.5 rounded hover:bg-[#161B22] border border-[#21262D] text-[#7D8590] hover:text-[#E6EDF3] cursor-pointer transition-all duration-150"
          title="Refresh stats"
        >
          <RefreshCw size={13} />
        </button>
      </div>

      {/* Critical Status Alerts */}
      {hasMissingCritical ? (
        <div className="mb-6 p-4 rounded-lg bg-[#FF4444]/15 border border-[#FF4444]/30">
          <div className="flex items-start gap-3">
            <AlertTriangle className="text-[#FF4444] mt-0.5" size={16} />
            <div className="flex-1">
              <h4 className="font-sans text-xs font-extrabold text-[#FF4444] uppercase tracking-wider mb-2">
                Authentication Incomplete: Environment Not Configured
              </h4>
              <p className="font-mono text-xs text-[#7D8590] mb-3 leading-relaxed">
                The application lacks the required host credentials. Ensure the following environment variables are registered in your secrets:
              </p>
              <div className="flex flex-wrap gap-2">
                {data.missingEnvVars.map((v) => (
                  <span
                    key={v}
                    className="px-2 py-0.5 rounded bg-[#FF4444]/10 border border-[#FF4444]/20 font-mono text-[11px] text-[#FF4444] font-bold"
                  >
                    {v}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="mb-6 p-4 rounded-lg bg-[#00FF88]/15 border border-[#00FF88]/30">
          <div className="flex items-start gap-3">
            <ShieldCheck className="text-[#00FF88]" size={18} />
            <div>
              <h4 className="font-sans text-xs font-extrabold text-[#00FF88] uppercase tracking-wider mb-1">
                SYSTEM FULLY COMPLIANT
              </h4>
              <p className="font-mono text-xs text-[#7D8590]">
                All Supabase configurations, database connections, and auth status layers are securely active.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Structured Diagnostics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        {/* Box 1: Supabase Configuration Status */}
        <div className="bg-[#080C10] border border-[#21262D] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3 text-[#00FF88]">
            <Database size={14} />
            <span className="font-sans text-xs font-bold text-[#E6EDF3]">Supabase Platform Status</span>
          </div>
          <div className="space-y-2 font-mono text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#7D8590]">SUPABASE_URL:</span>
              <span>
                {data.supabase.urlConfigured ? (
                  <span className="text-[#00FF88] font-bold">✓ Configured</span>
                ) : (
                  <span className="text-[#FF4444] font-bold">✗ Empty</span>
                )}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7D8590]">SUPABASE_ANON_KEY:</span>
              <span>
                {data.supabase.anonKeyConfigured ? (
                  <span className="text-[#00FF88] font-bold">✓ Configured</span>
                ) : (
                  <span className="text-[#FF4444] font-bold">✗ Empty</span>
                )}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7D8590]">DATABASE_URL (Pool):</span>
              <span>
                {data.supabase.databaseUrlConfigured ? (
                  <span className="text-[#00FF88] font-bold">✓ Active</span>
                ) : (
                  <span className="text-[#7D8590]">In-memory fallback</span>
                )}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7D8590]">DB Connection:</span>
              <span>
                {data.supabase.liveConnected ? (
                  <span className="text-[#00FF88] font-bold">✓ Connected</span>
                ) : (
                  <span className="text-[#FF4444] font-bold">✗ Connection Error</span>
                )}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7D8590]">Tables Verified:</span>
              <span>
                {data.supabase.tableVerified ? (
                  <span className="text-[#00FF88] font-bold">✓ Ready</span>
                ) : (
                  <span className="text-[#7D8590]">None</span>
                )}
              </span>
            </div>
          </div>
        </div>

        {/* Box 2: Unified App State / Client Session Details */}
        <div className="bg-[#080C10] border border-[#21262D] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3 text-[#58A6FF]">
            <Shield size={14} />
            <span className="font-sans text-xs font-bold text-[#E6EDF3]">Live Client Session Check</span>
          </div>
          <div className="space-y-2 font-mono text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#7D8590]">Session Status:</span>
              <span className="text-[#00FF88] font-bold">{clientSessionStatus}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7D8590]">Current User ID:</span>
              <span className="text-[#E6EDF3] select-all max-w-[150px] truncate" title={clientUserId || 'None'}>
                {clientUserId || 'None'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7D8590]">GitHub Username:</span>
              <span className="text-[#E6EDF3] font-bold">
                {clientGithubUsername ? `@${clientGithubUsername}` : 'None'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7D8590]">GitHub Access Token:</span>
              <span>
                {hasProviderToken ? (
                  <span className="text-[#00FF88] font-bold">✓ Available</span>
                ) : (
                  <span className="text-[#FF4444] font-bold">✗ Missing / Needs Login</span>
                )}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Authenticated User module */}
      {clientUserId && (
        <div className="bg-[#161B22] border border-[#21262D] rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full border border-[#21262D] bg-[#21262D] flex items-center justify-center text-[#00FF88]">
              <User size={18} />
            </div>
            <div>
              <span className="font-mono text-xs text-[#7D8590]">Current Session Active</span>
              <h4 className="font-sans text-xs font-bold text-[#E6EDF3] flex items-center gap-2">
                <ShieldCheck size={12} className="text-[#00FF88]" />
                {clientGithubUsername || 'Sandbox Dev'} (
                <span className="font-mono text-[11px] text-[#00FF88]">@{clientGithubUsername || 'guest-dev'}</span>)
              </h4>
            </div>
          </div>
          <div className="text-right font-mono text-[10px] text-[#7D8590]">
            ID: <span className="text-[#E6EDF3] select-all">{clientUserId}</span>
          </div>
        </div>
      )}
    </div>
  );
}
