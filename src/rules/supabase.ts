import { Rule } from '../types';

export const supabaseRules: Rule[] = [
  {
    id: 'SUPA-001',
    title: 'Client-Side Supabase Service Role Initialization',
    category: 'supabase',
    severity: 'critical',
    confidenceBase: 0.9,
    aiEligible: false,
    appliesTo: ['.jsx', '.tsx', '.js', '.ts'],
    description: 'Initializing a client with "service_role" privileges on client-facing applications exposes unlimited backend administrative power. Since RLS is bypassed entirely, clients can view and destroy database segments.',
    remediationTemplate: 'Restrict client-side configurations to the public "anon_key". Restrict "service_role" actions strictly to private backend edge systems (or verified APIs).',
    detectionType: 'regex',
    patternString: 'createClient\\(\\s*process\\.env\\.[a-zA-Z0-9_]+_URL\\s*,\\s*process\\.env\\.[a-zA-Z0-9_]+_SERVICE_ROLE_KEY'
  },
  {
    id: 'SUPA-002',
    title: 'Supabase Row Level Security (RLS) Bypass Warning',
    category: 'supabase',
    severity: 'high',
    confidenceBase: 0.7,
    aiEligible: true,
    appliesTo: ['.sql', '.ts', '.js'],
    description: 'Creating database clients or invoking db connectors using service level credentials bypasses active postguards and RLS filters. Ensure context variables are authenticated properly.',
    remediationTemplate: 'Utilize supabase.auth.user() or policy security rules to guarantee users access their resources only.',
    detectionType: 'regex',
    patternString: 'supabase\\.auth\\.setSession|service_role_key'
  }
];
