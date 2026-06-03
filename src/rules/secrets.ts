import { Rule } from '../types';

export const secretsRules: Rule[] = [
  {
    id: 'SEC-001',
    title: 'Hardcoded OpenAI API Key',
    category: 'secrets',
    severity: 'critical',
    confidenceBase: 0.95,
    aiEligible: false,
    appliesTo: ['.js', '.jsx', '.ts', '.tsx', '.json', '.env', '.env.example'],
    description: 'An OpenAI API key starting with "sk-" followed by alphanumeric characters was found in your repository. Unauthorized users can exploit this to consume your API budget.',
    remediationTemplate: 'Revoke the leaked key immediately in your OpenAI dashboard. Relocate it into an environment variable and load it securely via process.env.OPENAI_API_KEY.',
    detectionType: 'regex',
    patternString: 'sk-proj-[a-zA-Z0-9]{40,120}|sk-[a-zA-Z0-9]{48}'
  },
  {
    id: 'SEC-002',
    title: 'Hardcoded Anthropic API Key',
    category: 'secrets',
    severity: 'critical',
    confidenceBase: 0.95,
    aiEligible: false,
    appliesTo: ['.js', '.jsx', '.ts', '.tsx', '.json', '.env', '.env.example'],
    description: 'An Anthropic API token was detected. This token grants access to Anthropic model calls, which can lead to service billing abuse.',
    remediationTemplate: 'Revoke the exposed API token. Migrate key credentials into workspace environment variables and fetch using process.env.ANTHROPIC_API_KEY.',
    detectionType: 'regex',
    patternString: 'sk-ant-sid01-[a-zA-Z0-9_\\-]{36,256}'
  },
  {
    id: 'SEC-003',
    title: 'GitHub Personal Access Token (PAT)',
    category: 'secrets',
    severity: 'critical',
    confidenceBase: 0.9,
    aiEligible: false,
    appliesTo: ['.js', '.jsx', '.ts', '.tsx', '.json', '.sh', '.yaml', '.yml'],
    description: 'A GitHub Personal Access Token (PAT) was discovered. This token can allow third parties to view or modify your repositories, workflows, and account settings depending on access scopes.',
    remediationTemplate: 'Immediately delete or revoke the token from your GitHub Developer Settings. Replace with standard environment variables or GitHub Actions secrets.',
    detectionType: 'regex',
    patternString: 'ghp_[a-zA-Z0-9]{36,255}'
  },
  {
    id: 'SEC-004',
    title: 'Hardcoded JWT Signing Secret',
    category: 'secrets',
    severity: 'high',
    confidenceBase: 0.8,
    aiEligible: true,
    appliesTo: ['.js', '.ts', '.json', '.env'],
    description: 'A hardcoded text string or variable named as a JWT Secret, Signature Key, or Token Key was detected. Leaking signing secrets allows attackers to craft arbitrary JWT payloads.',
    remediationTemplate: 'Move token secrets into a secure environment configuration (e.g. JWT_SECRET). Ensure a strong, randomly generated key is used in production.',
    detectionType: 'regex',
    patternString: '(jwt_secret|jwtsecret|signing_key|jwt_token_secret)\\s*=\\s*[\'"][a-zA-Z0-9_\\-!@#$%^&*()]{8,128}[\'"]'
  },
  {
    id: 'SEC-005',
    title: 'Database connection password string exposure',
    category: 'secrets',
    severity: 'critical',
    confidenceBase: 0.85,
    aiEligible: false,
    appliesTo: ['.js', '.ts', '.json', '.env', '.yaml', '.yml'],
    description: 'A database connection string containing connection passwords in plaintext was found (e.g., PostgreSQL, MongoDB, MySQL).',
    remediationTemplate: 'Extract the database connection string and replace the credentials segment with private parameters. Store the complete authorization URI in a safe place.',
    detectionType: 'regex',
    patternString: '(postgres|postgresql|mongodb|mongodb\\+srv|mysql):\\/\\/[a-zA-Z0-9_]+:[^@]+@'
  },
  {
    id: 'SEC-006',
    title: 'Supabase Service Role Key Exposure',
    category: 'secrets',
    severity: 'critical',
    confidenceBase: 0.95,
    aiEligible: false,
    appliesTo: ['.js', '.jsx', '.ts', '.tsx', '.json', '.env', '.env.example'],
    description: 'The Supabase Service Role Key bypasses Row Level Security (RLS) entirely. Storing or committing this key exposed to codebase repositories permits absolute data reads and modifications.',
    remediationTemplate: 'Rotate the service role key immediately in the Supabase control panel. Never commit keys or pass them into frontend bundles.',
    detectionType: 'regex',
    patternString: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]{30,}'
  }
];
