import { Rule } from '../types';

export const vercelRules: Rule[] = [
  {
    id: 'VRC-001',
    title: 'NEXT_PUBLIC Server Secret Variable Leakage',
    category: 'vercel',
    severity: 'critical',
    confidenceBase: 0.9,
    aiEligible: false,
    appliesTo: ['.env', '.env.example', '.js', '.ts', '.tsx', 'next.config.js'],
    description: 'A variable named with the NEXT_PUBLIC_ prefix appears to reference a backend credential. Parameters prefixed with NEXT_PUBLIC_ are bundled into client configurations and visible publicly in browsers.',
    remediationTemplate: 'Remove NEXT_PUBLIC_ prefixes from AWS secrets, DB passwords, or platform keys. Handle these secrets exclusively inside server-side environments or secure Vercel edge/lambdas.',
    detectionType: 'regex',
    patternString: 'NEXT_PUBLIC_(?:AWS_SECRET|STRIPE_SECRET|STRIPE_KEY|JWT_SECRET|DB_PASSWORD|PASSWORD|PASSPHRASE|SECRET_KEY|DATABASE_URL)\\s*='
  },
  {
    id: 'VRC-002',
    title: 'Permissive CORS Access-Control-Allow-Origin: *',
    category: 'vercel',
    severity: 'medium',
    confidenceBase: 0.75,
    aiEligible: true,
    appliesTo: ['.js', '.ts', 'vercel.json'],
    description: 'Setting Access-Control-Allow-Origin to * allows external domains to query your serverless endpoints. This is dangerous if the endpoint processes sensitive cookies, user payloads, or financial actions.',
    remediationTemplate: 'Configure origins explicitly to reference trusted secure domains only.',
    detectionType: 'regex',
    patternString: 'Access-Control-Allow-Origin[\'"]\\s*,\\s*[\'"]\\*[\'"]|res\\.setHeader\\([\'"]Access-Control-Allow-Origin[\'"]\\s*,\\s*[\'"]\\*[\'"]\\)'
  }
];
