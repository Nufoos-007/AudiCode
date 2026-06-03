import { Rule } from '../types';

export const apiSecurityRules: Rule[] = [
  {
    id: 'API-001',
    title: 'Unvalidated String Concatenation SQL Query (SQL Injection)',
    category: 'api-security',
    severity: 'critical',
    confidenceBase: 0.7,
    aiEligible: true,
    appliesTo: ['.js', '.ts'],
    description: 'Concatenating raw variables directly into database request strings permits SQL Injection. Attackers can escape statements to destroy tables or access database cells.',
    remediationTemplate: 'Implement parametrized query bindings (e.g., SELECT * FROM users WHERE email = $1) to isolate raw strings safely.',
    detectionType: 'regex',
    patternString: 'query\\(\\s*[\'`"]SELECT.*WHERE.*=\\s*[\'`"]\\s*\\+\\s*[a-zA-Z0-9_.]+'
  },
  {
    id: 'API-002',
    title: 'Weak Webhook Signature Validation',
    category: 'api-security',
    severity: 'high',
    confidenceBase: 0.65,
    aiEligible: true,
    appliesTo: ['.js', '.ts'],
    description: 'Webhook routes designated to handle callbacks (e.g., stripe-webhook, stripe_webhook, etc.) should enforce request signature validation. Processing webhook payloads without validating signatures allows attackers to forge mock event structures.',
    remediationTemplate: 'Utilize specialized utility methods (e.g. stripe.webhooks.constructEvent) along with matching signature keys to authenticate inbound headers.',
    detectionType: 'regex',
    patternString: 'router\\.post\\(\\s*[\'"][^\'"]*webhook[^\'"]*[\'"]\\s*,\\s*(?:async\\s*)?\\(req,\\s*res\\)\\s*=>'
  }
];
