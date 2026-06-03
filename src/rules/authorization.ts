import { Rule } from '../types';

export const authorizationRules: Rule[] = [
  {
    id: 'AUTHZ-001',
    title: 'ID-Only Direct Database Queries (Potential IDOR / Ownership Bypass)',
    category: 'authorization',
    severity: 'high',
    confidenceBase: 0.65,
    aiEligible: true,
    appliesTo: ['.js', '.ts'],
    description: 'An entity is retrieved directly using an ID supplied by req.params or req.body without verifying that the requesting user owns that entity. This leads to Insecure Direct Object Reference (IDOR) vulnerabilities.',
    remediationTemplate: 'Always filter queries by BOTH the target entity ID and the requesting user ID from the verified token (e.g., SELECT * FROM tasks WHERE id = req.params.id AND user_id = req.user.id).',
    detectionType: 'regex',
    patternString: 'select\\s*\\*\\s*from\\s+[a-zA-Z0-9_]+\\s+where\\s+id\\s*=\\s*(req\\.params\\.[a-zA-Z0-9_]+|req\\.body\\.[a-zA-Z0-9_]+)'
  },
  {
    id: 'AUTHZ-002',
    title: 'Trusting Client-Sent Role Headers',
    category: 'authorization',
    severity: 'critical',
    confidenceBase: 0.85,
    aiEligible: true,
    appliesTo: ['.js', '.ts'],
    description: 'The application extracts user roles directly from client headers (e.g., x-user-role or x-role). Attackers can manipulate headers arbitrarily to escalate their permissions.',
    remediationTemplate: 'Extract the sub-identifier or user profile ID directly from a verified token payload. Query database roles securely server-side.',
    detectionType: 'regex',
    patternString: 'req\\.headers\\[[\'"]x-user-role[\'"]\\]|req\\.headers\\[[\'"]x-role[\'"]\\]'
  }
];
