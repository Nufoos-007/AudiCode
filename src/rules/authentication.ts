import { Rule } from '../types';

export const authenticationRules: Rule[] = [
  {
    id: 'AUTH-001',
    title: 'Missing Route Authentication Middleware',
    category: 'authentication',
    severity: 'high',
    confidenceBase: 0.7,
    aiEligible: true,
    appliesTo: ['.js', '.ts'],
    description: 'An API route handler was declared directly without an intermediate authorization or authentication middleware. This could permit anonymous users to trigger administrative endpoints.',
    remediationTemplate: 'Insert your verifyToken, checkAuth, or equivalent authentication middleware as the second argument in your Route declarations (e.g. router.get("/api/admin", checkAuth, handler)).',
    detectionType: 'regex',
    patternString: 'app\\.(get|post|put|delete)\\(\\s*[\'"]\\/api\\/.*[\'"]\\s*,\\s*(?:async\\s*)?\\([^)]*req\\s*,[^)]*res\\s*\\)\\s*=>'
  },
  {
    id: 'AUTH-002',
    title: 'Client-side Administrative Privileges Verification Check',
    category: 'authentication',
    severity: 'medium',
    confidenceBase: 0.8,
    aiEligible: true,
    appliesTo: ['.jsx', '.tsx', '.js', '.ts'],
    description: 'Verifying administrative permissions or critical roles solely in front-end client states allows users to easily spoof properties/local variables to bypass UI restrictions.',
    remediationTemplate: 'Administrative operations should restrict data endpoints by validating JWT tokens and user roles in backend endpoints, rather than checking client-side states.',
    detectionType: 'regex',
    patternString: 'localStorage\\.getItem\\([\'"]isAdmin[\'"]\\)|user\\.role\\s*===\\s*[\'"]admin[\'"]'
  }
];
