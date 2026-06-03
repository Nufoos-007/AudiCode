import { Rule } from '../types';

export const xssRules: Rule[] = [
  {
    id: 'XSS-001',
    title: 'Unsafe React dangerouslySetInnerHTML Usage',
    category: 'xss',
    severity: 'high',
    confidenceBase: 0.8,
    aiEligible: true,
    appliesTo: ['.jsx', '.tsx', '.js', '.ts'],
    description: 'React elements using "dangerouslySetInnerHTML" bypass standard escaping. Supplying unescaped, untrusted input into this prop allows malicious scripts to execute within visitor scopes.',
    remediationTemplate: 'Sanitize HTML text utilizing specialized filters such as dompurify before insertion, or rely on native text variables rather than raw structures.',
    detectionType: 'regex',
    patternString: 'dangerouslySetInnerHTML\\s*=\\s*\\{\\{\\s*__html:'
  },
  {
    id: 'XSS-002',
    title: 'Raw Direct DOM InnerHTML Assignment',
    category: 'xss',
    severity: 'medium',
    confidenceBase: 0.75,
    aiEligible: true,
    appliesTo: ['.js', '.ts', '.html'],
    description: 'Modifying DOM states through raw assignment of .innerHTML or document.write directly injects parsed elements. Without strict sanitization, this leads to Client-side XSS.',
    remediationTemplate: 'Set text nodes securely utilizing textContent or innerText, or sanitize elements explicitly before innerHTML insertion.',
    detectionType: 'regex',
    patternString: '\\.innerHTML\\s*=\\s*[a-zA-Z0-9_().]+|document\\.write\\('
  }
];
