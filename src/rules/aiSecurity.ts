import { Rule } from '../types';

export const aiSecurityRules: Rule[] = [
  {
    id: 'AI-SEC-001',
    title: 'Prompt Injection Susceptibility in LLM Instructions',
    category: 'ai-security',
    severity: 'medium',
    confidenceBase: 0.6,
    aiEligible: true,
    appliesTo: ['.ts', '.js'],
    description: 'An AI prompt is constructed by directly concatenating raw, untrusted user inputs into a system instruction context. This enables users to perform prompt injections that bypass safety guards.',
    remediationTemplate: 'Implement structural grounding, separate system instructions from user prompts, or enforce input validation on custom variables before placing them in prompts.',
    detectionType: 'regex',
    patternString: 'systemInstruction:\\s*[`\'"].*\\$\\{[a-zA-Z0-9_]+\\}.*[`\'"]'
  },
  {
    id: 'AI-SEC-002',
    title: 'Unsafe Execution of LLM Generated Code (Direct Code Execution)',
    category: 'ai-security',
    severity: 'critical',
    confidenceBase: 0.85,
    aiEligible: true,
    appliesTo: ['.ts', '.js'],
    description: 'Passing strings directly returned from dynamic model or function calls into evals or dynamic command shells creates arbitrary code execution vulnerabilities.',
    remediationTemplate: 'Parse function call parameters using deterministic schemas. Never run dynamic scripts directly in command shells.',
    detectionType: 'regex',
    patternString: 'eval\\(\\s*(?:[a-zA-Z0-9_]+\\.functionCall|[a-zA-Z0-9_]+\\.tool_use|[a-zA-Z0-9_]+\\.content)'
  }
];
