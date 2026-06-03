import { Rule } from '../types';
import { secretsRules } from './secrets';
import { authenticationRules } from './authentication';
import { authorizationRules } from './authorization';
import { xssRules } from './xss';
import { apiSecurityRules } from './apiSecurity';
import { supabaseRules } from './supabase';
import { aiSecurityRules } from './aiSecurity';
import { vercelRules } from './vercel';

export const ruleRegistry: Rule[] = [
  ...secretsRules,
  ...authenticationRules,
  ...authorizationRules,
  ...xssRules,
  ...apiSecurityRules,
  ...supabaseRules,
  ...aiSecurityRules,
  ...vercelRules
];

export function getRulesByCategory(category: string): Rule[] {
  return ruleRegistry.filter(rule => rule.category.toLowerCase() === category.toLowerCase());
}

export function getRulesBySeverity(severity: string): Rule[] {
  return ruleRegistry.filter(rule => rule.severity.toLowerCase() === severity.toLowerCase());
}

export function getRuleById(id: string): Rule | undefined {
  return ruleRegistry.find(rule => rule.id.toUpperCase() === id.toUpperCase());
}
