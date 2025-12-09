import * as path from 'path';
import * as fs from 'fs';
import type { SecurityRule } from '../types/index.js';

const DEFAULT_RULES_PATH = path.join(__dirname, '..', 'rules', 'security-rules.json');

let cachedRules: SecurityRule[] | null = null;

export function loadSecurityRules(customPath?: string): SecurityRule[] {
  if (cachedRules && !customPath) {
    return cachedRules;
  }

  const rulePath = customPath ?? DEFAULT_RULES_PATH;

  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    if (!fs.existsSync(rulePath)) {
      console.error(`Security rules file not found: ${rulePath}`);
      return [];
    }

    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const rulesData = fs.readFileSync(rulePath, 'utf8');
    const rulesConfig = JSON.parse(rulesData) as { rules: SecurityRule[] };
    
    if (!customPath) {
      cachedRules = rulesConfig.rules;
    }
    
    return rulesConfig.rules;
  } catch (error) {
    console.error(`Failed to load security rules from: ${rulePath}`, error);
    return [];
  }
}

export function clearRulesCache(): void {
  cachedRules = null;
}

export function getRuleById(rules: SecurityRule[], ruleId: string): SecurityRule | undefined {
  return rules.find(rule => rule.id === ruleId);
}

export function getRulesByPort(rules: SecurityRule[], port: number): SecurityRule[] {
  return rules.filter(rule => rule.port === port);
}

export function getRulesBySeverity(rules: SecurityRule[], severity: SecurityRule['severity']): SecurityRule[] {
  return rules.filter(rule => rule.severity === severity);
}
