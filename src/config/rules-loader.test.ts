import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { clearRulesCache, getRuleById, getRulesByPort, getRulesBySeverity, loadSecurityRules } from './rules-loader';
import type { SecurityRule } from '../types/index';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const mockRules: SecurityRule[] = [
  { id: 'sg-ssh-world', name: 'SSH Open to World', description: 'SSH port 22 is accessible from anywhere', severity: 'HIGH', port: 22, protocol: 'tcp', source: '0.0.0.0/0', recommendation: 'Restrict SSH access' },
  { id: 'sg-rdp-world', name: 'RDP Open to World', description: 'RDP port 3389 is accessible from anywhere', severity: 'HIGH', port: 3389, protocol: 'tcp', source: '0.0.0.0/0', recommendation: 'Restrict RDP access' },
  { id: 'sg-wide-port-range', name: 'Wide Port Range', description: 'Wide port range', severity: 'MEDIUM', recommendation: 'Restrict ports' },
  { id: 'sg-unused', name: 'Unused Security Group', description: 'Security group is not attached', severity: 'LOW', recommendation: 'Remove unused' }
];

describe('getRuleById', () => {
  it('should return rule when found', () => {
    const rule = getRuleById(mockRules, 'sg-ssh-world');
    expect(rule).toBeDefined();
    expect(rule?.id).toBe('sg-ssh-world');
    expect(rule?.severity).toBe('HIGH');
  });

  it('should return undefined when not found', () => {
    const rule = getRuleById(mockRules, 'non-existent');
    expect(rule).toBeUndefined();
  });
});

describe('getRulesByPort', () => {
  it('should return rules matching the port', () => {
    const rules = getRulesByPort(mockRules, 22);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe('sg-ssh-world');
  });

  it('should return empty array when no rules match', () => {
    const rules = getRulesByPort(mockRules, 9999);
    expect(rules).toEqual([]);
  });
});

describe('getRulesBySeverity', () => {
  it('should return all HIGH severity rules', () => {
    const rules = getRulesBySeverity(mockRules, 'HIGH');
    expect(rules).toHaveLength(2);
    expect(rules.every(r => r.severity === 'HIGH')).toBe(true);
  });

  it('should return all MEDIUM severity rules', () => {
    const rules = getRulesBySeverity(mockRules, 'MEDIUM');
    expect(rules).toHaveLength(1);
  });

  it('should return all LOW severity rules', () => {
    const rules = getRulesBySeverity(mockRules, 'LOW');
    expect(rules).toHaveLength(1);
  });
});

describe('clearRulesCache', () => {
  it('should not throw', () => {
    expect(() => clearRulesCache()).not.toThrow();
  });
});

describe('loadSecurityRules', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rules-test-'));
    clearRulesCache();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    clearRulesCache();
  });

  it('should return empty array when file does not exist', () => {
    const rules = loadSecurityRules('/nonexistent/path/rules.json');
    expect(rules).toEqual([]);
  });

  it('should return empty array when JSON is invalid', () => {
    const invalidPath = path.join(tempDir, 'invalid.json');
    fs.writeFileSync(invalidPath, '{ invalid json }');
    
    const rules = loadSecurityRules(invalidPath);
    expect(rules).toEqual([]);
  });

  it('should load rules from valid custom path', () => {
    const validPath = path.join(tempDir, 'valid.json');
    fs.writeFileSync(validPath, JSON.stringify({
      rules: [{ id: 'test-rule', name: 'Test', description: 'Test rule', severity: 'HIGH', recommendation: 'Fix it' }]
    }));
    
    const rules = loadSecurityRules(validPath);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe('test-rule');
  });

  it('should use cached rules on subsequent calls without customPath', () => {
    const rules1 = loadSecurityRules();
    const rules2 = loadSecurityRules();
    expect(rules1).toBe(rules2);
  });

  it('should not cache rules when customPath is provided', () => {
    const customPath = path.join(tempDir, 'custom.json');
    fs.writeFileSync(customPath, JSON.stringify({
      rules: [{ id: 'custom-rule', name: 'Custom', description: 'Custom rule', severity: 'LOW', recommendation: 'N/A' }]
    }));
    
    const customRules = loadSecurityRules(customPath);
    const defaultRules = loadSecurityRules();
    
    expect(customRules[0].id).toBe('custom-rule');
    expect(defaultRules).not.toBe(customRules);
  });
});
