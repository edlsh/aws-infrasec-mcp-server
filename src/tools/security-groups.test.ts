import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { EC2Client } from '@aws-sdk/client-ec2';
import { SecurityGroupTool, createSecurityGroupTool } from './security-groups';
import { SecurityGroupAnalyzer } from '../analyzers/index';
import { AWSClientService } from '../services/aws-client';
import type { SecurityGroupAnalysisResult } from '../types/index';

const mockEC2Client = {} as unknown as EC2Client;
const mockAWSClient = {
  getEC2Client: mock(() => mockEC2Client),
  getRegion: mock(() => 'us-east-1')
} as unknown as AWSClientService;

const mockAnalysisResult: SecurityGroupAnalysisResult = {
  summary: { totalGroups: 5, highRiskFindings: 2, mediumRiskFindings: 1, lowRiskFindings: 1 },
  findings: [
    { securityGroupId: 'sg-123', securityGroupName: 'test-sg', ruleId: 'sg-ssh-world', severity: 'HIGH', description: 'SSH open to world', recommendation: 'Restrict SSH access', affectedRule: { port: 22, protocol: 'tcp', source: '0.0.0.0/0' } },
    { securityGroupId: 'sg-456', securityGroupName: 'db-sg', ruleId: 'sg-mysql-exposed', severity: 'HIGH', description: 'MySQL exposed', recommendation: 'Move to private subnet', affectedRule: { port: 3306, protocol: 'tcp', source: '0.0.0.0/0' } },
    { securityGroupId: 'sg-789', securityGroupName: 'wide-sg', ruleId: 'sg-wide-port-range', severity: 'MEDIUM', description: 'Wide port range', recommendation: 'Restrict ports' },
    { securityGroupId: 'sg-unused', securityGroupName: 'unused-sg', ruleId: 'sg-unused', severity: 'LOW', description: 'Unused security group', recommendation: 'Remove unused' }
  ]
};

describe('SecurityGroupTool', () => {
  let mockAnalyzer: { analyze: ReturnType<typeof mock> };
  let tool: SecurityGroupTool;

  beforeEach(() => {
    mockAnalyzer = { analyze: mock(() => Promise.resolve(mockAnalysisResult)) };
    tool = new SecurityGroupTool({ awsClient: mockAWSClient, analyzer: mockAnalyzer as unknown as SecurityGroupAnalyzer });
  });

  describe('metadata', () => {
    it('should have correct name', () => {
      expect(tool.name).toBe('analyze_security_groups');
    });

    it('should have valid input schema', () => {
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties).toHaveProperty('region');
    });
  });

  describe('execute', () => {
    it('should return analysis results with correct structure', async () => {
      const result = await tool.execute({});
      expect(result.analysisType).toBe('security-group');
      expect(result.region).toBe('us-east-1');
      expect(result.summary).toBeDefined();
      expect(result.findings).toBeDefined();
    });

    it('should include summary with risk distribution', async () => {
      const result = await tool.execute({});
      expect(result.summary.totalGroups).toBe(5);
      expect(result.summary.riskDistribution.high).toBe(2);
    });

    it('should pass groupIds to analyzer when provided', async () => {
      await tool.execute({ groupIds: ['sg-123', 'sg-456'] });
      expect(mockAnalyzer.analyze).toHaveBeenCalledWith(mockEC2Client, ['sg-123', 'sg-456']);
    });
  });

  describe('error handling', () => {
    it('should throw on validation failure', async () => {
      await expect(tool.execute({ groupIds: 'not-an-array' })).rejects.toThrow('Input validation failed');
    });

    it('should throw on analyzer failure', async () => {
      mockAnalyzer.analyze.mockRejectedValueOnce(new Error('AWS error'));
      await expect(tool.execute({})).rejects.toThrow('Security group analysis failed');
    });
  });
});

describe('createSecurityGroupTool', () => {
  it('should create a new tool instance', () => {
    const tool = createSecurityGroupTool();
    expect(tool).toBeInstanceOf(SecurityGroupTool);
  });
});
