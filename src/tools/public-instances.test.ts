import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { EC2Client } from '@aws-sdk/client-ec2';
import { PublicInstanceTool, createPublicInstanceTool } from './public-instances';
import { PublicInstanceAnalyzer } from '../analyzers/index';
import { AWSClientService } from '../services/aws-client';
import type { PublicInstanceAnalysisResult } from '../types/index';

const mockEC2Client = {} as unknown as EC2Client;
const mockAWSClient = {
  getEC2Client: mock(() => mockEC2Client),
  getRegion: mock(() => 'us-east-1')
} as unknown as AWSClientService;

const mockAnalysisResult: PublicInstanceAnalysisResult = {
  summary: { totalInstances: 10, publicInstances: 3, totalExposedPorts: 5 },
  instances: [
    { instanceId: 'i-high-risk', publicIp: '1.2.3.4', securityGroups: ['sg-1'], exposedPorts: [22, 3306], riskLevel: 'HIGH', recommendations: ['Restrict SSH'] },
    { instanceId: 'i-medium-risk', publicIp: '5.6.7.8', securityGroups: ['sg-2'], exposedPorts: [80, 443, 8080, 8081, 8082, 8083], riskLevel: 'MEDIUM', recommendations: [] },
    { instanceId: 'i-low-risk', publicIp: '9.10.11.12', securityGroups: ['sg-3'], exposedPorts: [443], riskLevel: 'LOW', recommendations: [] }
  ]
};

describe('PublicInstanceTool', () => {
  let mockAnalyzer: { analyze: ReturnType<typeof mock> };
  let tool: PublicInstanceTool;

  beforeEach(() => {
    mockAnalyzer = { analyze: mock(() => Promise.resolve(mockAnalysisResult)) };
    tool = new PublicInstanceTool({ awsClient: mockAWSClient, analyzer: mockAnalyzer as unknown as PublicInstanceAnalyzer });
  });

  describe('metadata', () => {
    it('should have correct name', () => {
      expect(tool.name).toBe('analyze_public_instances');
    });

    it('should have valid input schema', () => {
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties).toHaveProperty('region');
    });
  });

  describe('execute', () => {
    it('should return analysis results with correct structure', async () => {
      const result = await tool.execute({});
      expect(result.analysisType).toBe('public-instance');
      expect(result.region).toBe('us-east-1');
      expect(result.summary).toBeDefined();
      expect(result.instances).toBeDefined();
    });

    it('should calculate public exposure rate correctly', async () => {
      const result = await tool.execute({});
      expect(result.summary.publicExposureRate).toBe('30%');
    });

    it('should handle zero public instances', async () => {
      mockAnalyzer.analyze.mockResolvedValueOnce({ summary: { totalInstances: 5, publicInstances: 0, totalExposedPorts: 0 }, instances: [] });
      const result = await tool.execute({});
      expect(result.summary.publicExposureRate).toBe('0%');
    });

    it('should generate risk assessment', async () => {
      const result = await tool.execute({});
      expect(result.riskAssessment.highRisk).toBe(1);
      expect(result.riskAssessment.mediumRisk).toBe(1);
      expect(result.riskAssessment.lowRisk).toBe(1);
    });
  });

  describe('error handling', () => {
    it('should throw on validation failure', async () => {
      await expect(tool.execute({ region: 123 })).rejects.toThrow('Input validation failed');
    });

    it('should throw on analyzer failure', async () => {
      mockAnalyzer.analyze.mockRejectedValueOnce(new Error('AWS error'));
      await expect(tool.execute({})).rejects.toThrow('Public instance analysis failed');
    });
  });
});

describe('createPublicInstanceTool', () => {
  it('should create a new tool instance', () => {
    const tool = createPublicInstanceTool();
    expect(tool).toBeInstanceOf(PublicInstanceTool);
  });
});
