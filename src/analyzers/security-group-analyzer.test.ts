import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { EC2Client } from '@aws-sdk/client-ec2';
import { SecurityGroupAnalyzer } from './security-group-analyzer';
import type { SecurityRule } from '../types/index';

const mockSend = mock(() => Promise.resolve({}));
const mockEC2Client = { send: mockSend } as unknown as EC2Client;

const mockRules: SecurityRule[] = [
  { id: 'sg-ssh-world', name: 'SSH Open to World', description: 'SSH port 22 is accessible from anywhere', severity: 'HIGH', port: 22, protocol: 'tcp', source: '0.0.0.0/0', recommendation: 'Restrict SSH access' },
  { id: 'sg-wide-port-range', name: 'Wide Port Range', description: 'Wide port range', severity: 'MEDIUM', recommendation: 'Restrict ports' },
  { id: 'sg-unused', name: 'Unused Security Group', description: 'Security group is not attached', severity: 'LOW', recommendation: 'Remove unused' },
  { id: 'sg-all-traffic', name: 'All Traffic Allowed', description: 'All traffic allowed', severity: 'HIGH', recommendation: 'Restrict traffic' }
];

describe('SecurityGroupAnalyzer', () => {
  let analyzer: SecurityGroupAnalyzer;

  beforeEach(() => {
    mockSend.mockClear();
    analyzer = new SecurityGroupAnalyzer({ rules: mockRules });
  });

  describe('analyze', () => {
    it('should identify HIGH severity finding for open SSH port', async () => {
      mockSend
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-1', GroupName: 'test-sg', IpPermissions: [{ FromPort: 22, ToPort: 22, IpProtocol: 'tcp', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] }]
        })
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ SecurityGroups: [{ GroupId: 'sg-1' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.highRiskFindings).toBe(1);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].ruleId).toBe('sg-ssh-world');
    });

    it('should identify HIGH severity finding for IPv6 open SSH port', async () => {
      mockSend
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-ipv6', GroupName: 'ipv6-sg', IpPermissions: [{ FromPort: 22, ToPort: 22, IpProtocol: 'tcp', Ipv6Ranges: [{ CidrIpv6: '::/0' }] }] }]
        })
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ SecurityGroups: [{ GroupId: 'sg-ipv6' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.highRiskFindings).toBe(1);
      expect(result.findings[0].ruleId).toBe('sg-ssh-world');
      expect(result.findings[0].affectedRule?.source).toBe('::/0');
    });

    it('should identify HIGH severity finding for all traffic with IPv6', async () => {
      mockSend
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-all', GroupName: 'all-traffic-sg', IpPermissions: [{ IpProtocol: '-1', Ipv6Ranges: [{ CidrIpv6: '::/0' }] }] }]
        })
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ SecurityGroups: [{ GroupId: 'sg-all' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.highRiskFindings).toBe(1);
      expect(result.findings[0].ruleId).toBe('sg-all-traffic');
      expect(result.findings[0].affectedRule?.source).toBe('::/0');
    });

    it('should identify MEDIUM severity finding for wide port range', async () => {
      mockSend
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-2', GroupName: 'wide-range-sg', IpPermissions: [{ FromPort: 1000, ToPort: 2000, IpProtocol: 'tcp', IpRanges: [{ CidrIp: '10.0.0.0/8' }] }] }]
        })
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ SecurityGroups: [{ GroupId: 'sg-2' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.mediumRiskFindings).toBe(1);
      expect(result.findings[0].severity).toBe('MEDIUM');
    });

    it('should identify LOW severity finding for unused security group', async () => {
      mockSend
        .mockResolvedValueOnce({ SecurityGroups: [{ GroupId: 'sg-unused', GroupName: 'unused-sg', IpPermissions: [] }] })
        .mockResolvedValueOnce({ Reservations: [] });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.lowRiskFindings).toBe(1);
      expect(result.findings[0].ruleId).toBe('sg-unused');
    });

    it('should propagate errors from DescribeSecurityGroups', async () => {
      mockSend.mockRejectedValueOnce(new Error('AWS API Error'));

      await expect(analyzer.analyze(mockEC2Client)).rejects.toThrow('Security group analysis failed');
    });

    it('should propagate errors from DescribeInstances in unused check', async () => {
      mockSend
        .mockResolvedValueOnce({ SecurityGroups: [{ GroupId: 'sg-1', GroupName: 'test-sg', IpPermissions: [] }] })
        .mockRejectedValueOnce(new Error('DescribeInstances failed'));

      await expect(analyzer.analyze(mockEC2Client)).rejects.toThrow('Security group analysis failed');
    });
  });
});
