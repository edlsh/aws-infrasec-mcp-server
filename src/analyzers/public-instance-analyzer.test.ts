import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { EC2Client } from '@aws-sdk/client-ec2';
import { PublicInstanceAnalyzer } from './public-instance-analyzer';

const mockSend = mock(() => Promise.resolve({}));
const mockEC2Client = { send: mockSend } as unknown as EC2Client;

describe('PublicInstanceAnalyzer', () => {
  let analyzer: PublicInstanceAnalyzer;

  beforeEach(() => {
    mockSend.mockClear();
    analyzer = new PublicInstanceAnalyzer();
  });

  describe('analyze', () => {
    it('should identify public instances with dangerous ports as HIGH risk', async () => {
      mockSend
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ InstanceId: 'i-1', PublicIpAddress: '1.2.3.4', State: { Name: 'running' }, SecurityGroups: [{ GroupId: 'sg-1' }] }] }]
        })
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-1', IpPermissions: [{ FromPort: 22, ToPort: 22, IpProtocol: 'tcp', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.publicInstances).toBe(1);
      expect(result.instances[0].riskLevel).toBe('HIGH');
      expect(result.instances[0].exposedPorts).toContain(22);
    });

    it('should identify public instances exposed via IPv6 as HIGH risk', async () => {
      mockSend
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ InstanceId: 'i-ipv6', PublicIpAddress: '1.2.3.4', State: { Name: 'running' }, SecurityGroups: [{ GroupId: 'sg-ipv6' }] }] }]
        })
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-ipv6', IpPermissions: [{ FromPort: 22, ToPort: 22, IpProtocol: 'tcp', Ipv6Ranges: [{ CidrIpv6: '::/0' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.publicInstances).toBe(1);
      expect(result.instances[0].riskLevel).toBe('HIGH');
      expect(result.instances[0].exposedPorts).toContain(22);
    });

    it('should identify instances with many exposed ports as MEDIUM risk', async () => {
      mockSend
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ InstanceId: 'i-2', PublicIpAddress: '5.6.7.8', State: { Name: 'running' }, SecurityGroups: [{ GroupId: 'sg-2' }] }] }]
        })
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-2', IpPermissions: [{ FromPort: 8080, ToPort: 8090, IpProtocol: 'tcp', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.instances[0].riskLevel).toBe('MEDIUM');
    });

    it('should identify instances with few safe ports as LOW risk', async () => {
      mockSend
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ InstanceId: 'i-3', PublicIpAddress: '9.10.11.12', State: { Name: 'running' }, SecurityGroups: [{ GroupId: 'sg-3' }] }] }]
        })
        .mockResolvedValueOnce({
          SecurityGroups: [{ GroupId: 'sg-3', IpPermissions: [{ FromPort: 443, ToPort: 443, IpProtocol: 'tcp', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] }]
        });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.instances[0].riskLevel).toBe('LOW');
    });

    it('should not include stopped instances', async () => {
      mockSend
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [
            { InstanceId: 'i-running', PublicIpAddress: '1.1.1.1', State: { Name: 'running' }, SecurityGroups: [{ GroupId: 'sg-1' }] },
            { InstanceId: 'i-stopped', PublicIpAddress: '2.2.2.2', State: { Name: 'stopped' }, SecurityGroups: [{ GroupId: 'sg-1' }] }
          ] }]
        })
        .mockResolvedValueOnce({ SecurityGroups: [{ GroupId: 'sg-1', IpPermissions: [] }] });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.publicInstances).toBe(1);
      expect(result.instances[0].instanceId).toBe('i-running');
    });

    it('should not include instances without public IPs', async () => {
      mockSend.mockResolvedValueOnce({
        Reservations: [{ Instances: [{ InstanceId: 'i-private', State: { Name: 'running' }, SecurityGroups: [{ GroupId: 'sg-1' }] }] }]
      });

      const result = await analyzer.analyze(mockEC2Client);

      expect(result.summary.publicInstances).toBe(0);
    });

    it('should propagate errors from DescribeInstances', async () => {
      mockSend.mockRejectedValueOnce(new Error('DescribeInstances failed'));

      await expect(analyzer.analyze(mockEC2Client)).rejects.toThrow('Public instance analysis failed');
    });

    it('should propagate errors from DescribeSecurityGroups', async () => {
      mockSend
        .mockResolvedValueOnce({
          Reservations: [{ Instances: [{ InstanceId: 'i-1', PublicIpAddress: '1.2.3.4', State: { Name: 'running' }, SecurityGroups: [{ GroupId: 'sg-1' }] }] }]
        })
        .mockRejectedValueOnce(new Error('DescribeSecurityGroups failed'));

      await expect(analyzer.analyze(mockEC2Client)).rejects.toThrow('Public instance analysis failed');
    });
  });
});
