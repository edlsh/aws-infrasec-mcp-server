import { describe, it, expect, beforeEach, afterAll, mock } from 'bun:test';
import { AWSClientService, getAWSClient, resetAWSClient } from './aws-client';

const mockSend = mock(() => Promise.resolve({ Regions: [] }));

mock.module('@aws-sdk/client-ec2', () => ({
  EC2Client: class {
    send = mockSend;
    config = { region: 'us-east-1' };
  },
  DescribeRegionsCommand: function() { return {}; },
  DescribeSecurityGroupsCommand: function() { return {}; },
  DescribeInstancesCommand: function() { return {}; },
}));

describe('AWSClientService', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    mockSend.mockClear();
    resetAWSClient();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('constructor', () => {
    it('should use region from config when provided', () => {
      const service = new AWSClientService({ region: 'eu-west-1' });
      expect(service).toBeDefined();
    });

    it('should use region from environment when config not provided', () => {
      process.env.AWS_REGION = 'ap-southeast-1';
      const service = new AWSClientService();
      expect(service).toBeDefined();
    });

    it('should default to us-east-1 when no region specified', () => {
      delete process.env.AWS_REGION;
      const service = new AWSClientService();
      expect(service.getRegion()).toBe('us-east-1');
    });
  });

  describe('getEC2Client', () => {
    it('should return an EC2Client instance', () => {
      const service = new AWSClientService();
      const client = service.getEC2Client();
      expect(client).toBeDefined();
    });

    it('should return the same client on multiple calls', () => {
      const service = new AWSClientService();
      const client1 = service.getEC2Client();
      const client2 = service.getEC2Client();
      expect(client1).toBe(client2);
    });
  });

  describe('testConnection', () => {
    it('should return true when connection succeeds', async () => {
      mockSend.mockResolvedValueOnce({ Regions: [] });
      const service = new AWSClientService();
      const result = await service.testConnection();
      expect(result).toBe(true);
    });

    it('should return false when connection fails', async () => {
      mockSend.mockRejectedValueOnce(new Error('Connection failed'));
      const service = new AWSClientService();
      const result = await service.testConnection();
      expect(result).toBe(false);
    });
  });
});

describe('getAWSClient singleton', () => {
  beforeEach(() => {
    resetAWSClient();
  });

  it('should return the same instance on multiple calls', () => {
    const client1 = getAWSClient();
    const client2 = getAWSClient();
    expect(client1).toBe(client2);
  });

  it('should create new instance after reset', () => {
    const client1 = getAWSClient();
    resetAWSClient();
    const client2 = getAWSClient();
    expect(client1).not.toBe(client2);
  });

  it('should return different instances for different regions', () => {
    const usClient = getAWSClient({ region: 'us-east-1' });
    const euClient = getAWSClient({ region: 'eu-west-1' });
    expect(usClient).not.toBe(euClient);
  });

  it('should return same instance for same region', () => {
    const client1 = getAWSClient({ region: 'us-west-2' });
    const client2 = getAWSClient({ region: 'us-west-2' });
    expect(client1).toBe(client2);
  });

  it('should return different instances for different credentials', () => {
    const client1 = getAWSClient({ region: 'us-east-1', accessKeyId: 'key1' });
    const client2 = getAWSClient({ region: 'us-east-1', accessKeyId: 'key2' });
    expect(client1).not.toBe(client2);
  });
});
