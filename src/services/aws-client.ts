import { EC2Client, EC2ClientConfig } from '@aws-sdk/client-ec2';
import type { AWSClientConfig } from '../types/index.js';

export { AWSClientConfig };

export class AWSClientService {
  private readonly ec2Client: EC2Client;

  constructor(config?: AWSClientConfig) {
    const clientConfig: EC2ClientConfig = {
      region: config?.region ?? process.env.AWS_REGION ?? 'us-east-1',
    };

    if (config?.accessKeyId && config?.secretAccessKey) {
      clientConfig.credentials = {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
      };
    } else if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
      clientConfig.credentials = {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      };
    }

    this.ec2Client = new EC2Client(clientConfig);
  }

  getEC2Client(): EC2Client {
    return this.ec2Client;
  }

  getRegion(): string {
    return this.ec2Client.config.region?.toString() ?? 'us-east-1';
  }

  async testConnection(): Promise<boolean> {
    try {
      const { DescribeRegionsCommand } = await import('@aws-sdk/client-ec2');
      await this.ec2Client.send(new DescribeRegionsCommand({}));
      return true;
    } catch (error) {
      console.error('AWS connection test failed:', error);
      return false;
    }
  }
}

const clientsByKey = new Map<string, AWSClientService>();

export function getAWSClient(config?: AWSClientConfig): AWSClientService {
  const key = JSON.stringify({
    region: config?.region ?? process.env.AWS_REGION ?? 'us-east-1',
    accessKeyId: config?.accessKeyId ?? process.env.AWS_ACCESS_KEY_ID ?? '',
  });
  
  let client = clientsByKey.get(key);
  if (!client) {
    client = new AWSClientService(config);
    clientsByKey.set(key, client);
  }
  return client;
}

export function resetAWSClient(): void {
  clientsByKey.clear();
}
