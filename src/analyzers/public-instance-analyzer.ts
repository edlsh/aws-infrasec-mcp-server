import { 
  Instance,
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  EC2Client 
} from '@aws-sdk/client-ec2';
import type { PublicInstanceInfo, PublicInstanceAnalysisResult, Severity } from '../types/index.js';
import { DANGEROUS_PORTS, EXPOSED_PORTS_MEDIUM_THRESHOLD } from '../config/constants.js';

export class PublicInstanceAnalyzer {
  async analyze(ec2Client: EC2Client): Promise<PublicInstanceAnalysisResult> {
    try {
      const response = await ec2Client.send(new DescribeInstancesCommand({}));
      
      const allInstances: Instance[] = [];
      const publicInstances: PublicInstanceInfo[] = [];

      for (const reservation of response.Reservations ?? []) {
        allInstances.push(...(reservation.Instances ?? []));
      }

      for (const instance of allInstances) {
        if (instance.PublicIpAddress && instance.State?.Name === 'running') {
          const securityGroupIds = instance.SecurityGroups
            ?.map(sg => sg.GroupId)
            .filter((id): id is string => Boolean(id)) ?? [];
          
          const exposedPorts = await this.getExposedPorts(ec2Client, securityGroupIds);
          const riskLevel = this.assessRisk(exposedPorts);
          const recommendations = this.generateRecommendations(exposedPorts);

          publicInstances.push({
            instanceId: instance.InstanceId ?? 'unknown',
            publicIp: instance.PublicIpAddress,
            securityGroups: securityGroupIds,
            exposedPorts,
            riskLevel,
            recommendations
          });
        }
      }

      const totalExposedPorts = publicInstances.reduce((sum, i) => sum + i.exposedPorts.length, 0);

      return {
        summary: {
          totalInstances: allInstances.length,
          publicInstances: publicInstances.length,
          totalExposedPorts,
        },
        instances: publicInstances
      };
    } catch (error) {
      console.error('Error analyzing public instances:', error);
      throw new Error(`Public instance analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async getExposedPorts(ec2Client: EC2Client, securityGroupIds: string[]): Promise<number[]> {
    if (securityGroupIds.length === 0) return [];

    const exposedPorts: number[] = [];
    
    const response = await ec2Client.send(new DescribeSecurityGroupsCommand({ GroupIds: securityGroupIds }));

    for (const sg of response.SecurityGroups ?? []) {
      for (const permission of sg.IpPermissions ?? []) {
        const ipv4Public = permission.IpRanges?.some(range => range.CidrIp === '0.0.0.0/0') ?? false;
        const ipv6Public = permission.Ipv6Ranges?.some(range => range.CidrIpv6 === '::/0') ?? false;

        if (ipv4Public || ipv6Public) {
          if (permission.FromPort !== undefined && permission.ToPort !== undefined) {
            for (let port = permission.FromPort; port <= permission.ToPort; port++) {
              if (!exposedPorts.includes(port)) exposedPorts.push(port);
            }
          }
        }
      }
    }

    return exposedPorts.sort((a, b) => a - b);
  }

  private assessRisk(exposedPorts: number[]): Severity {
    const hasDangerousPorts = exposedPorts.some(port => (DANGEROUS_PORTS as readonly number[]).includes(port));
    
    if (hasDangerousPorts) return 'HIGH';
    if (exposedPorts.length > EXPOSED_PORTS_MEDIUM_THRESHOLD) return 'MEDIUM';
    return 'LOW';
  }

  private generateRecommendations(exposedPorts: number[]): string[] {
    const recommendations: string[] = [];
    const exposedDangerousPorts = exposedPorts.filter(port => (DANGEROUS_PORTS as readonly number[]).includes(port));
    
    if (exposedDangerousPorts.length > 0) {
      recommendations.push(`Restrict access to dangerous ports: ${exposedDangerousPorts.join(', ')}`);
    }
    
    if (exposedPorts.length > EXPOSED_PORTS_MEDIUM_THRESHOLD) {
      recommendations.push('Consider reducing the number of exposed ports');
    }
    
    if (exposedPorts.length > 0) {
      recommendations.push('Use Application Load Balancer or NAT Gateway for controlled access');
      recommendations.push('Consider moving to private subnet with VPN access');
    }
    
    return recommendations;
  }
}
