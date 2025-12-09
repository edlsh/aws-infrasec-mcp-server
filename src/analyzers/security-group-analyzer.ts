import { 
  SecurityGroup, 
  IpPermission, 
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  EC2Client 
} from '@aws-sdk/client-ec2';
import type { SecurityRule, SecurityFinding, SecurityGroupAnalysisResult } from '../types/index.js';
import { loadSecurityRules, getRuleById } from '../config/rules-loader.js';
import { PORT_RANGE_THRESHOLD } from '../config/constants.js';

export interface SecurityGroupAnalyzerOptions {
  rules?: SecurityRule[];
}

export class SecurityGroupAnalyzer {
  private readonly rules: SecurityRule[];

  constructor(options?: SecurityGroupAnalyzerOptions) {
    this.rules = options?.rules ?? loadSecurityRules();
  }

  async analyze(ec2Client: EC2Client, groupIds?: string[]): Promise<SecurityGroupAnalysisResult> {
    try {
      const command = new DescribeSecurityGroupsCommand({ GroupIds: groupIds });
      const response = await ec2Client.send(command);
      const securityGroups = response.SecurityGroups ?? [];

      const findings: SecurityFinding[] = [];

      for (const sg of securityGroups) {
        findings.push(...this.analyzeSecurityGroup(sg));
      }

      const unusedFindings = await this.findUnusedSecurityGroups(ec2Client, securityGroups);
      findings.push(...unusedFindings);

      return {
        summary: this.generateSummary(findings, securityGroups.length),
        findings
      };
    } catch (error) {
      console.error('Error analyzing security groups:', error);
      throw new Error(`Security group analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private analyzeSecurityGroup(sg: SecurityGroup): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const sgId = sg.GroupId ?? 'unknown';
    const sgName = sg.GroupName ?? 'unknown';

    if (!sg.IpPermissions) return findings;

    for (const permission of sg.IpPermissions) {
      findings.push(...this.checkDangerousPorts(permission, sgId, sgName));
      findings.push(...this.checkWidePortRanges(permission, sgId, sgName));
      findings.push(...this.checkAllTrafficRules(permission, sgId, sgName));
    }

    return findings;
  }

  private checkDangerousPorts(permission: IpPermission, sgId: string, sgName: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const fromPort = permission.FromPort;
    const toPort = permission.ToPort;
    const protocol = permission.IpProtocol ?? 'unknown';

    const ipv4Public = permission.IpRanges?.some(range => range.CidrIp === '0.0.0.0/0') ?? false;
    const ipv6Public = permission.Ipv6Ranges?.some(range => range.CidrIpv6 === '::/0') ?? false;

    if (!ipv4Public && !ipv6Public) return findings;

    const publicSource = ipv4Public ? '0.0.0.0/0' : '::/0';

    const dangerousRules = this.rules.filter(rule => 
      rule.port !== undefined && rule.source === '0.0.0.0/0' && rule.protocol === protocol
    );

    for (const rule of dangerousRules) {
      if (fromPort !== undefined && toPort !== undefined && rule.port !== undefined) {
        if (fromPort <= rule.port && rule.port <= toPort) {
          findings.push({
            securityGroupId: sgId,
            securityGroupName: sgName,
            ruleId: rule.id,
            severity: rule.severity,
            description: rule.description,
            recommendation: rule.recommendation,
            affectedRule: { port: rule.port, protocol, source: publicSource }
          });
        }
      }
    }

    return findings;
  }

  private checkWidePortRanges(permission: IpPermission, sgId: string, sgName: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const fromPort = permission.FromPort;
    const toPort = permission.ToPort;

    if (fromPort !== undefined && toPort !== undefined) {
      const portRange = toPort - fromPort;
      
      if (portRange > PORT_RANGE_THRESHOLD) {
        const wideRangeRule = getRuleById(this.rules, 'sg-wide-port-range');
        if (wideRangeRule) {
          const ipv4Source = permission.IpRanges?.[0]?.CidrIp;
          const ipv6Source = permission.Ipv6Ranges?.[0]?.CidrIpv6;
          const source = ipv4Source ?? ipv6Source ?? 'unknown';

          findings.push({
            securityGroupId: sgId,
            securityGroupName: sgName,
            ruleId: wideRangeRule.id,
            severity: wideRangeRule.severity,
            description: `${wideRangeRule.description} (${fromPort}-${toPort})`,
            recommendation: wideRangeRule.recommendation,
            affectedRule: {
              port: `${fromPort}-${toPort}`,
              protocol: permission.IpProtocol ?? 'unknown',
              source
            }
          });
        }
      }
    }

    return findings;
  }

  private checkAllTrafficRules(permission: IpPermission, sgId: string, sgName: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    
    if (permission.IpProtocol === '-1') {
      const ipv4Public = permission.IpRanges?.some(range => range.CidrIp === '0.0.0.0/0') ?? false;
      const ipv6Public = permission.Ipv6Ranges?.some(range => range.CidrIpv6 === '::/0') ?? false;

      if (ipv4Public || ipv6Public) {
        const allTrafficRule = getRuleById(this.rules, 'sg-all-traffic');
        if (allTrafficRule) {
          findings.push({
            securityGroupId: sgId,
            securityGroupName: sgName,
            ruleId: allTrafficRule.id,
            severity: allTrafficRule.severity,
            description: allTrafficRule.description,
            recommendation: allTrafficRule.recommendation,
            affectedRule: { port: 'all', protocol: 'all', source: ipv4Public ? '0.0.0.0/0' : '::/0' }
          });
        }
      }
    }

    return findings;
  }

  private async findUnusedSecurityGroups(ec2Client: EC2Client, securityGroups: SecurityGroup[]): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    
    const instancesResponse = await ec2Client.send(new DescribeInstancesCommand({}));
    const usedSecurityGroups = new Set<string>();
    
    for (const reservation of instancesResponse.Reservations ?? []) {
      for (const instance of reservation.Instances ?? []) {
        for (const sg of instance.SecurityGroups ?? []) {
          if (sg.GroupId) usedSecurityGroups.add(sg.GroupId);
        }
      }
    }

    const unusedRule = getRuleById(this.rules, 'sg-unused');
    if (unusedRule) {
      for (const sg of securityGroups) {
        if (sg.GroupId && !usedSecurityGroups.has(sg.GroupId) && sg.GroupName !== 'default') {
          findings.push({
            securityGroupId: sg.GroupId,
            securityGroupName: sg.GroupName ?? 'unknown',
            ruleId: unusedRule.id,
            severity: unusedRule.severity,
            description: unusedRule.description,
            recommendation: unusedRule.recommendation
          });
        }
      }
    }

    return findings;
  }

  private generateSummary(findings: SecurityFinding[], totalGroups: number): SecurityGroupAnalysisResult['summary'] {
    return {
      totalGroups,
      highRiskFindings: findings.filter(f => f.severity === 'HIGH').length,
      mediumRiskFindings: findings.filter(f => f.severity === 'MEDIUM').length,
      lowRiskFindings: findings.filter(f => f.severity === 'LOW').length
    };
  }
}
