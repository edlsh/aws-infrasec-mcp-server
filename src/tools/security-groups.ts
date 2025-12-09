import { z } from 'zod';
import type { SecurityFinding, SecurityGroupToolOutput, McpTool } from '../types/index.js';
import { SecurityGroupAnalyzer } from '../analyzers/index.js';
import { getAWSClient, AWSClientService } from '../services/aws-client.js';

const SecurityGroupAnalysisSchema = z.object({
  region: z.string().optional(),
  groupIds: z.array(z.string()).optional(),
  includeUnused: z.boolean().optional().default(true)
});

export type SecurityGroupAnalysisInput = z.infer<typeof SecurityGroupAnalysisSchema>;

export interface SecurityGroupToolDependencies {
  awsClient?: AWSClientService;
  analyzer?: SecurityGroupAnalyzer;
}

export class SecurityGroupTool implements McpTool<unknown, SecurityGroupToolOutput> {
  readonly name = 'analyze_security_groups';
  readonly description = 'Analyze AWS Security Groups for potential security misconfigurations and vulnerabilities';

  readonly inputSchema = {
    type: 'object',
    properties: {
      region: { type: 'string', description: 'AWS region to analyze' },
      groupIds: { type: 'array', items: { type: 'string' }, description: 'Specific security group IDs to analyze' },
      includeUnused: { type: 'boolean', description: 'Include unused security groups', default: true }
    },
    required: []
  } as const;

  private readonly awsClient: AWSClientService;
  private readonly analyzer: SecurityGroupAnalyzer;

  constructor(deps?: SecurityGroupToolDependencies) {
    this.awsClient = deps?.awsClient ?? getAWSClient();
    this.analyzer = deps?.analyzer ?? new SecurityGroupAnalyzer();
  }

  async execute(input: unknown): Promise<SecurityGroupToolOutput> {
    try {
      const validatedInput = SecurityGroupAnalysisSchema.parse(input);
      const ec2Client = this.awsClient.getEC2Client();
      const region = validatedInput.region ?? this.awsClient.getRegion();

      const analysisResult = await this.analyzer.analyze(ec2Client, validatedInput.groupIds);

      return {
        analysisType: 'security-group',
        region,
        timestamp: new Date().toISOString(),
        summary: {
          ...analysisResult.summary,
          riskDistribution: {
            high: analysisResult.summary.highRiskFindings,
            medium: analysisResult.summary.mediumRiskFindings,
            low: analysisResult.summary.lowRiskFindings
          }
        },
        findings: analysisResult.findings,
        recommendations: this.generateRecommendations(analysisResult.findings)
      };
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(`Input validation failed: ${error.issues.map(e => e.message).join(', ')}`);
      }
      if (error instanceof Error) {
        throw new Error(`Security group analysis failed: ${error.message}`);
      }
      throw new Error('An unexpected error occurred during security group analysis');
    }
  }

  private generateRecommendations(findings: SecurityFinding[]): string[] {
    const recommendations: string[] = [];
    const highRiskCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumRiskCount = findings.filter(f => f.severity === 'MEDIUM').length;
    
    if (highRiskCount > 0) {
      recommendations.push(`Address ${highRiskCount} HIGH severity findings immediately`);
      recommendations.push('Implement principle of least privilege for security group rules');
      recommendations.push('Use specific IP ranges instead of 0.0.0.0/0 where possible');
    }
    
    if (mediumRiskCount > 0) {
      recommendations.push(`Review ${mediumRiskCount} MEDIUM severity findings`);
      recommendations.push('Consider implementing a security group naming convention');
    }
    
    recommendations.push('Regular security group audits should be performed');
    recommendations.push('Consider using AWS Config for continuous compliance monitoring');
    recommendations.push('Implement Infrastructure as Code (IaC) for consistent security group management');
    
    return recommendations;
  }
}

export function createSecurityGroupTool(deps?: SecurityGroupToolDependencies): SecurityGroupTool {
  return new SecurityGroupTool(deps);
}

export const securityGroupTool = new SecurityGroupTool();
