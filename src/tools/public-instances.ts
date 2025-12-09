import { z } from 'zod';
import type { PublicInstanceToolOutput, McpTool, CriticalPort, PublicInstanceInfo } from '../types/index.js';
import { PublicInstanceAnalyzer } from '../analyzers/index.js';
import { getAWSClient, AWSClientService } from '../services/aws-client.js';
import { CRITICAL_PORT_MAP } from '../config/constants.js';

const PublicInstanceAnalysisSchema = z.object({
  region: z.string().optional(),
  includeSecurityGroups: z.boolean().optional().default(true)
});

export type PublicInstanceAnalysisInput = z.infer<typeof PublicInstanceAnalysisSchema>;

export interface PublicInstanceToolDependencies {
  awsClient?: AWSClientService;
  analyzer?: PublicInstanceAnalyzer;
}

export class PublicInstanceTool implements McpTool<unknown, PublicInstanceToolOutput> {
  readonly name = 'analyze_public_instances';
  readonly description = 'Analyze EC2 instances for public IP exposure and associated security risks';

  readonly inputSchema = {
    type: 'object',
    properties: {
      region: { type: 'string', description: 'AWS region to scan' },
      includeSecurityGroups: { type: 'boolean', description: 'Include security group analysis', default: true }
    },
    required: []
  } as const;

  private readonly awsClient: AWSClientService;
  private readonly analyzer: PublicInstanceAnalyzer;

  constructor(deps?: PublicInstanceToolDependencies) {
    this.awsClient = deps?.awsClient ?? getAWSClient();
    this.analyzer = deps?.analyzer ?? new PublicInstanceAnalyzer();
  }

  async execute(input: unknown): Promise<PublicInstanceToolOutput> {
    try {
      const validatedInput = PublicInstanceAnalysisSchema.parse(input);
      const ec2Client = this.awsClient.getEC2Client();
      const region = validatedInput.region ?? this.awsClient.getRegion();

      const analysisResult = await this.analyzer.analyze(ec2Client);

      const instancesWithCriticalPorts = analysisResult.instances.map(instance => ({
        ...instance,
        criticalPorts: this.getCriticalPorts(instance.exposedPorts)
      }));

      const riskAssessment = this.generateRiskAssessment(analysisResult.instances);

      return {
        analysisType: 'public-instance',
        region,
        timestamp: new Date().toISOString(),
        summary: {
          ...analysisResult.summary,
          publicExposureRate: analysisResult.summary.totalInstances > 0 
            ? `${Math.round((analysisResult.summary.publicInstances / analysisResult.summary.totalInstances) * 100)}%`
            : '0%',
          averageExposedPorts: analysisResult.summary.publicInstances > 0
            ? Math.round(analysisResult.summary.totalExposedPorts / analysisResult.summary.publicInstances)
            : 0
        },
        instances: instancesWithCriticalPorts,
        riskAssessment,
        recommendations: this.generateRecommendations(analysisResult.instances, riskAssessment)
      };
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(`Input validation failed: ${error.issues.map(e => e.message).join(', ')}`);
      }
      if (error instanceof Error) {
        throw new Error(`Public instance analysis failed: ${error.message}`);
      }
      throw new Error('An unexpected error occurred during public instance analysis');
    }
  }

  private getCriticalPorts(exposedPorts: number[]): CriticalPort[] {
    return exposedPorts
      .filter(port => CRITICAL_PORT_MAP.has(port))
      .map(port => ({ port, service: CRITICAL_PORT_MAP.get(port) ?? 'Unknown' }));
  }

  private generateRiskAssessment(instances: PublicInstanceInfo[]): PublicInstanceToolOutput['riskAssessment'] {
    const criticalServiceExposures = instances.reduce((acc, instance) => {
      return acc + this.getCriticalPorts(instance.exposedPorts).length;
    }, 0);

    return {
      highRisk: instances.filter(i => i.riskLevel === 'HIGH').length,
      mediumRisk: instances.filter(i => i.riskLevel === 'MEDIUM').length,
      lowRisk: instances.filter(i => i.riskLevel === 'LOW').length,
      criticalServiceExposures
    };
  }

  private generateRecommendations(
    instances: PublicInstanceInfo[],
    riskAssessment: PublicInstanceToolOutput['riskAssessment']
  ): string[] {
    const recommendations: string[] = [];

    if (instances.length === 0) {
      recommendations.push('No public instances detected - good security posture');
      recommendations.push('Continue regular monitoring for new public instances');
      return recommendations;
    }

    if (riskAssessment.highRisk > 0) {
      recommendations.push(`${riskAssessment.highRisk} high-risk public instances require immediate attention`);
      recommendations.push('Consider moving critical services to private subnets');
      recommendations.push('Implement bastion hosts or VPN for administrative access');
    }

    if (riskAssessment.criticalServiceExposures > 0) {
      recommendations.push(`${riskAssessment.criticalServiceExposures} critical service ports exposed`);
      recommendations.push('Use Application Load Balancers to reduce direct instance exposure');
      recommendations.push('Consider CloudFront for web applications');
    }

    recommendations.push('Implement Infrastructure as Code for consistent security configurations');
    recommendations.push('Set up CloudWatch alerts for new public instance creation');
    recommendations.push('Regular security assessments should be automated');

    return recommendations;
  }
}

export function createPublicInstanceTool(deps?: PublicInstanceToolDependencies): PublicInstanceTool {
  return new PublicInstanceTool(deps);
}

export const publicInstanceTool = new PublicInstanceTool();
