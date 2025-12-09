export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export interface JsonSchemaProperty {
  type: string;
  description?: string;
  default?: unknown;
  items?: JsonSchemaProperty;
  enum?: string[];
  [key: string]: unknown;
}

export interface McpToolInputSchema {
  type: 'object';
  properties?: Record<string, JsonSchemaProperty>;
  required?: readonly string[] | string[];
  [key: string]: unknown;
}

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  port?: number;
  protocol?: string;
  source?: string;
  recommendation: string;
}

export interface SecurityFinding {
  securityGroupId: string;
  securityGroupName: string;
  ruleId: string;
  severity: Severity;
  description: string;
  recommendation: string;
  affectedRule?: {
    port: number | string;
    protocol: string;
    source: string;
  };
}

export interface SecurityGroupSummary {
  totalGroups: number;
  highRiskFindings: number;
  mediumRiskFindings: number;
  lowRiskFindings: number;
}

export interface SecurityGroupAnalysisResult {
  summary: SecurityGroupSummary;
  findings: SecurityFinding[];
}

export interface PublicInstanceInfo {
  instanceId: string;
  publicIp: string;
  securityGroups: string[];
  exposedPorts: number[];
  riskLevel: Severity;
  recommendations: string[];
}

export interface PublicInstanceSummary {
  totalInstances: number;
  publicInstances: number;
  totalExposedPorts: number;
}

export interface PublicInstanceAnalysisResult {
  summary: PublicInstanceSummary;
  instances: PublicInstanceInfo[];
}

export interface CriticalPort {
  port: number;
  service: string;
}

export interface SecurityGroupToolOutput {
  analysisType: 'security-group';
  region: string;
  timestamp: string;
  summary: SecurityGroupSummary & {
    riskDistribution: { high: number; medium: number; low: number };
  };
  findings: SecurityFinding[];
  recommendations: string[];
}

export interface PublicInstanceToolOutput {
  analysisType: 'public-instance';
  region: string;
  timestamp: string;
  summary: PublicInstanceSummary & {
    publicExposureRate: string;
    averageExposedPorts: number;
  };
  instances: Array<PublicInstanceInfo & { criticalPorts: CriticalPort[] }>;
  riskAssessment: {
    highRisk: number;
    mediumRisk: number;
    lowRisk: number;
    criticalServiceExposures: number;
  };
  recommendations: string[];
}

export interface McpTool<TInput = unknown, TOutput = unknown> {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: McpToolInputSchema;
  execute(args: TInput): Promise<TOutput>;
}

export interface AWSClientConfig {
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}
