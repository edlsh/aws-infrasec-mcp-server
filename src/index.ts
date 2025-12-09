import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from '@modelcontextprotocol/sdk/types.js';
import type { McpTool } from './types/index.js';
import { securityGroupTool } from './tools/security-groups.js';
import { publicInstanceTool } from './tools/public-instances.js';

class AWSInfraSecMCPServer {
  private readonly server: Server;
  private readonly tools: Map<string, McpTool>;

  constructor() {
    this.server = new Server(
      { name: 'aws-infrasec-mcp-server', version: '1.0.0' },
      { capabilities: { tools: {} } }
    );

    this.tools = new Map();
    this.registerTools();
    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  private registerTools(): void {
    this.tools.set(securityGroupTool.name, securityGroupTool);
    this.tools.set(publicInstanceTool.name, publicInstanceTool);
  }

  private setupToolHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: Array.from(this.tools.values()).map(tool => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
      })),
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const tool = this.tools.get(name);

      if (!tool) {
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
      }

      try {
        const result = await tool.execute(args);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error) {
        if (error instanceof McpError) throw error;

        if (error instanceof Error) {
          if (error.name === 'UnauthorizedOperation') {
            throw new McpError(ErrorCode.InvalidRequest, `AWS Permission Denied: ${error.message}`);
          }
          if (error.name === 'NetworkingError' || error.name === 'TimeoutError') {
            throw new McpError(ErrorCode.InternalError, `AWS Connection Error: ${error.message}`);
          }
          throw new McpError(ErrorCode.InternalError, `Tool execution failed: ${error.message}`);
        }

        throw new McpError(ErrorCode.InternalError, 'An unexpected error occurred');
      }
    });
  }

  private setupErrorHandling(): void {
    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      process.exit(1);
    });

    process.on('unhandledRejection', (reason) => {
      console.error('Unhandled Rejection:', reason);
      process.exit(1);
    });
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('AWS Infrastructure Security MCP Server started');
  }
}

async function main(): Promise<void> {
  const requiredEnvVars = ['AWS_REGION'];
  // eslint-disable-next-line security/detect-object-injection
  const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
  
  if (missingEnvVars.length > 0) {
    console.error('Missing required environment variables:', missingEnvVars.join(', '));
    process.exit(1);
  }

  const server = new AWSInfraSecMCPServer();
  await server.run();
}

process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));

if (require.main === module) {
  main().catch((error) => {
    console.error('Server startup failed:', error);
    process.exit(1);
  });
}

export { AWSInfraSecMCPServer };
