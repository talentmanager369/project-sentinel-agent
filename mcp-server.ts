import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequest,
  ListToolsRequest,
  Tool,
  TextContent,
} from "@modelcontextprotocol/sdk/types.js";
import { MongoClient, Db, Collection } from "mongodb";

// MongoDB Configuration
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const DB_NAME = "sentinel_threat_db";
const THREAT_COLLECTION = "threat_registry";

// Types
interface ThreatPayload {
  applicationHash: string;
  packageName: string;
  developerSignature: string;
  riskScore: number;
  structuralAnomalies: string[];
  timestamp: Date;
  detectionMethod: string;
}

interface ThreatQuery {
  packageName?: string;
  riskScoreMin?: number;
  riskScoreMax?: number;
  developerSignature?: string;
  limit?: number;
}

// Initialize MongoDB connection
let mongoClient: MongoClient;
let threatDb: Db;
let threatCollection: Collection<ThreatPayload>;

async function initializeDatabase(): Promise<void> {
  try {
    mongoClient = new MongoClient(MONGODB_URI);
    await mongoClient.connect();
    console.log("✓ Connected to MongoDB");

    threatDb = mongoClient.db(DB_NAME);
    threatCollection = threatDb.collection<ThreatPayload>(THREAT_COLLECTION);

    // Create indexes for efficient querying
    await threatCollection.createIndex({ packageName: 1 });
    await threatCollection.createIndex({ riskScore: -1 });
    await threatCollection.createIndex({ developerSignature: 1 });
    await threatCollection.createIndex({ timestamp: -1 });

    console.log("✓ Database initialized with indexes");
  } catch (error) {
    console.error("MongoDB initialization error:", error);
    throw error;
  }
}

// Calculate risk assessment score
function calculateRiskAssessment(payload: Omit<ThreatPayload, "timestamp" | "riskScore">): number {
  let baseRisk = 0;

  // Hash anomaly detection
  if (payload.applicationHash && payload.applicationHash.length < 32) {
    baseRisk += 15;
  }

  // Package name analysis
  if (payload.packageName) {
    const suspiciousPatterns = /clone|fake|fraud|malware|scam|phishing/i;
    if (suspiciousPatterns.test(payload.packageName)) {
      baseRisk += 30;
    }
  }

  // Structural anomalies
  if (payload.structuralAnomalies && payload.structuralAnomalies.length > 0) {
    baseRisk += Math.min(payload.structuralAnomalies.length * 10, 40);
  }

  // Developer signature verification
  if (!payload.developerSignature || payload.developerSignature === "unknown") {
    baseRisk += 20;
  }

  return Math.min(baseRisk, 100);
}

// Tool: Query Threat Registry
async function queryThreatRegistry(params: ThreatQuery): Promise<string> {
  try {
    const query: Record<string, unknown> = {};

    if (params.packageName) {
      query.packageName = { $regex: params.packageName, $options: "i" };
    }

    if (params.riskScoreMin !== undefined || params.riskScoreMax !== undefined) {
      query.riskScore = {};
      if (params.riskScoreMin !== undefined) {
        (query.riskScore as Record<string, number>).$gte = params.riskScoreMin;
      }
      if (params.riskScoreMax !== undefined) {
        (query.riskScore as Record<string, number>).$lte = params.riskScoreMax;
      }
    }

    if (params.developerSignature) {
      query.developerSignature = params.developerSignature;
    }

    const results = await threatCollection
      .find(query)
      .sort({ timestamp: -1 })
      .limit(params.limit || 10)
      .toArray();

    if (results.length === 0) {
      return JSON.stringify({
        success: true,
        message: "No threats matching query found",
        count: 0,
        results: [],
      });
    }

    return JSON.stringify({
      success: true,
      message: `Found ${results.length} threat(s)`,
      count: results.length,
      results: results.map((threat) => ({
        packageName: threat.packageName,
        riskScore: threat.riskScore,
        detectionMethod: threat.detectionMethod,
        timestamp: threat.timestamp.toISOString(),
        anomalies: threat.structuralAnomalies,
      })),
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return JSON.stringify({
      success: false,
      error: `Query failed: ${errorMessage}`,
    });
  }
}

// Tool: Write Emerging Threat
async function writeEmergingThreat(payload: Omit<ThreatPayload, "timestamp" | "riskScore">): Promise<string> {
  try {
    // Validate required fields
    if (!payload.packageName || !payload.applicationHash) {
      throw new Error("Missing required fields: packageName and applicationHash");
    }

    // Calculate risk assessment
    const calculatedRiskScore = calculateRiskAssessment(payload);

    // Create threat document
    const threatDoc: ThreatPayload = {
      ...payload,
      riskScore: calculatedRiskScore,
      timestamp: new Date(),
    };

    // Write to database
    const result = await threatCollection.insertOne(threatDoc);

    // Alert if high-risk
    if (calculatedRiskScore >= 70) {
      console.warn(`🚨 HIGH-RISK THREAT DETECTED: ${payload.packageName} (Score: ${calculatedRiskScore})`);
    }

    return JSON.stringify({
      success: true,
      message: "Threat recorded successfully",
      documentId: result.insertedId.toString(),
      riskScore: calculatedRiskScore,
      alert: calculatedRiskScore >= 70 ? "HIGH-RISK THREAT FLAGGED" : "Normal monitoring",
      timestamp: threatDoc.timestamp.toISOString(),
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return JSON.stringify({
      success: false,
      error: `Failed to write threat: ${errorMessage}`,
    });
  }
}

// Initialize MCP Server
async function main(): Promise<void> {
  // Initialize database first
  await initializeDatabase();

  const server = new Server({
    name: "project-sentinel-agent",
    version: "1.0.0",
  });

  // Define tools
  const tools: Tool[] = [
    {
      name: "query_threat_registry",
      description: "Query the MongoDB threat registry for suspicious packages and anomalies",
      inputSchema: {
        type: "object",
        properties: {
          packageName: {
            type: "string",
            description: "Package name to search for (regex supported)",
          },
          riskScoreMin: {
            type: "number",
            description: "Minimum risk score (0-100)",
          },
          riskScoreMax: {
            type: "number",
            description: "Maximum risk score (0-100)",
          },
          developerSignature: {
            type: "string",
            description: "Developer signature to filter by",
          },
          limit: {
            type: "number",
            description: "Maximum number of results (default: 10)",
          },
        },
      },
    },
    {
      name: "write_emerging_threat",
      description: "Record a new emerging threat to the database with automatic risk assessment",
      inputSchema: {
        type: "object",
        properties: {
          applicationHash: {
            type: "string",
            description: "SHA256 hash of the malicious application",
          },
          packageName: {
            type: "string",
            description: "Application package name",
          },
          developerSignature: {
            type: "string",
            description: "Developer signature or certificate hash",
          },
          structuralAnomalies: {
            type: "array",
            items: { type: "string" },
            description: "List of detected structural anomalies",
          },
          detectionMethod: {
            type: "string",
            description: "Method used to detect the threat (e.g., 'signature_match', 'behavior_analysis')",
          },
        },
        required: ["applicationHash", "packageName", "detectionMethod"],
      },
    },
  ];

  // Handle tool listing
  server.setRequestHandler(ListToolsRequest, async () => ({
    tools: tools,
  }));

  // Handle tool calls
  server.setRequestHandler(CallToolRequest, async (request) => {
    try {
      let result: string;

      if (request.params.name === "query_threat_registry") {
        result = await queryThreatRegistry(request.params.arguments as ThreatQuery);
      } else if (request.params.name === "write_emerging_threat") {
        result = await writeEmergingThreat(
          request.params.arguments as Omit<ThreatPayload, "timestamp" | "riskScore">
        );
      } else {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Unknown tool: ${request.params.name}` }),
            },
          ],
        };
      }

      return {
        content: [
          {
            type: "text" as const,
            text: result,
          } as TextContent,
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ error: errorMessage }),
          } as TextContent,
        ],
      };
    }
  });

  // Start server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.log("✓ Project Sentinel MCP Server started successfully");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});