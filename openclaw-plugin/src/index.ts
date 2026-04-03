/**
 * ClawGuard monitoring plugin for OpenClaw.
 *
 * Monitors OpenClaw agent activity by subscribing to runtime event streams
 * (onSessionTranscriptUpdate / onAgentEvent). Captures tool calls, detects
 * sensitive content, and streams events to the ClawGuard backend for
 * real-time Telegram commentary and risk analysis.
 *
 * Note: OpenClaw's plugin hook system (registerHook / api.on) does not fire
 * for embedded agents due to a hook runner timing bug (#5513). This plugin
 * bypasses hooks entirely and uses runtime.events instead.
 *
 * Installation:
 *   openclaw plugins install @clawguard/openclaw-plugin
 *
 * Configuration (openclaw config):
 *   plugins:
 *     @clawguard/openclaw-plugin:
 *       backendUrl: "https://clawguard.example.com"
 *       apiKey: "cg_..."
 *       agentId: "my-research-bot"
 */

import { randomUUID } from "node:crypto";
import { ClawGuardClient } from "./client.js";
import {
  detectSensitiveContent,
  isHighRiskTool,
  isSensitivePath,
} from "./sensitive.js";
import type {
  ClawGuardPluginConfig,
  EventPayload,
  HookContext,
  HookDecision,
  OpenClawPluginApi,
} from "./types.js";
import { DEFAULT_CONFIG, definePluginEntry } from "./types.js";

/** Active session tracking. */
interface ActiveSession {
  sessionId: string;
  agentId: string;
  task: string;
  startedAt: number;
  toolCallCount: number;
  recentOutputs: Array<{ toolName: string; outputPrefix: string }>;
  sensitiveAccessed: boolean;
}

/** Per-session-key tracking of active sessions. */
const sessions = new Map<string, ActiveSession>();

/** Security limits for session tracking. */
const MAX_SESSIONS = 100;
const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

// Use Symbol.for() only for the boolean init guard (no sensitive data).
// Client and config are module-scoped only — not stored on globalThis —
// so other plugins cannot enumerate symbols to steal the API key.
const INIT_KEY = Symbol.for("clawguard-monitor-initialized");
const _global = globalThis as Record<symbol, unknown>;

let client: ClawGuardClient;
let pluginConfig: ClawGuardPluginConfig;
let initialized: boolean = (_global[INIT_KEY] as boolean) ?? false;

/**
 * Resolve a session for a given context, creating one if needed.
 */
async function resolveSession(ctx: HookContext): Promise<ActiveSession> {
  const key = ctx.sessionKey || "main";

  // Evict expired sessions to prevent unbounded memory growth
  const now = Date.now();
  for (const [k, s] of sessions.entries()) {
    if (now - s.startedAt > SESSION_TTL_MS) {
      sessions.delete(k);
    }
  }

  let session = sessions.get(key);
  if (session) return session;

  // Enforce session limit
  if (sessions.size >= MAX_SESSIONS) {
    // Evict the oldest session
    let oldestKey: string | undefined;
    let oldestTime = Infinity;
    for (const [k, s] of sessions.entries()) {
      if (s.startedAt < oldestTime) {
        oldestTime = s.startedAt;
        oldestKey = k;
      }
    }
    if (oldestKey) sessions.delete(oldestKey);
  }

  // Create a new session
  const agentId = ctx.agentId || pluginConfig.agentId;
  const task = ""; // Task isn't known until first user message
  const sessionId = await client.startSession(agentId, task);

  session = {
    sessionId,
    agentId,
    task,
    startedAt: Date.now(),
    toolCallCount: 0,
    recentOutputs: [],
    sensitiveAccessed: false,
  };
  sessions.set(key, session);

  // Log session_start event
  await client.sendEventImmediate(
    makeEvent(session, "session_start", {
      agent_id: agentId,
      task,
    }),
  );

  return session;
}

/**
 * Build an EventPayload.
 */
function makeEvent(
  session: ActiveSession,
  eventType: EventPayload["event_type"],
  data: Record<string, unknown>,
  riskFlags: string[] = [],
): EventPayload {
  return {
    event_id: randomUUID(),
    session_id: session.sessionId,
    agent_id: session.agentId,
    event_type: eventType,
    timestamp: new Date().toISOString(),
    data,
    risk_flags: riskFlags,
  };
}

/**
 * Truncate a string for summary fields.
 */
function truncate(text: unknown, maxLen: number): string {
  const s = String(text ?? "");
  return s.length > maxLen ? s.slice(0, maxLen) + "..." : s;
}

/**
 * Handle a tool call event.
 * Captures tool call data, detects sensitive access, sends events to backend.
 */
async function handleToolCall(ctx: HookContext): Promise<void> {
  const session = await resolveSession(ctx);
  const toolName = ctx.tool || "unknown";
  const toolArgs = ctx.args || {};
  session.toolCallCount++;

  // Build risk flags
  const riskFlags: string[] = [];

  // Check for sensitive file path in args
  const pathArg =
    (toolArgs.path as string) ||
    (toolArgs.file as string) ||
    (toolArgs.filename as string) ||
    "";
  if (pathArg && isSensitivePath(pathArg)) {
    riskFlags.push("sensitive_path");
  }

  // Check for sensitive content in input
  const inputStr = JSON.stringify(toolArgs);
  const sensitiveInput = detectSensitiveContent(inputStr);
  if (sensitiveInput.length > 0) {
    riskFlags.push("sensitive_input");
  }

  // Check for high-risk tool
  if (isHighRiskTool(toolName)) {
    riskFlags.push("high_risk_tool");

    // If agent previously accessed sensitive content and is now making
    // an outbound request, flag potential exfiltration
    if (session.sensitiveAccessed) {
      riskFlags.push("potential_exfiltration");
    }
  }

  // Build event data
  const data: Record<string, unknown> = {
    tool_name: toolName,
    input_summary: truncate(inputStr, 200),
  };

  if (pluginConfig.captureFullIo) {
    data.full_input = truncate(inputStr, pluginConfig.maxFullIoBytes);
  }

  if (pathArg) {
    data.target = pathArg;
  }

  if (sensitiveInput.length > 0) {
    data.sensitive_patterns = sensitiveInput;
  }

  // Send tool_call event (immediate for alerts, batched otherwise)
  const event = makeEvent(session, "tool_call", data, riskFlags);

  if (riskFlags.length > 0) {
    await client.sendEventImmediate(event);
  } else {
    client.queueEvent(event);
  }
}

/**
 * Handle tool result (after tool execution).
 */
function handleToolResult(
  session: ActiveSession,
  toolName: string,
  result: unknown,
  durationMs?: number,
): void {
  const outputStr = String(result ?? "");
  const riskFlags: string[] = [];

  // Detect sensitive content in output
  const sensitiveOutput = detectSensitiveContent(outputStr);
  if (sensitiveOutput.length > 0) {
    riskFlags.push("sensitive_output");
    session.sensitiveAccessed = true;
  }

  // Check file path in output
  if (isSensitivePath(toolName)) {
    session.sensitiveAccessed = true;
  }

  // Track recent outputs for data flow analysis
  session.recentOutputs.push({
    toolName,
    outputPrefix: outputStr.slice(0, 500),
  });
  // Keep only last 10
  if (session.recentOutputs.length > 10) {
    session.recentOutputs.shift();
  }

  // Build event data
  const data: Record<string, unknown> = {
    tool_name: toolName,
    output_summary: truncate(outputStr, 300),
    output_size_bytes: outputStr.length,
  };

  if (durationMs !== undefined) {
    data.duration_ms = durationMs;
  }

  if (sensitiveOutput.length > 0) {
    data.sensitive = true;
    data.sensitive_patterns = sensitiveOutput;
  }

  if (pluginConfig.captureFullIo) {
    data.full_output = truncate(outputStr, pluginConfig.maxFullIoBytes);
  }

  const event = makeEvent(session, "tool_output", data, riskFlags);

  if (riskFlags.length > 0) {
    client.sendEventImmediate(event).catch((err) => {
      console.error("[clawguard] send error:", err.message);
    });
  } else {
    client.queueEvent(event);
  }
}

/**
 * Handle outbound agent message.
 */
async function handleMessage(ctx: HookContext): Promise<void> {
  const session = await resolveSession(ctx);
  const message = ctx.message || "";
  const channel = ctx.channel || "unknown";

  // Detect sensitive content in outgoing message
  const sensitive = detectSensitiveContent(message);
  const riskFlags: string[] = [];

  if (sensitive.length > 0) {
    riskFlags.push("sensitive_in_response");
  }

  const data: Record<string, unknown> = {
    direction: "outbound",
    channel,
    content_preview: truncate(message, 200),
    content_length: message.length,
  };

  if (sensitive.length > 0) {
    data.sensitive = true;
    data.sensitive_patterns = sensitive;
  }

  const event = makeEvent(session, "action", data, riskFlags);

  if (riskFlags.length > 0) {
    await client.sendEventImmediate(event);
  } else {
    client.queueEvent(event);
  }
}

/**
 * End a session and clean up.
 */
async function endSessionForKey(
  key: string,
  status: "completed" | "aborted" = "completed",
): Promise<void> {
  const session = sessions.get(key);
  if (!session) return;

  // Log session_end event
  const durationSeconds = (Date.now() - session.startedAt) / 1000;
  await client.sendEventImmediate(
    makeEvent(session, "session_end", {
      status,
      duration_seconds: durationSeconds,
      tool_call_count: session.toolCallCount,
    }),
  );

  // End session on backend (triggers metrics computation)
  try {
    await client.endSession(session.sessionId, status);
  } catch (err) {
    console.error("[clawguard] end session error:", (err as Error).message);
  }

  sessions.delete(key);
}

// --- Plugin entry point ---

/**
 * Load plugin configuration from OpenClaw config or environment.
 */
function loadConfig(api: OpenClawPluginApi): ClawGuardPluginConfig {
  const config = { ...DEFAULT_CONFIG };

  // Plugin-specific config from plugins.entries.<id>.config
  const pc = api.pluginConfig;
  if (pc) {
    if (typeof pc.backendUrl === "string") config.backendUrl = pc.backendUrl;
    if (typeof pc.apiKey === "string") config.apiKey = pc.apiKey;
    if (typeof pc.agentId === "string") config.agentId = pc.agentId;
    if (typeof pc.captureFullIo === "boolean") config.captureFullIo = pc.captureFullIo;
    if (typeof pc.blockSensitiveAccess === "boolean") config.blockSensitiveAccess = pc.blockSensitiveAccess;
    if (typeof pc.requireApprovalForHighRisk === "boolean") config.requireApprovalForHighRisk = pc.requireApprovalForHighRisk;
  }

  // Environment variable overrides
  if (process.env.CLAWGUARD_BACKEND_URL) {
    config.backendUrl = process.env.CLAWGUARD_BACKEND_URL;
  }
  if (process.env.CLAWGUARD_API_KEY) {
    config.apiKey = process.env.CLAWGUARD_API_KEY;
  }
  if (process.env.CLAWGUARD_AGENT_ID) {
    config.agentId = process.env.CLAWGUARD_AGENT_ID;
  }

  return config;
}

/**
 * OpenClaw plugin entry point using definePluginEntry format.
 */
export default definePluginEntry({
  id: "clawguard-monitor",
  name: "ClawGuard Monitor",
  description: "Security monitoring for OpenClaw agents — detects risky behavior and sends Telegram alerts",
  register(api) {
    // Prevent duplicate initialization
    if (initialized) {
      return;
    }

    // Only fully initialize in "full" registration mode
    if (api.registrationMode && api.registrationMode !== "full") {
      return;
    }

    pluginConfig = loadConfig(api);

    if (!pluginConfig.apiKey) {
      console.warn(
        "[clawguard] No API key configured. Set CLAWGUARD_API_KEY or configure in plugin settings.",
      );
      return;
    }

    initialized = true;
    _global[INIT_KEY] = true;

    console.log("[clawguard] Monitoring active");
    if (api.logger?.debug) {
      api.logger.debug(`[clawguard] backend: ${pluginConfig.backendUrl}, agent: ${pluginConfig.agentId}`);
    }

    // Initialize HTTP client (module-scoped, not on globalThis, to protect API key)
    client = new ClawGuardClient(pluginConfig);
    client.start();

    // --- Event-based monitoring ---
    // OpenClaw's plugin hook system (registerHook / api.on) does not fire
    // for embedded agents due to hook runner timing bug (#5513 — the
    // internal hook handler registry is empty at dispatch time). We bypass
    // hooks entirely and subscribe to runtime.events, which are wired
    // directly into the agent loop.

    const runtimeAny = api.runtime as unknown as Record<string, unknown> | undefined;
    const eventsObj = runtimeAny?.events as Record<string, unknown> | undefined;

    if (!eventsObj) {
      console.warn("[clawguard] runtime.events not available — monitoring disabled");
      return;
    }

    // onSessionTranscriptUpdate: fires when messages are written to the
    // session transcript. This is the primary monitoring channel.
    // Shape: { sessionFile, sessionKey, message, messageId }
    // message.content[] contains toolCall, toolResult, and text blocks.
    if (typeof eventsObj.onSessionTranscriptUpdate === "function") {
      (eventsObj.onSessionTranscriptUpdate as Function)((update: Record<string, unknown>) => {
        const sessionKey = String(update.sessionKey || "main");
        const message = update.message as Record<string, unknown> | undefined;
        if (!message) return;

        const role = String(message.role || "");
        const content = message.content as Array<Record<string, unknown>> | undefined;
        if (!content || !Array.isArray(content)) return;

        for (const block of content) {
          const blockType = String(block.type || "");

          // Tool call: assistant is invoking a tool
          if (blockType === "toolCall") {
            const toolName = String(block.name || block.tool || "unknown");
            let args: Record<string, unknown> = {};
            try {
              if (typeof block.arguments === "string") {
                const parsed = JSON.parse(block.arguments);
                args = (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed))
                  ? parsed as Record<string, unknown>
                  : { raw: String(block.arguments) };
              } else {
                args = (block.arguments as Record<string, unknown>) || {};
              }
            } catch {
              args = { raw: String(block.arguments || "") };
            }

            const ctx: HookContext = {
              tool: toolName,
              args,
              sessionKey,
              agentId: pluginConfig.agentId,
            };
            handleToolCall(ctx).catch(err => {
              console.error("[clawguard] tool call error:", (err as Error).message);
            });
          }

          // Tool result: tool has completed
          if (blockType === "toolResult") {
            const toolName = String(block.name || block.tool || "unknown");
            const result = block.content || block.output || block.result || "";
            const session = sessions.get(sessionKey);
            if (session) {
              handleToolResult(session, toolName, result);
            }
          }

          // Agent text response
          if (blockType === "text" && role === "assistant") {
            const text = String(block.text || "");
            if (text.length > 0) {
              const ctx: HookContext = {
                message: text,
                channel: "agent",
                sessionKey,
                agentId: pluginConfig.agentId,
              };
              handleMessage(ctx).catch(err => {
                console.error("[clawguard] message error:", (err as Error).message);
              });
            }
          }
        }
      });
    }

    // onAgentEvent: streaming events from the agent loop.
    // Shape: { runId, stream, data, sessionKey, seq, ts }
    // Used as a secondary channel to catch tool events that may not
    // appear in transcript updates.
    if (typeof eventsObj.onAgentEvent === "function") {
      (eventsObj.onAgentEvent as Function)((event: Record<string, unknown>) => {
        const sessionKey = String(event.sessionKey || "main");
        const data = event.data as Record<string, unknown> | undefined;
        const stream = String(event.stream || "");

        if (!data) return;

        const dataType = String(data.type || data.kind || data.event || "");
        const toolName = String(data.tool || data.toolName || data.name || "");

        // Only process tool-related streaming events
        if (!toolName && !/tool/i.test(dataType) && !/tool/i.test(stream)) return;

        const ctx: HookContext = {
          tool: toolName,
          args: (data.params || data.args || data.input || data.arguments) as Record<string, unknown> | undefined,
          result: data.result || data.output || data.content,
          sessionKey,
          agentId: pluginConfig.agentId,
        };

        if (/start|begin|invoke|call/i.test(dataType) || /start/i.test(stream)) {
          handleToolCall(ctx).catch(err => {
            console.error("[clawguard] agent event error:", (err as Error).message);
          });
        } else if (/end|complete|result|done/i.test(dataType) || /end|result/i.test(stream)) {
          const session = sessions.get(sessionKey);
          if (session && toolName) {
            handleToolResult(session, toolName, ctx.result);
          }
        }
      });
    }

    // Flush remaining events on shutdown (best-effort, non-blocking)
    process.on("SIGTERM", () => {
      client.flush().catch(() => {});
    });
  },
});

// Export for direct usage / testing
export { ClawGuardClient } from "./client.js";
export { detectSensitiveContent, isHighRiskTool, isSensitivePath } from "./sensitive.js";
export type { AnalyzeThreadRequest, AnalyzeThreadResponse, ClawGuardPluginConfig, EventPayload } from "./types.js";
export { DEFAULT_CONFIG } from "./types.js";
