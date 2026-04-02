/**
 * ClawGuard monitoring plugin for OpenClaw.
 *
 * Hooks into OpenClaw's tool execution lifecycle to capture every tool call,
 * detect sensitive content, and stream events to the ClawGuard backend for
 * real-time Telegram commentary and risk analysis.
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
  ConversationBinding,
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

const INIT_KEY = Symbol.for("clawguard-monitor-initialized");
const CLIENT_KEY = Symbol.for("clawguard-monitor-client");
const CONFIG_KEY = Symbol.for("clawguard-monitor-config");
const SESSIONS_KEY = Symbol.for("clawguard-monitor-sessions");

const _global = globalThis as Record<symbol, unknown>;

let client: ClawGuardClient = _global[CLIENT_KEY] as ClawGuardClient;
let pluginConfig: ClawGuardPluginConfig = _global[CONFIG_KEY] as ClawGuardPluginConfig;
let initialized: boolean = (_global[INIT_KEY] as boolean) ?? false;

/**
 * Resolve a session for a given context, creating one if needed.
 */
async function resolveSession(ctx: HookContext): Promise<ActiveSession> {
  const key = ctx.sessionKey || "main";

  let session = sessions.get(key);
  if (session) return session;

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
 * Handle before_tool_call hook.
 * Captures tool call data, detects sensitive access, optionally blocks.
 */
async function handleBeforeToolCall(
  ctx: HookContext,
): Promise<HookDecision | void> {
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

  // Optionally block sensitive access
  if (
    pluginConfig.blockSensitiveAccess &&
    riskFlags.includes("sensitive_path")
  ) {
    return { block: true };
  }

  // Optionally require approval for high-risk + exfiltration
  if (
    pluginConfig.requireApprovalForHighRisk &&
    riskFlags.includes("potential_exfiltration")
  ) {
    return { requireApproval: true };
  }
}

/**
 * Handle tool result (after tool execution).
 * We register this as a separate hook that fires after the tool completes.
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
 * Handle message_sending hook.
 * Captures agent responses being sent to channels.
 */
async function handleMessageSending(
  ctx: HookContext,
): Promise<HookDecision | void> {
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

    console.log(
      `[clawguard] Monitoring active - backend: ${pluginConfig.backendUrl}, agent: ${pluginConfig.agentId}`,
    );

    // Initialize HTTP client
    client = new ClawGuardClient(pluginConfig);
    _global[CLIENT_KEY] = client;
    _global[CONFIG_KEY] = pluginConfig;
    client.start();

    // --- Deep diagnostic ---
    // Hook system is completely disconnected from embedded agent tool pipeline
    // (OpenClaw #5513). Inspect internal state to find an alternative intercept.

    // Dump api.runtime structure
    const rt = api.runtime;
    if (rt) {
      console.log("[clawguard] DIAG api.runtime keys:", Object.keys(rt).join(", "));
      for (const key of Object.keys(rt)) {
        const val = (rt as unknown as Record<string, unknown>)[key];
        const type = val === null ? "null" : Array.isArray(val) ? "array" : typeof val;
        if (type === "object" && val) {
          console.log(`[clawguard] DIAG runtime.${key}: ${type} keys=[${Object.keys(val as object).join(", ")}]`);
        } else {
          console.log(`[clawguard] DIAG runtime.${key}: ${type}`);
        }
      }
    } else {
      console.log("[clawguard] DIAG api.runtime is", typeof rt);
    }

    // Dump api.config top-level keys
    if (api.config) {
      console.log("[clawguard] DIAG api.config keys:", Object.keys(api.config).join(", "));
    }

    // Check if api has any EventEmitter-like internals
    const apiAny = api as unknown as Record<string, unknown>;
    for (const key of ["_events", "_emitter", "emitter", "eventBus", "bus", "hookRunner", "hooks", "_hooks", "toolRunner", "agentRunner", "sessionManager", "toolExecutor"]) {
      if (apiAny[key] !== undefined) {
        const val = apiAny[key];
        const type = val === null ? "null" : typeof val;
        console.log(`[clawguard] DIAG api.${key}: ${type}${type === "object" && val ? " keys=[" + Object.keys(val as object).join(", ") + "]" : ""}`);
      }
    }

    // Check globalThis for OpenClaw singletons
    const gKeys = Object.getOwnPropertyNames(globalThis).filter(k =>
      /openclaw|hook|agent|tool|runner|session|gateway/i.test(k)
    );
    if (gKeys.length > 0) {
      console.log("[clawguard] DIAG globalThis relevant keys:", gKeys.join(", "));
      for (const k of gKeys.slice(0, 10)) {
        const val = (globalThis as Record<string, unknown>)[k];
        const type = val === null ? "null" : typeof val;
        console.log(`[clawguard] DIAG globalThis.${k}: ${type}${type === "object" && val ? " keys=[" + Object.keys(val as object).slice(0, 15).join(", ") + "]" : ""}`);
      }
    } else {
      console.log("[clawguard] DIAG no relevant globalThis keys found");
    }

    // Check Symbol-keyed properties on globalThis for internal registries
    const symKeys = Object.getOwnPropertySymbols(globalThis);
    const relevantSyms = symKeys.filter(s => {
      const desc = s.description || s.toString();
      return /openclaw|hook|agent|tool|runner|session|gateway|plugin|registry/i.test(desc);
    });
    if (relevantSyms.length > 0) {
      console.log("[clawguard] DIAG globalThis symbols:", relevantSyms.map(s => s.description || s.toString()).join(", "));
      for (const s of relevantSyms.slice(0, 10)) {
        const val = (globalThis as Record<symbol, unknown>)[s];
        const type = val === null ? "null" : typeof val;
        console.log(`[clawguard] DIAG sym(${s.description}): ${type}${type === "object" && val ? " keys=[" + Object.keys(val as object).slice(0, 15).join(", ") + "]" : ""}`);
      }
    } else {
      console.log("[clawguard] DIAG no relevant globalThis symbols found (checked", symKeys.length, "total)");
    }

    // Register hooks anyway (in case future versions fix #5513)
    try {
      api.registerHook("before_tool_call", async (ctx: HookContext) => {
        console.log("[clawguard] hook fired: before_tool_call", ctx?.tool || "no-tool");
        try { return await handleBeforeToolCall(ctx); }
        catch (err) { console.error("[clawguard] before_tool_call error:", (err as Error).message); }
      }, {
        name: "clawguard.before-tool-call",
        description: "ClawGuard security monitoring — captures tool calls",
      });
      api.registerHook("message_sending", async (ctx: HookContext) => {
        console.log("[clawguard] hook fired: message_sending");
        try { return await handleMessageSending(ctx); }
        catch (err) { console.error("[clawguard] message_sending error:", (err as Error).message); }
      }, {
        name: "clawguard.message-sending",
        description: "ClawGuard security monitoring — captures outbound messages",
      });
      console.log("[clawguard] Hooks registered (for future compatibility)");
    } catch (err) {
      console.error("[clawguard] Hook registration failed:", (err as Error).message);
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
export type { ClawGuardPluginConfig, EventPayload } from "./types.js";
export { DEFAULT_CONFIG } from "./types.js";
