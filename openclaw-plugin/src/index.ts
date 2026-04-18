/**
 * ClawGuard monitoring plugin for OpenClaw.
 *
 * Monitors OpenClaw agent activity by subscribing to runtime event streams
 * and standard plugin hooks. Captures tool calls, detects sensitive content,
 * and streams events to the ClawGuard backend for real-time Telegram
 * commentary and risk analysis.
 *
 * runtime.events remains the primary signal path, but we also register
 * standard hooks as a compatibility fallback because host behavior differs
 * across OpenClaw versions.
 *
 * Installation:
 *   openclaw plugins install clawhub:clawguard-monitor
 *
 * Configuration (openclaw config):
 *   plugins:
 *     entries:
 *       clawguard-monitor:
 *         enabled: false
 *         config:
 *           backendUrl: "https://clawguard.example.com"
 *           apiKey: "cg_..."
 *           agentId: "my-research-bot"
 */

import { randomUUID } from "node:crypto";
import { ClawGuardClient } from "./client.js";
import {
  assessToolCall,
  classifyTargetPath,
  detectSensitiveContent,
  extractCommandText,
  extractTargetFromCommand,
  hasHighImpactSensitiveMatch,
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
const RECENT_EVENT_TTL_MS = 750;

// Use Symbol.for() only for the boolean init guard (no sensitive data).
// Client and config are module-scoped only — not stored on globalThis —
// so other plugins cannot enumerate symbols to steal the API key.
const INIT_KEY = Symbol.for("clawguard-monitor-initialized");
const _global = globalThis as Record<symbol, unknown>;
const recentEventFingerprints = new Map<string, number>();

let client: ClawGuardClient;
let pluginConfig: ClawGuardPluginConfig;
let initialized: boolean = (_global[INIT_KEY] as boolean) ?? false;

function readOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function readObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function getConfiguredPluginEntry(api: OpenClawPluginApi): Record<string, unknown> | undefined {
  const config = readObject(api.config);
  const plugins = readObject(config?.plugins);
  const entries = readObject(plugins?.entries);
  const entry = readObject(entries?.["clawguard-monitor"]);
  if (entry) {
    return entry;
  }

  return readObject(plugins?.["clawguard-monitor"])
    ?? readObject(plugins?.["@clawguard/openclaw-plugin"]);
}

type ConfigSource = "default" | "openclaw config" | "plugin runtime" | "environment";

interface LoadedConfigResult {
  config: ClawGuardPluginConfig;
  sources: {
    backendUrl: ConfigSource;
    apiKey: ConfigSource;
    agentId: ConfigSource;
  };
  warnings: string[];
}

const CONFIG_ENV_VARS = {
  backendUrl: "CLAWGUARD_BACKEND_URL",
  apiKey: "CLAWGUARD_API_KEY",
  agentId: "CLAWGUARD_AGENT_ID",
} as const;

const CONFIG_LABELS = {
  backendUrl: "backend URL",
  apiKey: "API key",
  agentId: "agent ID",
} as const;

function makeConfigOverrideWarning(
  field: keyof LoadedConfigResult["sources"],
  source: ConfigSource,
  previousSource: ConfigSource,
): string {
  const label = CONFIG_LABELS[field];

  if (source === "environment") {
    const envVar = CONFIG_ENV_VARS[field];
    const hint = field === "apiKey"
      ? " If requests return 401, update or clear that environment variable on this machine."
      : "";
    return `[clawguard] ${envVar} is overriding the ${previousSource} ${label}.${hint}`;
  }

  return `[clawguard] ${source} ${label} overrides the ${previousSource} ${label}.`;
}

function applyConfiguredString(
  config: ClawGuardPluginConfig,
  sources: LoadedConfigResult["sources"],
  warnings: string[],
  field: keyof LoadedConfigResult["sources"],
  rawValue: unknown,
  source: ConfigSource,
): void {
  const value = readOptionalString(rawValue);
  if (!value) {
    return;
  }

  const previousSource = sources[field];
  if (previousSource !== "default" && previousSource !== source && config[field] !== value) {
    warnings.push(makeConfigOverrideWarning(field, source, previousSource));
  }

  config[field] = value;
  sources[field] = source;
}

function applyNonStringConfig(config: ClawGuardPluginConfig, raw: Record<string, unknown>): void {
  if (typeof raw.captureFullIo === "boolean") config.captureFullIo = raw.captureFullIo;
  if (typeof raw.maxFullIoBytes === "number" && Number.isFinite(raw.maxFullIoBytes) && raw.maxFullIoBytes > 0) {
    config.maxFullIoBytes = raw.maxFullIoBytes;
  }
  if (typeof raw.blockSensitiveAccess === "boolean") config.blockSensitiveAccess = raw.blockSensitiveAccess;
  if (typeof raw.requireApprovalForHighRisk === "boolean") config.requireApprovalForHighRisk = raw.requireApprovalForHighRisk;
  if (typeof raw.batchSize === "number" && Number.isFinite(raw.batchSize) && raw.batchSize > 0) {
    config.batchSize = raw.batchSize;
  }
  if (typeof raw.flushIntervalMs === "number" && Number.isFinite(raw.flushIntervalMs) && raw.flushIntervalMs > 0) {
    config.flushIntervalMs = raw.flushIntervalMs;
  }
}

function resolveConfig(api: OpenClawPluginApi): LoadedConfigResult {
  const config = { ...DEFAULT_CONFIG };
  const sources: LoadedConfigResult["sources"] = {
    backendUrl: "default",
    apiKey: "default",
    agentId: "default",
  };
  const warnings: string[] = [];

  const configuredEntry = getConfiguredPluginEntry(api);
  const configuredEntryConfig = readObject(configuredEntry?.config);
  const runtimePluginConfig = readObject(api.pluginConfig);

  if (configuredEntryConfig) {
    applyConfiguredString(config, sources, warnings, "backendUrl", configuredEntryConfig.backendUrl, "openclaw config");
    applyConfiguredString(config, sources, warnings, "apiKey", configuredEntryConfig.apiKey, "openclaw config");
    applyConfiguredString(config, sources, warnings, "agentId", configuredEntryConfig.agentId, "openclaw config");
    applyNonStringConfig(config, configuredEntryConfig);
  }

  if (runtimePluginConfig) {
    applyConfiguredString(config, sources, warnings, "backendUrl", runtimePluginConfig.backendUrl, "plugin runtime");
    applyConfiguredString(config, sources, warnings, "apiKey", runtimePluginConfig.apiKey, "plugin runtime");
    applyConfiguredString(config, sources, warnings, "agentId", runtimePluginConfig.agentId, "plugin runtime");
    applyNonStringConfig(config, runtimePluginConfig);
  }

  applyConfiguredString(config, sources, warnings, "backendUrl", process.env.CLAWGUARD_BACKEND_URL, "environment");
  applyConfiguredString(config, sources, warnings, "apiKey", process.env.CLAWGUARD_API_KEY, "environment");
  applyConfiguredString(config, sources, warnings, "agentId", process.env.CLAWGUARD_AGENT_ID, "environment");

  return { config, sources, warnings };
}

function stableSerialize(value: unknown): string {
  if (value === null || value === undefined) {
    return String(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableSerialize).join(",")}]`;
  }

  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableSerialize(obj[key])}`).join(",")}}`;
  }

  return JSON.stringify(value);
}

function pruneRecentEventFingerprints(now = Date.now()): void {
  for (const [fingerprint, seenAt] of recentEventFingerprints.entries()) {
    if (now - seenAt > RECENT_EVENT_TTL_MS) {
      recentEventFingerprints.delete(fingerprint);
    }
  }
}

function shouldCaptureEvent(fingerprint: string): boolean {
  const now = Date.now();
  pruneRecentEventFingerprints(now);

  const seenAt = recentEventFingerprints.get(fingerprint);
  if (seenAt !== undefined && now - seenAt <= RECENT_EVENT_TTL_MS) {
    return false;
  }

  recentEventFingerprints.set(fingerprint, now);
  return true;
}

function normalizeHookContext(raw: HookContext | Record<string, unknown>): HookContext {
  const record = readObject(raw) ?? {};
  const messageObj = readObject(record.message);
  const sessionObj = readObject(record.session);
  const toolObj = readObject(record.tool);
  const rawArgs = record.args ?? record.params ?? record.input ?? record.arguments;
  const normalizedArgs = readObject(rawArgs)
    ?? (readOptionalString(rawArgs) ? { raw: String(rawArgs) } : undefined);

  return {
    tool:
      readOptionalString(record.tool)
      ?? readOptionalString(toolObj?.name)
      ?? readOptionalString(record.toolName)
      ?? readOptionalString(record.name),
    args: normalizedArgs,
    result: record.result ?? record.output ?? record.content,
    message:
      readOptionalString(record.message)
      ?? readOptionalString(messageObj?.text)
      ?? readOptionalString(messageObj?.content)
      ?? readOptionalString(record.text),
    channel:
      readOptionalString(record.channel)
      ?? readOptionalString(messageObj?.channel)
      ?? "agent",
    sessionKey:
      readOptionalString(record.sessionKey)
      ?? readOptionalString(record.runId)
      ?? readOptionalString(sessionObj?.key),
    agentId: readOptionalString(record.agentId),
  };
}

function makeToolCallFingerprint(ctx: HookContext): string {
  return [
    ctx.sessionKey || "main",
    "tool_call",
    ctx.tool || "unknown",
    stableSerialize(ctx.args || {}),
  ].join("|");
}

function makeToolResultFingerprint(
  sessionKey: string,
  toolName: string,
  result: unknown,
): string {
  return [
    sessionKey,
    "tool_output",
    toolName,
    stableSerialize(result),
  ].join("|");
}

function makeMessageFingerprint(ctx: HookContext): string {
  return [
    ctx.sessionKey || "main",
    "action",
    ctx.channel || "agent",
    stableSerialize(ctx.message || ""),
  ].join("|");
}

async function captureToolCall(rawCtx: HookContext | Record<string, unknown>): Promise<void> {
  const ctx = normalizeHookContext(rawCtx);
  if (!shouldCaptureEvent(makeToolCallFingerprint(ctx))) {
    return;
  }
  await handleToolCall(ctx);
}

function captureToolResult(rawCtx: HookContext | Record<string, unknown>): void {
  const ctx = normalizeHookContext(rawCtx);
  const sessionKey = ctx.sessionKey || "main";
  const toolName = ctx.tool || "unknown";
  const session = sessions.get(sessionKey);

  if (!session || !shouldCaptureEvent(makeToolResultFingerprint(sessionKey, toolName, ctx.result))) {
    return;
  }

  handleToolResult(session, toolName, ctx.result);
}

async function captureMessage(rawCtx: HookContext | Record<string, unknown>): Promise<void> {
  const ctx = normalizeHookContext(rawCtx);
  if (!ctx.message || !shouldCaptureEvent(makeMessageFingerprint(ctx))) {
    return;
  }
  await handleMessage(ctx);
}

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
    sessions.delete(oldestKey!);
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
  const assessment = assessToolCall(toolName, toolArgs);

  // Build risk flags
  const riskFlags: string[] = [];

  // Check for sensitive file path in args
  const explicitPathArg =
    (toolArgs.path as string) ||
    (toolArgs.literalPath as string) ||
    (toolArgs.file as string) ||
    (toolArgs.filename as string) ||
    (toolArgs.target as string) ||
    (toolArgs.destination as string) ||
    (toolArgs.dest as string) ||
    (toolArgs.recipient as string) ||
    (toolArgs.to as string) ||
    (toolArgs.channel as string) ||
    (toolArgs.chat_id as string) ||
    (toolArgs.chatId as string) ||
    (toolArgs.channel_id as string) ||
    (toolArgs.channelId as string) ||
    (toolArgs.thread_id as string) ||
    (toolArgs.threadId as string) ||
    (toolArgs.message_thread_id as string) ||
    (toolArgs.messageThreadId as string) ||
    (toolArgs.conversation_id as string) ||
    (toolArgs.conversationId as string) ||
    (toolArgs.room as string) ||
    (toolArgs.room_id as string) ||
    (toolArgs.roomId as string) ||
    (toolArgs.user_id as string) ||
    (toolArgs.userId as string) ||
    (toolArgs.phone as string) ||
    (toolArgs.phone_number as string) ||
    (toolArgs.phoneNumber as string) ||
    (toolArgs.url as string) ||
    (toolArgs.uri as string) ||
    (toolArgs.endpoint as string) ||
    (toolArgs.href as string) ||
    (toolArgs.webhook as string) ||
    (toolArgs.webhookUrl as string) ||
    "";
  const commandText = extractCommandText(toolArgs);
  const inferredTarget = explicitPathArg || extractTargetFromCommand(commandText);
  const targetKind = inferredTarget ? classifyTargetPath(inferredTarget) : "";
  if (inferredTarget && isSensitivePath(inferredTarget)) {
    riskFlags.push("sensitive_path");
    session.sensitiveAccessed = true;
  }

  // Check for sensitive content in input
  const inputStr = JSON.stringify(toolArgs);
  const sensitiveInput = detectSensitiveContent(inputStr);
  const hasHighImpactInput = hasHighImpactSensitiveMatch(sensitiveInput);
  if (sensitiveInput.length > 0 && hasHighImpactInput) {
    riskFlags.push("sensitive_input");
    session.sensitiveAccessed = true;
  }

  // Check for high-risk tool
  if (assessment.isHighRisk) {
    riskFlags.push("high_risk_tool");
  }

  // If agent previously accessed sensitive content and is now making
  // a data-egress capable request, flag potential exfiltration.
  if (session.sensitiveAccessed && assessment.canEgressData) {
    riskFlags.push("potential_exfiltration");
  }

  // Build event data
  const data: Record<string, unknown> = {
    tool_name: toolName,
    input_summary: truncate(inputStr, 200),
    tool_category: assessment.toolCategory,
    operation_kind: assessment.operationKind,
  };

  if (assessment.deliveryScope) {
    data.delivery_scope = assessment.deliveryScope;
  }

  if (assessment.channelType) {
    data.channel_type = assessment.channelType;
  }

  if (pluginConfig.captureFullIo) {
    data.full_input = truncate(inputStr, pluginConfig.maxFullIoBytes);
  }

  if (inferredTarget) {
    data.target = inferredTarget;
    if (targetKind) {
      data.target_kind = targetKind;
    }
  }

  if (sensitiveInput.length > 0) {
    data.sensitive_patterns = sensitiveInput;
  }

  if (riskFlags.includes("sensitive_path") || hasHighImpactInput) {
    data.sensitive = true;
  }

  if (assessment.canEgressData) {
    data.direction = "outbound";
  }

  if (assessment.severity) {
    data.severity = assessment.severity;
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
  const hasHighImpactOutput = hasHighImpactSensitiveMatch(sensitiveOutput);
  if (sensitiveOutput.length > 0 && hasHighImpactOutput) {
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
    data.sensitive_patterns = sensitiveOutput;
  }

  if (hasHighImpactOutput) {
    data.sensitive = true;
    data.severity = "high";
  }

  if (pluginConfig.captureFullIo) {
    data.full_output = truncate(outputStr, pluginConfig.maxFullIoBytes);
  }

  const event = makeEvent(session, "tool_output", data, riskFlags);

  if (riskFlags.length > 0) {
    client.sendEventImmediate(event).catch((err) => {
      console.warn("[clawguard] send error (agent unaffected):", err.message);
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
  const hasHighImpactMessage = hasHighImpactSensitiveMatch(sensitive);
  const riskFlags: string[] = [];

  if (sensitive.length > 0 && hasHighImpactMessage) {
    riskFlags.push("sensitive_in_response");
  }

  const data: Record<string, unknown> = {
    operation_kind: "trusted_delivery",
    delivery_scope: "first_party",
    channel_type: channel,
    channel,
    content_preview: truncate(message, 200),
    content_length: message.length,
  };

  if (sensitive.length > 0) {
    data.sensitive_patterns = sensitive;
  }

  if (hasHighImpactMessage) {
    data.sensitive = true;
    data.severity = "high";
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
    console.warn("[clawguard] end session error (agent unaffected):", (err as Error).message);
  }

  sessions.delete(key);
}

// --- Plugin entry point ---

/**
 * Load plugin configuration from OpenClaw config or environment.
 */
function loadConfig(api: OpenClawPluginApi): ClawGuardPluginConfig {
  return resolveConfig(api).config;
}

function resetStateForTests(): void {
  sessions.clear();
  recentEventFingerprints.clear();
  initialized = false;
  _global[INIT_KEY] = false;
}

function setStateForTests(state: {
  client?: ClawGuardClient;
  pluginConfig?: ClawGuardPluginConfig;
  initialized?: boolean;
}): void {
  if (state.client) {
    client = state.client;
  }
  if (state.pluginConfig) {
    pluginConfig = state.pluginConfig;
  }
  if (typeof state.initialized === "boolean") {
    initialized = state.initialized;
    _global[INIT_KEY] = state.initialized;
  }
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

    let startedClient: ClawGuardClient | undefined;

    try {
      const configuredEntry = getConfiguredPluginEntry(api);
      if (configuredEntry && configuredEntry.enabled !== true) {
        console.warn(
          "[clawguard] Plugin is not explicitly enabled. Monitoring stays disabled until plugins.entries.clawguard-monitor.enabled is set to true.",
        );
        return;
      }

      const loadedConfig = resolveConfig(api);
      pluginConfig = loadedConfig.config;

      for (const warning of loadedConfig.warnings) {
        console.warn(warning);
      }

      if (!pluginConfig.apiKey) {
        console.warn(
          "[clawguard] No API key configured. Monitoring stays disabled until the user sets one explicitly.",
        );
        return;
      }
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

      // Initialize HTTP client only after we know monitoring can actually run.
      startedClient = new ClawGuardClient(pluginConfig);
      startedClient.start();
      client = startedClient;

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
            captureToolCall(ctx).catch(err => {
              // Log as warning — monitoring errors should not disrupt the agent
              console.warn("[clawguard] monitoring error (agent unaffected):", (err as Error).message);
            });
          }

          // Tool result: tool has completed
          if (blockType === "toolResult") {
            const toolName = String(block.name || block.tool || "unknown");
            const result = block.content || block.output || block.result || "";
            captureToolResult({ sessionKey, tool: toolName, result });
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
              captureMessage(ctx).catch(err => {
                console.warn("[clawguard] message error (agent unaffected):", (err as Error).message);
              });
            }
          }

          // Agent thinking/reasoning blocks — capture as decision events
          if ((blockType === "thinking" || blockType === "reasoning") && role === "assistant") {
            const text = String(block.text || block.thinking || block.reasoning || "");
            if (text.length > 0) {
              const session = sessions.get(sessionKey);
              if (session) {
                const data: Record<string, unknown> = {
                  reasoning: truncate(text, 500),
                };
                if (pluginConfig.captureFullIo) {
                  data.full_reasoning = truncate(text, pluginConfig.maxFullIoBytes);
                }
                const event = makeEvent(session, "decision", data);
                client.queueEvent(event);
              }
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
          captureToolCall(ctx).catch(err => {
            console.warn("[clawguard] agent event error (agent unaffected):", (err as Error).message);
          });
        } else if (/end|complete|result|done/i.test(dataType) || /end|result/i.test(stream)) {
          captureToolResult(ctx);
        }
      });
    }

    const registerCompatHook = typeof api.on === "function"
      ? api.on.bind(api)
      : (typeof api.registerHook === "function" ? api.registerHook.bind(api) : undefined);

    if (registerCompatHook) {
      registerCompatHook("before_tool_call", async (ctx: HookContext) => {
        await captureToolCall(ctx).catch((err) => {
          console.warn("[clawguard] hook monitoring error (agent unaffected):", (err as Error).message);
        });
      });

      registerCompatHook("after_tool_call", async (ctx: HookContext) => {
        try {
          captureToolResult(ctx);
        } catch (err) {
          console.warn("[clawguard] hook result error (agent unaffected):", (err as Error).message);
        }
      });

      registerCompatHook("message_sent", async (ctx: HookContext) => {
        await captureMessage(ctx).catch((err) => {
          console.warn("[clawguard] hook message error (agent unaffected):", (err as Error).message);
        });
      });

      registerCompatHook("session_end", async (ctx: HookContext) => {
        const normalized = normalizeHookContext(ctx);
        await endSessionForKey(normalized.sessionKey || "main").catch((err) => {
          console.warn("[clawguard] hook session end error (agent unaffected):", (err as Error).message);
        });
      });
    }

    // Flush remaining events on shutdown (best-effort, non-blocking)
    process.on("SIGTERM", () => {
      client.flush().catch(() => {});
    });
      initialized = true;
      _global[INIT_KEY] = true;

      console.log("[clawguard] Monitoring active");
      if (api.logger?.debug) {
        api.logger.debug(
          `[clawguard] backend: ${pluginConfig.backendUrl}, agent: ${pluginConfig.agentId}, apiKeySource: ${loadedConfig.sources.apiKey}`,
        );
      }
    } catch (err) {
      initialized = false;
      _global[INIT_KEY] = false;
      if (startedClient) {
        startedClient.stop().catch(() => {});
      }
      console.warn(
        "[clawguard] startup error (monitoring disabled, agent unaffected):",
        (err as Error).message,
      );
    }
  },
});

// Export for direct usage / testing
export const __testing = {
  MAX_SESSIONS,
  SESSION_TTL_MS,
  sessions,
  stableSerialize,
  pruneRecentEventFingerprints,
  shouldCaptureEvent,
  captureMessage,
  resolveSession,
  makeEvent,
  truncate,
  handleToolCall,
  handleToolResult,
  handleMessage,
  endSessionForKey,
  loadConfig,
  resolveConfig,
  resetStateForTests,
  setStateForTests,
};
export { ClawGuardClient } from "./client.js";
export { detectSensitiveContent, isHighRiskTool, isSensitivePath } from "./sensitive.js";
export type { AnalyzeThreadRequest, AnalyzeThreadResponse, ClawGuardPluginConfig, EventPayload } from "./types.js";
export { DEFAULT_CONFIG } from "./types.js";
