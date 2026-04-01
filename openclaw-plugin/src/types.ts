/**
 * Type definitions for ClawGuard OpenClaw plugin.
 *
 * These mirror the ClawGuard backend API schemas and the
 * OpenClaw plugin SDK interfaces we hook into.
 */

// --- ClawGuard API types ---

export type EventType =
  | "prompt"
  | "decision"
  | "tool_call"
  | "tool_output"
  | "data_access"
  | "action"
  | "alert"
  | "session_start"
  | "session_end";

export interface EventPayload {
  event_id: string;
  session_id: string;
  agent_id: string;
  event_type: EventType;
  timestamp: string; // ISO 8601
  data: Record<string, unknown>;
  risk_flags: string[];
}

export interface BatchEventRequest {
  events: EventPayload[];
}

export interface SessionStartRequest {
  agent_id: string;
  task: string;
}

export interface SessionStartResponse {
  session_id: string;
}

export interface SessionEndRequest {
  session_id: string;
  status: "active" | "completed" | "aborted";
}

// --- OpenClaw plugin SDK types (minimal subset we use) ---

export interface OpenClawPluginApi {
  registerHook(event: string, handler: HookHandler): void;
  /** Plugin-specific config from plugins.entries.<id>.config */
  pluginConfig: Record<string, unknown>;
  /** Full OpenClaw config snapshot */
  config?: Record<string, unknown>;
  /** Runtime helpers */
  runtime?: PluginRuntime;
  /** Scoped logger */
  logger?: { debug(...args: unknown[]): void; info(...args: unknown[]): void; warn(...args: unknown[]): void; error(...args: unknown[]): void };
}

export interface HookHandler {
  (ctx: HookContext): Promise<HookDecision | void>;
}

export interface HookContext {
  /** The tool being called */
  tool?: string;
  /** Tool input arguments */
  args?: Record<string, unknown>;
  /** Tool output/result (for after-hooks) */
  result?: unknown;
  /** Message content (for message_sending) */
  message?: string;
  /** Channel the message is being sent to */
  channel?: string;
  /** Session key */
  sessionKey?: string;
  /** Agent ID */
  agentId?: string;
}

export interface HookDecision {
  block?: boolean;
  requireApproval?: boolean;
  cancel?: boolean;
}

export interface BackgroundService {
  start(): Promise<void>;
  stop(): Promise<void>;
}

export interface PluginRuntime {
  config: Record<string, unknown>;
}

// --- OpenClaw plugin entry point ---

export interface PluginEntry {
  id: string;
  name: string;
  description?: string;
  register: (api: OpenClawPluginApi) => void;
}

/**
 * Type-safe helper matching OpenClaw's definePluginEntry API.
 * We define it locally so we don't need openclaw as a build dependency.
 */
export function definePluginEntry(entry: PluginEntry): PluginEntry {
  return entry;
}

// --- Plugin configuration ---

export interface ClawGuardPluginConfig {
  /** ClawGuard backend URL (e.g. https://clawguard.example.com) */
  backendUrl: string;
  /** API key for authentication */
  apiKey: string;
  /** Agent identifier for this OpenClaw instance */
  agentId: string;
  /** Whether to capture full tool input/output (default: false, uses summaries) */
  captureFullIo: boolean;
  /** Max bytes for full I/O capture (default: 50000) */
  maxFullIoBytes: number;
  /** Whether to block tool calls that access sensitive patterns (default: false) */
  blockSensitiveAccess: boolean;
  /** Whether to require approval for high-risk actions (default: false) */
  requireApprovalForHighRisk: boolean;
  /** Event batch size before flushing (default: 10) */
  batchSize: number;
  /** Max time in ms before flushing event batch (default: 5000) */
  flushIntervalMs: number;
}

export const DEFAULT_CONFIG: ClawGuardPluginConfig = {
  backendUrl: "http://localhost:8000",
  apiKey: "",
  agentId: "openclaw-agent",
  captureFullIo: false,
  maxFullIoBytes: 50_000,
  blockSensitiveAccess: false,
  requireApprovalForHighRisk: false,
  batchSize: 10,
  flushIntervalMs: 5000,
};
