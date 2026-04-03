/**
 * HTTP client for communicating with the ClawGuard backend API.
 *
 * Handles authentication, batching, and retry logic.
 * Uses native fetch() (Node 22+).
 */

import type {
  AnalyzeThreadRequest,
  AnalyzeThreadResponse,
  BatchEventRequest,
  ClawGuardPluginConfig,
  EventPayload,
  SessionEndRequest,
  SessionStartRequest,
  SessionStartResponse,
} from "./types.js";

/** Max queued events before oldest are dropped to prevent memory exhaustion. */
const MAX_BUFFER_SIZE = 10_000;

export class ClawGuardClient {
  private config: ClawGuardPluginConfig;
  private eventBuffer: EventPayload[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: ClawGuardPluginConfig) {
    this.config = config;
    this.validateBackendUrl(config.backendUrl);
  }

  /**
   * Validate backend URL to prevent SSRF attacks against internal services.
   * Blocks private IPs, metadata endpoints, and non-HTTP protocols.
   */
  private validateBackendUrl(url: string): void {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`[clawguard] Invalid backend URL: ${url}`);
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error(`[clawguard] Backend URL must use http or https protocol`);
    }

    const hostname = parsed.hostname;
    // Block cloud metadata endpoints and private IP ranges (except localhost for dev)
    const blockedPatterns = [
      /^169\.254\./, // AWS/Azure metadata
      /^10\./,
      /^172\.(1[6-9]|2\d|3[01])\./,
      /^192\.168\./,
      /^0\./,
      /^\[?fe80:/i, // IPv6 link-local
      /^\[?::1\]?$/,  // IPv6 loopback
    ];

    if (blockedPatterns.some((p) => p.test(hostname))) {
      throw new Error(`[clawguard] Backend URL points to a private/internal address`);
    }

    // Warn if non-localhost URL uses plain HTTP (credentials sent in cleartext)
    if (parsed.protocol === "http:" && hostname !== "localhost" && hostname !== "127.0.0.1") {
      console.warn(
        `[clawguard] WARNING: Backend URL uses HTTP — API key will be sent in cleartext. Use HTTPS in production.`,
      );
    }
  }

  /** Start the periodic flush timer. */
  start(): void {
    if (this.flushTimer) return;
    this.flushTimer = setInterval(() => {
      this.flush().catch((err) => {
        console.error("[clawguard] flush error:", err.message);
      });
    }, this.config.flushIntervalMs);
    // Don't let the timer prevent the process from exiting
    this.flushTimer.unref();
  }

  /** Stop the timer and flush remaining events. */
  async stop(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  /** Create a session on the backend. */
  async startSession(agentId: string, task: string): Promise<string> {
    const body: SessionStartRequest = { agent_id: agentId, task };
    const res = await this.post<SessionStartResponse>("/v1/sessions/start", body);
    return res.session_id;
  }

  /** End a session on the backend. */
  async endSession(
    sessionId: string,
    status: "completed" | "aborted" = "completed",
  ): Promise<void> {
    const body: SessionEndRequest = { session_id: sessionId, status };
    await this.post("/v1/sessions/end", body);
  }

  /** Queue an event for batched sending. */
  queueEvent(event: EventPayload): void {
    // Drop oldest events if buffer is full to prevent memory exhaustion
    if (this.eventBuffer.length >= MAX_BUFFER_SIZE) {
      this.eventBuffer.splice(0, this.eventBuffer.length - MAX_BUFFER_SIZE + 1);
    }
    this.eventBuffer.push(event);
    if (this.eventBuffer.length >= this.config.batchSize) {
      this.flush().catch((err) => {
        console.error("[clawguard] flush error:", err.message);
      });
    }
  }

  /** Send an event immediately (bypasses batch). */
  async sendEventImmediate(event: EventPayload): Promise<void> {
    await this.post("/v1/events", event);
  }

  /** Flush buffered events to the backend. */
  async flush(): Promise<void> {
    if (this.eventBuffer.length === 0) return;

    const events = this.eventBuffer.splice(0, this.eventBuffer.length);
    const body: BatchEventRequest = { events };

    try {
      await this.post("/v1/events/batch", body);
    } catch (err) {
      // Put events back for retry, but respect buffer cap to prevent unbounded growth
      const available = MAX_BUFFER_SIZE - this.eventBuffer.length;
      if (available > 0) {
        this.eventBuffer.unshift(...events.slice(-available));
      }
      throw err;
    }
  }

  /** Analyze a batch of events into threads (stateless, no DB persistence). */
  async analyzeThread(request: AnalyzeThreadRequest): Promise<AnalyzeThreadResponse> {
    return this.post<AnalyzeThreadResponse>("/v1/analyze-thread", request);
  }

  /** Make an authenticated POST request to the backend. */
  private async post<T = unknown>(path: string, body: unknown): Promise<T> {
    const url = `${this.config.backendUrl}${path}`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": this.config.apiKey,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      // Don't include response body — it may contain sensitive data or be attacker-controlled
      throw new Error(
        `ClawGuard API error: ${response.status} ${response.statusText}`,
      );
    }

    return response.json() as Promise<T>;
  }
}
