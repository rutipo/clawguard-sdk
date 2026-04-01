/**
 * HTTP client for communicating with the ClawGuard backend API.
 *
 * Handles authentication, batching, and retry logic.
 * Uses native fetch() (Node 22+).
 */

import type {
  BatchEventRequest,
  ClawGuardPluginConfig,
  EventPayload,
  SessionEndRequest,
  SessionStartRequest,
  SessionStartResponse,
} from "./types.js";

export class ClawGuardClient {
  private config: ClawGuardPluginConfig;
  private eventBuffer: EventPayload[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: ClawGuardPluginConfig) {
    this.config = config;
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
      // Put events back at the front of the buffer for retry
      this.eventBuffer.unshift(...events);
      throw err;
    }
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
      const text = await response.text().catch(() => "");
      throw new Error(
        `ClawGuard API error: ${response.status} ${response.statusText} - ${text}`,
      );
    }

    return response.json() as Promise<T>;
  }
}
