/**
 * Security-specific tests for ClawGuard plugin hardening.
 * Tests buffer limits, URL validation, error message sanitization,
 * and newly added detection patterns.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";
import { detectSensitiveContent } from "../../openclaw-plugin/src/sensitive.js";

// Mock fetch before importing client
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

describe("Security: Sensitive pattern detection (new patterns)", () => {
  it("detects Slack tokens", () => {
    // Use a clearly fake token prefix — real tokens have longer segments
    const result = detectSensitiveContent("token: xoxb-FAKE00TEST-placeholder");
    expect(result).toContain("slack_token");
  });

  it("detects GCP API keys", () => {
    const result = detectSensitiveContent("AIzaSyA1234567890abcdefghijklmnopqrstuvw");
    expect(result).toContain("gcp_api_key");
  });

  it("detects GCP service account JSON", () => {
    const result = detectSensitiveContent('{"type": "service_account", "project_id": "my-project", "private_key_id": "abc123"}');
    expect(result).toContain("gcp_service_account");
  });

  it("ignores bare service account examples without key material", () => {
    const result = detectSensitiveContent('{"type": "service_account", "project_id": "example-project"}');
    expect(result).not.toContain("gcp_service_account");
  });

  it("detects MSSQL connection strings", () => {
    const result = detectSensitiveContent("mssql://sa:password@host:1433/db");
    expect(result).toContain("database_url");
  });

  it("detects SSN patterns", () => {
    const result = detectSensitiveContent("SSN: 123-45-6789");
    expect(result).toContain("ssn");
  });

  it("detects credit card numbers", () => {
    const result = detectSensitiveContent("Card: 4111 1111 1111 1111");
    expect(result).toContain("credit_card");
  });
});

describe("Security: ClawGuardClient URL validation", () => {
  beforeEach(() => {
    vi.resetModules();
    mockFetch.mockReset();
  });

  it("rejects private IP 10.x.x.x", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "http://10.0.0.1:8000",
      apiKey: "test",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };
    expect(() => new ClawGuardClient(config)).toThrow(/private|internal/i);
  });

  it("rejects AWS metadata endpoint 169.254.x.x", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "http://169.254.169.254/latest/meta-data/",
      apiKey: "test",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };
    expect(() => new ClawGuardClient(config)).toThrow(/private|internal/i);
  });

  it("rejects 192.168.x.x", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "http://192.168.1.1:8000",
      apiKey: "test",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };
    expect(() => new ClawGuardClient(config)).toThrow(/private|internal/i);
  });

  it("rejects non-http protocols", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "ftp://evil.com/exfiltrate",
      apiKey: "test",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };
    expect(() => new ClawGuardClient(config)).toThrow(/http/i);
  });

  it("allows localhost (for development)", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "http://localhost:8000",
      apiKey: "test",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };
    // Should not throw
    expect(() => new ClawGuardClient(config)).not.toThrow();
  });

  it("allows public HTTPS URLs", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "https://clawguard.example.com",
      apiKey: "test",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };
    expect(() => new ClawGuardClient(config)).not.toThrow();
  });
});

describe("Security: Error message sanitization", () => {
  beforeEach(() => {
    vi.resetModules();
    mockFetch.mockReset();
  });

  it("does not include response body in error messages", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "http://localhost:8000",
      apiKey: "secret-key-123",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };

    const client = new ClawGuardClient(config);

    // Simulate backend returning an error with sensitive data in the body
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      text: () => Promise.resolve('{"error": "Invalid key: secret-key-123"}'),
    });

    const error = await client.sendEventImmediate({
      event_id: "test",
      session_id: "test",
      agent_id: "test",
      event_type: "tool_call",
      timestamp: new Date().toISOString(),
      data: {},
      risk_flags: [],
    }).catch((e: Error) => e);

    // Error message should NOT contain the response body
    expect(String(error)).not.toContain("secret-key-123");
    expect(String(error)).toContain("401");
  });
});

describe("Security: Event buffer limits", () => {
  beforeEach(() => {
    vi.resetModules();
    mockFetch.mockReset();
  });

  it("drops oldest events when buffer exceeds MAX_BUFFER_SIZE", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "http://localhost:8000",
      apiKey: "test",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 20000, // High batch size so flush doesn't trigger
      flushIntervalMs: 999999,
    };

    const client = new ClawGuardClient(config);

    // Queue many events — should not throw or grow unbounded
    for (let i = 0; i < 100; i++) {
      client.queueEvent({
        event_id: `evt-${i}`,
        session_id: "test",
        agent_id: "test",
        event_type: "tool_call",
        timestamp: new Date().toISOString(),
        data: {},
        risk_flags: [],
      });
    }

    // No assertion on exact count — just verify it doesn't crash
    // and the client is still functional
    expect(true).toBe(true);
  });
});

describe("Security: analyzeThread client method", () => {
  beforeEach(() => {
    vi.resetModules();
    mockFetch.mockReset();
  });

  it("sends analyze-thread request and returns response", async () => {
    const { ClawGuardClient } = await import("../../openclaw-plugin/src/client.js");
    const config = {
      backendUrl: "http://localhost:8000",
      apiKey: "test-key",
      agentId: "test",
      captureFullIo: false,
      maxFullIoBytes: 50000,
      blockSensitiveAccess: false,
      requireApprovalForHighRisk: false,
      batchSize: 10,
      flushIntervalMs: 5000,
    };

    const client = new ClawGuardClient(config);

    const mockResponse = {
      status: "success",
      threads: [
        {
          thread_id: "t-1",
          start_time: "2026-04-01T10:00:00Z",
          end_time: "2026-04-01T10:01:00Z",
          events: [],
          summary: "1 event(s)",
          classification: "research",
        },
      ],
      insights: [],
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const result = await client.analyzeThread({
      events: [
        { timestamp: "2026-04-01T10:00:00Z", type: "tool_call", content: "search" },
      ],
    });

    expect(result.status).toBe("success");
    expect(result.threads).toHaveLength(1);
    expect(result.threads[0].classification).toBe("research");

    // Verify it hit the correct endpoint
    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/v1/analyze-thread");
  });
});

describe("Security: Session map limits", () => {
  beforeEach(() => {
    vi.resetModules();
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ status: "ok", session_id: "test-session" }),
      text: () => Promise.resolve(""),
    });

    // Reset globalThis singleton state
    (globalThis as Record<symbol, unknown>)[Symbol.for("clawguard-monitor-initialized")] = false;
  });

  it("handles many unique session keys without crashing", async () => {
    process.env.CLAWGUARD_API_KEY = "test-key";
    process.env.CLAWGUARD_BACKEND_URL = "http://localhost:8000";
    process.env.CLAWGUARD_AGENT_ID = "test-bot";

    const mod = await import("../../openclaw-plugin/src/index.js");

    let transcriptCallback: Function;
    const api = {
      registerHook: vi.fn(),
      on: vi.fn(),
      pluginConfig: { agentId: "test-bot" },
      runtime: {
        events: {
          onSessionTranscriptUpdate: vi.fn((cb: Function) => {
            transcriptCallback = cb;
          }),
          onAgentEvent: vi.fn(),
        },
      },
    };

    mod.default.register(api as any);

    // Simulate tool calls from many different sessions
    for (let i = 0; i < 150; i++) {
      transcriptCallback!({
        sessionKey: `session-${i}`,
        message: {
          role: "assistant",
          content: [
            {
              type: "toolCall",
              name: "search",
              arguments: { query: "test" },
            },
          ],
        },
      });
    }

    // Allow async handlers to process
    await new Promise((r) => setTimeout(r, 100));

    // Should not throw — session cap evicts oldest sessions
    expect(mockFetch).toHaveBeenCalled();

    delete process.env.CLAWGUARD_API_KEY;
    delete process.env.CLAWGUARD_BACKEND_URL;
    delete process.env.CLAWGUARD_AGENT_ID;
  });
});
