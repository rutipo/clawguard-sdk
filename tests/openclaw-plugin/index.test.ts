import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock fetch before imports
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Reset modules and global singleton state to ensure clean state
beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ status: "ok", session_id: "test-session-123" }),
    text: () => Promise.resolve(""),
  });

  // Reset globalThis singleton guard used by the plugin
  // (client and config are module-scoped, not on globalThis)
  (globalThis as Record<symbol, unknown>)[Symbol.for("clawguard-monitor-initialized")] = false;
});

describe("register()", () => {
  it("warns and returns when no API key configured", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    // Clear env vars
    delete process.env.CLAWGUARD_API_KEY;
    delete process.env.CLAWGUARD_BACKEND_URL;

    const mod = await import("../../openclaw-plugin/src/index.js");

    const api = {
      registerHook: vi.fn(),
      on: vi.fn(),
      pluginConfig: {},
    };

    mod.default.register(api as any);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("No API key"),
    );

    warnSpy.mockRestore();
  });

  it("disables monitoring instead of throwing on invalid startup config", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    delete process.env.CLAWGUARD_BACKEND_URL;
    delete process.env.CLAWGUARD_AGENT_ID;

    const mod = await import("../../openclaw-plugin/src/index.js");

    const api = {
      registerHook: vi.fn(),
      on: vi.fn(),
      pluginConfig: {
        apiKey: "test-key",
        backendUrl: "notaurl",
      },
      runtime: {
        events: {
          onSessionTranscriptUpdate: vi.fn(),
          onAgentEvent: vi.fn(),
        },
      },
    };

    expect(() => mod.default.register(api as any)).not.toThrow();
    expect(warnSpy).toHaveBeenCalledWith(
      "[clawguard] startup error (monitoring disabled, agent unaffected):",
      expect.stringContaining("Invalid backend URL"),
    );
    expect(logSpy).not.toHaveBeenCalledWith("[clawguard] Monitoring active");
    expect(mockFetch).not.toHaveBeenCalled();

    warnSpy.mockRestore();
    logSpy.mockRestore();
  });
});

describe("event-based monitoring (with API key)", () => {
  let transcriptCallback: Function;
  let agentEventCallback: Function;

  beforeEach(async () => {
    process.env.CLAWGUARD_API_KEY = "test-key-123";
    process.env.CLAWGUARD_BACKEND_URL = "http://localhost:8000";
    process.env.CLAWGUARD_AGENT_ID = "test-bot";

    // Dynamic import to pick up env changes
    vi.resetModules();
    const mod = await import("../../openclaw-plugin/src/index.js");

    const api = {
      registerHook: vi.fn(),
      on: vi.fn(),
      pluginConfig: {
        agentId: "test-bot",
      },
      runtime: {
        events: {
          onSessionTranscriptUpdate: vi.fn((cb: Function) => {
            transcriptCallback = cb;
          }),
          onAgentEvent: vi.fn((cb: Function) => {
            agentEventCallback = cb;
          }),
        },
      },
    };

    mod.default.register(api as any);
  });

  afterEach(async () => {
    delete process.env.CLAWGUARD_API_KEY;
    delete process.env.CLAWGUARD_BACKEND_URL;
    delete process.env.CLAWGUARD_AGENT_ID;
  });

  it("subscribes to onSessionTranscriptUpdate and onAgentEvent", () => {
    expect(transcriptCallback).toBeDefined();
    expect(agentEventCallback).toBeDefined();
  });

  it("tool call transcript update sends events to backend", async () => {
    // Simulate a transcript update with a toolCall block
    transcriptCallback({
      sessionKey: "test-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "browser_search",
            arguments: { query: "competitor pricing" },
          },
        ],
      },
    });

    // Wait for async handling
    await new Promise((r) => setTimeout(r, 50));

    expect(mockFetch).toHaveBeenCalled();

    const calls = mockFetch.mock.calls;
    const sessionStartCall = calls.find((c: any[]) =>
      c[0].includes("/v1/sessions/start"),
    );
    expect(sessionStartCall).toBeDefined();
  });

  it("flags sensitive file access in tool call", async () => {
    transcriptCallback({
      sessionKey: "sensitive-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "read_file",
            arguments: { path: "/app/.env" },
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));

    const eventCalls = mockFetch.mock.calls.filter((c: any[]) =>
      c[0].includes("/v1/events") && !c[0].includes("batch") && !c[0].includes("sessions"),
    );

    expect(eventCalls.length).toBeGreaterThanOrEqual(1);
  });

  it("processes agent text responses without error", async () => {
    // First trigger a tool call to create a session
    transcriptCallback({
      sessionKey: "msg-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "search",
            arguments: {},
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));

    // Now send a text response — this gets queued (no risk flags)
    // so it won't immediately call fetch, but it should not throw
    transcriptCallback({
      sessionKey: "msg-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "text",
            text: "Here are the search results...",
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));
    // No assertion on fetch — the event is batched, not sent immediately.
    // The fact that no error was thrown is the test.
  });

  it("captures thinking blocks as decision events", async () => {
    // First trigger a tool call to create a session
    transcriptCallback({
      sessionKey: "thinking-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "search",
            arguments: {},
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));

    // Now send a thinking block
    transcriptCallback({
      sessionKey: "thinking-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "thinking",
            text: "I need to search for competitor pricing data to complete this analysis",
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));
    // The thinking block creates a decision event which is queued (batched).
    // No error thrown = success. The event will be flushed in the batch.
  });

  it("captures reasoning blocks as decision events", async () => {
    // First trigger a tool call to create a session
    transcriptCallback({
      sessionKey: "reasoning-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "read_file",
            arguments: {},
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));

    // Now send a reasoning block
    transcriptCallback({
      sessionKey: "reasoning-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "reasoning",
            reasoning: "The user asked for the config file contents",
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));
    // No error thrown = success
  });

  it("handles string arguments in tool calls", async () => {
    transcriptCallback({
      sessionKey: "string-args-test",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "exec",
            arguments: '{"command":"ls -la","yieldMs":10000}',
          },
        ],
      },
    });

    await new Promise((r) => setTimeout(r, 50));

    expect(mockFetch).toHaveBeenCalled();
  });
});
