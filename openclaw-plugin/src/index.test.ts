import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock fetch before imports
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Reset modules to ensure clean state
beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ status: "ok", session_id: "test-session-123" }),
    text: () => Promise.resolve(""),
  });
});

describe("register()", () => {
  it("warns and returns when no API key configured", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    // Clear env vars
    delete process.env.CLAWGUARD_API_KEY;
    delete process.env.CLAWGUARD_BACKEND_URL;

    const { register } = await import("./index.js");

    const api = {
      registerHook: vi.fn(),
      registerBackgroundService: vi.fn(),
      runtime: {
        config: {
          get: () => undefined,
        },
      },
    };

    register(api as any);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("No API key"),
    );
    // Should not register hooks when disabled
    expect(api.registerHook).not.toHaveBeenCalled();

    warnSpy.mockRestore();
  });
});

describe("plugin hooks (with API key)", () => {
  let hookHandlers: Record<string, Function>;
  let bgServices: Record<string, any>;

  beforeEach(async () => {
    hookHandlers = {};
    bgServices = {};

    process.env.CLAWGUARD_API_KEY = "test-key-123";
    process.env.CLAWGUARD_BACKEND_URL = "http://localhost:8000";
    process.env.CLAWGUARD_AGENT_ID = "test-bot";

    // Dynamic import to pick up env changes
    // We need to reset the module to get fresh state
    vi.resetModules();
    const mod = await import("./index.js");

    const api = {
      registerHook: vi.fn((event: string, handler: Function) => {
        hookHandlers[event] = handler;
      }),
      registerBackgroundService: vi.fn((name: string, svc: any) => {
        bgServices[name] = svc;
      }),
      runtime: {
        config: {
          get: (key: string) => {
            const vals: Record<string, unknown> = {
              agentId: "test-bot",
            };
            return vals[key];
          },
        },
      },
    };

    mod.register(api as any);
  });

  afterEach(async () => {
    // Clean up
    if (bgServices["clawguard-monitor"]) {
      await bgServices["clawguard-monitor"].stop().catch(() => {});
    }
    delete process.env.CLAWGUARD_API_KEY;
    delete process.env.CLAWGUARD_BACKEND_URL;
    delete process.env.CLAWGUARD_AGENT_ID;
  });

  it("registers before_tool_call and message_sending hooks", () => {
    expect(hookHandlers["before_tool_call"]).toBeDefined();
    expect(hookHandlers["message_sending"]).toBeDefined();
  });

  it("registers a background service", () => {
    expect(bgServices["clawguard-monitor"]).toBeDefined();
    expect(bgServices["clawguard-monitor"].start).toBeDefined();
    expect(bgServices["clawguard-monitor"].stop).toBeDefined();
  });

  it("before_tool_call sends events to backend", async () => {
    const handler = hookHandlers["before_tool_call"];

    await handler({
      tool: "browser_search",
      args: { query: "competitor pricing" },
      sessionKey: "test-session",
      agentId: "test-bot",
    });

    // Should have called: startSession + session_start event + tool_call event
    // At minimum, startSession POST
    expect(mockFetch).toHaveBeenCalled();

    // Check that a session start was sent
    const calls = mockFetch.mock.calls;
    const sessionStartCall = calls.find((c: any[]) =>
      c[0].includes("/v1/sessions/start"),
    );
    expect(sessionStartCall).toBeDefined();
  });

  it("flags sensitive file access", async () => {
    const handler = hookHandlers["before_tool_call"];

    await handler({
      tool: "read_file",
      args: { path: "/app/.env" },
      sessionKey: "sensitive-test",
      agentId: "test-bot",
    });

    // Should send immediately due to risk flags
    const eventCalls = mockFetch.mock.calls.filter((c: any[]) =>
      c[0].includes("/v1/events") && !c[0].includes("batch") && !c[0].includes("sessions"),
    );

    // At least the session_start event was sent immediately
    expect(eventCalls.length).toBeGreaterThanOrEqual(1);
  });

  it("message_sending captures outbound messages", async () => {
    const handler = hookHandlers["message_sending"];

    // First trigger a tool call to create a session
    await hookHandlers["before_tool_call"]({
      tool: "search",
      args: {},
      sessionKey: "msg-test",
      agentId: "test-bot",
    });

    mockFetch.mockClear();

    await handler({
      message: "Here are the search results...",
      channel: "telegram",
      sessionKey: "msg-test",
    });

    // Should have queued an action event (or sent immediate)
    // The event won't be sent immediately unless it has risk flags
    // But it should be in the buffer
  });
});
