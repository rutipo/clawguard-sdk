import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ClawGuardPluginConfig } from "../../openclaw-plugin/src/types.js";
import { DEFAULT_CONFIG } from "../../openclaw-plugin/src/types.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeConfig(overrides: Partial<ClawGuardPluginConfig> = {}): ClawGuardPluginConfig {
  return {
    ...DEFAULT_CONFIG,
    backendUrl: "http://localhost:8000",
    apiKey: "test-key",
    agentId: "test-agent",
    ...overrides,
  };
}

function makeSession(overrides: Record<string, unknown> = {}) {
  return {
    sessionId: "sess-1",
    agentId: "test-agent",
    task: "",
    startedAt: Date.now(),
    toolCallCount: 0,
    recentOutputs: [] as Array<{ toolName: string; outputPrefix: string }>,
    sensitiveAccessed: false,
    ...overrides,
  };
}

function makeMockClient() {
  return {
    start: vi.fn(),
    startSession: vi.fn().mockResolvedValue("new-session"),
    sendEventImmediate: vi.fn().mockResolvedValue(undefined),
    queueEvent: vi.fn(),
    endSession: vi.fn().mockResolvedValue(undefined),
    flush: vi.fn().mockResolvedValue(undefined),
  };
}

async function loadModule() {
  vi.resetModules();
  const mod = await import("../../openclaw-plugin/src/index.js");
  mod.__testing.resetStateForTests();
  return mod;
}

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ status: "ok", session_id: "generated-session" }),
    text: () => Promise.resolve(""),
  });
  delete process.env.CLAWGUARD_API_KEY;
  delete process.env.CLAWGUARD_BACKEND_URL;
  delete process.env.CLAWGUARD_AGENT_ID;
  (globalThis as Record<symbol, unknown>)[Symbol.for("clawguard-monitor-initialized")] = false;
});

afterEach(() => {
  delete process.env.CLAWGUARD_API_KEY;
  delete process.env.CLAWGUARD_BACKEND_URL;
  delete process.env.CLAWGUARD_AGENT_ID;
  vi.restoreAllMocks();
});

describe("index __testing helpers", () => {
  it("defaults the initialized flag when the global marker is absent", async () => {
    vi.resetModules();
    delete (globalThis as Record<symbol, unknown>)[Symbol.for("clawguard-monitor-initialized")];

    const mod = await import("../../openclaw-plugin/src/index.js");

    expect(mod.default).toBeDefined();
    mod.__testing.resetStateForTests();
  });

  it("resolveSession returns an existing session without creating a new one", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    const existing = makeSession({ sessionId: "existing-session" });
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("main", existing);

    const session = await mod.__testing.resolveSession({});

    expect(session).toBe(existing);
    expect(client.startSession).not.toHaveBeenCalled();
    expect(client.sendEventImmediate).not.toHaveBeenCalled();
  });

  it("resolveSession evicts expired sessions before creating a new one", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    const now = Date.now();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set(
      "expired",
      makeSession({ sessionId: "expired-session", startedAt: now - mod.__testing.SESSION_TTL_MS - 1 }),
    );

    const session = await mod.__testing.resolveSession({ sessionKey: "fresh", agentId: "override-agent" });

    expect(client.startSession).toHaveBeenCalledWith("override-agent", "");
    expect(client.sendEventImmediate).toHaveBeenCalledOnce();
    expect(mod.__testing.sessions.has("expired")).toBe(false);
    expect(session.sessionId).toBe("new-session");
  });

  it("resolveSession evicts the oldest session when the max session limit is reached", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    const now = Date.now();

    for (let i = 0; i < mod.__testing.MAX_SESSIONS; i++) {
      mod.__testing.sessions.set(
        `key-${i}`,
        makeSession({ sessionId: `sess-${i}`, startedAt: now - (mod.__testing.MAX_SESSIONS - i) }),
      );
    }

    await mod.__testing.resolveSession({ sessionKey: "new-key" });

    expect(mod.__testing.sessions.has("key-0")).toBe(false);
    expect(mod.__testing.sessions.has("new-key")).toBe(true);
  });

  it("handleToolCall sends high-risk events immediately with full input details", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    const session = makeSession({ sensitiveAccessed: true });
    mod.__testing.setStateForTests({
      client: client as any,
      pluginConfig: makeConfig({ captureFullIo: true, maxFullIoBytes: 10 }),
    });
    mod.__testing.sessions.set("sess-key", session);

    await mod.__testing.handleToolCall({
      sessionKey: "sess-key",
      tool: "http_post",
      args: {
        path: "/app/.env",
        token: "sk-abc123def456ghi789jkl012mno",
      },
    });

    expect(client.sendEventImmediate).toHaveBeenCalledOnce();
    const event = client.sendEventImmediate.mock.calls[0][0];
    expect(event.risk_flags).toEqual(
      expect.arrayContaining([
        "sensitive_path",
        "sensitive_input",
        "high_risk_tool",
        "potential_exfiltration",
      ]),
    );
    expect(event.data.target).toBe("/app/.env");
    expect(event.data.full_input).toBeDefined();
    expect(event.data.sensitive_patterns).toContain("api_key_sk");
  });

  it("handleToolCall queues benign events", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("sess-key", makeSession());

    await mod.__testing.handleToolCall({
      sessionKey: "sess-key",
      tool: "browser_search",
      args: { query: "pricing" },
    });

    expect(client.queueEvent).toHaveBeenCalledOnce();
    expect(client.sendEventImmediate).not.toHaveBeenCalled();
  });

  it("handleToolCall treats read-only http requests as normal activity", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("sess-key", makeSession());

    await mod.__testing.handleToolCall({
      sessionKey: "sess-key",
      tool: "http_request",
      args: { method: "GET", url: "https://docs.example.com" },
    });

    expect(client.queueEvent).toHaveBeenCalledOnce();
    expect(client.sendEventImmediate).not.toHaveBeenCalled();
  });

  it("handleToolCall still alerts on outbound requests with payload", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("sess-key", makeSession());

    await mod.__testing.handleToolCall({
      sessionKey: "sess-key",
      tool: "http_request",
      args: { method: "POST", url: "https://api.example.com/upload", body: "{\"ok\":true}" },
    });

    expect(client.sendEventImmediate).toHaveBeenCalledOnce();
    const event = client.sendEventImmediate.mock.calls[0][0];
    expect(event.risk_flags).toContain("high_risk_tool");
    expect(event.data.direction).toBe("outbound");
    expect(event.data.severity).toBe("high");
  });

  it("handleToolCall treats read-only exec commands as normal activity", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("sess-key", makeSession());

    await mod.__testing.handleToolCall({
      sessionKey: "sess-key",
      tool: "exec",
      args: { command: "Get-Content C:\\repo\\README.md" },
    });

    expect(client.queueEvent).toHaveBeenCalledOnce();
    expect(client.sendEventImmediate).not.toHaveBeenCalled();
  });

  it("handleToolCall still alerts on sensitive paths inside shell commands", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("sess-key", makeSession());

    await mod.__testing.handleToolCall({
      sessionKey: "sess-key",
      tool: "exec",
      args: { command: "Get-Content C:\\repo\\.env" },
    });

    expect(client.sendEventImmediate).toHaveBeenCalledOnce();
    const event = client.sendEventImmediate.mock.calls[0][0];
    expect(event.risk_flags).toContain("sensitive_path");
    expect(event.risk_flags).not.toContain("high_risk_tool");
  });

  it("handleToolResult queues benign outputs with duration and full output", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    const session = makeSession();
    mod.__testing.setStateForTests({
      client: client as any,
      pluginConfig: makeConfig({ captureFullIo: true, maxFullIoBytes: 12 }),
    });

    mod.__testing.handleToolResult(session, "browser_search", "plain result", 55);

    expect(client.queueEvent).toHaveBeenCalledOnce();
    const event = client.queueEvent.mock.calls[0][0];
    expect(event.data.duration_ms).toBe(55);
    expect(event.data.full_output).toBe("plain result");
    expect(session.recentOutputs).toHaveLength(1);
  });

  it("handleToolResult marks sensitive access, trims output history, and warns on send failure", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const session = makeSession({
      recentOutputs: Array.from({ length: 10 }, (_, i) => ({
        toolName: `tool-${i}`,
        outputPrefix: `output-${i}`,
      })),
    });
    client.sendEventImmediate.mockRejectedValueOnce(new Error("send failed"));
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });

    mod.__testing.handleToolResult(
      session,
      "/app/.env",
      "SECRET_KEY=mysecretvalue123",
      undefined,
    );
    await Promise.resolve();

    expect(session.sensitiveAccessed).toBe(true);
    expect(session.recentOutputs).toHaveLength(10);
    expect(client.sendEventImmediate).toHaveBeenCalledOnce();
    expect(warnSpy).toHaveBeenCalledWith(
      "[clawguard] send error (agent unaffected):",
      "send failed",
    );
  });

  it("handleMessage queues benign and low-signal pii, but sends secret-like content immediately", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("sess-key", makeSession());

    await mod.__testing.handleMessage({
      sessionKey: "sess-key",
      message: "normal status update",
      channel: "agent",
    });
    await mod.__testing.handleMessage({
      sessionKey: "sess-key",
      message: "Send this to user@example.com",
      channel: "email",
    });
    await mod.__testing.handleMessage({
      sessionKey: "sess-key",
      message: "Leaked key sk-abc123def456ghi789jkl012mno",
      channel: "agent",
    });

    expect(client.queueEvent).toHaveBeenCalledTimes(2);
    expect(client.sendEventImmediate).toHaveBeenCalledOnce();
    expect(client.sendEventImmediate.mock.calls[0][0].risk_flags).toContain("sensitive_in_response");
  });

  it("endSessionForKey is a no-op for missing sessions and cleans up even when backend end fails", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });

    await mod.__testing.endSessionForKey("missing");
    mod.__testing.sessions.set("sess-key", makeSession({ toolCallCount: 3, startedAt: Date.now() - 1000 }));
    client.endSession.mockRejectedValueOnce(new Error("end failed"));

    await mod.__testing.endSessionForKey("sess-key", "aborted");

    expect(client.sendEventImmediate).toHaveBeenCalledOnce();
    expect(client.endSession).toHaveBeenCalledWith("sess-1", "aborted");
    expect(mod.__testing.sessions.has("sess-key")).toBe(false);
    expect(warnSpy).toHaveBeenCalledWith(
      "[clawguard] end session error (agent unaffected):",
      "end failed",
    );
  });

  it("loadConfig merges plugin config with environment overrides", async () => {
    const mod = await loadModule();
    process.env.CLAWGUARD_BACKEND_URL = "https://env.example.com";
    process.env.CLAWGUARD_API_KEY = "env-key";
    process.env.CLAWGUARD_AGENT_ID = "env-agent";

    const config = mod.__testing.loadConfig({
      pluginConfig: {
        backendUrl: "https://config.example.com",
        apiKey: "config-key",
        agentId: "config-agent",
        captureFullIo: true,
        maxFullIoBytes: 1234,
        blockSensitiveAccess: true,
        requireApprovalForHighRisk: true,
        batchSize: 7,
        flushIntervalMs: 2500,
      },
    } as any);

    expect(config.backendUrl).toBe("https://env.example.com");
    expect(config.apiKey).toBe("env-key");
    expect(config.agentId).toBe("env-agent");
    expect(config.captureFullIo).toBe(true);
    expect(config.maxFullIoBytes).toBe(1234);
    expect(config.blockSensitiveAccess).toBe(true);
    expect(config.requireApprovalForHighRisk).toBe(true);
    expect(config.batchSize).toBe(7);
    expect(config.flushIntervalMs).toBe(2500);
  });

  it("falls back to the full OpenClaw config snapshot when pluginConfig is absent", async () => {
    const mod = await loadModule();

    const resolved = mod.__testing.resolveConfig({
      config: {
        plugins: {
          entries: {
            "clawguard-monitor": {
              config: {
                backendUrl: "https://snapshot.example.com",
                apiKey: "snapshot-key",
                agentId: "snapshot-agent",
                batchSize: 11,
              },
            },
          },
        },
      },
    } as any);

    expect(resolved.config.backendUrl).toBe("https://snapshot.example.com");
    expect(resolved.config.apiKey).toBe("snapshot-key");
    expect(resolved.config.agentId).toBe("snapshot-agent");
    expect(resolved.config.batchSize).toBe(11);
    expect(resolved.sources.apiKey).toBe("openclaw config");
  });

  it("records a warning when CLAWGUARD_API_KEY overrides plugin config", async () => {
    const mod = await loadModule();
    process.env.CLAWGUARD_API_KEY = "env-key";

    const resolved = mod.__testing.resolveConfig({
      pluginConfig: {
        apiKey: "plugin-key",
      },
    } as any);

    expect(resolved.config.apiKey).toBe("env-key");
    expect(resolved.warnings).toContain(
      "[clawguard] CLAWGUARD_API_KEY is overriding the plugin runtime API key. If requests return 401, update or clear that environment variable on this machine.",
    );
  });

  it("falls back for nullish helper inputs and config without plugin config", async () => {
    const mod = await loadModule();
    const client = makeMockClient();
    mod.__testing.setStateForTests({ client: client as any, pluginConfig: makeConfig() });
    mod.__testing.sessions.set("main", makeSession());

    expect(mod.__testing.truncate(undefined, 10)).toBe("");
    expect(mod.__testing.loadConfig({} as any)).toEqual(DEFAULT_CONFIG);

    await mod.__testing.handleToolCall({});
    mod.__testing.handleToolResult(makeSession(), "browser_search", undefined);
    await mod.__testing.handleMessage({ sessionKey: "main" });

    expect(client.queueEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: "tool_call",
        data: expect.objectContaining({
          tool_name: "unknown",
        }),
      }),
    );
    expect(client.queueEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: "action",
        data: expect.objectContaining({
          channel: "unknown",
          content_length: 0,
        }),
      }),
    );
  });

  it("ignores blank string config values so stale entries do not override safe defaults", async () => {
    const mod = await loadModule();
    process.env.CLAWGUARD_BACKEND_URL = "   ";
    process.env.CLAWGUARD_API_KEY = " ";
    process.env.CLAWGUARD_AGENT_ID = "\t";

    const config = mod.__testing.loadConfig({
      pluginConfig: {
        backendUrl: "   ",
        apiKey: "   ",
        agentId: "",
      },
    } as any);

    expect(config).toEqual(DEFAULT_CONFIG);
  });
});

describe("index register edge cases", () => {
  async function registerWithRuntime(overrides: Record<string, unknown> = {}) {
    const mod = await loadModule();
    let transcriptCallback: ((update: Record<string, unknown>) => void) | undefined;
    let agentEventCallback: ((event: Record<string, unknown>) => void) | undefined;
    let signalHandler: (() => void) | undefined;

    const intervalTimer = { unref: vi.fn() };
    vi.spyOn(globalThis, "setInterval").mockImplementation(
      (() => intervalTimer as unknown as ReturnType<typeof setInterval>) as typeof setInterval,
    );
    vi.spyOn(process, "on").mockImplementation(((signal, handler) => {
      if (signal === "SIGTERM") {
        signalHandler = handler as () => void;
      }
      return process;
    }) as typeof process.on);

    const api = {
      registerHook: vi.fn(),
      on: vi.fn(),
      pluginConfig: { apiKey: "plugin-key", agentId: "plugin-agent", backendUrl: "http://localhost:8000" },
      runtime: {
        events: {
          onSessionTranscriptUpdate: vi.fn((cb: (update: Record<string, unknown>) => void) => {
            transcriptCallback = cb;
          }),
          onAgentEvent: vi.fn((cb: (event: Record<string, unknown>) => void) => {
            agentEventCallback = cb;
          }),
        },
      },
      ...overrides,
    };

    mod.default.register(api as any);
    return { mod, api, transcriptCallback, agentEventCallback, signalHandler };
  }

  it("returns early when already initialized or registration mode is not full", async () => {
    const mod = await loadModule();
    const api = { registerHook: vi.fn(), on: vi.fn(), pluginConfig: { apiKey: "key" } };

    mod.__testing.setStateForTests({ initialized: true });
    mod.default.register(api as any);

    mod.__testing.resetStateForTests();
    mod.default.register({ ...api, registrationMode: "setup-only" } as any);

    expect(api.registerHook).not.toHaveBeenCalled();
    expect(api.on).not.toHaveBeenCalled();
  });

  it("warns when runtime events are unavailable and stays inactive", async () => {
    const mod = await loadModule();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "setInterval").mockImplementation(
      (() => ({ unref: vi.fn() } as unknown as ReturnType<typeof setInterval>)) as typeof setInterval,
    );

    mod.default.register({
      pluginConfig: { apiKey: "plugin-key", agentId: "plugin-agent", backendUrl: "http://localhost:8000" },
      logger: { debug: vi.fn() },
      runtime: {},
    } as any);

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("runtime.events not available"));
    expect(logSpy).not.toHaveBeenCalledWith("[clawguard] Monitoring active");
  });

  it("stays inactive until the config entry is explicitly enabled", async () => {
    const mod = await loadModule();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "setInterval").mockImplementation(
      (() => ({ unref: vi.fn() } as unknown as ReturnType<typeof setInterval>)) as typeof setInterval,
    );

    mod.default.register({
      pluginConfig: { apiKey: "plugin-key", agentId: "plugin-agent", backendUrl: "http://localhost:8000" },
      config: {
        plugins: {
          entries: {
            "clawguard-monitor": {},
          },
        },
      },
      runtime: {
        events: {
          onSessionTranscriptUpdate: vi.fn(),
          onAgentEvent: vi.fn(),
        },
      },
    } as any);

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("not explicitly enabled"));
    expect(logSpy).not.toHaveBeenCalledWith("[clawguard] Monitoring active");
  });

  it("accepts the explicit enabled flag from the full config snapshot", async () => {
    const debug = vi.fn();

    await registerWithRuntime({
      config: {
        plugins: {
          entries: {
            "clawguard-monitor": {
              enabled: true,
            },
          },
        },
      },
      logger: { debug },
    });

    expect(debug).toHaveBeenCalledWith(
      expect.stringContaining("backend: http://localhost:8000, agent: plugin-agent"),
    );
  });

  it("logs debug details when monitoring starts successfully", async () => {
    const debug = vi.fn();

    await registerWithRuntime({
      logger: { debug },
    });

    expect(debug).toHaveBeenCalledWith(
      expect.stringContaining("backend: http://localhost:8000, agent: plugin-agent"),
    );
  });

  it("registers compatibility hooks and emits events when those hooks fire", async () => {
    const { api } = await registerWithRuntime();
    const onMock = api.on as { mock: { calls: Array<[string, Function]> } };
    const hookHandlers = Object.fromEntries(
      onMock.mock.calls.map(([name, handler]) => [name, handler]),
    ) as Record<string, Function>;

    expect(hookHandlers.before_tool_call).toBeTypeOf("function");
    expect(hookHandlers.after_tool_call).toBeTypeOf("function");
    expect(hookHandlers.message_sent).toBeTypeOf("function");
    expect(hookHandlers.session_end).toBeTypeOf("function");

    hookHandlers.before_tool_call({
      sessionKey: "hook-session",
      tool: "exec",
      args: { command: "Remove-Item temp.txt" },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    hookHandlers.after_tool_call({
      sessionKey: "hook-session",
      tool: "exec",
      result: "ok",
    });
    hookHandlers.message_sent({
      sessionKey: "hook-session",
      message: "sk-abc123def456ghi789jkl012mno",
      channel: "agent",
    });
    hookHandlers.session_end({ sessionKey: "hook-session" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(mockFetch.mock.calls.some(([url]) => typeof url === "string" && url.endsWith("/v1/sessions/start"))).toBe(true);
    expect(mockFetch.mock.calls.some(([url]) => typeof url === "string" && url.endsWith("/v1/sessions/end"))).toBe(true);

    const eventBodies = mockFetch.mock.calls
      .filter(([url]) => typeof url === "string" && url.endsWith("/v1/events"))
      .map(([, init]) => JSON.parse((init as RequestInit).body as string));

    expect(eventBodies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event_type: "tool_call",
        }),
        expect.objectContaining({
          event_type: "action",
          risk_flags: expect.arrayContaining(["sensitive_in_response"]),
        }),
      ]),
    );
  });

  it("deduplicates identical tool calls that arrive through both runtime events and compatibility hooks", async () => {
    const { api, transcriptCallback } = await registerWithRuntime();
    const onMock = api.on as { mock: { calls: Array<[string, Function]> } };
    const hookHandlers = Object.fromEntries(
      onMock.mock.calls.map(([name, handler]) => [name, handler]),
    ) as Record<string, Function>;

    transcriptCallback?.({
      sessionKey: "dup-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "exec",
            arguments: { command: "Remove-Item temp.txt" },
          },
        ],
      },
    });
    hookHandlers.before_tool_call({
      sessionKey: "dup-session",
      tool: "exec",
      args: { command: "Remove-Item temp.txt" },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const toolCalls = mockFetch.mock.calls
      .filter(([url]) => typeof url === "string" && url.endsWith("/v1/events"))
      .map(([, init]) => JSON.parse((init as RequestInit).body as string))
      .filter((body) => body.event_type === "tool_call");

    expect(toolCalls).toHaveLength(1);
  });

  it("disables monitoring and stops the client if startup fails after the client was created", async () => {
    const mod = await loadModule();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const clientModule = await import("../../openclaw-plugin/src/client.js");
    const stopSpy = vi.spyOn(clientModule.ClawGuardClient.prototype, "stop").mockRejectedValueOnce(
      new Error("stop failed"),
    );
    vi.spyOn(globalThis, "setInterval").mockImplementation(
      (() => ({ unref: vi.fn() } as unknown as ReturnType<typeof setInterval>)) as typeof setInterval,
    );
    vi.spyOn(process, "on").mockImplementation((() => {
      throw new Error("signal registration failed");
    }) as typeof process.on);

    expect(() => mod.default.register({
      pluginConfig: { apiKey: "plugin-key", agentId: "plugin-agent", backendUrl: "http://localhost:8000" },
      runtime: {
        events: {
          onSessionTranscriptUpdate: vi.fn(),
          onAgentEvent: vi.fn(),
        },
      },
    } as any)).not.toThrow();

    await Promise.resolve();

    expect(stopSpy).toHaveBeenCalledOnce();
    expect(warnSpy).toHaveBeenCalledWith(
      "[clawguard] startup error (monitoring disabled, agent unaffected):",
      "signal registration failed",
    );
  });

  it("tolerates missing transcript and agent event hooks", async () => {
    const mod = await loadModule();

    vi.spyOn(globalThis, "setInterval").mockImplementation(
      (() => ({ unref: vi.fn() } as unknown as ReturnType<typeof setInterval>)) as typeof setInterval,
    );

    mod.default.register({
      pluginConfig: { apiKey: "plugin-key", agentId: "plugin-agent", backendUrl: "http://localhost:8000" },
      runtime: { events: {} },
    } as any);

    expect(true).toBe(true);
  });

  it("handles malformed transcript updates, parsing fallbacks, tool results, message errors, and reasoning capture", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const flushSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockFetch.mockImplementation((url: string, init?: RequestInit) => {
      const body = init?.body ? JSON.parse(init.body as string) : {};
      if (url.endsWith("/v1/sessions/start")) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ session_id: "generated-session" }),
        });
      }
      if (url.endsWith("/v1/events") && body.event_type === "action") {
        return Promise.reject(new Error("message failure"));
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ status: "ok" }),
        text: () => Promise.resolve(""),
      });
    });

    const { transcriptCallback, signalHandler } = await registerWithRuntime({
      pluginConfig: {
        apiKey: "plugin-key",
        agentId: "plugin-agent",
        backendUrl: "http://localhost:8000",
        captureFullIo: true,
        maxFullIoBytes: 50,
        batchSize: 10,
      },
    });

    expect(transcriptCallback).toBeDefined();
    transcriptCallback?.({ sessionKey: "missing-message" });
    transcriptCallback?.({ sessionKey: "bad-content", message: { role: "assistant", content: "not-an-array" } });
    transcriptCallback?.({
      sessionKey: "tool-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "exec",
            arguments: "{bad json",
          },
        ],
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    transcriptCallback?.({
      sessionKey: "tool-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolResult",
            name: "exec",
            output: "plain output",
          },
        ],
      },
    });
    transcriptCallback?.({
      sessionKey: "tool-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "thinking",
            text: "internal reasoning",
          },
        ],
      },
    });

    transcriptCallback?.({
      sessionKey: "tool-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "text",
            text: "Send this secret sk-abc123def456ghi789jkl012mno",
          },
        ],
      },
    });
    signalHandler?.();
    await new Promise((resolve) => setTimeout(resolve, 0));

    const batchCalls = mockFetch.mock.calls
      .filter(([url]) => typeof url === "string" && url.endsWith("/v1/events/batch"))
      .map(([, init]) => JSON.parse((init as RequestInit).body as string));

    expect(batchCalls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          events: expect.arrayContaining([
            expect.objectContaining({
              event_type: "tool_call",
              data: expect.objectContaining({
                input_summary: expect.stringContaining("{bad json"),
              }),
            }),
            expect.objectContaining({
              event_type: "decision",
              data: expect.objectContaining({
                full_reasoning: "internal reasoning",
              }),
            }),
          ]),
        }),
      ]),
    );
    expect(warnSpy).toHaveBeenCalledWith(
      "[clawguard] message error (agent unaffected):",
      "message failure",
    );
    expect(flushSpy).toHaveBeenCalledWith("[clawguard] Monitoring active");
  });

  it("covers transcript callback fallback fields and empty branches", async () => {
    const { transcriptCallback, signalHandler } = await registerWithRuntime({
      pluginConfig: {
        apiKey: "plugin-key",
        agentId: "plugin-agent",
        backendUrl: "http://localhost:8000",
        captureFullIo: true,
        maxFullIoBytes: 50,
        batchSize: 10,
      },
    });

    transcriptCallback?.({
      message: {
        content: [
          {},
          {
            type: "toolCall",
            tool: "browser_search",
          },
        ],
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    transcriptCallback?.({
      sessionKey: "main",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            arguments: "42",
          },
          {
            type: "toolCall",
            arguments: "",
          },
          {
            type: "toolResult",
            result: "tool-result-value",
          },
          {
            type: "toolResult",
          },
          {
            type: "text",
          },
          {
            type: "thinking",
            thinking: "alternate thinking path",
          },
          {
            type: "thinking",
          },
        ],
      },
    });
    transcriptCallback?.({
      sessionKey: "missing-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolResult",
            tool: "browser_search",
            output: "ignored result",
          },
          {
            type: "thinking",
            text: "orphaned reasoning",
          },
        ],
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    signalHandler?.();
    await new Promise((resolve) => setTimeout(resolve, 0));

    const eventCalls = mockFetch.mock.calls
      .filter(([url]) => typeof url === "string" && url.endsWith("/v1/events"))
      .map(([, init]) => JSON.parse((init as RequestInit).body as string));
    const batchCalls = mockFetch.mock.calls
      .filter(([url]) => typeof url === "string" && url.endsWith("/v1/events/batch"))
      .map(([, init]) => JSON.parse((init as RequestInit).body as string));

    expect(eventCalls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event_type: "session_start",
        }),
      ]),
    );
    expect(batchCalls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          events: expect.arrayContaining([
            expect.objectContaining({
              event_type: "tool_call",
              data: expect.objectContaining({
                tool_name: "browser_search",
              }),
            }),
            expect.objectContaining({
              event_type: "tool_call",
              data: expect.objectContaining({
                tool_name: "unknown",
                input_summary: expect.stringContaining("\"42\""),
              }),
            }),
            expect.objectContaining({
              event_type: "decision",
              data: expect.objectContaining({
                reasoning: "alternate thinking path",
              }),
            }),
          ]),
        }),
      ]),
    );
  });

  it("logs monitoring warnings when transcript and agent event handlers fail", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockFetch.mockRejectedValue(new Error("tool call failure"));

    const { transcriptCallback, agentEventCallback } = await registerWithRuntime();

    transcriptCallback?.({
      sessionKey: "fail-session",
      message: {
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "browser_search",
            arguments: {},
          },
        ],
      },
    });
    agentEventCallback?.({
      sessionKey: "fail-agent-event",
      data: {
        type: "tool_start",
        tool: "browser_search",
        args: {},
      },
      stream: "start",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(mockFetch).toHaveBeenCalled();
    expect(warnSpy).toHaveBeenCalledWith(
      "[clawguard] monitoring error (agent unaffected):",
      "tool call failure",
    );
    expect(warnSpy).toHaveBeenCalledWith(
      "[clawguard] agent event error (agent unaffected):",
      "tool call failure",
    );
  });

  it("handles agent event start/result flows, ignores non-tool events, and flushes on SIGTERM", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const { agentEventCallback, signalHandler } = await registerWithRuntime();

    agentEventCallback?.({
      sessionKey: "no-data",
      stream: "start",
    });
    agentEventCallback?.({
      sessionKey: "ignore-me",
      stream: "message",
      data: { type: "content", content: "hello" },
    });
    agentEventCallback?.({
      sessionKey: "agent-event-session",
      stream: "start",
      data: {
        type: "tool_start",
        tool: "browser_search",
        args: { query: "pricing" },
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    agentEventCallback?.({
      sessionKey: "agent-event-session",
      stream: "result",
      data: {
        type: "tool_result",
        tool: "browser_search",
        output: "result body",
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(signalHandler).toBeDefined();
    signalHandler?.();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining("agent event error"));
    expect(mockFetch.mock.calls.some(([url]) => typeof url === "string" && url.endsWith("/v1/events/batch"))).toBe(true);
  });

  it("covers agent event fallback fields and swallows flush errors on shutdown", async () => {
    mockFetch.mockImplementation((url: string) => {
      if (url.endsWith("/v1/events/batch")) {
        return Promise.reject(new Error("flush failed"));
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ status: "ok", session_id: "generated-session" }),
        text: () => Promise.resolve(""),
      });
    });

    const { agentEventCallback, signalHandler } = await registerWithRuntime();

    agentEventCallback?.({
      data: {
        kind: "tool_start",
        toolName: "browser_search",
        input: { query: "pricing" },
      },
      stream: "tool-stream",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    agentEventCallback?.({
      sessionKey: "main",
      data: {
        name: "browser_search",
        content: "finished via stream fallback",
      },
      stream: "result",
    });
    agentEventCallback?.({
      sessionKey: "main",
      data: {
        event: "done",
        name: "browser_search",
        content: "finished result",
      },
      stream: "end",
    });
    agentEventCallback?.({
      sessionKey: "main",
      data: {
        tool: "browser_search",
      },
    });
    agentEventCallback?.({
      sessionKey: "main",
      data: {
        kind: "tool_result",
      },
      stream: "result",
    });
    signalHandler?.();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(mockFetch).toHaveBeenCalled();
  });
});
