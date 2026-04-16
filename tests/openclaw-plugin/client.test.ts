import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ClawGuardClient } from "../../openclaw-plugin/src/client.js";
import type { ClawGuardPluginConfig, EventPayload } from "../../openclaw-plugin/src/types.js";
import { DEFAULT_CONFIG } from "../../openclaw-plugin/src/types.js";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeConfig(overrides: Partial<ClawGuardPluginConfig> = {}): ClawGuardPluginConfig {
  return {
    ...DEFAULT_CONFIG,
    backendUrl: "http://localhost:8000",
    apiKey: "test-key",
    agentId: "test-agent",
    batchSize: 3,
    flushIntervalMs: 100,
    ...overrides,
  };
}

function makeEvent(overrides: Partial<EventPayload> = {}): EventPayload {
  return {
    event_id: "evt-1",
    session_id: "sess-1",
    agent_id: "test-agent",
    event_type: "tool_call",
    timestamp: new Date().toISOString(),
    data: { tool_name: "search" },
    risk_flags: [],
    ...overrides,
  };
}

describe("ClawGuardClient", () => {
  let client: ClawGuardClient;

  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ status: "ok" }),
      text: () => Promise.resolve(""),
    });
    client = new ClawGuardClient(makeConfig());
  });

  afterEach(async () => {
    await client.stop();
  });

  describe("startSession", () => {
    it("calls /v1/sessions/start with correct payload", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ session_id: "new-sess-123" }),
      });

      const sessionId = await client.startSession("my-agent", "research task");

      expect(sessionId).toBe("new-sess-123");
      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:8000/v1/sessions/start",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "X-API-Key": "test-key",
          }),
          body: JSON.stringify({ agent_id: "my-agent", task: "research task" }),
        }),
      );
    });
  });

  describe("validation and timers", () => {
    it("throws for invalid backend URLs", () => {
      expect(() => new ClawGuardClient(makeConfig({ backendUrl: "not a url" }))).toThrow(
        /invalid backend url/i,
      );
    });

    it("normalizes trailing slashes in backend URLs before making requests", async () => {
      client = new ClawGuardClient(makeConfig({ backendUrl: "http://localhost:8000///" }));

      await client.sendEventImmediate(makeEvent());

      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:8000/v1/events",
        expect.anything(),
      );
    });

    it("warns for public HTTP backend URLs", () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      new ClawGuardClient(makeConfig({ backendUrl: "http://example.com" }));

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("API key will be sent in cleartext"),
      );
      warnSpy.mockRestore();
    });

    it("starts only one interval and reports interval flush failures", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const timer = { unref: vi.fn() };
      let intervalCallback: (() => void) | undefined;
      const setIntervalSpy = vi
        .spyOn(globalThis, "setInterval")
        .mockImplementation(((cb: TimerHandler) => {
          intervalCallback = cb as () => void;
          return timer as unknown as ReturnType<typeof setInterval>;
        }) as typeof setInterval);
      const clearIntervalSpy = vi
        .spyOn(globalThis, "clearInterval")
        .mockImplementation(() => undefined);

      client = new ClawGuardClient(makeConfig());
      const flushSpy = vi
        .spyOn(client, "flush")
        .mockRejectedValueOnce(new Error("interval boom"))
        .mockResolvedValue(undefined);

      client.start();
      client.start();
      intervalCallback?.();
      await Promise.resolve();
      await client.stop();

      expect(setIntervalSpy).toHaveBeenCalledTimes(1);
      expect(timer.unref).toHaveBeenCalledOnce();
      expect(clearIntervalSpy).toHaveBeenCalledWith(timer);
      expect(flushSpy).toHaveBeenCalledTimes(2);
      expect(warnSpy).toHaveBeenCalledWith(
        "[clawguard] flush error (agent unaffected):",
        "interval boom",
      );
    });
  });

  describe("endSession", () => {
    it("calls /v1/sessions/end", async () => {
      await client.endSession("sess-1", "completed");

      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:8000/v1/sessions/end",
        expect.objectContaining({
          body: JSON.stringify({ session_id: "sess-1", status: "completed" }),
        }),
      );
    });
  });

  describe("sendEventImmediate", () => {
    it("sends directly to /v1/events", async () => {
      const event = makeEvent();
      await client.sendEventImmediate(event);

      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:8000/v1/events",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(event),
        }),
      );
    });
  });

  describe("queueEvent + flush", () => {
    it("drops the oldest buffered event when the max buffer size is exceeded", () => {
      const overflowClient = new ClawGuardClient(makeConfig({ batchSize: 20_000 }));

      for (let i = 0; i < 10_001; i++) {
        overflowClient.queueEvent(makeEvent({ event_id: `evt-${i}` }));
      }

      expect((overflowClient as any).eventBuffer).toHaveLength(10_000);
      expect((overflowClient as any).eventBuffer[0].event_id).toBe("evt-1");
    });

    it("buffers events until flush", async () => {
      client.queueEvent(makeEvent({ event_id: "e1" }));
      client.queueEvent(makeEvent({ event_id: "e2" }));

      // Not sent yet (batch size is 3)
      expect(mockFetch).not.toHaveBeenCalled();

      await client.flush();

      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:8000/v1/events/batch",
        expect.objectContaining({
          method: "POST",
        }),
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.events).toHaveLength(2);
    });

    it("auto-flushes when batch size reached", async () => {
      client.queueEvent(makeEvent({ event_id: "e1" }));
      client.queueEvent(makeEvent({ event_id: "e2" }));
      client.queueEvent(makeEvent({ event_id: "e3" }));

      // Wait for the async flush to complete
      await new Promise((r) => setTimeout(r, 50));

      expect(mockFetch).toHaveBeenCalled();
    });

    it("warns when auto-flush fails after the batch size is reached", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const autoClient = new ClawGuardClient(makeConfig({ batchSize: 1 }));
      vi.spyOn(autoClient, "flush").mockRejectedValueOnce(new Error("auto flush failed"));

      autoClient.queueEvent(makeEvent({ event_id: "e1" }));
      await Promise.resolve();

      expect(warnSpy).toHaveBeenCalledWith(
        "[clawguard] flush error (agent unaffected):",
        "auto flush failed",
      );
      warnSpy.mockRestore();
    });

    it("flush is a no-op when buffer is empty", async () => {
      await client.flush();
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe("error handling", () => {
    it("throws on non-OK response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        text: () => Promise.resolve("Invalid API key"),
      });

      await expect(
        client.sendEventImmediate(makeEvent()),
      ).rejects.toThrow(
        "ClawGuard API authentication failed on /v1/events: 401 Unauthorized. Verify the API key configured on this machine",
      );
    });

    it("retries timeout once for de-duplicated event endpoints", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      mockFetch.mockRejectedValueOnce(new DOMException("timed out", "TimeoutError"));

      await client.sendEventImmediate(makeEvent());

      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("retrying once"),
      );
      warnSpy.mockRestore();
    });

    it("does not retry timeout for session creation", async () => {
      mockFetch.mockRejectedValueOnce(new DOMException("timed out", "TimeoutError"));

      await expect(
        client.startSession("my-agent", "research task"),
      ).rejects.toThrow("timed out");

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("re-queues events on flush failure", async () => {
      client.queueEvent(makeEvent({ event_id: "e1" }));
      client.queueEvent(makeEvent({ event_id: "e2" }));

      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      await expect(client.flush()).rejects.toThrow("Network error");

      // Events should be back in the buffer
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: "ok" }),
      });

      await client.flush();
      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.events).toHaveLength(2);
    });

    it("drops failed flush events when no buffer space remains", async () => {
      const failedEvents = [
        makeEvent({ event_id: "failed-1" }),
        makeEvent({ event_id: "failed-2" }),
      ];
      const fakeClient: any = {
        eventBuffer: failedEvents,
        post: vi.fn().mockImplementation(async () => {
          fakeClient.eventBuffer = Array.from({ length: 10_000 }, (_, i) =>
            makeEvent({ event_id: `existing-${i}` }),
          );
          throw new Error("Network error");
        }),
      };

      await expect((ClawGuardClient.prototype as any).flush.call(fakeClient)).rejects.toThrow(
        "Network error",
      );
      expect(fakeClient.eventBuffer).toHaveLength(10_000);
      expect(fakeClient.eventBuffer.some((event: EventPayload) => event.event_id === "failed-1")).toBe(false);
    });
  });
});
