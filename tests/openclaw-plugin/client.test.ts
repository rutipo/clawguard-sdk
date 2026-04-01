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
      ).rejects.toThrow("ClawGuard API error: 401");
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
  });
});
