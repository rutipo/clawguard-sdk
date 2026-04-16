import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const pluginRoot = resolve(import.meta.dirname, "../../openclaw-plugin");
const packageJson = JSON.parse(readFileSync(resolve(pluginRoot, "package.json"), "utf8"));
const manifest = JSON.parse(readFileSync(resolve(pluginRoot, "openclaw.plugin.json"), "utf8"));

describe("package metadata", () => {
  it("ships the OpenClaw manifest and has no install-time scripts", () => {
    expect(packageJson.files).toContain("openclaw.plugin.json");
    expect(packageJson.scripts).not.toHaveProperty("preinstall");
    expect(packageJson.scripts).not.toHaveProperty("install");
    expect(packageJson.scripts).not.toHaveProperty("postinstall");
    expect(packageJson.scripts).not.toHaveProperty("prepare");
  });

  it("uses a stable plugin id and a non-blocking optional config schema", () => {
    expect(manifest.id).toBe("clawguard-monitor");
    expect(manifest.configSchema).toMatchObject({
      type: "object",
      additionalProperties: true,
    });
    expect(manifest.configSchema.required ?? []).toEqual([]);

    expect(Object.keys(manifest.configSchema.properties).sort()).toEqual([
      "agentId",
      "apiKey",
      "backendUrl",
      "batchSize",
      "blockSensitiveAccess",
      "captureFullIo",
      "flushIntervalMs",
      "maxFullIoBytes",
      "requireApprovalForHighRisk",
    ]);

    for (const value of Object.values(manifest.configSchema.properties) as Array<Record<string, unknown>>) {
      expect(value).toHaveProperty("description");
      expect(value).not.toHaveProperty("default");
      expect(value).not.toHaveProperty("type");
      expect(value).not.toHaveProperty("minLength");
      expect(value).not.toHaveProperty("minimum");
      expect(value).not.toHaveProperty("pattern");
      expect(value).not.toHaveProperty("format");
      expect(value).not.toHaveProperty("enum");
    }
  });
});
