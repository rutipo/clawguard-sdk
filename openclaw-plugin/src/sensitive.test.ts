import { describe, expect, it } from "vitest";
import {
  detectSensitiveContent,
  isHighRiskTool,
  isSensitivePath,
} from "./sensitive.js";

describe("detectSensitiveContent", () => {
  it("detects AWS access keys", () => {
    const result = detectSensitiveContent("AKIAIOSFODNN7EXAMPLE");
    expect(result).toContain("aws_access_key");
  });

  it("detects sk- API keys", () => {
    const result = detectSensitiveContent("sk-abc123def456ghi789jkl012mno");
    expect(result).toContain("api_key_sk");
  });

  it("detects GitHub tokens", () => {
    const result = detectSensitiveContent(
      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
    );
    expect(result).toContain("github_token");
  });

  it("detects Bearer tokens", () => {
    const result = detectSensitiveContent("Authorization: Bearer eyJhbGciOi...");
    expect(result).toContain("bearer_token");
  });

  it("detects private keys", () => {
    const result = detectSensitiveContent("-----BEGIN PRIVATE KEY-----");
    expect(result).toContain("private_key");
  });

  it("detects RSA private keys", () => {
    const result = detectSensitiveContent("-----BEGIN RSA PRIVATE KEY-----");
    expect(result).toContain("private_key");
  });

  it("detects database URLs", () => {
    const result = detectSensitiveContent(
      "postgres://user:pass@host:5432/db",
    );
    expect(result).toContain("database_url");
  });

  it("detects SECRET_KEY in config", () => {
    const result = detectSensitiveContent("SECRET_KEY=mysecretvalue123");
    expect(result).toContain("secret_in_config");
  });

  it("detects email addresses", () => {
    const result = detectSensitiveContent("user@example.com");
    expect(result).toContain("email_address");
  });

  it("detects phone numbers", () => {
    const result = detectSensitiveContent("Call me at (555) 123-4567");
    expect(result).toContain("phone_number");
  });

  it("returns empty for clean text", () => {
    const result = detectSensitiveContent(
      "This is just a normal search result about pricing.",
    );
    expect(result).toEqual([]);
  });

  it("returns empty for empty/null input", () => {
    expect(detectSensitiveContent("")).toEqual([]);
    expect(detectSensitiveContent(null as unknown as string)).toEqual([]);
  });

  it("detects multiple patterns in one string", () => {
    const result = detectSensitiveContent(
      "DATABASE_URL=postgres://user:pass@host/db\nAPI_KEY=sk-abc123def456ghi789jkl012mno",
    );
    expect(result.length).toBeGreaterThanOrEqual(2);
    expect(result).toContain("database_url");
    expect(result).toContain("api_key_sk");
  });
});

describe("isSensitivePath", () => {
  it("detects .env files", () => {
    expect(isSensitivePath("/app/.env")).toBe(true);
    expect(isSensitivePath("/app/.env.production")).toBe(true);
  });

  it("detects credentials files", () => {
    expect(isSensitivePath("/home/user/.aws/credentials")).toBe(true);
  });

  it("detects SSH keys", () => {
    expect(isSensitivePath("/home/user/.ssh/id_rsa")).toBe(true);
  });

  it("detects PEM files", () => {
    expect(isSensitivePath("/certs/server.pem")).toBe(true);
  });

  it("detects key files", () => {
    expect(isSensitivePath("/certs/private.key")).toBe(true);
  });

  it("returns false for normal files", () => {
    expect(isSensitivePath("/data/report.csv")).toBe(false);
    expect(isSensitivePath("/app/src/index.ts")).toBe(false);
  });

  it("returns false for empty input", () => {
    expect(isSensitivePath("")).toBe(false);
  });
});

describe("isHighRiskTool", () => {
  it("flags outbound HTTP tools", () => {
    expect(isHighRiskTool("http_post")).toBe(true);
    expect(isHighRiskTool("http_put")).toBe(true);
    expect(isHighRiskTool("fetch")).toBe(true);
    expect(isHighRiskTool("curl")).toBe(true);
  });

  it("flags execution tools", () => {
    expect(isHighRiskTool("shell_exec")).toBe(true);
    expect(isHighRiskTool("bash")).toBe(true);
    expect(isHighRiskTool("exec")).toBe(true);
  });

  it("flags communication tools", () => {
    expect(isHighRiskTool("send_email")).toBe(true);
    expect(isHighRiskTool("send_message")).toBe(true);
  });

  it("returns false for safe tools", () => {
    expect(isHighRiskTool("browser_search")).toBe(false);
    expect(isHighRiskTool("read_file")).toBe(false);
    expect(isHighRiskTool("write_file")).toBe(false);
  });
});
