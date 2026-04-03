/**
 * Sensitive content detection - mirrors clawguard/monitor/sensitive.py
 *
 * Detects credentials, API keys, PII, and other sensitive patterns
 * in tool inputs and outputs.
 */

interface SensitivePattern {
  name: string;
  pattern: RegExp;
}

const SENSITIVE_PATTERNS: SensitivePattern[] = [
  // AWS keys
  { name: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "aws_secret_key", pattern: /(?:aws_secret|secret_access_key)\s*[=:]\s*\S{20,}/ },

  // OpenAI / Anthropic / generic sk- keys
  { name: "api_key_sk", pattern: /sk-[a-zA-Z0-9]{20,}/ },

  // GitHub tokens
  { name: "github_token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/ },

  // Generic Bearer tokens
  { name: "bearer_token", pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/ },

  // Private keys
  { name: "private_key", pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/ },

  // Database connection strings
  { name: "database_url", pattern: /(?:postgres|mysql|mongodb|redis|mssql|oracle):\/\/[^\s]+/ },

  // Slack tokens
  { name: "slack_token", pattern: /xox[bpras]-[A-Za-z0-9-]{10,}/ },

  // GCP API keys
  { name: "gcp_api_key", pattern: /AIza[0-9A-Za-z\-_]{35}/ },

  // GCP service account key files
  { name: "gcp_service_account", pattern: /"type"\s*:\s*"service_account"/ },

  // Generic secret/password in config
  { name: "secret_in_config", pattern: /(?:SECRET|PASSWORD|TOKEN|API_KEY)[_A-Z]*\s*[=:]\s*\S{8,}/ },

  // Email addresses (PII)
  { name: "email_address", pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },

  // Phone numbers (PII)
  { name: "phone_number", pattern: /(?:\+\d{1,3}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/ },

  // Credit card numbers
  { name: "credit_card", pattern: /\b(?:\d{4}[\s-]?){3}\d{4}\b/ },

  // SSN
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
];

/** Sensitive file path patterns */
const SENSITIVE_PATHS = [
  /\.env$/,
  /\.env\.\w+$/,
  /credentials/i,
  /secrets?\./i,
  /\.pem$/,
  /\.key$/,
  /id_rsa/,
  /\.ssh\//,
  /\.aws\//,
  /\.gnupg\//,
  /\/etc\/shadow/,
  /\/etc\/passwd/,
  /\.netrc/,
  /\.npmrc/,
  /\.pypirc/,
];

/**
 * Detect sensitive content patterns in text.
 * Returns list of matched pattern names, or empty array if clean.
 */
export function detectSensitiveContent(text: string): string[] {
  if (!text) return [];

  const matches: string[] = [];
  for (const { name, pattern } of SENSITIVE_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(name);
    }
  }
  return matches;
}

/**
 * Check if a file path is sensitive.
 */
export function isSensitivePath(path: string): boolean {
  if (!path) return false;
  return SENSITIVE_PATHS.some((pattern) => pattern.test(path));
}

/**
 * High-risk tool names that warrant extra scrutiny.
 */
const HIGH_RISK_TOOLS = new Set([
  "http_post",
  "http_put",
  "http_request",
  "fetch",
  "curl",
  "shell_exec",
  "bash",
  "exec",
  "run_command",
  "send_email",
  "send_message",
  "upload_file",
]);

/**
 * Check if a tool name is considered high-risk (outbound/execution).
 */
export function isHighRiskTool(toolName: string): boolean {
  return HIGH_RISK_TOOLS.has(toolName.toLowerCase());
}
