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

export interface ToolRiskAssessment {
  toolCategory: string;
  operationKind: string;
  isHighRisk: boolean;
  canEgressData: boolean;
  severity?: "medium" | "high";
  title?: string;
  deliveryScope?: "first_party" | "external";
  channelType?: string;
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

  // GCP service account key files with actual key fields
  { name: "gcp_service_account", pattern: /"type"\s*:\s*"service_account"[\s\S]{0,400}"private_key(?:_id)?"\s*:/ },

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
  /\.ssh[\\/]/,
  /\.aws[\\/]/,
  /\.gnupg[\\/]/,
  /\/etc\/shadow/,
  /\/etc\/passwd/,
  /\.netrc/,
  /\.npmrc/,
  /\.pypirc/,
];

const NON_SENSITIVE_PATHS = [
  /\.env\.(example|sample|template|test)\b/,
  /(^|[\\/])example\.env\b/,
  /(^|[\\/])sample\.env\b/,
  /(^|[\\/])template\.env\b/,
  /(^|[\\/])(__fixtures__|fixtures?|testdata|samples?|examples?)([\\/]|$)/,
  /(^|[\\/])docs?([\\/]|$)/,
  /(^|[\\/])README(?:\.[^.\\/]+)?$/i,
  /(^|[\\/])CHANGELOG(?:\.[^.\\/]+)?$/i,
  /(^|[\\/])LICENSE(?:\.[^.\\/]+)?$/i,
];

const MEMORY_PATH_PATTERNS = [
  /(^|[\\/])(?:claude|agents|memory)\.md$/i,
  /(^|[\\/])\.(?:claude|codex|openclaw|clawguard|cursor|windsurf|roo)([\\/]|$)/,
];

const LOCAL_CONFIG_PATH_PATTERNS = [
  /(^|[\\/])package(?:-lock)?\.json$/i,
  /(^|[\\/])pnpm-lock\.ya?ml$/i,
  /(^|[\\/])yarn\.lock$/i,
  /(^|[\\/])\.vscode([\\/]|$)/i,
  /(^|[\\/])\.devcontainer([\\/]|$)/i,
  /(^|[\\/])pyproject\.toml$/i,
  /(^|[\\/])poetry\.lock$/i,
  /(^|[\\/])requirements(?:\.[^.\\/]+)?\.txt$/i,
  /(^|[\\/])cargo\.(?:toml|lock)$/i,
  /(^|[\\/])go\.(?:mod|sum)$/i,
  /(^|[\\/])composer\.(?:json|lock)$/i,
  /(^|[\\/])tsconfig(?:\.[^.\\/]+)?\.json$/i,
  /(^|[\\/])\.eslintrc(?:\.[^.\\/]+)?$/i,
  /(^|[\\/])eslint\.config\.[^.\\/]+$/i,
  /(^|[\\/])\.prettierrc(?:\.[^.\\/]+)?$/i,
  /(^|[\\/])prettier\.config\.[^.\\/]+$/i,
  /(^|[\\/])vitest\.config\.[^.\\/]+$/i,
  /(^|[\\/])jest\.config\.[^.\\/]+$/i,
  /(^|[\\/])ruff\.toml$/i,
  /(^|[\\/])mypy\.ini$/i,
  /(^|[\\/])pytest\.ini$/i,
  /(^|[\\/])\.editorconfig$/i,
  /(^|[\\/])\.gitignore$/i,
];

const EXECUTION_SURFACE_PATH_PATTERNS = [
  /(^|[\\/])\.github[\\/]workflows[\\/]/,
  /(^|[\\/])\.git[\\/]hooks[\\/]/,
  /(^|[\\/])dockerfile(?:\.[^.\\/]+)?$/i,
  /(^|[\\/])(?:docker-)?compose\.(?:ya?ml)$/i,
  /(^|[\\/])procfile$/i,
  /(^|[\\/])railway\.json$/i,
  /(^|[\\/])netlify\.toml$/i,
  /(^|[\\/])vercel\.json$/i,
];

const SYSTEM_PERSISTENCE_PATH_PATTERNS = [
  /^\$profile$/i,
  /(^|[\\/])\.bash(?:rc|_profile)$/i,
  /(^|[\\/])\.zshrc$/i,
  /(^|[\\/])\.profile$/i,
  /(^|[\\/])(?:microsoft\.)?powershell_profile\.ps1$/i,
  /(^|[\\/])profile\.ps1$/i,
  /(^|[\\/])crontab$/i,
  /(^|[\\/])etc[\\/]cron\./i,
  /(^|[\\/])etc[\\/]systemd[\\/]/i,
  /(^|[\\/])library[\\/]launchagents[\\/]/i,
  /(^|[\\/])appdata[\\/]roaming[\\/]microsoft[\\/]windows[\\/]start menu[\\/]programs[\\/]startup[\\/]/i,
];

const LOW_IMPACT_SENSITIVE_MATCHES = new Set([
  "email_address",
  "phone_number",
]);

const PLACEHOLDER_VALUE_PATTERNS = [
  /^<[^>]+>$/,
  /^\$\{[^}]+\}$/,
  /^\[[^\]]+\]$/,
  /^(?:your|example|sample|dummy|fake|test|placeholder|changeme|replace(?:[-_ ]with)?|redacted|notasecret)[-_a-z0-9./:]*$/i,
  /^(?:api[_-]?key|token|secret|password|username|user|dbname|database|host|port)(?:[-_ ]?(?:here|value|placeholder|example|sample|test))?$/i,
  /^(?:xxx+|\*+|\.{3,})$/i,
];

/**
 * Detect sensitive content patterns in text.
 * Returns list of matched pattern names, or empty array if clean.
 */
export function detectSensitiveContent(text: string): string[] {
  if (!text) return [];

  const matches: string[] = [];
  for (const { name, pattern } of SENSITIVE_PATTERNS) {
    const match = text.match(pattern);
    if (match?.[0] && !isLikelyPlaceholderMatch(name, match[0])) {
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
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  if (NON_SENSITIVE_PATHS.some((pattern) => pattern.test(normalized))) {
    return false;
  }
  return SENSITIVE_PATHS.some((pattern) => pattern.test(normalized));
}

export function hasHighImpactSensitiveMatch(matches: string[]): boolean {
  return matches.some((match) => !LOW_IMPACT_SENSITIVE_MATCHES.has(match));
}

export function classifyTargetPath(path: string): string {
  if (!path) return "unknown";

  const normalized = path.replace(/\\/g, "/").toLowerCase();
  if (/^https?:\/\//.test(normalized)) {
    return "unknown";
  }

  if (NON_SENSITIVE_PATHS.some((pattern) => pattern.test(normalized))) {
    return "workspace_file";
  }

  if (SENSITIVE_PATHS.some((pattern) => pattern.test(normalized))) {
    return "secret_store";
  }

  if (SYSTEM_PERSISTENCE_PATH_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return "system_persistence";
  }

  if (EXECUTION_SURFACE_PATH_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return "execution_surface";
  }

  if (MEMORY_PATH_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return "memory_file";
  }

  if (LOCAL_CONFIG_PATH_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return "local_config";
  }

  return "workspace_file";
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

const SHELL_LIKE_TOOLS = new Set([
  "shell_exec",
  "bash",
  "exec",
  "run_command",
  "shell",
]);

const HTTP_LIKE_TOOLS = new Set([
  "http_post",
  "http_put",
  "http_request",
  "fetch",
  "curl",
]);

const DATA_EGRESS_TOOLS = new Set([
  "send_email",
  "send_message",
  "upload_file",
]);

const CHAT_CHANNEL_HINTS = [
  "agent",
  "chat",
  "conversation",
  "telegram",
  "discord",
  "whatsapp",
  "slack",
  "dm",
  "direct",
  "private",
  "reply",
  "thread",
];

const EXTERNAL_DESTINATION_HINTS = [
  "webhook",
  "broadcast",
  "announcement",
  "public",
  "publish",
  "forum",
  "feed",
];

const SEARCH_HINTS = [
  "search",
  "lookup",
  "google",
  "bing",
  "duckduckgo",
  "serp",
  "wiki",
];

const SEARCH_URL_PATTERNS = [
  /googleapis\.com\/customsearch/i,
  /google\.[^/]+\/search/i,
  /bing\.com\/search/i,
  /duckduckgo\.com/i,
  /search\.brave\.com/i,
  /serpapi\.com/i,
  /\/(search|customsearch|query|lookup)\b/i,
];

const SEARCH_QUERY_KEYS = new Set([
  "q",
  "query",
  "search",
  "searchquery",
  "searchterm",
  "keywords",
  "term",
  "terms",
  "topic",
]);

const SEARCH_ALLOWED_KEYS = new Set([
  "q",
  "query",
  "search",
  "searchquery",
  "searchterm",
  "keywords",
  "term",
  "terms",
  "topic",
  "site",
  "sitefilter",
  "domain",
  "domains",
  "includedomains",
  "excludedomains",
  "language",
  "lang",
  "locale",
  "region",
  "country",
  "market",
  "gl",
  "hl",
  "lr",
  "safe",
  "safesearch",
  "freshness",
  "timerange",
  "daterange",
  "num",
  "count",
  "limit",
  "offset",
  "page",
  "pagesize",
  "start",
  "cursor",
  "sort",
  "order",
  "filter",
  "filters",
]);

const READ_QUERY_HINTS = [
  "graphql",
  "jql",
  "query",
  "retrieval",
  "vector",
  "search",
  "lookup",
];

const READ_QUERY_URL_PATTERNS = [
  /\/graphql\b/i,
  /\/(?:search|query|lookup|retrieval)\b/i,
  /\/search\/jql\b/i,
  /\/vector\b/i,
];

const READ_QUERY_KEYS = new Set([
  "query",
  "variables",
  "operationname",
  "jql",
  "ql",
  "searchtext",
  "text",
  "q",
  "term",
  "terms",
  "topic",
  "keywords",
  "filter",
  "filters",
]);

const READ_QUERY_ALLOWED_KEYS = new Set([
  ...READ_QUERY_KEYS,
  "limit",
  "count",
  "maxresults",
  "topk",
  "k",
  "cursor",
  "offset",
  "page",
  "pagesize",
  "sort",
  "order",
  "fields",
  "project",
  "repo",
  "owner",
  "gl",
  "hl",
  "num",
  "after",
  "before",
  "first",
  "last",
  "expand",
  "include",
  "exclude",
  "language",
  "lang",
  "locale",
  "region",
  "country",
  "market",
  "safe",
  "safesearch",
  "freshness",
  "timerange",
  "daterange",
]);

const SEARCH_BLOCKED_KEYS = new Set([
  "file",
  "files",
  "upload",
  "attachment",
  "attachments",
  "infile",
  "content",
  "message",
  "prompt",
  "input",
  "document",
  "documents",
]);

const READ_ONLY_COMMAND_PATTERNS = [
  /^(get-childitem|gci|dir)\b/,
  /^(get-item|gi)\b/,
  /^(get-content|gc|type|cat)\b/,
  /^(select-string|sls|findstr|rg|grep)\b/,
  /^(resolve-path|test-path|get-command|get-location|where|which)\b/,
  /^(get-process|ps|get-service)\b/,
  /^(ls|find|pwd|realpath|stat|wc|head|tail)\b/,
  /^tree\b/,
  /^sed\s+-n\b/,
  /^git\s+(status|diff|log|show)\b/,
  /^git\s+grep\b/,
  /^git\s+(ls-files|rev-parse|worktree\s+list)\b/,
  /^git\s+remote(?:\s+-v|\s+show|\s*$)/,
  /^git\s+branch\s+--show-current\b/,
  /^(pytest|vitest|jest|mocha|ava|nose2?|rspec)\b/,
  /^(npm|pnpm|yarn)\s+(test|run test|run lint|run build)\b/,
  /^(cargo|go|dotnet|mvn|gradle)\s+(test|build|check)\b/,
  /^python\s+-m\s+(pytest|compileall)\b/,
  /^(tsc|eslint|ruff|mypy|flake8|black)\b/,
];

const LOCAL_DEV_COMMAND_PATTERNS = [
  /^(npm|pnpm|yarn)\s+(run\s+dev|dev)\b/,
  /^uvicorn\b.*\b--reload\b/,
  /^python\s+-m\s+http\.server\b/,
  /^docker(?:\s+compose)?\s+logs\b/,
];

const GIT_WORKFLOW_COMMAND_PATTERNS = [
  /^git\s+(add|commit|checkout|switch|merge|rebase|stash|restore|branch)\b/,
  /^git\s+(fetch|pull|clone|push)\b/,
];

const PACKAGE_INSTALL_COMMAND_PATTERNS = [
  /^(npm|pnpm|yarn)\s+(install|add|ci)\b/,
  /^(pip|uv)\s+install\b/,
  /^python\s+-m\s+pip\s+install\b/,
  /^poetry\s+(install|add)\b/,
  /^cargo\s+install\b/,
  /^(go\s+get|go\s+install)\b/,
  /^(brew|apt|apt-get|yum|dnf|pacman|winget|choco)\s+install\b/,
];

const FILE_WRITE_COMMAND_PATTERNS = [
  /^(set-content|add-content|out-file|copy-item|move-item|rename-item|new-item|mkdir)\b/,
  /^(cp|mv|touch|mkdir)\b/,
  /^tee(?:-object)?\b/,
  /^echo\b.+\s>{1,2}\s*\S+/,
  /^printf\b.+\s>{1,2}\s*\S+/,
  /^git\s+(apply|am)\b/,
];

const DESTRUCTIVE_COMMAND_PATTERNS = [
  /^(remove-item|del|erase|rmdir|rd)\b/,
  /^rm\b/,
  /^git\s+(reset\s+--hard|clean\s+-[a-z]*f)/,
  /^(shutdown|reboot|restart-computer)\b/,
];

const IMPACTFUL_SYSTEM_COMMAND_PATTERNS = [
  /^(invoke-expression|iex)\b/,
  /^powershell\b.*\s-enc(?:odedcommand)?\b/,
  /^(schtasks|taskkill|sc|netsh|reg)\b/,
  /^(systemctl|service)\b.*\b(start|stop|restart|enable|disable)\b/,
  /^(start-service|stop-service|restart-service|set-acl|chmod|chown|useradd|add-user|passwd)\b/,
];

const DATA_EGRESS_COMMAND_PATTERNS = [
  /^(scp|sftp|rsync)\b/,
  /^(send-mailmessage)\b/,
  /^docker\s+push\b/,
  /^(npm|pnpm|yarn)\s+publish\b/,
  /^twine\s+upload\b/,
  /^aws\s+s3\s+(cp|sync)\b.*\bs3:\/\//,
  /^az\s+storage\s+blob\s+upload\b/,
];

const REMOTE_EXECUTION_COMMAND_PATTERNS = [
  /\bcurl\b.*\|\s*(bash|sh|powershell|pwsh|iex)\b/,
  /\b(irm|invoke-webrequest)\b.*\|\s*(iex|invoke-expression)\b/,
];

function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ").toLowerCase();
}

function looksLikePlaceholderValue(value: string): boolean {
  const normalized = stripWrappingQuotes(value.trim().replace(/[;,]+$/, ""));
  if (!normalized) {
    return true;
  }

  return PLACEHOLDER_VALUE_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isLikelyPlaceholderMatch(name: string, matchedValue: string): boolean {
  const normalized = matchedValue.trim().toLowerCase();

  if (name === "aws_access_key") {
    return normalized.includes("example");
  }

  if (name === "database_url") {
    return /:\/\/[^/\s]*(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|example\.org|example\.net)\b/.test(normalized)
      || /<[^>]+>|\$\{[^}]+\}/.test(matchedValue);
  }

  if (name === "aws_secret_key" || name === "secret_in_config") {
    const [, rawValue = matchedValue] = matchedValue.split(/[=:]/, 2);
    return looksLikePlaceholderValue(rawValue);
  }

  return false;
}

function stripWrappingQuotes(value: string): string {
  if (
    (value.startsWith("\"") && value.endsWith("\""))
    || (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function extractFlagValue(command: string, flagNames: string[]): string {
  const pattern = new RegExp(`-(?:${flagNames.join("|")})\\s+("[^"]+"|'[^']+'|\\S+)`, "i");
  const match = command.match(pattern);
  return match?.[1] ? stripWrappingQuotes(match[1]) : "";
}

function joinPathSegments(basePath: string, childName: string): string {
  if (!basePath) {
    return childName;
  }

  if (!childName) {
    return basePath;
  }

  if (/^[A-Za-z]:[\\/]/.test(childName) || /^[\\/]{1,2}/.test(childName)) {
    return childName;
  }

  const separator = basePath.includes("\\") ? "\\" : "/";
  return basePath.replace(/[\\/]+$/, "") + separator + childName.replace(/^[\\/]+/, "");
}

export function extractCommandText(args?: Record<string, unknown>): string {
  if (!args) return "";

  for (const key of ["command", "cmd", "script", "raw"]) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  return "";
}

export function isReadOnlyShellCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  if (!normalized) return false;
  return READ_ONLY_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isGitWorkflowCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  return GIT_WORKFLOW_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isPackageInstallCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  return PACKAGE_INSTALL_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isLocalDevCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  return LOCAL_DEV_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isFileWriteCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  return FILE_WRITE_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isDestructiveCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  return DESTRUCTIVE_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isImpactfulSystemCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  return IMPACTFUL_SYSTEM_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isRemoteExecutionCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  return REMOTE_EXECUTION_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

function isDataEgressCommand(command: string): boolean {
  const normalized = normalizeCommand(command);
  if (DATA_EGRESS_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return true;
  }

  if (/\bcurl\b/.test(normalized) || /\bwget\b/.test(normalized)) {
    return /(?:-x\s+(post|put|patch|delete)|--request\s+(post|put|patch|delete)|-d\b|--data\b|-f\b|--form\b|--upload-file\b)/.test(normalized);
  }

  if (/\b(invoke-webrequest|invoke-restmethod|iwr|irm)\b/.test(normalized)) {
    return /(?:-method\s+(post|put|patch|delete)|-body\b|-form\b|-infile\b|-\w*contenttype\b)/.test(normalized);
  }

  return false;
}

function extractStringArg(
  args: Record<string, unknown> | undefined,
  keys: string[],
): string | undefined {
  if (!args) return undefined;
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

function extractCommunicationTarget(args?: Record<string, unknown>): string {
  return extractStringArg(args, [
    "target",
    "destination",
    "dest",
    "recipient",
    "to",
    "channel",
    "chat_id",
    "chatId",
    "channel_id",
    "channelId",
    "thread_id",
    "threadId",
    "message_thread_id",
    "messageThreadId",
    "conversation_id",
    "conversationId",
    "room",
    "room_id",
    "roomId",
    "user_id",
    "userId",
    "phone",
    "phone_number",
    "phoneNumber",
    "url",
    "uri",
    "endpoint",
    "href",
    "webhook",
    "webhookUrl",
  ]) ?? "";
}

function inferChannelType(args?: Record<string, unknown>): string {
  const channelHints = [
    extractStringArg(args, ["channel", "platform", "service", "provider", "transport"]),
    extractCommunicationTarget(args),
  ]
    .filter((value): value is string => Boolean(value))
    .map((value) => value.toLowerCase());

  for (const hint of channelHints) {
    if (hint.includes("telegram")) return "telegram";
    if (hint.includes("discord")) return "discord";
    if (hint.includes("whatsapp")) return "whatsapp";
    if (hint.includes("slack")) return "slack";
    if (hint.includes("email")) return "email";
    if (/^\+?\d[\d\s\-().]{6,}$/.test(hint)) return "whatsapp";
  }

  return "chat";
}

function messageHasAttachment(args?: Record<string, unknown>): boolean {
  if (!args) {
    return false;
  }

  for (const key of ["file", "files", "attachment", "attachments", "upload", "document", "documents"]) {
    const value = args[key];
    if (value !== undefined && value !== null && value !== "") {
      return true;
    }
  }

  return false;
}

function looksLikeExternalDestination(args?: Record<string, unknown>): boolean {
  const target = extractCommunicationTarget(args);
  if (!target) {
    return false;
  }

  const normalized = target.toLowerCase();
  if (/^https?:\/\//.test(normalized)) {
    return true;
  }

  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) {
    return true;
  }

  return EXTERNAL_DESTINATION_HINTS.some((hint) => normalized.includes(hint));
}

function looksLikeTrustedChatDelivery(args?: Record<string, unknown>): boolean {
  if (!args) {
    return true;
  }

  if (looksLikeExternalDestination(args) || messageHasAttachment(args)) {
    return false;
  }

  const explicitChannel = extractStringArg(args, ["channel", "platform", "service", "provider", "transport"]) ?? "";
  const target = extractCommunicationTarget(args);
  const combined = `${explicitChannel} ${target}`.toLowerCase();

  if (CHAT_CHANNEL_HINTS.some((hint) => combined.includes(hint))) {
    return true;
  }

  if (
    args.chat_id !== undefined
    || args.chatId !== undefined
    || args.channel_id !== undefined
    || args.channelId !== undefined
    || args.thread_id !== undefined
    || args.threadId !== undefined
    || args.message_thread_id !== undefined
    || args.messageThreadId !== undefined
    || args.conversation_id !== undefined
    || args.conversationId !== undefined
    || args.room !== undefined
    || args.room_id !== undefined
    || args.roomId !== undefined
    || args.user_id !== undefined
    || args.userId !== undefined
    || args.phone !== undefined
    || args.phone_number !== undefined
    || args.phoneNumber !== undefined
  ) {
    return true;
  }

  return !target;
}

function assessDataEgressTool(
  toolName: string,
  args?: Record<string, unknown>,
): ToolRiskAssessment {
  if (toolName === "upload_file") {
    return {
      toolCategory: "filesystem",
      operationKind: "upload_file",
      isHighRisk: true,
      canEgressData: true,
      severity: "high",
      title: "File upload",
      deliveryScope: "external",
      channelType: "file_transfer",
    };
  }

  if (toolName === "send_email") {
    return {
      toolCategory: "communication",
      operationKind: "send_email",
      isHighRisk: true,
      canEgressData: true,
      severity: "high",
      title: "External email send",
      deliveryScope: "external",
      channelType: "email",
    };
  }

  if (messageHasAttachment(args)) {
    return {
      toolCategory: "communication",
      operationKind: "send_message",
      isHighRisk: true,
      canEgressData: true,
      severity: "high",
      title: "Message send with attachment",
      deliveryScope: "external",
      channelType: inferChannelType(args),
    };
  }

  if (looksLikeExternalDestination(args)) {
    return {
      toolCategory: "communication",
      operationKind: "send_message",
      isHighRisk: true,
      canEgressData: true,
      severity: "high",
      title: "External message send",
      deliveryScope: "external",
      channelType: inferChannelType(args),
    };
  }

  if (looksLikeTrustedChatDelivery(args)) {
    return {
      toolCategory: "communication",
      operationKind: "trusted_delivery",
      isHighRisk: false,
      canEgressData: false,
      deliveryScope: "first_party",
      channelType: inferChannelType(args),
    };
  }

  return {
    toolCategory: "communication",
    operationKind: "send_message",
    isHighRisk: true,
    canEgressData: true,
    severity: "medium",
    title: "Unclassified message send",
    deliveryScope: "external",
    channelType: inferChannelType(args),
  };
}

export function extractTargetFromCommand(command: string): string {
  if (!command) return "";

  const pathFlagValue = extractFlagValue(command, ["literalpath", "path", "filepath", "infile", "outfile"]);
  const nameFlagValue = extractFlagValue(command, ["name"]);

  if (/^(?:new-item|ni)\b/i.test(command) && nameFlagValue) {
    return joinPathSegments(pathFlagValue, nameFlagValue);
  }

  if (pathFlagValue) {
    return pathFlagValue;
  }

  const urlMatch = command.match(/\bhttps?:\/\/\S+/i);
  if (urlMatch?.[0]) {
    return urlMatch[0].replace(/[)"']+$/, "");
  }

  const positionalPathMatch = command.match(/^(?:get-content|gc|type|cat|get-childitem|gci|dir|copy-item|move-item|rename-item|set-content|add-content|remove-item|del|rm|cp|mv|touch)\s+("[^"]+"|'[^']+'|\S+)/i);
  if (positionalPathMatch?.[1]) {
    const candidate = stripWrappingQuotes(positionalPathMatch[1]);
    if (!candidate.startsWith("-")) {
      return candidate;
    }
  }

  const newItemMatch = command.match(/^(?:new-item|mkdir|touch)\s+("[^"]+"|'[^']+'|\S+)/i);
  if (newItemMatch?.[1]) {
    const candidate = stripWrappingQuotes(newItemMatch[1]);
    if (!candidate.startsWith("-")) {
      return candidate;
    }
  }

  const teeMatch = command.match(/^(?:tee(?:-object)?|out-file)\s+("[^"]+"|'[^']+'|\S+)/i);
  if (teeMatch?.[1]) {
    const candidate = stripWrappingQuotes(teeMatch[1]);
    if (!candidate.startsWith("-")) {
      return candidate;
    }
  }

  const redirectMatch = command.match(/>{1,2}\s*("[^"]+"|'[^']+'|\S+)$/i);
  if (redirectMatch?.[1]) {
    return stripWrappingQuotes(redirectMatch[1]);
  }

  return "";
}

function extractHttpMethod(toolName: string, args?: Record<string, unknown>): string {
  const normalizedTool = toolName.toLowerCase();
  if (normalizedTool === "http_post") return "POST";
  if (normalizedTool === "http_put") return "PUT";

  const explicit = extractStringArg(args, ["method", "httpMethod", "verb", "customMethod"]);
  return explicit ? explicit.toUpperCase() : "GET";
}

function requestHasPayload(args?: Record<string, unknown>): boolean {
  if (!args) return false;
  for (const key of ["body", "data", "form", "json", "file", "files", "inFile", "upload"]) {
    if (args[key] !== undefined && args[key] !== null && args[key] !== "") {
      return true;
    }
  }
  return false;
}

function extractRequestUrl(args?: Record<string, unknown>): string {
  return extractStringArg(args, ["url", "uri", "endpoint", "href"]) ?? "";
}

function normalizePayloadKey(key: string): string {
  return key.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function parseStructuredPayload(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }

  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return undefined;
  }
}

function hasBlockedSearchPayloadKey(record: Record<string, unknown>): boolean {
  return Object.keys(record).some((key) => SEARCH_BLOCKED_KEYS.has(normalizePayloadKey(key)));
}

function payloadLooksLikeSearch(record: Record<string, unknown>): boolean {
  const keys = Object.keys(record).map(normalizePayloadKey);
  if (keys.length === 0) {
    return false;
  }

  if (hasBlockedSearchPayloadKey(record)) {
    return false;
  }

  const hasQueryField = keys.some((key) => SEARCH_QUERY_KEYS.has(key));
  if (!hasQueryField) {
    return false;
  }

  return keys.every((key) => SEARCH_ALLOWED_KEYS.has(key));
}

function payloadLooksLikeReadQuery(record: Record<string, unknown>): boolean {
  const keys = Object.keys(record).map(normalizePayloadKey);
  if (keys.length === 0) {
    return false;
  }

  if (hasBlockedSearchPayloadKey(record)) {
    return false;
  }

  const queryValue = record.query;
  if (typeof queryValue === "string" && /\bmutation\b/i.test(queryValue)) {
    return false;
  }

  const hasQueryField = keys.some((key) => READ_QUERY_KEYS.has(key));
  if (!hasQueryField) {
    return false;
  }

  return keys.every((key) => READ_QUERY_ALLOWED_KEYS.has(key));
}

function textPayloadLooksLikeSearch(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  if (/^(?:q|query|search|keywords|term)=/.test(normalized) || /[?&](?:q|query|search|keywords|term)=/.test(normalized)) {
    return !/[?&]?(?:file|files|upload|attachment|content|message|prompt|input)=/.test(normalized);
  }

  const structured = parseStructuredPayload(value);
  return structured ? payloadLooksLikeSearch(structured) : false;
}

function requestPayloadLooksLikeSearch(args?: Record<string, unknown>): boolean {
  if (!args) {
    return false;
  }

  for (const key of ["body", "data", "json", "form"]) {
    const value = args[key];
    if (typeof value === "string" && textPayloadLooksLikeSearch(value)) {
      return true;
    }

    const structured = parseStructuredPayload(value);
    if (structured && payloadLooksLikeSearch(structured)) {
      return true;
    }
  }

  return false;
}

function requestPayloadLooksLikeReadQuery(args?: Record<string, unknown>): boolean {
  if (!args) {
    return false;
  }

  for (const key of ["body", "data", "json", "form"]) {
    const value = args[key];
    if (typeof value === "string") {
      const structured = parseStructuredPayload(value);
      if (structured && payloadLooksLikeReadQuery(structured)) {
        return true;
      }
    } else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      if (payloadLooksLikeReadQuery(value as Record<string, unknown>)) {
        return true;
      }
    }
  }

  return false;
}

function requestLooksLikeWebSearch(toolName: string, args?: Record<string, unknown>): boolean {
  const normalizedTool = toolName.toLowerCase();
  if (SEARCH_HINTS.some((hint) => normalizedTool.includes(hint))) {
    return true;
  }

  if (!args) {
    return false;
  }

  const explicitQuery = extractStringArg(args, ["query", "q", "search", "keywords", "term"]);
  if (
    explicitQuery
    && (!requestHasPayload(args) || requestPayloadLooksLikeSearch(args))
    && args.file === undefined
    && args.files === undefined
    && args.upload === undefined
    && args.inFile === undefined
  ) {
    return true;
  }

  const url = extractRequestUrl(args);
  if (!url) {
    return false;
  }

  const urlLooksSearchLike = SEARCH_URL_PATTERNS.some((pattern) => pattern.test(url));
  if (!urlLooksSearchLike) {
    return false;
  }

  const method = extractHttpMethod(toolName, args);
  if (["GET", "HEAD", "OPTIONS"].includes(method)) {
    return true;
  }

  return requestPayloadLooksLikeSearch(args);
}

function requestLooksLikeExternalReadQuery(toolName: string, args?: Record<string, unknown>): boolean {
  if (!args) {
    return false;
  }

  const normalizedTool = toolName.toLowerCase();
  const method = extractHttpMethod(toolName, args);
  if (!["POST", "GET", "HEAD", "OPTIONS"].includes(method)) {
    return false;
  }

  const url = extractRequestUrl(args);
  const explicitQuery = extractStringArg(args, ["query", "jql", "q"]);
  const payloadLooksReadOnly = requestPayloadLooksLikeReadQuery(args);
  const urlLooksReadLike = url ? READ_QUERY_URL_PATTERNS.some((pattern) => pattern.test(url)) : false;
  const toolLooksReadLike = READ_QUERY_HINTS.some((hint) => normalizedTool.includes(hint));

  if (payloadLooksReadOnly && (urlLooksReadLike || toolLooksReadLike)) {
    return true;
  }

  if (explicitQuery && (!requestHasPayload(args) || payloadLooksReadOnly)) {
    return true;
  }

  return false;
}

function assessHttpLikeTool(toolName: string, args?: Record<string, unknown>): ToolRiskAssessment {
  if (requestLooksLikeWebSearch(toolName, args)) {
    return {
      toolCategory: "discovery",
      operationKind: "web_search",
      isHighRisk: false,
      canEgressData: false,
    };
  }

  if (requestLooksLikeExternalReadQuery(toolName, args)) {
    return {
      toolCategory: "discovery",
      operationKind: "external_read_query",
      isHighRisk: false,
      canEgressData: false,
    };
  }

  const method = extractHttpMethod(toolName, args);
  const hasPayload = requestHasPayload(args);

  if (toolName === "http_post" || toolName === "http_put" || !["GET", "HEAD", "OPTIONS"].includes(method) || hasPayload) {
    return {
      toolCategory: "network",
      operationKind: "outbound_request",
      isHighRisk: true,
      canEgressData: true,
      severity: "high",
      title: "Outbound request with payload",
    };
  }

  return {
    toolCategory: "network",
    operationKind: "fetch",
    isHighRisk: false,
    canEgressData: false,
  };
}

function assessShellLikeTool(command: string): ToolRiskAssessment {
  if (!command) {
    return {
      toolCategory: "shell",
      operationKind: "command_execution",
      isHighRisk: false,
      canEgressData: false,
    };
  }

  if (isReadOnlyShellCommand(command)) {
    return {
      toolCategory: "shell",
      operationKind: "read_only",
      isHighRisk: false,
      canEgressData: false,
    };
  }

  if (isLocalDevCommand(command)) {
    return {
      toolCategory: "system",
      operationKind: "local_dev_runtime",
      isHighRisk: false,
      canEgressData: false,
    };
  }

  if (isGitWorkflowCommand(command)) {
    return {
      toolCategory: "vcs",
      operationKind: normalizeCommand(command).startsWith("git push") ? "git_push" : "git_workflow",
      isHighRisk: false,
      canEgressData: normalizeCommand(command).startsWith("git push"),
    };
  }

  if (isPackageInstallCommand(command)) {
    return {
      toolCategory: "package",
      operationKind: "package_install",
      isHighRisk: false,
      canEgressData: false,
    };
  }

  if (isRemoteExecutionCommand(command)) {
    return {
      toolCategory: "shell",
      operationKind: "remote_code_execution",
      isHighRisk: true,
      canEgressData: true,
      severity: "high",
      title: "Remote code execution pattern",
    };
  }

  if (isDataEgressCommand(command)) {
    return {
      toolCategory: "network",
      operationKind: "outbound_transfer",
      isHighRisk: true,
      canEgressData: true,
      severity: "high",
      title: "Outbound shell transfer",
    };
  }

  if (isDestructiveCommand(command)) {
    return {
      toolCategory: "filesystem",
      operationKind: "destructive_command",
      isHighRisk: true,
      canEgressData: false,
      severity: "high",
      title: "Destructive shell command",
    };
  }

  if (isImpactfulSystemCommand(command)) {
    return {
      toolCategory: "system",
      operationKind: "system_mutation",
      isHighRisk: true,
      canEgressData: false,
      severity: "high",
      title: "Impactful system command",
    };
  }

  if (isFileWriteCommand(command)) {
    return {
      toolCategory: "filesystem",
      operationKind: "file_write",
      isHighRisk: false,
      canEgressData: false,
    };
  }

  return {
    toolCategory: "shell",
    operationKind: "command_execution",
    isHighRisk: false,
    canEgressData: false,
  };
}

function applyTargetRiskContext(
  assessment: ToolRiskAssessment,
  args?: Record<string, unknown>,
): ToolRiskAssessment {
  const explicitTarget = extractStringArg(args, ["path", "file", "filename", "target"]);
  const commandTarget = extractTargetFromCommand(extractCommandText(args));
  const target = explicitTarget || commandTarget;
  if (!target) {
    return assessment;
  }

  const targetKind = classifyTargetPath(target);
  if (assessment.operationKind !== "file_write") {
    return targetKind === "secret_store"
      ? { ...assessment, operationKind: assessment.operationKind === "read_only" ? "secret_store_read" : assessment.operationKind }
      : assessment;
  }

  if (targetKind === "memory_file") {
    return { ...assessment, operationKind: "memory_write" };
  }

  if (targetKind === "local_config") {
    return { ...assessment, operationKind: "config_write" };
  }

  if (targetKind === "execution_surface") {
    return {
      ...assessment,
      operationKind: "execution_surface_write",
      isHighRisk: true,
      severity: "medium",
      title: "Execution-surface file update",
    };
  }

  if (targetKind === "system_persistence") {
    return {
      ...assessment,
      operationKind: "system_persistence_write",
      isHighRisk: true,
      severity: "high",
      title: "Persistence or startup file update",
    };
  }

  if (targetKind === "secret_store") {
    return { ...assessment, operationKind: "secret_store_write" };
  }

  return assessment;
}

/**
 * Check if a tool name is considered high-risk (outbound/execution).
 */
export function isHighRiskTool(toolName: string): boolean {
  return HIGH_RISK_TOOLS.has(toolName.toLowerCase());
}

/**
 * Check whether a specific tool invocation should be treated as high-risk.
 *
 * Shell-like tools are judged by the command they execute. Read-only commands
 * such as directory listing and file reads are normal agent behavior and
 * should not be raised as risk alerts on their own.
 */
export function isHighRiskToolCall(
  toolName: string,
  args?: Record<string, unknown>,
): boolean {
  return assessToolCall(toolName, args).isHighRisk;
}

export function assessToolCall(
  toolName: string,
  args?: Record<string, unknown>,
): ToolRiskAssessment {
  const normalizedTool = toolName.toLowerCase();

  if (DATA_EGRESS_TOOLS.has(normalizedTool)) {
    return assessDataEgressTool(normalizedTool, args);
  }

  if (HTTP_LIKE_TOOLS.has(normalizedTool)) {
    return applyTargetRiskContext(assessHttpLikeTool(normalizedTool, args), args);
  }

  if (SHELL_LIKE_TOOLS.has(normalizedTool)) {
    return applyTargetRiskContext(assessShellLikeTool(extractCommandText(args)), args);
  }

  if (normalizedTool.includes("read")) {
    return applyTargetRiskContext({
      toolCategory: "filesystem",
      operationKind: "file_read",
      isHighRisk: false,
      canEgressData: false,
    }, args);
  }

  if (normalizedTool.includes("write") || normalizedTool.includes("edit") || normalizedTool.includes("patch")) {
    return applyTargetRiskContext({
      toolCategory: "filesystem",
      operationKind: "file_write",
      isHighRisk: false,
      canEgressData: false,
    }, args);
  }

  if (normalizedTool.includes("search") || normalizedTool.includes("grep") || normalizedTool.includes("find")) {
    return applyTargetRiskContext({
      toolCategory: "discovery",
      operationKind: "search",
      isHighRisk: false,
      canEgressData: false,
    }, args);
  }

  return applyTargetRiskContext({
    toolCategory: "unknown",
    operationKind: "tool_call",
    isHighRisk: false,
    canEgressData: false,
  }, args);
}

export const __testing = {
  classifyTargetPath,
  joinPathSegments,
  looksLikePlaceholderValue,
  parseStructuredPayload,
  payloadLooksLikeReadQuery,
  requestPayloadLooksLikeReadQuery,
  requestLooksLikeExternalReadQuery,
  requestPayloadLooksLikeSearch,
  requestLooksLikeWebSearch,
};
