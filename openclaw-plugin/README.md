# clawguard-monitor

Security monitoring plugin for [OpenClaw](https://github.com/openclaw/openclaw) agents. Monitors agent activity via OpenClaw's runtime event streams, detects sensitive content, and streams events to the ClawGuard backend for real-time Telegram alerts and thread analysis.

## How it works

```
OpenClaw Agent                       ClawGuard Backend
     |                                      |
     | tool call / text response            |
     |----> runtime.events --------------->| POST /v1/events
     |   (onSessionTranscriptUpdate)        |     |
     |   (onAgentEvent)                     |  thread segmentation
     |                                      |  + risk scoring
     |                                      |     |
     |                                      |  Telegram alert (if risky)
     |                                      |
     | POST /analyze-thread (on demand)     |
     |------------------------------------->| stateless thread analysis
     |<-------------------------------------| threads + insights
```

The plugin:
- Subscribes to `runtime.events.onSessionTranscriptUpdate` to capture tool calls, results, and agent text
- Subscribes to `runtime.events.onAgentEvent` as a secondary event stream
- Detects sensitive file access (.env, credentials, SSH keys)
- Detects credentials/PII in tool outputs (AWS, GCP, Slack, GitHub tokens, etc.)
- Tracks data flow (sensitive read followed by outbound request = exfiltration flag)
- Exposes `/analyze-thread` endpoint for on-demand thread analysis
- Optionally blocks dangerous tool calls or requires approval
- Batches events for efficiency, sends high-risk events immediately
- Never breaks agent execution (all monitoring errors are caught)

> **Note**: This plugin uses `runtime.events` instead of OpenClaw's hook system (`registerHook`/`api.on`) due to a known hook runner timing issue for embedded agents (OpenClaw #5513).

## Installation

### From ClawHub (recommended)

```bash
openclaw plugins install clawhub:clawguard-monitor
```

### From a local source checkout (unpublished/local testing only)

```bash
git clone https://github.com/rutipo/clawguard-plugin.git
cd clawguard-plugin/openclaw-plugin
openclaw plugins install -l .
```

Because `dist/` is checked in, you do not need `npm install` for a user-style local install. Run `npm ci && npm run build` only if you are actively changing the TypeScript source and need to rebuild it.

ClawGuard itself does not rewrite `~/.openclaw/openclaw.json` or try to repair plugin config. OpenClaw may still create or enable the plugin entry during installation, so verify the resulting config after install.

## Configuration

Choose one of the following configuration sources. None of them should be written automatically during installation.

If the config is missing, blank, or malformed, ClawGuard stays inactive and logs a warning. It does not rewrite OpenClaw config, self-enable, or try to repair stale entries.

**Option A: Environment variables**

```bash
export CLAWGUARD_BACKEND_URL=https://your-clawguard-server.com
export CLAWGUARD_API_KEY=cg_your_api_key_here
export CLAWGUARD_AGENT_ID=my-research-bot
```

If OpenClaw is launched from a service manager, put the same variables in that service's environment file instead of rewriting plugin config during install.

**Option B: Explicit OpenClaw config commands**

```bash
openclaw config set plugins.entries.clawguard-monitor.config.backendUrl "https://your-clawguard-server.com"
openclaw config set plugins.entries.clawguard-monitor.config.apiKey "cg_your_api_key_here"
openclaw config set plugins.entries.clawguard-monitor.config.agentId "my-research-bot"
```

**Option C: Edit config file**

Add to your OpenClaw config (`~/.openclaw/openclaw.json` or equivalent):

```json
{
  "plugins": {
    "entries": {
      "clawguard-monitor": {
        "enabled": false,
        "config": {
          "backendUrl": "https://your-clawguard-server.com",
          "apiKey": "cg_your_api_key_here",
          "agentId": "my-research-bot"
        }
      }
    }
  }
}
```

## Verify or change the enabled state

After installation and configuration, check the resulting plugin entry:

```bash
openclaw config get plugins.entries.clawguard-monitor
```

If you want to enable it explicitly:

```bash
openclaw config set plugins.entries.clawguard-monitor.enabled true
openclaw gateway restart
```

If you edited `openclaw.json` manually and already set `"enabled": true`, you can skip the extra `config set ...enabled true` command.

To disable it again:

```bash
openclaw config set plugins.entries.clawguard-monitor.enabled false
openclaw gateway restart
```

To rotate the API key later, update the environment variable or rerun the explicit `openclaw config set ...apiKey` command. Reinstalling the plugin should never be required just to change secrets.

### Configuration options

| Option | Env var | Default | Description |
|--------|---------|---------|-------------|
| `backendUrl` | `CLAWGUARD_BACKEND_URL` | `http://localhost:8000` | ClawGuard backend URL |
| `apiKey` | `CLAWGUARD_API_KEY` | (required to monitor) | API key from `/v1/register` |
| `agentId` | `CLAWGUARD_AGENT_ID` | `openclaw-agent` | Identifier for this agent |
| `captureFullIo` | - | `false` | Capture full tool input/output (up to 50KB) |
| `maxFullIoBytes` | - | `50000` | Maximum full I/O bytes when `captureFullIo` is enabled |
| `blockSensitiveAccess` | - | `false` | Block tool calls to sensitive files |
| `requireApprovalForHighRisk` | - | `false` | Require user approval for potential exfiltration |
| `batchSize` | - | `10` | Events buffered before sending |
| `flushIntervalMs` | - | `5000` | Max time before flushing event buffer |

## Install integrity check

On machines that have OpenClaw installed, you can verify that plugin installation does not mutate `openclaw.json`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify_openclaw_plugin_install_integrity.ps1
```

That script hashes `~/.openclaw/openclaw.json` before and after `openclaw plugins install -l .` and exits non-zero if the hash changes without an explicit config command.

## Thread Analysis API

The plugin proxies thread analysis requests to the ClawGuard backend. Send raw events and get back structured threads with goal classification and security insights:

```typescript
import { ClawGuardClient } from "clawguard-monitor";

const client = new ClawGuardClient(config);
const result = await client.analyzeThread({
  events: [
    { timestamp: "2026-04-01T10:00:00Z", type: "tool_call", content: "read_file", metadata: { tool_name: "read_file", target: "/app/.env" } },
    { timestamp: "2026-04-01T10:00:05Z", type: "tool_call", content: "http_post", metadata: { tool_name: "http_post", target: "https://external.com" } },
  ],
  context: { session_id: "optional-session-id" },
});

// result.threads — segmented execution threads with classification
// result.insights — security findings (sensitive_access, potential_exfiltration, etc.)
```

## Security & Permissions

This plugin:
- **Network**: Makes outbound HTTPS requests only to the configured `backendUrl`. No other network access.
- **Filesystem**: Does not read or write any files.
- **Shell**: Does not execute shell commands.
- **Secrets**: API key is read from environment variables or plugin config. Never logged or included in error messages.
- **Data sent**: Tool names, input summaries (truncated to 200 chars), output summaries (300 chars), risk flags, timestamps. Full I/O capture is opt-in via `captureFullIo`.
- **Trust model**: The plugin runs in the OpenClaw process and trusts the OpenClaw plugin sandbox. Other plugins in the same process share the same runtime.
- **URL validation**: Backend URL is validated on startup — private IPs and cloud metadata endpoints are blocked to prevent SSRF.
- **Buffer limits**: Event buffers and session maps are capped to prevent memory exhaustion.

## Prerequisites

ClawGuard backend must be running and accessible from the OpenClaw machine. See the [ClawGuard server repository](https://github.com/rutipo/ClawGuard) for full setup instructions.

```bash
# On your server
git clone https://github.com/rutipo/ClawGuard.git
cd ClawGuard
pip install -e ".[server]"
alembic upgrade head
uvicorn clawguard.backend.main:app --host 0.0.0.0 --port 8000

# Create an account
curl -X POST http://localhost:8000/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
# Save the returned API key
```

## Development

```bash
cd openclaw-plugin
npm install
npm run build
npm test
```

## Architecture

- `src/index.ts` - Plugin entry point, event stream subscriptions, session management
- `src/client.ts` - HTTP client for ClawGuard API (batching, retry, thread analysis)
- `src/sensitive.ts` - Pattern detection (credentials, PII, sensitive paths)
- `src/types.ts` - TypeScript type definitions

## License

MIT
