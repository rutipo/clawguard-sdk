# @clawguard/openclaw-plugin

Security monitoring plugin for [OpenClaw](https://github.com/openclaw/openclaw) agents. Hooks into the OpenClaw tool execution lifecycle to capture every tool call, detect sensitive content, and stream events to the ClawGuard backend for real-time Telegram alerts and analysis.

## How it works

```
OpenClaw Agent                   ClawGuard Backend
     |                                  |
     | tool call (read_file, http_post) |
     |----> before_tool_call hook ----->| POST /v1/events
     |                                  |     |
     |                                  |  analysis + risk scoring
     |                                  |     |
     |                                  |  Telegram alert (if risky)
     |                                  |
     | message sent to channel          |
     |----> message_sending hook ------>| POST /v1/events
```

The plugin:
- Intercepts every tool call via `before_tool_call` hook
- Detects sensitive file access (.env, credentials, SSH keys)
- Detects credentials/PII in tool outputs (AWS keys, tokens, etc.)
- Tracks data flow (sensitive read followed by outbound request = exfiltration flag)
- Optionally blocks dangerous tool calls or requires approval
- Batches events for efficiency, sends high-risk events immediately
- Never breaks agent execution (all monitoring errors are caught)

## Installation

### On the OpenClaw machine

```bash
# Install the plugin
openclaw plugins install @clawguard/openclaw-plugin
```

Or install from source:

```bash
git clone https://github.com/rutipo/clawguard-plugin.git
cd clawguard-plugin/openclaw-plugin
npm install && npm run build
```

Then add the plugin to your OpenClaw config with a local `path` pointing to the `openclaw-plugin` directory (see Configuration below).

### Configuration

**Option A: CLI (recommended)**

```bash
openclaw config set plugins.entries.clawguard-monitor.config.backendUrl "https://your-clawguard-server.com"
openclaw config set plugins.entries.clawguard-monitor.config.apiKey "cg_your_api_key_here"
openclaw config set plugins.entries.clawguard-monitor.config.agentId "my-research-bot"
openclaw gateway restart
```

**Option B: Edit config file**

Add to your OpenClaw config (`~/.openclaw/openclaw.json` or equivalent):

```json
{
  "plugins": {
    "entries": {
      "clawguard-monitor": {
        "enabled": true,
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

**Option C: Environment variables**

```bash
export CLAWGUARD_BACKEND_URL=https://your-clawguard-server.com
export CLAWGUARD_API_KEY=cg_your_api_key_here
export CLAWGUARD_AGENT_ID=my-research-bot
```

### Configuration options

| Option | Env var | Default | Description |
|--------|---------|---------|-------------|
| `backendUrl` | `CLAWGUARD_BACKEND_URL` | `http://localhost:8000` | ClawGuard backend URL |
| `apiKey` | `CLAWGUARD_API_KEY` | (required) | API key from `/v1/register` |
| `agentId` | `CLAWGUARD_AGENT_ID` | `openclaw-agent` | Identifier for this agent |
| `captureFullIo` | - | `false` | Capture full tool input/output (up to 50KB) |
| `blockSensitiveAccess` | - | `false` | Block tool calls to sensitive files |
| `requireApprovalForHighRisk` | - | `false` | Require user approval for potential exfiltration |
| `batchSize` | - | `10` | Events buffered before sending |
| `flushIntervalMs` | - | `5000` | Max time before flushing event buffer |

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

- `src/index.ts` - Plugin entry point, hook handlers, session management
- `src/client.ts` - HTTP client for ClawGuard API (batching, retry)
- `src/sensitive.ts` - Pattern detection (credentials, PII, sensitive paths)
- `src/types.ts` - TypeScript type definitions
