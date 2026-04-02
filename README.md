# ClawGuard

> **This is the public distribution repo.** It contains the OpenClaw plugin that users install on their machines to connect to the ClawGuard monitoring service. The backend, analysis engine, and Telegram bot are in the private [`rutipo/ClawGuard`](https://github.com/rutipo/ClawGuard) repository and are never distributed to users.

Security monitoring plugin for [OpenClaw](https://github.com/openclaw/openclaw) agents. Hooks into the tool execution lifecycle to capture every tool call, detect sensitive content, and stream events to the ClawGuard backend for real-time Telegram alerts and analysis.

## How It Works

```
OpenClaw Agent                     ClawGuard Backend
+---------------------+           +---------------------------+
|  OpenClaw (Node.js)  |          |  ClawGuard Backend (Py)   |
|   + ClawGuard plugin |--HTTPS-->|  FastAPI + PostgreSQL     |
|     (TypeScript)     |          |       |                   |
+---------------------+           |  Analysis Engine          |
                                  |       |                   |
                                  |  Telegram Bot --> alerts  |
                                  +---------------------------+
```

The plugin intercepts every tool call and outbound message via OpenClaw's `before_tool_call` and `message_sending` hooks. Events are streamed to the ClawGuard backend for risk analysis and Telegram commentary.

## Installation

```bash
openclaw plugins install clawguard-monitor
```

Or install from source:

```bash
git clone https://github.com/rutipo/clawguard-plugin.git
cd clawguard-plugin/openclaw-plugin
npm install && npm run build
```

Then add the plugin to your OpenClaw config with a local `path` pointing to the `openclaw-plugin` directory (see Configuration below).

## Configuration

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
|---|---|---|---|
| `backendUrl` | `CLAWGUARD_BACKEND_URL` | `http://localhost:8000` | ClawGuard backend URL |
| `apiKey` | `CLAWGUARD_API_KEY` | (required) | API key from registration |
| `agentId` | `CLAWGUARD_AGENT_ID` | `openclaw-agent` | Identifier for this agent |
| `captureFullIo` | - | `false` | Capture full tool input/output (up to 50KB) |
| `blockSensitiveAccess` | - | `false` | Block tool calls to sensitive files |
| `requireApprovalForHighRisk` | - | `false` | Require user approval for potential exfiltration |
| `batchSize` | - | `10` | Events buffered before sending |
| `flushIntervalMs` | - | `5000` | Max time before flushing event buffer |

## What Gets Detected

### Local (plugin-side)
- **Sensitive file access** — `.env`, `.ssh/`, `credentials`, `private_key`, etc.
- **Credential exposure** — AWS keys, API tokens, private keys in tool output
- **Data flow tracking** — sensitive read followed by outbound request (exfiltration flag)

### Server-side analysis
- **Behavioral anomaly** — actions outside the agent's learned baseline
- **Goal deviation** — agent thread doing something unrelated to the stated task
- **Cross-thread escalation** — progressive risk pattern across execution threads
- **Thread segmentation** — groups related actions into causal threads for deeper analysis

## Prerequisites

You need a running ClawGuard backend. See the [ClawGuard server repository](https://github.com/rutipo/ClawGuard) for setup instructions.

Quick setup:

```bash
git clone https://github.com/rutipo/ClawGuard.git
cd ClawGuard
pip install -e ".[server]"

# Start PostgreSQL
docker compose up -d postgres

# Configure
cp .env.example .env
# Edit .env: set DATABASE_URL, TELEGRAM_BOT_TOKEN

# Run migrations + bootstrap
alembic upgrade head
python scripts/bootstrap.py --email you@example.com

# Start backend
uvicorn clawguard.backend.main:app --host 0.0.0.0 --port 8000

# Start Telegram bot (separate terminal)
python -m clawguard.bot.bot
```

### Connect Telegram

1. Message [@BotFather](https://t.me/BotFather) on Telegram and create a bot
2. Set `TELEGRAM_BOT_TOKEN` in your `.env`
3. Register: `curl -X POST http://localhost:8000/v1/register -H "Content-Type: application/json" -d '{"email": "you@example.com"}'`
4. Save the returned API key

## Telegram Bot Commands

Once connected, use these commands in the ClawGuard Telegram bot:

| Command | Description |
|---|---|
| `/help` | Available commands |
| `/status` | Active monitoring sessions |
| `/last` | Latest alert details |
| `/recent` | Recent alerts list |
| `/session <id>` | Session narrative and timeline |
| `/watch` | Toggle live activity feed |
| `/label <session> tp\|fp\|nr` | Mark alert as true/false positive |
| `/feedback <message>` | Send feedback |

## Development

```bash
cd openclaw-plugin
npm install
npm run build
npm test
```

## License

MIT
