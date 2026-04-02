# ClawGuard SDK

Python SDK for **ClawGuard** — real-time security monitoring for AI agents. Wraps your agent's tool calls, detects risky behavior (data exfiltration, prompt injection, credential access), and sends alerts to Telegram.

> **This is the public distribution repo.** It contains only the client-side SDK, CLI, and OpenClaw plugin — the code users install on their OpenClaw machines to connect to the ClawGuard monitoring service. The backend, analysis engine, and Telegram bot are in the private [`rutipo/ClawGuard`](https://github.com/rutipo/ClawGuard) repository and are never distributed to users.

## How It Works

```
Your Python Agent                    ClawGuard Backend
+------------------+                +---------------------+
|  Agent code      |                |  FastAPI + Postgres  |
|  + ClawGuard SDK |--- HTTPS --->  |  Analysis Engine     |
|  (wraps tools)   |                |  Telegram Bot -----> alerts
+------------------+                +---------------------+
```

The SDK intercepts every tool call your agent makes, captures structured events (what tool, what input, what output, timing), runs local risk checks, and streams everything to the ClawGuard backend for analysis. You get real-time Telegram alerts when something looks wrong.

## Installation

```bash
pip install clawguard-sdk
```

With CLI tools (for account setup):

```bash
pip install "clawguard-sdk[cli]"
```

## Quick Start

### 1. Get an Account

You need a ClawGuard backend running (self-hosted or managed). Then register:

```bash
# Create your account (saves API key locally)
clawguard create-user --email you@example.com --backend-url https://your-server:8000
```

This gives you an API key (`cg_...`) and saves it to `~/.clawguard/config.json`.

Or register via the API directly:

```bash
curl -X POST https://your-server:8000/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

### 2. Connect Telegram (optional, recommended)

To receive real-time alerts on your phone:

1. Find the ClawGuard bot on Telegram (your server admin will share the bot name)
2. Run:
   ```bash
   clawguard connect-telegram
   ```
3. Send the displayed code to the bot: `/connect <CODE>`

### 3. Instrument Your Agent

```python
from clawguard import secure_run

# Your existing agent (any object with a .run() method and .tools)
result = secure_run(agent, task="Summarize Q4 financial reports")
```

That's it. Every tool call is now monitored.

## Usage

### Basic: `secure_run`

The simplest API — wraps and runs your agent in one call:

```python
from clawguard import secure_run

result = secure_run(
    agent,
    task="Research competitor pricing",
)
```

### Context Manager: `clawguard_context`

For more control (multiple tasks in one session, custom events):

```python
from clawguard.sdk.runner import clawguard_context

with clawguard_context(agent) as guard:
    result1 = guard.run("Find pricing data")
    result2 = guard.run("Summarize findings")
```

### Manual Event Logging

Log custom decision points from within your agent code:

```python
from clawguard.sdk.runner import capture_decision

# Inside your agent's logic
capture_decision(
    "Decided to access production database instead of staging",
    metadata={"reason": "staging data is stale"}
)
```

### Wrapping Individual Tools

For fine-grained control, wrap specific tools:

```python
from clawguard.sdk.wrappers import wrap_tool
from clawguard.sdk.logger import EventLogger
from clawguard.sdk.risk_engine import SessionRiskContext

event_logger = EventLogger(session_id="my-session", config=config)
event_logger.start()

my_safe_tool = wrap_tool(
    original_tool_fn,
    tool_name="web_search",
    event_logger=event_logger,
    risk_ctx=SessionRiskContext(session_id="my-session"),
)
```

## Configuration

Set via environment variables or pass a `ClawGuardConfig` object:

```python
from clawguard import ClawGuardConfig, secure_run

config = ClawGuardConfig(
    api_key="cg_your_key_here",
    backend_url="https://your-server:8000",
    enabled=True,
)

result = secure_run(agent, task="...", config=config)
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CLAWGUARD_API_KEY` | `""` | Your API key |
| `CLAWGUARD_BACKEND_URL` | `http://localhost:8000` | Backend server URL |
| `CLAWGUARD_ENABLED` | `true` | Enable/disable monitoring |
| `CLAWGUARD_LOG_TO_STDERR` | `true` | Log events to stderr |
| `CLAWGUARD_CAPTURE_FULL_IO` | `false` | Capture full tool I/O (large payloads) |
| `CLAWGUARD_MAX_FULL_IO_BYTES` | `50000` | Max bytes for full I/O capture |
| `CLAWGUARD_CAPTURE_TIMING` | `true` | Record tool execution timing |
| `CLAWGUARD_FLUSH_INTERVAL_SECONDS` | `2.0` | How often to batch-send events |

## What Gets Detected

The SDK runs local risk checks on every event, and the backend runs deeper analysis:

### Local (SDK-side) Detection
- **Prompt injection** — external content with override/ignore language patterns
- **Sensitive file access** — `.env`, `.ssh/`, `credentials`, `private_key`, etc.
- **Credential exposure** — AWS keys, API tokens, private keys in tool output
- **Exfiltration chains** — sensitive data read followed by outbound request
- **Communication spikes** — burst of outbound requests
- **Chain escalation** — accumulating medium-risk events escalating to high

### Server-side Analysis
- **Behavioral anomaly** — actions outside the agent's learned baseline
- **Goal deviation** — agent thread doing something unrelated to the stated task
- **Cross-thread escalation** — progressive risk pattern across execution threads
- **Data flow tracking** — sensitive data propagation from read to send
- **Thread segmentation** — groups related actions into causal threads for deeper analysis

## Agent Compatibility

The SDK works with any Python agent that has:
- A `.run(task)` method
- A `.tools` attribute (list or dict of callable tools)

This includes agents built with LangChain, CrewAI, AutoGen, or custom frameworks.

```python
# LangChain example
from langchain.agents import create_openai_tools_agent
agent = create_openai_tools_agent(llm, tools, prompt)
result = secure_run(agent, task="...")

# Custom agent
class MyAgent:
    def __init__(self):
        self.tools = [search, read_file, send_email]

    def run(self, task):
        # your logic
        ...

result = secure_run(MyAgent(), task="...")
```

## Telegram Commands

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

## Self-Hosting the Backend

To run your own ClawGuard backend, see the [ClawGuard server repository](https://github.com/rutipo/ClawGuard).

Quick setup:

```bash
git clone https://github.com/rutipo/ClawGuard.git
cd ClawGuard
pip install -e ".[server]"

# Start PostgreSQL (install directly or use Docker)
# Create database: createdb clawguard

# Configure
cp .env.example .env
# Edit .env: set DATABASE_URL, TELEGRAM_BOT_TOKEN

# Run migrations
alembic upgrade head

# Start backend
uvicorn clawguard.backend.main:app --host 0.0.0.0 --port 8000

# Start Telegram bot (separate terminal)
python -m clawguard.bot.bot
```

### Setting Up Telegram Bot

1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the bot token to your `.env` as `TELEGRAM_BOT_TOKEN`
4. Start the bot process: `python -m clawguard.bot.bot`

## API Reference

The SDK communicates with these backend endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/v1/register` | POST | Create user account |
| `/v1/sessions/start` | POST | Start monitoring session |
| `/v1/sessions/end` | POST | End monitoring session |
| `/v1/events` | POST | Submit single event |
| `/v1/events/batch` | POST | Submit event batch |
| `/v1/connect-telegram` | POST | Register Telegram code |
| `/health` | GET | Backend health check |

## License

MIT
