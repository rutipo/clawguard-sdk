# Changelog

## 1.0.0 (2026-04-03)

Initial ClawHub release.

### Features
- Real-time monitoring via `runtime.events` (onSessionTranscriptUpdate, onAgentEvent)
- Sensitive content detection: AWS, GCP, Slack, GitHub tokens, PII, database URLs, private keys
- Sensitive file path detection (.env, credentials, SSH keys, PEM files)
- High-risk tool flagging (http_post, shell_exec, send_email, etc.)
- Exfiltration pattern detection (sensitive read followed by outbound request)
- Thread analysis endpoint (`/analyze-thread`) for on-demand event segmentation
- Event batching with configurable batch size and flush interval
- Telegram alert integration via ClawGuard backend
- Session lifecycle management (auto-create, end, metrics)

### Security
- API key transmitted via header only, never logged or included in error messages
- Backend URL validation blocks SSRF to private IPs and cloud metadata endpoints
- Event buffer capped at 10,000 to prevent memory exhaustion
- Session map capped at 100 with 1-hour TTL
- JSON parse output validated before processing
- No filesystem access, no shell execution, no eval()

### Compatibility
- OpenClaw plugin API >= 2026.3.24
- Node.js >= 22.0.0
