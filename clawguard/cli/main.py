"""ClawGuard CLI — login and Telegram connection.

Requires: pip install clawguard[cli]
"""

import json
import os
from pathlib import Path

try:
    import typer
    from rich.console import Console
except ImportError:
    raise SystemExit(
        "CLI dependencies not installed. Run: pip install clawguard[cli]"
    )

app = typer.Typer(name="clawguard", help="ClawGuard - Security monitoring for OpenClaw agents")
console = Console()

CONFIG_DIR = Path(os.environ.get("CLAWGUARD_CONFIG_DIR", Path.home() / ".clawguard"))
CONFIG_FILE = CONFIG_DIR / "config.json"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def _save_config(config: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    CONFIG_FILE.chmod(0o600)


@app.command()
def login(api_key: str = typer.Option(..., prompt=True, hide_input=True, help="Your API key")) -> None:
    """Save your ClawGuard API key locally."""
    config = _load_config()
    config["api_key"] = api_key
    _save_config(config)
    console.print("[green]API key saved.[/green]")


@app.command()
def connect_telegram() -> None:
    """Connect your Telegram account to ClawGuard."""
    import secrets
    import time

    import httpx

    config = _load_config()
    api_key = config.get("api_key")
    if not api_key:
        console.print("[red]Run 'clawguard login' first.[/red]")
        raise typer.Exit(1)

    backend_url = config.get("backend_url", "http://localhost:8000")
    code = secrets.token_hex(3).upper()  # 6-char hex code

    console.print(f"\n[bold]Your connection code: {code}[/bold]")
    console.print("Open Telegram, search for [bold]@clawguard_alerts_bot[/bold], and send:")
    console.print(f"  /connect {code}\n")

    try:
        resp = httpx.post(
            f"{backend_url}/v1/connect-telegram",
            json={"code": code},
            headers={"X-API-Key": api_key},
            timeout=10,
        )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        console.print(f"[red]Failed to register code: {e}[/red]")
        raise typer.Exit(1)

    console.print("Waiting for confirmation...", end="")
    for _ in range(60):
        time.sleep(2)
        try:
            check = httpx.get(
                f"{backend_url}/v1/connect-telegram/status",
                params={"code": code},
                headers={"X-API-Key": api_key},
                timeout=10,
            )
            if check.status_code == 200 and check.json().get("connected"):
                console.print("\n[green]Telegram connected![/green]")
                return
        except httpx.HTTPError:
            pass
        console.print(".", end="")

    console.print("\n[yellow]Timed out. Try again.[/yellow]")


@app.command()
def create_user(
    email: str = typer.Option(..., prompt=True, help="Email for the new account"),
    backend_url: str = typer.Option("http://localhost:8000", help="Backend URL"),
) -> None:
    """Create a new ClawGuard user and save the API key locally."""
    import httpx

    try:
        resp = httpx.post(
            f"{backend_url}/v1/register",
            json={"email": email},
            timeout=10,
        )
        if resp.status_code == 409:
            console.print(f"[red]Email '{email}' is already registered.[/red]")
            raise typer.Exit(1)
        resp.raise_for_status()

        data = resp.json()
        api_key = data["api_key"]

        # Save locally
        config = _load_config()
        config["api_key"] = api_key
        config["backend_url"] = backend_url
        config["email"] = email
        _save_config(config)

        console.print("\n[green]Account created![/green]")
        console.print(f"Email: {email}")
        console.print(f"API Key: [bold]{api_key}[/bold]")
        console.print(f"\nKey saved to {CONFIG_FILE}")
        console.print("\nNext: connect Telegram with [bold]clawguard connect-telegram[/bold]")

    except httpx.ConnectError:
        console.print(f"[red]Cannot connect to backend at {backend_url}. Is it running?[/red]")
        raise typer.Exit(1)
    except httpx.HTTPError as e:
        console.print(f"[red]Registration failed: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
