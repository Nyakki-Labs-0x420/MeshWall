"""Command-line interface for MeshWall."""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from meshwall.config import load_config
from meshwall.fetcher import FeedUpdater
from meshwall.domain_fetcher import DomainFeedUpdater
from meshwall.ipset_manager import IPSetManager
from meshwall.iptables_manager import IPTablesManager
from meshwall.listener import ListenerDaemon
from meshwall.trace import IPTracer
from meshwall.utils import setup_logging
from meshwall.ai.summarizer import ScanSummarizer

console = Console()


def check_root() -> bool:
    return os.geteuid() == 0


@click.group()
@click.option("--config", "-c", envvar="MESHWALL_CONFIG", default="/etc/meshwall/meshwall.conf")
@click.option("--debug", is_flag=True, help="Enable debug logging to console")
@click.pass_context
def cli(ctx: click.Context, config: str, debug: bool) -> None:
    """MeshWall – Adaptive firewall augmentation."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = Path(config)
    ctx.obj["debug"] = debug
    cfg = load_config(ctx.obj["config_path"])
    ctx.obj["config"] = cfg
    if debug:
        cfg.log_level = "DEBUG"
        cfg.log_json = False
    setup_logging(cfg.log_level, cfg.log_file, cfg.log_json, debug=debug)


@cli.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed progress")
@click.option("--dry-run", is_flag=True, help="Fetch feeds but don't modify ipset/iptables")
@click.option("--with-domains", is_flag=True, help="Also update domain blocklists")
@click.pass_context
def update(ctx: click.Context, verbose: bool, dry_run: bool, with_domains: bool) -> None:
    """Force immediate feed update and apply blocklists."""
    if not check_root():
        console.print("[red]Error: This command requires root privileges (iptables/ipset).[/]")
        console.print("[yellow]Run with: sudo meshwall update[/]")
        sys.exit(1)

    cfg = ctx.obj["config"]
    debug = ctx.obj.get("debug", False)

    if dry_run:
        console.print("[yellow]Dry run mode – no ipset/iptables changes will be made[/]")
        cfg.dry_run = True
    else:
        cfg.dry_run = False

    console.print("[bold green]Updating threat feeds...[/]")

    try:
        updater = FeedUpdater(cfg, debug=debug)
        asyncio.run(asyncio.wait_for(updater.run(verbose=verbose), timeout=300.0))
        console.print("[bold green]Update complete.[/]")
    except asyncio.TimeoutError:
        console.print("[red]Update timed out after 5 minutes. Check network or feed URLs.[/]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("[yellow]Update cancelled by user.[/]")
        sys.exit(1)

    if with_domains:
        console.print("[bold green]Updating domain blocklists...[/]")
        domain_updater = DomainFeedUpdater(cfg, debug=debug)
        try:
            asyncio.run(asyncio.wait_for(domain_updater.run(verbose=verbose), timeout=300.0))
            console.print("[bold green]Domain update complete.[/]")
        except Exception as e:
            console.print(f"[red]Domain update failed: {e}[/]")


@cli.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed progress")
@click.option("--dry-run", is_flag=True, help="Fetch domain feeds but don't apply changes")
@click.pass_context
def domain_update(ctx: click.Context, verbose: bool, dry_run: bool) -> None:
    """Update the DNS domain blocklist."""
    if not check_root():
        console.print("[red]Error: This command requires root privileges.[/]")
        console.print("[yellow]Run with: sudo meshwall domain-update[/]")
        sys.exit(1)

    cfg = ctx.obj["config"]
    debug = ctx.obj.get("debug", False)

    if dry_run:
        console.print("[yellow]Dry run mode – no changes will be made[/]")
        cfg.dry_run = True
    else:
        cfg.dry_run = False

    console.print("[bold green]Updating domain blocklists...[/]")

    try:
        updater = DomainFeedUpdater(cfg, debug=debug)
        asyncio.run(asyncio.wait_for(updater.run(verbose=verbose), timeout=300.0))
        console.print("[bold green]Domain update complete.[/]")
    except asyncio.TimeoutError:
        console.print("[red]Update timed out after 5 minutes. Check network or feed URLs.[/]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("[yellow]Update cancelled by user.[/]")
        sys.exit(1)


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show active ipsets, counts, and last update."""
    cfg = ctx.obj["config"]
    ipset = IPSetManager(cfg)
    ipt = IPTablesManager(cfg)

    table = Table(title="MeshWall Status")
    table.add_column("Item", style="cyan")
    table.add_column("Value", style="green")

    sets = ipset.list_sets()
    for set_name, count in sets.items():
        table.add_row(f"IPSet {set_name}", f"{count} entries")

    last_update = cfg.data_dir / "last_update"
    if last_update.exists():
        table.add_row("Last update", last_update.read_text().strip())

    iptables_rules = ipt.list_meshwall_rules()
    table.add_row("IPTables rules", str(len(iptables_rules)))

    console.print(table)


@cli.command()
@click.pass_context
def listen(ctx: click.Context) -> None:
    """Start the active listener daemon (port scan detection)."""
    if not check_root():
        console.print("[red]Error: This command requires root privileges.[/]")
        console.print("[yellow]Run with: sudo meshwall listen[/]")
        sys.exit(1)

    cfg = ctx.obj["config"]
    console.print("[bold green]Starting MeshWall active listener (NFLOG)...[/]")
    from meshwall.listener_nflog import LightListener
    daemon = LightListener(cfg)
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        console.print("[yellow]Listener stopped by user[/]")
        daemon.stop()


@cli.command() # TUI is now since deprecated, cli ref is kept due to maybe in the future i add it back if people want a lighter solution than a full web/flask app
@click.pass_context
def monitor(ctx: click.Context) -> None:
    """Launch the MeshWall web dashboard (replaces the old TUI)."""
    console.print("[yellow]The TUI dashboard has been replaced by the web dashboard. Starting 'meshwall web'...[/]")
    ctx.invoke(web)


@cli.command()
@click.argument("action", type=click.Choice(["add", "remove", "list"]))
@click.argument("ip", required=False)
@click.pass_context
def whitelist(ctx: click.Context, action: str, ip: Optional[str]) -> None:
    """Manage the whitelist."""
    cfg = ctx.obj["config"]
    whitelist_file = cfg.data_dir / "whitelist.txt"
    whitelist_file.parent.mkdir(parents=True, exist_ok=True)

    if action == "list":
        if whitelist_file.exists():
            console.print(whitelist_file.read_text())
        else:
            console.print("[yellow]Whitelist is empty.[/]")
    elif action == "add" and ip:
        with open(whitelist_file, "a") as f:
            f.write(f"{ip}\n")
        console.print(f"[green]Added {ip} to whitelist.[/]")
    elif action == "remove" and ip:
        lines = whitelist_file.read_text().splitlines() if whitelist_file.exists() else []
        new_lines = [l for l in lines if l.strip() != ip]
        whitelist_file.write_text("\n".join(new_lines) + "\n")
        console.print(f"[green]Removed {ip} from whitelist.[/]")
    else:
        console.print("[red]Missing IP address.[/]")


@cli.command()
@click.argument("ip")
@click.pass_context
def trace(ctx: click.Context, ip: str) -> None:
    """Run traceroute and geolocation on an IP."""
    cfg = ctx.obj["config"]
    tracer = IPTracer(cfg)
    result = asyncio.run(tracer.trace(ip))
    console.print_json(data=result)


@cli.command()
@click.option("--tail", is_flag=True)
@click.pass_context
def log(ctx: click.Context, tail: bool) -> None:
    """View the MeshWall log file."""
    cfg = ctx.obj["config"]
    log_path = Path(cfg.log_file)
    if tail:
        import subprocess
        subprocess.run(["tail", "-f", str(log_path)])
    else:
        if log_path.exists():
            console.print(log_path.read_text())
        else:
            console.print("[yellow]Log file not found.[/]")


@cli.command()
@click.pass_context
def stats(ctx: click.Context) -> None:
    """Show summary of blocked attempts."""
    cfg = ctx.obj["config"]
    ipset = IPSetManager(cfg)
    counts = ipset.list_sets()
    total_blocked = sum(counts.values())
    console.print(f"Total blocked IPs: [bold red]{total_blocked}[/]")


@cli.command()
@click.option("--hours", "-h", default=24, help="Number of hours to look back")
@click.pass_context
def summarize(ctx: click.Context, hours: int) -> None:
    """Generate an AI summary of recent scan activity (requires Ollama)."""
    cfg = ctx.obj["config"]

    async def _run():
        summarizer = ScanSummarizer(cfg)
        try:
            console.print("[bold]Analyzing scan events...[/]")
            summary = await summarizer.summarize_recent(hours=hours)
            if summary:
                console.print(summary)
            else:
                console.print("[red]Failed to generate summary. Is Ollama running?[/]")
        finally:
            await summarizer.close()

    asyncio.run(_run())


@cli.command()
@click.argument("question", nargs=-1)
@click.pass_context
def ask(ctx: click.Context, question: tuple) -> None:
    """Ask a question about past scan events (RAG)."""
    cfg = ctx.obj["config"]
    question_str = " ".join(question)

    async def _run():
        summarizer = ScanSummarizer(cfg)
        try:
            console.print("[bold]Thinking...[/]")
            answer = await summarizer.ask(question_str)
            if answer:
                console.print(answer)
            else:
                console.print("[red]Failed to get answer. Is Ollama running?[/]")
        finally:
            await summarizer.close()

    asyncio.run(_run())


@cli.command()
@click.pass_context
def test(ctx: click.Context) -> None:
    """Test connectivity to threat feeds."""
    import aiohttp

    cfg = ctx.obj["config"]
    console.print("[bold]Testing feed connectivity...[/]")

    async def test_url(url):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                start = asyncio.get_event_loop().time()
                async with session.get(url) as resp:
                    elapsed = asyncio.get_event_loop().time() - start
                    return url, resp.status, elapsed, None
        except Exception as e:
            return url, None, None, str(e)

    async def run_tests():
        tasks = [test_url(url) for url in cfg.feed_urls]
        return await asyncio.gather(*tasks)

    results = asyncio.run(run_tests())
    for url, status, elapsed, error in results:
        if error:
            console.print(f"[red]✗ {url}[/] - Error: {error}")
        else:
            color = "green" if status == 200 else "yellow"
            console.print(f"[{color}]✓ {url}[/] - Status: {status}, Time: {elapsed:.2f}s")


@cli.command()
@click.pass_context
def diag(ctx: click.Context) -> None:
    """Diagnose MeshWall environment."""
    cfg = ctx.obj["config"]

    console.print("[bold]MeshWall Diagnostics[/]\n")

    # Check ipset
    console.print("[cyan]Checking ipset...[/]")
    try:
        import subprocess
        ver = subprocess.run(["ipset", "--version"], capture_output=True, text=True, timeout=5)
        if ver.returncode == 0:
            console.print(f"  [green]✓[/] ipset version: {ver.stdout.strip()}")
        else:
            console.print("  [red]✗[/] ipset not working")
    except Exception as e:
        console.print(f"  [red]✗[/] ipset error: {e}")

    # Check iptables
    console.print("[cyan]Checking iptables...[/]")
    try:
        ver = subprocess.run(["iptables", "--version"], capture_output=True, text=True, timeout=5)
        if ver.returncode == 0:
            console.print(f"  [green]✓[/] iptables: {ver.stdout.strip()}")
        else:
            console.print("  [red]✗[/] iptables not working")
    except Exception as e:
        console.print(f"  [red]✗[/] iptables error: {e}")

    # Check data directory
    console.print("[cyan]Data directory...[/]")
    console.print(f"  Path: {cfg.data_dir}")
    console.print(f"  Writable: {'[green]Yes[/]' if os.access(cfg.data_dir, os.W_OK) else '[red]No[/]'}")

    # Test ipset creation
    console.print("[cyan]Testing ipset creation...[/]")
    try:
        subprocess.run(["ipset", "create", "meshwall-test", "hash:net"],
                       capture_output=True, timeout=5, check=True)
        subprocess.run(["ipset", "destroy", "meshwall-test"],
                       capture_output=True, timeout=5)
        console.print("  [green]✓[/] ipset works")
    except Exception as e:
        console.print(f"  [red]✗[/] ipset test failed: {e}")


@cli.command()
@click.option('--host', default=None, help='Bind address')
@click.option('--port', default=None, type=int, help='Port')
@click.pass_context
def web(ctx: click.Context, host: str, port: int) -> None:
    """Start the MeshWall web dashboard."""
    from meshwall.webapp.app import create_app
    app = create_app()
    app.run(
        host=host or '0.0.0.0',
        port=port or 22355,
        debug=False
    )


@cli.command()
@click.pass_context
def init_db(ctx: click.Context) -> None:
    """Create database tables if they don't exist."""
    from meshwall.db import init_db
    init_db()
    console.print("[green]Database tables created successfully.[/]")


def main() -> None:
    """Entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
