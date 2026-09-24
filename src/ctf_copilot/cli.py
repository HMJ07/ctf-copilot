"""Command-line interface for ctf-copilot (``ctfc`` / ``ctf-copilot``)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ctf_copilot import __version__
from ctf_copilot.models import ParseResult, Suggestion
from ctf_copilot.notebook import append_session, notebook_path, read_notebook
from ctf_copilot.parsers import detect_and_parse, parse_with
from ctf_copilot.rules import load_default_engine

console = Console()
error_console = Console(stderr=True, style="bold red")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfc",
        description="Local-first recon copilot for CTFs and pentests.",
    )
    parser.add_argument("--version", action="version", version=f"ctf-copilot {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    feed = subparsers.add_parser(
        "feed", help="Parse tool output (file or stdin) and log findings/suggestions."
    )
    feed.add_argument("input", help="Path to a file, or '-' to read from stdin.")
    feed.add_argument("--target", required=True, help="Target host/IP this output is about.")
    feed.add_argument(
        "--tool",
        choices=["auto", "nmap", "dirscan"],
        default="auto",
        help="Force a specific parser instead of auto-detecting (default: auto).",
    )
    feed.add_argument(
        "--llm",
        action="store_true",
        help="Also ask the configured LLM backend for extra suggestions (network call).",
    )
    feed.add_argument(
        "--no-notebook",
        action="store_true",
        help="Don't write to the target's notebook, just print to the terminal.",
    )
    feed.set_defaults(handler=cmd_feed)

    notes = subparsers.add_parser("notes", help="Show the running notebook for a target.")
    notes.add_argument("target", help="Target host/IP.")
    notes.add_argument(
        "--path", action="store_true", help="Print only the notebook's file path."
    )
    notes.set_defaults(handler=cmd_notes)

    suggest = subparsers.add_parser(
        "suggest", help="One-off rule lookup for a service/version, no file needed."
    )
    suggest.add_argument("--service", required=True, help="Service name, e.g. smb, ftp, http.")
    suggest.add_argument("--version", default="", help="Product/version banner text, e.g. 'Samba 4.3.9'.")
    suggest.add_argument("--port", type=int, default=None, help="Port number (optional).")
    suggest.add_argument("--target", default="", help="Target placeholder for command templates.")
    suggest.set_defaults(handler=cmd_suggest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (ValueError, FileNotFoundError) as exc:
        error_console.print(f"Error: {exc}")
        return 1


def _read_input(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"No such file: {source}")
    return path.read_text(encoding="utf-8", errors="replace")


def cmd_feed(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    if args.tool == "auto":
        result = detect_and_parse(text)
    else:
        result = parse_with(args.tool, text)

    if not result.host:
        result.host = args.target

    engine = load_default_engine()
    suggestions: list[Suggestion] = engine.suggest_all(result.ports, result.paths, args.target)

    if args.llm:
        suggestions = suggestions + _maybe_llm_suggestions(result, args.target, suggestions)

    _render_findings(result)
    _render_suggestions(suggestions)

    if not args.no_notebook:
        source_label = args.input if args.input != "-" else "stdin"
        note_path = append_session(args.target, result, suggestions, source_label)
        console.print(f"\n[dim]Logged to {note_path}[/dim]")

    return 0


def _maybe_llm_suggestions(result: ParseResult, target: str, existing: list[Suggestion]):
    from ctf_copilot.llm import LLMError, get_llm_suggestions

    try:
        return get_llm_suggestions(result, target, existing)
    except LLMError as exc:
        error_console.print(f"[yellow]LLM suggestions skipped:[/yellow] {exc}")
        return []


def cmd_notes(args: argparse.Namespace) -> int:
    path = notebook_path(args.target)
    if args.path:
        console.print(str(path))
        return 0

    content = read_notebook(args.target)
    if not content:
        console.print(
            f"[yellow]No notebook yet for '{args.target}'.[/yellow] "
            f"It will be created at: {path}"
        )
        return 0

    console.print(content, markup=False, highlight=False)
    return 0


def cmd_suggest(args: argparse.Namespace) -> int:
    engine = load_default_engine()
    suggestions = engine.suggest_for_service(
        service=args.service, version=args.version, port=args.port, target=args.target
    )
    if not suggestions:
        console.print(
            f"[yellow]No rule matched service='{args.service}' version='{args.version}'.[/yellow]"
        )
        return 0
    _render_suggestions(sorted(suggestions, key=lambda s: s.priority, reverse=True))
    return 0


def _render_findings(result: ParseResult) -> None:
    if result.ports:
        table = Table(title="Ports / services", show_lines=False)
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("State", style="green")
        table.add_column("Service", style="magenta")
        table.add_column("Banner")
        for port_finding in sorted(result.ports, key=lambda p: p.port):
            table.add_row(
                f"{port_finding.port}/{port_finding.protocol}",
                port_finding.state,
                port_finding.service,
                port_finding.banner,
            )
        console.print(table)

    if result.paths:
        table = Table(title="Discovered paths", show_lines=False)
        table.add_column("Path", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Size", style="magenta")
        for path_finding in result.paths:
            status = str(path_finding.status) if path_finding.status is not None else ""
            size = str(path_finding.size) if path_finding.size is not None else ""
            table.add_row(path_finding.path, status, size)
        console.print(table)

    if not result.ports and not result.paths:
        console.print("[yellow]No structured findings extracted from this input.[/yellow]")


def _render_suggestions(suggestions: list[Suggestion]) -> None:
    if not suggestions:
        console.print("[dim]No suggestions.[/dim]")
        return

    for suggestion in suggestions:
        stars = "*" * suggestion.priority
        title = f"[{stars}] {suggestion.text}"
        body = f"[bold]$[/bold] {suggestion.command}" if suggestion.command else ""
        style = "red" if suggestion.priority >= 4 else "yellow" if suggestion.priority >= 3 else "blue"
        source_tag = " (llm)" if suggestion.source == "llm" else ""
        console.print(
            Panel(body or "(no command)", title=title + source_tag, border_style=style)
        )


if __name__ == "__main__":
    raise SystemExit(main())
