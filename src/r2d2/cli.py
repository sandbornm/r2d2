"""Typer-based CLI for r2d2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.json import JSON
from rich.table import Table

from .llm import OpenAIClient
from .state import AppState, build_state
from .utils import to_json

app = typer.Typer(add_completion=False)
console = Console()


@app.command()
def analyze(
    binary: Path = typer.Argument(..., help="Path to ELF or supported binary"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    quick: bool = typer.Option(False, "--quick", help="Quick scan only"),
    skip_deep: bool = typer.Option(False, "--skip-deep", help="Skip deep analysis stage"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of table"),
    ask: Optional[str] = typer.Option(None, "--ask", help="Question to ask LLM about analysis"),
) -> None:
    """Analyze the supplied binary and optionally query the LLM."""

    if not binary.exists():
        raise typer.BadParameter(f"Binary path does not exist: {binary}")

    state: AppState = build_state(config_path)

    plan = state.orchestrator.create_plan(quick_only=quick, skip_deep=skip_deep)
    result = state.orchestrator.analyze(binary, plan)

    if json_output:
        console.print(JSON.from_data(json.loads(to_json(result))))
    else:
        _render_result(result)

    if ask:
        try:
            client = OpenAIClient(state.config)
        except Exception as exc:
            console.print(f"[red]LLM unavailable: {exc}")
        else:
            summary = {
                "quick": result.quick_scan,
                "deep": result.deep_scan,
                "notes": result.notes,
                "issues": result.issues,
            }
            response = client.summarize_analysis({"question": ask, "analysis": summary})
            console.rule("LLM Response")
            console.print(response)


@app.command("env")
def env_check(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
) -> None:
    """Run environment diagnostics."""

    state = build_state(config_path)
    _render_env_report(state.env)


@app.command()
def trajectories(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
) -> None:
    """List stored analysis trajectories."""

    state = build_state(config_path)
    if not state.dao:
        console.print("[yellow]Storage disabled; configure storage.database_path to enable trajectories")
        raise typer.Exit(code=1)

    table = Table(title="Recent Trajectories")
    table.add_column("ID")
    table.add_column("Binary")
    table.add_column("Created")
    table.add_column("Completed")

    for trajectory in state.dao.list_recent():
        table.add_row(
            trajectory.trajectory_id,
            trajectory.binary_path,
            trajectory.created_at.isoformat(),
            trajectory.completed_at.isoformat() if trajectory.completed_at else "-",
        )

    console.print(table)


def _render_result(result) -> None:
    console.rule(f"Analysis: {result.binary.name}")
    meta = result.quick_scan.get("identification", {})
    info = result.quick_scan.get("radare2", {}).get("info", {}) if isinstance(result.quick_scan.get("radare2"), dict) else {}

    table = Table(show_header=False)
    table.add_row("Binary", str(result.binary))
    table.add_row("Type", str(meta.get("description", "unknown")))
    if isinstance(info, dict):
        bin_info = info.get("bin", {})
        if isinstance(bin_info, dict):
            table.add_row("Arch", str(bin_info.get("arch", "?")))
            table.add_row("Bits", str(bin_info.get("bits", "?")))
    console.print(table)

    if result.issues:
        console.print("[red]Issues:")
        for issue in result.issues:
            console.print(f"  • {issue}")

    if result.notes:
        console.print("[cyan]Notes:")
        for note in result.notes:
            console.print(f"  • {note}")


def _render_env_report(report: EnvironmentReport) -> None:
    console.rule("Environment Report")
    table = Table(title="Tooling")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Details")
    for tool in report.tools:
        status = "[green]OK" if tool.available else "[red]Missing"
        table.add_row(tool.name, status, tool.version or tool.details or "")
    console.print(table)

    if report.ghidra:
        ghidra_status = "[green]Ready" if report.ghidra.is_ready else "[red]Not ready"
        console.print(f"Ghidra: {ghidra_status}")
        for issue in report.ghidra.issues:
            console.print(f"  • [red]{issue}")
        for note in report.ghidra.notes:
            console.print(f"  • [cyan]{note}")

    if report.issues:
        console.print("[red]Blocking issues detected:")
        for issue in report.issues:
            console.print(f"  • {issue}")

    if report.notes:
        console.print("[cyan]Notes:")
        for note in report.notes:
            console.print(f"  • {note}")


def run() -> None:
    app()
