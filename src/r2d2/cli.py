"""Typer-based CLI for r2d2."""

from __future__ import annotations

import shlex
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from .analysis.briefing import build_briefing, render_briefing_markdown
from .analysis.handoff import publish_analysis_session
from .analysis.insights import extract_insights, save_lab_note
from .analysis.record import AnalysisRecordStore
from .analysis.result_dto import analysis_result_to_public_dict
from .config import load_config
from .environment import MCPConnectionCheck, EnvironmentReport, detect_environment, detect_mcp_connections
from .environment.ghidra import detect_ghidra
from .environment.ghidra_setup import GhidraSetupError, GhidraSetupResult, setup_ghidra
from .environment.mcp_launcher import MCPLaunchError, MCPLaunchResult, launch_mcp_services
from .llm import ChatMessage as LLMChatMessage, LLMBridge, LLMError
from .llm.prompts import ANALYST_SYSTEM
from .state import AppState, build_state
from .utils.serialization import to_json

app = typer.Typer(add_completion=False)
ghidra_app = typer.Typer(help="Inspect or install a local Ghidra distribution.", add_completion=False)
records_app = typer.Typer(help="List or reopen tagged per-binary analysis records.", add_completion=False)
app.add_typer(ghidra_app, name="ghidra")
app.add_typer(records_app, name="records")
console = Console()


def _emit_json(payload: Any) -> None:
    """Write JSON to stdout without Rich wrapping or ANSI."""
    sys.stdout.write(to_json(payload) + "\n")


@app.command()
def analyze(
    binary: Path = typer.Argument(..., help="Path to ELF or supported binary"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    quick: bool = typer.Option(False, "--quick", help="Quick scan only"),
    skip_deep: bool = typer.Option(False, "--skip-deep", help="Skip deep analysis stage"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of table"),
    brief: bool = typer.Option(False, "--brief", help="Print ranked region briefing instead of the full dump"),
    ask: Optional[str] = typer.Option(None, "--ask", help="Question to ask LLM about the briefing"),
    ask_regions: int = typer.Option(0, "--ask-regions", help="Send the first N region asks to the LLM"),
    tags: Optional[list[str]] = typer.Option(None, "--tag", help="Extra record tags. Repeatable."),
) -> None:
    """Analyze the supplied binary and optionally query the LLM."""

    if not binary.exists():
        raise typer.BadParameter(f"Binary path does not exist: {binary}")

    state: AppState = build_state(config_path)

    plan = state.orchestrator.create_plan(quick_only=quick, skip_deep=skip_deep)
    result = state.orchestrator.analyze(binary, plan)
    record = _persist_record(state, result, binary, extra_tags=tags)
    public = analysis_result_to_public_dict(result, record=record)
    session = _publish_session(state, result, public)
    if session:
        public["session_id"] = session.session_id
    briefing = public.get("briefing") or build_briefing(public)

    if json_output:
        payload = briefing if brief else public
        _emit_json(payload)
    elif brief:
        console.print(render_briefing_markdown(briefing))
    else:
        _render_result(result)
        if record:
            console.print(f"[cyan]Record[/] {record.get('record_id')}  rev {record.get('revision')}  {record.get('directory')}")
        console.print(render_briefing_markdown(briefing, include_asks=False))

    if ask or ask_regions:
        _ask_briefing(state, briefing, question=ask, region_count=ask_regions)


@app.command()
def brief(
    binary: Path = typer.Argument(..., help="Path to ELF, firmware blob, or carved child"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    quick: bool = typer.Option(False, "--quick", help="Quick scan only"),
    skip_deep: bool = typer.Option(False, "--skip-deep", help="Skip deep analysis stage"),
    json_output: bool = typer.Option(False, "--json", help="Emit briefing JSON"),
    ask: bool = typer.Option(False, "--ask", help="Send the overall briefing ask to the LLM"),
    ask_regions: int = typer.Option(0, "--ask-regions", help="Send the first N region asks to the LLM"),
    max_regions: int = typer.Option(6, "--max-regions", help="Cap ranked regions"),
    tags: Optional[list[str]] = typer.Option(None, "--tag", help="Extra record tags. Repeatable."),
) -> None:
    """Break a binary into ranked regions and emit Qwen-sized snippet asks."""

    if not binary.exists():
        raise typer.BadParameter(f"Binary path does not exist: {binary}")

    state: AppState = build_state(config_path)
    plan = state.orchestrator.create_plan(quick_only=quick, skip_deep=skip_deep)
    result = state.orchestrator.analyze(binary, plan)
    record = _persist_record(state, result, binary, extra_tags=tags)
    public = analysis_result_to_public_dict(result, record=record)
    session = _publish_session(state, result, public)
    briefing = build_briefing(result, max_regions=max_regions)
    if record:
        console.print(f"[cyan]Record[/] {record.get('record_id')}  rev {record.get('revision')}  {record.get('directory')}")
    if session:
        console.print(f"[cyan]Session[/] {session.session_id}")

    if json_output:
        _emit_json(briefing)
    else:
        console.print(render_briefing_markdown(briefing))

    if ask or ask_regions:
        _ask_briefing(
            state,
            briefing,
            question=briefing.get("overall_ask") if ask else None,
            region_count=ask_regions,
        )


@app.command("env")
def env_check(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of tables"),
) -> None:
    """Run environment diagnostics (tools, LLM key presence, Ghidra, MCP)."""

    config = load_config(config_path)
    report = detect_environment(config)
    if json_output:
        # Raw stdout so SSH/scripts can pipe this. Do not send it through Rich.
        _emit_json(report)
        return
    _render_env_report(report)


@app.command("mcp")
def mcp_check(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of tables"),
) -> None:
    """Check configured MCP services and show launch commands."""

    config = load_config(config_path)
    checks = detect_mcp_connections(config)
    if json_output:
        _emit_json({name: asdict(check) for name, check in checks.items()})
        return
    _render_mcp_connections(checks)


@app.command("mcp-start")
def mcp_start(
    services: Optional[list[str]] = typer.Option(
        None,
        "--service",
        "-s",
        help="Configured MCP service to start. Repeat for multiple services. Defaults to all configured services.",
    ),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print launch plan without starting processes."),
    foreground: bool = typer.Option(False, "--foreground", help="Run each command in the foreground and wait for exit."),
    log_dir: Optional[Path] = typer.Option(None, "--log-dir", help="Directory for MCP service logs."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of tables"),
) -> None:
    """Start configured MCP analysis services from r2d2."""

    config = load_config(config_path)
    try:
        results = launch_mcp_services(
            config,
            selected=services,
            dry_run=dry_run,
            foreground=foreground,
            log_dir=log_dir,
        )
    except MCPLaunchError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if json_output:
        _emit_json({name: _mcp_launch_to_dict(result) for name, result in results.items()})
        return

    _render_mcp_launch_results(results)


@ghidra_app.command("status")
def ghidra_status(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of text"),
) -> None:
    """Show Ghidra headless/bridge readiness."""

    config = load_config(config_path)
    detection = detect_ghidra(config)
    if json_output:
        _emit_json(_ghidra_detection_to_dict(detection))
        return

    status = "[green]Ready" if detection.is_ready else "[red]Not ready"
    console.print(f"Ghidra: {status}")
    if detection.install_dir:
        console.print(f"Install dir: {detection.install_dir}")
    if detection.headless_path:
        console.print(f"Headless: {detection.headless_path}")
    bridge = "[green]connected" if detection.bridge_ready else "[yellow]not connected"
    console.print(f"Bridge: {bridge}")
    for issue in detection.issues:
        console.print(f"  • [red]{issue}")
    for note in detection.notes:
        console.print(f"  • [cyan]{note}")


@ghidra_app.command("setup")
def ghidra_setup(
    version: Optional[str] = typer.Option(
        None,
        "--version",
        "-v",
        help="Official Ghidra version to resolve via NSA/Ghidra release metadata, for example 11.4.2.",
    ),
    url: Optional[str] = typer.Option(None, "--url", help="Explicit Ghidra .zip archive URL."),
    archive: Optional[Path] = typer.Option(None, "--archive", help="Local Ghidra .zip archive to install."),
    install_root: Path = typer.Option(
        Path("~/.local/share/r2d2/tools").expanduser(),
        "--install-root",
        help="Directory that will contain the extracted Ghidra installation.",
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing install directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Resolve and print the setup plan without downloading/extracting."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of text"),
) -> None:
    """Install Ghidra from a version, explicit URL, or local archive."""

    try:
        result = setup_ghidra(
            version=version,
            url=url,
            archive=archive,
            install_root=install_root,
            force=force,
            dry_run=dry_run,
        )
    except GhidraSetupError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if json_output:
        _emit_json(_ghidra_setup_to_dict(result))
        return

    title = "Ghidra setup plan" if result.dry_run else "Ghidra installed"
    table = Table(title=title, show_header=False)
    if result.version:
        table.add_row("Version", result.version)
    if result.archive_url:
        table.add_row("Archive URL", result.archive_url)
    if result.archive_path:
        table.add_row("Archive", str(result.archive_path))
    table.add_row("Install dir", str(result.install_dir))
    table.add_row("Headless", str(result.headless_path or "-"))
    console.print(table)
    console.print(result.env_line)
    if not result.dry_run:
        console.print("Run `uv run r2d2 ghidra status` after exporting GHIDRA_INSTALL_DIR.")


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


def _publish_session(state: AppState, result: Any, public: dict[str, Any]):
    if not state.chat_dao:
        return None
    try:
        return publish_analysis_session(state.chat_dao, result, public)
    except Exception as exc:
        console.print(f"[yellow]Session not published: {exc}")
        return None


def _persist_record(
    state: AppState,
    result: Any,
    binary: Path,
    *,
    extra_tags: list[str] | None = None,
) -> dict[str, Any] | None:
    try:
        store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
        return store.persist(result, binary=binary, extra_tags=extra_tags)
    except Exception as exc:
        console.print(f"[yellow]Record not persisted: {exc}")
        return None


@records_app.command("list")
def records_list(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """List tagged analysis records."""
    state = build_state(config_path)
    store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
    rows = store.list_records(tag=tag)
    if json_output:
        _emit_json(rows)
        return
    table = Table(title="Analysis records")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Tags")
    table.add_column("Rev")
    table.add_column("Updated")
    for row in rows:
        names = ", ".join(str(name) for name in (row.get("names") or [])[:2]) or "-"
        tags = ", ".join(str(item) for item in (row.get("tags") or [])[:6])
        table.add_row(str(row.get("record_id") or "")[:16], names, tags, str(row.get("revision") or 1), str(row.get("updated_at") or ""))
    console.print(table)


@records_app.command("show")
def records_show(
    record_id: str = typer.Argument(..., help="SHA-256 (or unique prefix)"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    json_output: bool = typer.Option(False, "--json", help="Emit record JSON"),
    blobs: bool = typer.Option(False, "--blobs", help="Include tool/region/CFG blobs"),
) -> None:
    """Reopen a persisted analysis record."""
    state = build_state(config_path)
    store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
    resolved = _resolve_record_id(store, record_id)
    record = store.load(resolved, include_blobs=blobs)
    if not record:
        raise typer.BadParameter(f"Record not found: {record_id}")
    if json_output:
        _emit_json(record)
        return
    console.rule(f"Record {record.get('record_id')}")
    table = Table(show_header=False)
    table.add_row("Directory", str(record.get("directory")))
    table.add_row("Names", ", ".join(record.get("names") or []))
    table.add_row("Tags", ", ".join(record.get("tags") or []))
    table.add_row("Revision", str(record.get("revision")))
    table.add_row("Tools", ", ".join(record.get("tool_names") or []))
    table.add_row("Regions", str(record.get("region_count")))
    table.add_row("CFGs", str(record.get("cfg_count")))
    console.print(table)
    commentary_path = Path(str(record.get("directory") or "")) / "commentary.md"
    if commentary_path.is_file():
        console.print(commentary_path.read_text(encoding="utf-8"))


@app.command()
def insights(
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Restrict to a tag"),
    record_id: Optional[str] = typer.Option(None, "--record", help="Focus on siblings of this record"),
    save: bool = typer.Option(False, "--save", help="Write a lab note under artifacts/insights/"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Distill recurring facts from persisted records. Not a skill writer."""
    state = build_state(config_path)
    store = AnalysisRecordStore(Path(state.config.output.artifacts_dir))
    focus = _resolve_record_id(store, record_id) if record_id else None
    payload = extract_insights(store, focus_id=focus, tag=tag)
    if json_output:
        _emit_json(payload)
        return
    if not payload.get("ready"):
        console.print(f"[yellow]{payload.get('reason')}")
        return
    console.rule(f"Insights from {payload.get('sibling_count')} records")
    for pattern in payload.get("patterns") or []:
        console.print(f"[bold]{pattern.get('title')}[/]")
        console.print(f"  {pattern.get('why')}")
        console.print(f"  next: {pattern.get('next_action')}")
    console.print(payload.get("skill_hint") or "")
    if save:
        path = save_lab_note(store, payload)
        console.print(f"[cyan]Lab note[/] {path}")


def _resolve_record_id(store: AnalysisRecordStore, record_id: str) -> str:
    text = record_id.strip().lower()
    if len(text) >= 64:
        return text
    matches = [row for row in store.list_records(limit=500) if str(row.get("record_id") or "").startswith(text)]
    if len(matches) == 1:
        return str(matches[0]["record_id"])
    if not matches:
        return text
    raise typer.BadParameter(f"Ambiguous record id {record_id}; matches {len(matches)}")


def _ask_briefing(
    state: AppState,
    briefing: dict[str, Any],
    *,
    question: str | None,
    region_count: int,
) -> None:
    """Send compact briefing asks instead of dumping adapter JSON."""
    asks: list[tuple[str, str]] = []
    if question:
        asks.append(("overall", question))
    for region in (briefing.get("regions") or [])[: max(0, region_count)]:
        if isinstance(region, dict) and region.get("ask"):
            asks.append((str(region.get("title") or region.get("id") or "region"), str(region["ask"])))
    if not asks:
        return

    bridge = LLMBridge(state.config)
    context = render_briefing_markdown(briefing, include_asks=False)
    system = ANALYST_SYSTEM
    for title, ask_text in asks:
        messages = [
            LLMChatMessage(role="system", content=system),
            LLMChatMessage(role="user", content=f"{ask_text}\n\nBriefing:\n{context}"),
        ]
        try:
            response = bridge.chat(messages)
        except (LLMError, RuntimeError) as exc:
            console.print(f"[red]LLM unavailable: {exc}")
            return
        console.rule(f"LLM ({bridge.last_provider or 'unknown'}): {title}")
        console.print(response)


def _render_result(result: Any) -> None:
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
    if report.llm:
        llm_table = Table(title="LLM")
        llm_table.add_column("Field")
        llm_table.add_column("Value")
        llm_table.add_row("Provider", report.llm.provider)
        llm_table.add_row("Model", report.llm.model)
        llm_table.add_row("Key env", report.llm.api_key_env or "-")
        llm_table.add_row("Key present", "yes" if report.llm.api_key_present else "no")
        llm_table.add_row("OpenAI-compat URL", report.llm.openai_base_url or "-")
        if report.llm.hint:
            llm_table.add_row("Hint", report.llm.hint)
        console.print(llm_table)

    table = Table(title="Tooling")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Details")
    for tool in report.tools:
        status = "[green]OK" if tool.available else "[red]Missing"
        table.add_row(tool.name, status, tool.version or tool.details or "")
    console.print(table)

    if report.mcp_connections:
        _render_mcp_connections(report.mcp_connections)

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


def _render_mcp_connections(connections: dict[str, MCPConnectionCheck]) -> None:
    mcp_table = Table(title="MCP Connections")
    mcp_table.add_column("Server")
    mcp_table.add_column("Status")
    mcp_table.add_column("Transport")
    mcp_table.add_column("Endpoint")
    mcp_table.add_column("Details")
    for name, check in connections.items():
        status = "[green]Reachable" if check.available else "[red]Unavailable"
        endpoint = check.active_url or check.url or _format_mcp_command(check) or ""
        mcp_table.add_row(name, status, check.transport, endpoint, check.details or "")
    console.print(mcp_table)

    launch_rows = [
        (name, check)
        for name, check in connections.items()
        if check.start_command or check.command or check.working_dir or check.install_hint
    ]
    if not launch_rows:
        return

    launch_table = Table(title="MCP Setup / Launch")
    launch_table.add_column("Server")
    launch_table.add_column("Working Dir")
    launch_table.add_column("Command")
    launch_table.add_column("Hint")
    for name, check in launch_rows:
        launch_table.add_row(
            name,
            check.working_dir or "-",
            _format_mcp_command(check) or "-",
            check.install_hint or "",
        )
    console.print(launch_table)


def _render_mcp_launch_results(results: dict[str, MCPLaunchResult]) -> None:
    table = Table(title="MCP Launch")
    table.add_column("Server")
    table.add_column("Status")
    table.add_column("Command")
    table.add_column("Working Dir")
    table.add_column("PID")
    table.add_column("Details")
    for name, result in results.items():
        status = {
            "started": "[green]Started",
            "planned": "[cyan]Planned",
            "completed": "[green]Completed",
            "skipped": "[yellow]Skipped",
            "disabled": "[yellow]Disabled",
            "failed": "[red]Failed",
        }.get(result.status, result.status)
        table.add_row(
            name,
            status,
            shlex.join(result.command) if result.command else "-",
            result.working_dir or "-",
            str(result.pid) if result.pid else "-",
            result.details,
        )
    console.print(table)


def _format_mcp_command(check: MCPConnectionCheck) -> str | None:
    if check.start_command:
        return shlex.join(check.start_command)
    if check.command:
        return shlex.join([check.command, *check.args])
    return None


def _ghidra_setup_to_dict(result: GhidraSetupResult) -> dict[str, Any]:
    return {
        "archive_url": result.archive_url,
        "archive_path": str(result.archive_path) if result.archive_path else None,
        "install_dir": str(result.install_dir),
        "headless_path": str(result.headless_path) if result.headless_path else None,
        "version": result.version,
        "dry_run": result.dry_run,
        "ready": result.ready,
        "env": result.env_line,
    }


def _ghidra_detection_to_dict(detection: Any) -> dict[str, Any]:
    return {
        "install_dir": str(detection.install_dir) if detection.install_dir else None,
        "headless_path": str(detection.headless_path) if detection.headless_path else None,
        "bridge_available": detection.bridge_available,
        "bridge_connected": detection.bridge_connected,
        "bridge_program_loaded": detection.bridge_program_loaded,
        "extension_root": str(detection.extension_root),
        "issues": detection.issues,
        "notes": detection.notes,
        "ready": detection.is_ready,
    }


def _mcp_launch_to_dict(result: MCPLaunchResult) -> dict[str, Any]:
    return asdict(result)


def run() -> None:
    app()
