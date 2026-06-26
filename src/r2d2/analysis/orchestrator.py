"""Analysis orchestration pipeline."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, cast

from ..config import AppConfig
from ..environment import EnvironmentReport
from ..storage.dao import TrajectoryDAO
from ..storage.models import AnalysisTrajectory, TrajectoryAction
from .resource_tree import BinaryResource, FunctionResource, Resource
from .runtime_requirements import get_runtime_requirements
from .graph import build_analysis_graph
from ..adapters.base import AdapterRegistry, AdapterUnavailable, AnalyzerAdapter
from ..adapters import (
    AngrAdapter,
    AngrMCPAdapter,
    AutoProfileAdapter,
    CapstoneAdapter,
    DWARFAdapter,
    FirmwareAdapter,
    FridaAdapter,
    GEFAdapter,
    GhidraAdapter,
    GhidraGDBMCPAdapter,
    LibmagicAdapter,
    Radare2Adapter,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalysisPlan:
    quick: bool = True
    deep: bool = True
    run_angr: bool = False
    persist_trajectory: bool = True
    profile: str = "standard"


@dataclass(slots=True)
class AnalysisResult:
    binary: Path
    plan: AnalysisPlan
    trajectory_id: str | None = None
    resource_tree: Resource | None = None
    quick_scan: dict[str, Any] = field(default_factory=dict)
    deep_scan: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    tool_availability: dict[str, bool] = field(default_factory=dict)  # Which tools were available
    tool_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_coverage: dict[str, Any] = field(default_factory=dict)
    analysis_graph: dict[str, Any] = field(default_factory=dict)


class AnalysisOrchestrator:
    """Coordinate analysis adapters according to plan."""

    def __init__(
        self,
        config: AppConfig,
        env: EnvironmentReport,
        trajectory_dao: TrajectoryDAO | None = None,
    ) -> None:
        self._config = config
        self._env = env
        self._trajectory_dao = trajectory_dao

        adapters: list[AnalyzerAdapter] = []
        # AutoProfile runs first for quick characterization
        adapters.append(cast(AnalyzerAdapter, AutoProfileAdapter()))
        adapters.append(cast(AnalyzerAdapter, FirmwareAdapter(
            artifacts_dir=config.output.artifacts_dir / "firmware",
        )))
        adapters.append(cast(AnalyzerAdapter, LibmagicAdapter()))
        adapters.append(cast(AnalyzerAdapter, Radare2Adapter(profile=config.analysis.default_radare_profile)))
        adapters.append(cast(AnalyzerAdapter, CapstoneAdapter()))
        adapters.append(cast(AnalyzerAdapter, DWARFAdapter()))

        if config.analysis.enable_ghidra and env.ghidra:
            adapters.append(cast(AnalyzerAdapter, GhidraAdapter(
                detection=env.ghidra,
                project_dir=config.ghidra.project_dir,
                settings=config.ghidra,
            )))
        if config.analysis.enable_angr:
            adapters.append(cast(AnalyzerAdapter, AngrAdapter()))
        if config.analysis.enable_frida:
            adapters.append(cast(AnalyzerAdapter, FridaAdapter()))
        if config.analysis.enable_gef:
            adapters.append(cast(AnalyzerAdapter, GEFAdapter(
                timeout=config.analysis.gef_timeout,
                max_instructions=config.analysis.gef_max_instructions,
            )))
        if config.mcp.ghidra_gdb.enabled:
            adapters.append(cast(AnalyzerAdapter, GhidraGDBMCPAdapter(
                settings=config.mcp.ghidra_gdb,
                connection=env.mcp_connections.get("ghidra_gdb"),
                scan_timeout=float(config.analysis.timeout_deep),
            )))
        if config.mcp.angr_mcp.enabled:
            adapters.append(cast(AnalyzerAdapter, AngrMCPAdapter(
                settings=config.mcp.angr_mcp,
                connection=env.mcp_connections.get("angr_mcp"),
                scan_timeout=float(config.analysis.timeout_deep),
            )))

        self._registry = AdapterRegistry(adapters)

    def create_plan(
        self,
        *,
        quick_only: bool = False,
        skip_deep: bool = False,
        profile: str | None = None,
    ) -> AnalysisPlan:
        normalized_profile = (profile or ("triage" if quick_only else "standard")).strip().lower()
        if normalized_profile not in {"triage", "standard", "exhaustive"}:
            normalized_profile = "standard"
        plan = AnalysisPlan(profile=normalized_profile)
        if quick_only or normalized_profile == "triage":
            plan.deep = False
        if skip_deep:
            plan.deep = False
        plan.run_angr = self._config.analysis.enable_angr and plan.deep
        if normalized_profile == "exhaustive":
            plan.deep = True
            plan.run_angr = self._config.analysis.enable_angr
        plan.persist_trajectory = self._config.analysis.enable_trajectory_recording
        return plan

    def analyze(
        self,
        binary: Path,
        plan: AnalysisPlan | None = None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> AnalysisResult:
        plan = plan or self.create_plan()
        binary = binary.resolve()
        if self._config.analysis.require_elf:
            self._ensure_elf(binary)
        result = AnalysisResult(binary=binary, plan=plan)

        # Collect tool availability info for transparency
        for adapter in self._registry._adapters:
            try:
                result.tool_availability[adapter.name] = adapter.is_available()
            except Exception:
                result.tool_availability[adapter.name] = False
        for name, check in self._env.mcp_connections.items():
            result.tool_availability.setdefault(name, check.available)
            result.tool_status.setdefault(name, asdict(check))

        self._emit_progress(
            progress_callback,
            "analysis_started",
            {"binary": str(binary), "plan": asdict(plan)},
        )

        trajectory: AnalysisTrajectory | None = None
        if plan.persist_trajectory and self._trajectory_dao:
            trajectory = self._trajectory_dao.start_trajectory(binary)
            result.trajectory_id = trajectory.trajectory_id
            _LOGGER.debug("Trajectory %s started", trajectory.trajectory_id)

        try:
            self._run_quick(binary, result, trajectory, progress_callback)
            if plan.deep:
                self._run_deep(binary, result, trajectory, progress_callback, plan)
            if not result.analysis_graph:
                result.analysis_graph = build_analysis_graph(result)
        finally:
            if trajectory and self._trajectory_dao:
                self._trajectory_dao.finish_trajectory(trajectory)

        self._emit_progress(
            progress_callback,
            "analysis_completed",
            {
                "binary": str(binary),
                "issues": result.issues,
                "notes": result.notes,
            },
        )

        return result

    def _run_quick(
        self,
        binary: Path,
        result: AnalysisResult,
        trajectory: AnalysisTrajectory | None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None,
    ) -> None:
        _LOGGER.info("Starting quick scan: %s", binary)
        self._emit_progress(progress_callback, "stage_started", {"stage": "quick"})

        autoprofile = self._registry.get("autoprofile") if self._has_adapter("autoprofile") else None
        firmware = self._registry.get("firmware") if self._has_adapter("firmware") else None
        libmagic = self._registry.get("libmagic") if self._has_adapter("libmagic") else None
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None

        def elapsed_ms(start: float) -> int:
            return int((time.perf_counter() - start) * 1000)

        def update_quick_status(adapter_name: str, payload: dict[str, Any] | None, start: float, error: str | None = None) -> None:
            summary = self._summarize_tool_payload(adapter_name, payload, result.quick_scan)
            summary["stage"] = "quick"
            summary["duration_ms"] = elapsed_ms(start)
            if error:
                summary["status"] = "failed"
                summary["error"] = error
            result.tool_status[adapter_name] = summary

        # Run autoprofile first for quick characterization
        if autoprofile:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "autoprofile"})
                profile = autoprofile.quick_scan(binary)
                result.quick_scan["autoprofile"] = profile
                update_quick_status("autoprofile", profile, start)
                self._record_action(trajectory, "autoprofile.quick", profile)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "autoprofile", "payload": profile},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                update_quick_status("autoprofile", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "autoprofile", "error": str(exc)},
                )

        if firmware:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "firmware"})
                inventory = firmware.quick_scan(binary)
                result.quick_scan["firmware"] = inventory
                update_quick_status("firmware", inventory, start)
                self._record_action(trajectory, "firmware.quick", inventory)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "firmware", "payload": inventory},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                update_quick_status("firmware", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "firmware", "error": str(exc)},
                )

        if libmagic:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "libmagic"})
                info = libmagic.quick_scan(binary)
                result.quick_scan["identification"] = info
                update_quick_status("libmagic", info, start)
                self._record_action(trajectory, "libmagic.quick", info)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "libmagic", "payload": info},
                )
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                update_quick_status("libmagic", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "libmagic", "error": str(exc)},
                )

        if self._is_elf_subject(binary, result):
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "runtime"})
                runtime_info = get_runtime_requirements(binary)
                if "error" in runtime_info:
                    result.quick_scan["runtime"] = {"error": runtime_info["error"]}
                else:
                    result.quick_scan["runtime"] = runtime_info.get("runtime", {})
                    result.quick_scan["readelf"] = runtime_info.get("readelf", {})
                    result.quick_scan["packer"] = runtime_info.get("packer", {})
                result.tool_status["runtime"] = {
                    "status": "completed" if "error" not in runtime_info else "partial",
                    "stage": "quick",
                    "duration_ms": elapsed_ms(start),
                    "warnings": [str(runtime_info["error"])] if "error" in runtime_info else [],
                }
                self._record_action(trajectory, "runtime.quick", runtime_info)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "runtime", "payload": runtime_info},
                )
            except Exception as exc:  # pragma: no cover - best effort
                result.notes.append(f"runtime requirements failed: {exc}")
                result.tool_status["runtime"] = {
                    "status": "failed",
                    "stage": "quick",
                    "duration_ms": elapsed_ms(start),
                    "error": str(exc),
                }
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "runtime", "error": str(exc)},
                )
        else:
            runtime_info = {
                "skipped": True,
                "reason": "top-level subject is not ELF; firmware inventory should identify embedded analysis targets",
            }
            result.quick_scan["runtime"] = runtime_info
            result.tool_status["runtime"] = {"status": "skipped", "stage": "quick", "duration_ms": 0, **runtime_info}
            self._record_action(trajectory, "runtime.skipped", runtime_info)
            self._emit_progress(
                progress_callback,
                "adapter_skipped",
                {"stage": "quick", "adapter": "runtime", **runtime_info},
            )

        if radare:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "radare2"})
                scan = radare.quick_scan(binary)
                result.quick_scan["radare2"] = scan
                result.resource_tree = self._init_resource_tree(binary, scan)
                update_quick_status("radare2", scan, start)
                self._record_action(trajectory, "radare2.quick", scan)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "radare2", "payload": scan},
                )
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                update_quick_status("radare2", None, start, error=str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "radare2", "error": str(exc)},
                )
        else:
            result.notes.append("radare2 adapter unavailable; quick scan limited")
            result.tool_status["radare2"] = {
                "status": "skipped",
                "stage": "quick",
                "duration_ms": 0,
                "reason": "unavailable",
            }
            self._emit_progress(
                progress_callback,
                "adapter_skipped",
                {"stage": "quick", "adapter": "radare2", "reason": "unavailable"},
            )

        self._emit_progress(progress_callback, "stage_completed", {"stage": "quick"})

    def _run_deep(
        self,
        binary: Path,
        result: AnalysisResult,
        trajectory: AnalysisTrajectory | None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None,
        plan: AnalysisPlan | None = None,
    ) -> None:
        _LOGGER.info("Starting deep analysis: %s", binary)
        self._emit_progress(progress_callback, "stage_started", {"stage": "deep"})
        lock = threading.Lock()

        def update_tool_status(
            adapter_name: str,
            payload: dict[str, Any] | None,
            error: str | None = None,
            duration_ms: int | None = None,
        ) -> None:
            summary = self._summarize_tool_payload(adapter_name, payload, result.quick_scan)
            summary["stage"] = "deep"
            if duration_ms is not None:
                summary["duration_ms"] = duration_ms
            if error:
                summary["status"] = "failed"
                summary["error"] = error
            with lock:
                result.tool_status[adapter_name] = summary

        def run_adapter(
            adapter_name: str,
            adapter: AnalyzerAdapter,
            runner: Callable[[], dict[str, Any]],
            *,
            issue_on_fail: bool,
            note_on_fail: bool,
        ) -> None:
            start = time.perf_counter()
            try:
                self._emit_progress(
                    progress_callback, "adapter_started", {"stage": "deep", "adapter": adapter_name}
                )
                payload = runner()
                duration_ms = int((time.perf_counter() - start) * 1000)
                with lock:
                    result.deep_scan[adapter_name] = payload
                self._record_action(trajectory, f"{adapter_name}.deep", payload)
                self._emit_progress(
                    progress_callback, "adapter_completed", {"stage": "deep", "adapter": adapter_name, "payload": payload}
                )
                update_tool_status(adapter_name, payload, duration_ms=duration_ms)
            except AdapterUnavailable as exc:
                duration_ms = int((time.perf_counter() - start) * 1000)
                if issue_on_fail:
                    result.issues.append(str(exc))
                if note_on_fail:
                    result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback, "adapter_failed", {"stage": "deep", "adapter": adapter_name, "error": str(exc)}
                )
                update_tool_status(adapter_name, None, error=str(exc), duration_ms=duration_ms)
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None
        ghidra = self._registry.get("ghidra") if self._has_adapter("ghidra") else None
        capstone = self._registry.get("capstone") if self._has_adapter("capstone") else None
        dwarf = self._registry.get("dwarf") if self._has_adapter("dwarf") else None
        # Only get angr adapter if run_angr is enabled in plan
        run_angr = plan.run_angr if plan else self._config.analysis.enable_angr
        angr = self._registry.get("angr") if self._has_adapter("angr") and run_angr else None
        gef = self._registry.get("gef") if self._has_adapter("gef") and self._config.analysis.enable_gef else None
        ghidra_gdb = self._registry.get("ghidra_gdb") if self._has_adapter("ghidra_gdb") else None
        angr_mcp = self._registry.get("angr_mcp") if self._has_adapter("angr_mcp") else None
        subject_is_elf = self._is_elf_subject(binary, result)
        non_elf_reason = "top-level subject is not ELF; select an embedded firmware artifact for code analysis"

        def skip_adapter(adapter_name: str, reason: str) -> None:
            payload = {"skipped": True, "reason": reason}
            with lock:
                result.tool_status[adapter_name] = {"status": "skipped", "stage": "deep", "duration_ms": 0, **payload}
            self._record_action(trajectory, f"{adapter_name}.skipped", payload)
            self._emit_progress(
                progress_callback,
                "adapter_skipped",
                {"stage": "deep", "adapter": adapter_name, **payload},
            )

        if not subject_is_elf:
            self._run_firmware_child_fanout(
                result,
                trajectory,
                progress_callback,
                {
                    "radare2": radare,
                    "ghidra": ghidra,
                    "angr": angr,
                    "ghidra_gdb": ghidra_gdb,
                    "angr_mcp": angr_mcp,
                },
            )

        if radare and subject_is_elf:
            start = time.perf_counter()
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "radare2"})
                deep = radare.deep_scan(binary, resource_tree=result.resource_tree)
                duration_ms = int((time.perf_counter() - start) * 1000)
                result.deep_scan["radare2"] = deep
                result.resource_tree = self._populate_tree_from_radare(
                    result.resource_tree, deep
                )
                self._record_action(trajectory, "radare2.deep", deep)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": "radare2", "payload": deep},
                )
                update_tool_status("radare2", deep, duration_ms=duration_ms)
            except AdapterUnavailable as exc:
                duration_ms = int((time.perf_counter() - start) * 1000)
                result.issues.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "radare2", "error": str(exc)},
                )
                update_tool_status("radare2", None, error=str(exc), duration_ms=duration_ms)
        elif radare:
            skip_adapter("radare2", non_elf_reason)

        tasks: list[tuple[str, AnalyzerAdapter, Callable[[], dict[str, Any]], bool, bool]] = []

        if ghidra and subject_is_elf:
            tasks.append((
                "ghidra",
                ghidra,
                lambda: ghidra.deep_scan(binary, resource_tree=result.resource_tree),
                True,
                False,
            ))
        elif ghidra:
            skip_adapter("ghidra", non_elf_reason)

        if capstone and result.resource_tree and subject_is_elf:
            def _capstone_run() -> dict[str, Any]:
                quick = result.quick_scan.get("radare2", {})
                info = quick.get("info", {}) if isinstance(quick, dict) else {}
                arch = info.get("bin", {}).get("arch") if isinstance(info.get("bin"), dict) else None
                entry = info.get("bin", {}).get("baddr") if isinstance(info.get("bin"), dict) else None
                return capstone.quick_scan(binary, arch=arch, entry=entry)

            tasks.append(("capstone", capstone, _capstone_run, False, True))
        elif capstone and not subject_is_elf:
            skip_adapter("capstone", non_elf_reason)

        if dwarf and subject_is_elf:
            tasks.append(("dwarf", dwarf, lambda: dwarf.deep_scan(binary), False, True))
        elif dwarf:
            skip_adapter("dwarf", non_elf_reason)

        if angr and subject_is_elf:
            tasks.append(("angr", angr, lambda: angr.deep_scan(binary), False, True))
        elif angr:
            skip_adapter("angr", non_elf_reason)

        if angr_mcp and subject_is_elf:
            tasks.append(("angr_mcp", angr_mcp, lambda: angr_mcp.deep_scan(binary), False, True))
        elif angr_mcp:
            skip_adapter("angr_mcp", non_elf_reason)

        if gef and subject_is_elf:
            tasks.append(("gef", gef, lambda: gef.deep_scan(binary), False, True))
        elif gef:
            skip_adapter("gef", non_elf_reason)

        if ghidra_gdb and subject_is_elf:
            tasks.append(("ghidra_gdb", ghidra_gdb, lambda: ghidra_gdb.deep_scan(binary), False, True))
        elif ghidra_gdb:
            skip_adapter("ghidra_gdb", non_elf_reason)

        if tasks:
            with ThreadPoolExecutor(max_workers=min(len(tasks), self._config.performance.parallel_functions)) as executor:
                futures = {
                    executor.submit(run_adapter, name, adapter, runner, issue_on_fail=issue, note_on_fail=note): name
                    for name, adapter, runner, issue, note in tasks
                }
                for future in as_completed(futures):
                    future.result()

        self._emit_progress(progress_callback, "stage_completed", {"stage": "deep"})

        result.evidence_coverage = self._build_evidence_coverage(result)
        result.analysis_graph = build_analysis_graph(result)

    def _init_resource_tree(self, binary: Path, scan: dict[str, Any]) -> Resource:
        info = scan.get("info", {}) if isinstance(scan, dict) else {}
        bin_meta = info.get("bin", {}) if isinstance(info, dict) else {}
        architecture = bin_meta.get("arch") if isinstance(bin_meta, dict) else None

        return BinaryResource(
            kind="binary",
            name=binary.name,
            path=str(binary),
            architecture=architecture,
            metadata={"size": bin_meta.get("bintype"), "format": bin_meta.get("class")},
        )

    def _populate_tree_from_radare(
        self,
        resource_tree: Resource | None,
        deep_scan: dict[str, Any],
    ) -> Resource | None:
        if resource_tree is None:
            return None

        functions = deep_scan.get("functions") or []
        if isinstance(functions, list):
            for func in functions[:200]:
                if not isinstance(func, dict):
                    continue
                if any(child.metadata.get("offset") == func.get("offset") for child in resource_tree.children):
                    continue
                function_node = FunctionResource(
                    kind="function",
                    name=str(func.get("name", "func")),
                    metadata=func,
                    address=func.get("offset"),
                    size=func.get("size"),
                )
                resource_tree.add_child(function_node)

        return resource_tree

    def _run_firmware_child_fanout(
        self,
        result: AnalysisResult,
        trajectory: AnalysisTrajectory | None,
        progress_callback: Callable[[str, dict[str, Any]], None] | None,
        adapters: dict[str, AnalyzerAdapter | None],
    ) -> None:
        firmware = result.quick_scan.get("firmware") if isinstance(result.quick_scan, dict) else None
        if not isinstance(firmware, dict):
            return

        fanout_tasks = firmware.get("fanout_tasks")
        carved_targets = firmware.get("carved_targets")
        if not isinstance(fanout_tasks, list) or not isinstance(carved_targets, list):
            return

        code_targets: list[dict[str, Any]] = []
        for target in carved_targets:
            if not isinstance(target, dict):
                continue
            if target.get("analysis_role") == "code" and target.get("carved_path"):
                code_targets.append(target)
        code_targets = code_targets[:4]

        fanout_result: dict[str, Any] = {
            "mode": "firmware_child_fanout",
            "targets": code_targets,
            "tasks": fanout_tasks,
            "analyses": [],
            "skipped": [],
        }

        if not code_targets:
            fanout_result["skipped"].append({
                "reason": "No carved ELF/code targets were found in the firmware inventory.",
            })
            result.deep_scan["firmware_children"] = fanout_result
            self._record_action(trajectory, "firmware_children.skipped", fanout_result)
            return

        adapter_plan = {
            name: adapter
            for name, adapter in adapters.items()
            if adapter is not None and name in {"radare2", "ghidra", "angr", "ghidra_gdb", "angr_mcp"}
        }
        if not adapter_plan:
            fanout_result["skipped"].append({
                "reason": "No code analyzers are available for carved firmware children.",
                "wanted": ["radare2", "ghidra", "angr", "ghidra_gdb", "angr_mcp"],
            })
            result.deep_scan["firmware_children"] = fanout_result
            self._record_action(trajectory, "firmware_children.skipped", fanout_result)
            return

        def run_child_tool(target: dict[str, Any], name: str, adapter: AnalyzerAdapter) -> dict[str, Any]:
            target_path = Path(str(target["carved_path"]))
            payload: dict[str, Any] = {
                "target": str(target_path),
                "offset": target.get("offset"),
                "kind": target.get("kind"),
                "tool": name,
                "status": "completed",
            }
            try:
                self._emit_progress(
                    progress_callback,
                    "adapter_started",
                    {"stage": "deep", "adapter": f"firmware_child.{name}", "binary": str(target_path)},
                )
                if name == "radare2":
                    quick = adapter.quick_scan(target_path)
                    deep = adapter.deep_scan(target_path)
                    payload["quick"] = quick
                    payload["deep"] = deep
                else:
                    payload["deep"] = adapter.deep_scan(target_path)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": f"firmware_child.{name}", "payload": payload},
                )
            except Exception as exc:
                payload["status"] = "failed"
                payload["error"] = str(exc)
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": f"firmware_child.{name}", "error": str(exc)},
                )
            return payload

        jobs: list[tuple[dict[str, Any], str, AnalyzerAdapter]] = []
        for target in code_targets:
            requested_tools = target.get("fanout_tools") if isinstance(target.get("fanout_tools"), list) else []
            for name, adapter in adapter_plan.items():
                if name in requested_tools:
                    jobs.append((target, name, adapter))

        if not jobs:
            fanout_result["skipped"].append({
                "reason": "Carved code targets did not request any currently available analyzer.",
                "available": sorted(adapter_plan),
            })
        else:
            with ThreadPoolExecutor(max_workers=min(len(jobs), self._config.performance.parallel_functions)) as executor:
                futures = [executor.submit(run_child_tool, target, name, adapter) for target, name, adapter in jobs]
                for future in as_completed(futures):
                    fanout_result["analyses"].append(future.result())

        result.deep_scan["firmware_children"] = fanout_result
        self._record_action(trajectory, "firmware_children.fanout", fanout_result)

    def _has_adapter(self, name: str) -> bool:
        try:
            self._registry.get(name)
        except AdapterUnavailable:
            return False
        return True

    def _record_action(
        self,
        trajectory: AnalysisTrajectory | None,
        action: str,
        payload: Any,
    ) -> None:
        if not trajectory or not self._trajectory_dao:
            return
        action_entry = TrajectoryAction(action=action, payload=payload)
        self._trajectory_dao.append_action(trajectory, action_entry)

    def _summarize_tool_payload(
        self,
        adapter_name: str,
        payload: dict[str, Any] | None,
        quick_scan: dict[str, Any],
    ) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "status": "completed" if payload else "failed",
            "functions_count": 0,
            "cfg_nodes": 0,
            "cfg_edges": 0,
            "memory_allocations": [],
            "warnings": [],
        }
        if not payload:
            return summary

        def extract_symbol_names(entries: list[dict[str, Any]]) -> list[str]:
            names: list[str] = []
            for entry in entries:
                name = entry.get("name")
                if isinstance(name, str):
                    names.append(name)
            return names

        alloc_symbols = {
            "malloc",
            "calloc",
            "realloc",
            "free",
            "new",
            "delete",
            "operator_new",
            "operator_delete",
            "mmap",
            "brk",
        }

        functions = payload.get("functions", [])
        if isinstance(functions, list):
            summary["functions_count"] = len(functions)

        if adapter_name == "radare2":
            function_cfgs = payload.get("function_cfgs", [])
            if isinstance(function_cfgs, list):
                block_count = 0
                edge_count = 0
                for fn in function_cfgs:
                    blocks = fn.get("blocks", []) if isinstance(fn, dict) else []
                    if isinstance(blocks, list):
                        block_count += len(blocks)
                        for block in blocks:
                            if not isinstance(block, dict):
                                continue
                            if block.get("jump"):
                                edge_count += 1
                            if block.get("fail"):
                                edge_count += 1
                summary["cfg_nodes"] = block_count
                summary["cfg_edges"] = edge_count
            imports = quick_scan.get("radare2", {}).get("imports", [])
            if isinstance(imports, list):
                names = extract_symbol_names(imports)
                summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})

        if adapter_name in {"angr", "angr_mcp"}:
            cfg = payload.get("cfg", {})
            if isinstance(cfg, dict):
                summary["cfg_nodes"] = int(cfg.get("node_count") or cfg.get("nodes") or 0)
                summary["cfg_edges"] = int(cfg.get("edge_count") or cfg.get("edges") or 0)
            names = extract_symbol_names(functions) if isinstance(functions, list) else []
            summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})
            if adapter_name == "angr_mcp" and payload.get("errors"):
                summary["status"] = "partial"
                summary["warnings"].append(f"{len(payload['errors'])} MCP tool call(s) returned errors.")

        if adapter_name == "ghidra":
            names = extract_symbol_names(functions) if isinstance(functions, list) else []
            summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})

        if adapter_name == "ghidra_gdb":
            summary["status"] = "completed"
            if payload.get("errors"):
                summary["warnings"].append(f"{len(payload['errors'])} endpoint(s) returned errors.")
                summary["status"] = "partial"
            imports = payload.get("imports")
            if isinstance(imports, list):
                names = extract_symbol_names(imports)
                summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})
            cfg = payload.get("cfg")
            if isinstance(cfg, dict):
                summary["cfg_nodes"] = int(cfg.get("node_count") or 0)
                summary["cfg_edges"] = int(cfg.get("edge_count") or 0)
            summary["strings_count"] = len(payload.get("strings") or []) if isinstance(payload.get("strings"), list) else 0
            summary["sections_count"] = len(payload.get("sections") or []) if isinstance(payload.get("sections"), list) else 0

        if adapter_name == "firmware":
            summary["status"] = "completed"
            artifacts = payload.get("embedded_artifacts")
            targets = payload.get("recommended_targets")
            summary["artifact_count"] = len(artifacts) if isinstance(artifacts, list) else 0
            summary["recommended_target_count"] = len(targets) if isinstance(targets, list) else 0
            summary["top_level_format"] = payload.get("top_level_format")
            summary["container_type"] = payload.get("container_type")

        if adapter_name == "capstone":
            summary["warnings"].append("Instruction-only output (no functions/CFG).")
            summary["status"] = "partial"

        if summary["functions_count"] == 0 and summary["cfg_nodes"] == 0 and adapter_name in {"radare2", "angr", "angr_mcp", "ghidra"}:
            summary["status"] = "partial"
            summary["warnings"].append("No functions/CFG extracted.")

        return summary

    def _build_evidence_coverage(self, result: AnalysisResult) -> dict[str, Any]:
        columns = ["functions", "cfg", "strings", "imports", "runtime", "allocs", "packer"]
        rows = ["firmware", "radare2", "ghidra", "ghidra_gdb", "angr", "angr_mcp", "capstone", "dwarf", "readelf", "packer"]

        r2_quick = result.quick_scan.get("radare2", {}) if isinstance(result.quick_scan, dict) else {}
        r2_strings = r2_quick.get("strings", []) if isinstance(r2_quick, dict) else []
        r2_imports = r2_quick.get("imports", []) if isinstance(r2_quick, dict) else []

        runtime = result.quick_scan.get("runtime", {})
        packer = result.quick_scan.get("packer", {})

        def status_cell(value: bool | None) -> str:
            if value is None:
                return "missing"
            return "present" if value else "missing"

        matrix: dict[str, dict[str, str]] = {row: {col: "missing" for col in columns} for row in rows}

        firmware = result.quick_scan.get("firmware", {}) if isinstance(result.quick_scan, dict) else {}
        if isinstance(firmware, dict):
            matrix["firmware"]["strings"] = "partial" if firmware.get("embedded_artifacts") else "missing"
            matrix["firmware"]["runtime"] = "partial" if firmware.get("recommended_targets") else "missing"

        tool_status = result.tool_status or {}
        for tool in ("radare2", "ghidra", "ghidra_gdb", "angr", "angr_mcp", "capstone", "dwarf"):
            summary = tool_status.get(tool, {})
            functions = (summary.get("functions_count") or 0) > 0
            cfg = (summary.get("cfg_nodes") or 0) > 0
            allocs = bool(summary.get("memory_allocations"))
            matrix[tool]["functions"] = status_cell(functions)
            matrix[tool]["cfg"] = "present" if cfg else ("partial" if summary.get("status") == "partial" else "missing")
            matrix[tool]["allocs"] = status_cell(allocs)

        ghidra_gdb = result.deep_scan.get("ghidra_gdb", {}) if isinstance(result.deep_scan, dict) else {}
        if isinstance(ghidra_gdb, dict):
            matrix["ghidra_gdb"]["strings"] = status_cell(bool(ghidra_gdb.get("strings")))
            matrix["ghidra_gdb"]["imports"] = status_cell(bool(ghidra_gdb.get("imports")))

        matrix["radare2"]["strings"] = status_cell(len(r2_strings) > 0)
        matrix["radare2"]["imports"] = status_cell(len(r2_imports) > 0)

        matrix["readelf"]["runtime"] = status_cell(bool(runtime) and "error" not in runtime)
        matrix["readelf"]["imports"] = status_cell(bool(runtime) and bool(runtime.get("needed")))
        matrix["readelf"]["strings"] = "missing"

        matrix["packer"]["packer"] = status_cell(bool(packer) and bool(packer.get("detected")))
        if packer and packer.get("detected") is False:
            matrix["packer"]["packer"] = "partial"

        return {
            "columns": columns,
            "rows": rows,
            "matrix": matrix,
        }

    def _emit_progress(
        self,
        callback: Callable[[str, dict[str, Any]], None] | None,
        event: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        if not callback:
            return
        try:
            callback(event, payload or {})
        except Exception:  # pragma: no cover - defensive hook
            _LOGGER.exception("Progress callback failed for event %s", event)

    def _ensure_elf(self, binary: Path) -> None:
        try:
            with binary.open("rb") as handle:
                magic = handle.read(4)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"Binary not found: {binary}") from exc
        except OSError as exc:  # pragma: no cover - unexpected IO error
            raise RuntimeError(f"Unable to read binary {binary}: {exc}") from exc

        if magic != b"\x7fELF":
            raise ValueError(
                f"{binary} is not an ELF binary (expected 0x7f454c46 header, got {magic!r})"
            )

    def _is_elf_subject(self, binary: Path, result: AnalysisResult | None = None) -> bool:
        firmware = (result.quick_scan.get("firmware") if result and isinstance(result.quick_scan, dict) else None)
        if isinstance(firmware, dict) and isinstance(firmware.get("is_elf"), bool):
            return bool(firmware["is_elf"])
        try:
            with binary.open("rb") as handle:
                return handle.read(4) == b"\x7fELF"
        except OSError:
            return False
