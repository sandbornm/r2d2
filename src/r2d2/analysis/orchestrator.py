"""Analysis orchestration pipeline."""

from __future__ import annotations

import logging
import threading
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
from ..adapters.base import AdapterRegistry, AdapterUnavailable, AnalyzerAdapter
from ..adapters import (
    AngrAdapter,
    AutoProfileAdapter,
    CapstoneAdapter,
    DWARFAdapter,
    FridaAdapter,
    GEFAdapter,
    GhidraAdapter,
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

        self._registry = AdapterRegistry(adapters)

    def create_plan(self, *, quick_only: bool = False, skip_deep: bool = False) -> AnalysisPlan:
        plan = AnalysisPlan()
        if quick_only:
            plan.deep = False
        if skip_deep:
            plan.deep = False
        plan.run_angr = self._config.analysis.enable_angr and not quick_only
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
        libmagic = self._registry.get("libmagic") if self._has_adapter("libmagic") else None
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None

        # Run autoprofile first for quick characterization
        if autoprofile:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "autoprofile"})
                profile = autoprofile.quick_scan(binary)
                result.quick_scan["autoprofile"] = profile
                self._record_action(trajectory, "autoprofile.quick", profile)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "autoprofile", "payload": profile},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "autoprofile", "error": str(exc)},
                )

        if libmagic:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "libmagic"})
                info = libmagic.quick_scan(binary)
                result.quick_scan["identification"] = info
                self._record_action(trajectory, "libmagic.quick", info)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "libmagic", "payload": info},
                )
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "libmagic", "error": str(exc)},
                )

        try:
            self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "runtime"})
            runtime_info = get_runtime_requirements(binary)
            if "error" in runtime_info:
                result.quick_scan["runtime"] = {"error": runtime_info["error"]}
            else:
                result.quick_scan["runtime"] = runtime_info.get("runtime", {})
                result.quick_scan["readelf"] = runtime_info.get("readelf", {})
                result.quick_scan["packer"] = runtime_info.get("packer", {})
            self._record_action(trajectory, "runtime.quick", runtime_info)
            self._emit_progress(
                progress_callback,
                "adapter_completed",
                {"stage": "quick", "adapter": "runtime", "payload": runtime_info},
            )
        except Exception as exc:  # pragma: no cover - best effort
            result.notes.append(f"runtime requirements failed: {exc}")
            self._emit_progress(
                progress_callback,
                "adapter_failed",
                {"stage": "quick", "adapter": "runtime", "error": str(exc)},
            )

        if radare:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "quick", "adapter": "radare2"})
                scan = radare.quick_scan(binary)
                result.quick_scan["radare2"] = scan
                result.resource_tree = self._init_resource_tree(binary, scan)
                self._record_action(trajectory, "radare2.quick", scan)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "quick", "adapter": "radare2", "payload": scan},
                )
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "quick", "adapter": "radare2", "error": str(exc)},
                )
        else:
            result.notes.append("radare2 adapter unavailable; quick scan limited")
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

        def update_tool_status(adapter_name: str, payload: dict[str, Any] | None, error: str | None = None) -> None:
            summary = self._summarize_tool_payload(adapter_name, payload, result.quick_scan)
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
            try:
                self._emit_progress(
                    progress_callback, "adapter_started", {"stage": "deep", "adapter": adapter_name}
                )
                payload = runner()
                with lock:
                    result.deep_scan[adapter_name] = payload
                self._record_action(trajectory, f"{adapter_name}.deep", payload)
                self._emit_progress(
                    progress_callback, "adapter_completed", {"stage": "deep", "adapter": adapter_name, "payload": payload}
                )
                update_tool_status(adapter_name, payload)
            except AdapterUnavailable as exc:
                if issue_on_fail:
                    result.issues.append(str(exc))
                if note_on_fail:
                    result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback, "adapter_failed", {"stage": "deep", "adapter": adapter_name, "error": str(exc)}
                )
                update_tool_status(adapter_name, None, error=str(exc))
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None
        ghidra = self._registry.get("ghidra") if self._has_adapter("ghidra") else None
        capstone = self._registry.get("capstone") if self._has_adapter("capstone") else None
        dwarf = self._registry.get("dwarf") if self._has_adapter("dwarf") else None
        # Only get angr adapter if run_angr is enabled in plan
        run_angr = plan.run_angr if plan else self._config.analysis.enable_angr
        angr = self._registry.get("angr") if self._has_adapter("angr") and run_angr else None
        frida = self._registry.get("frida") if self._has_adapter("frida") and self._config.analysis.enable_frida else None
        gef = self._registry.get("gef") if self._has_adapter("gef") and self._config.analysis.enable_gef else None

        if radare:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "radare2"})
                deep = radare.deep_scan(binary, resource_tree=result.resource_tree)
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
                update_tool_status("radare2", deep)
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "radare2", "error": str(exc)},
                )
                update_tool_status("radare2", None, error=str(exc))

        tasks: list[tuple[str, AnalyzerAdapter, Callable[[], dict[str, Any]], bool, bool]] = []

        if ghidra:
            tasks.append((
                "ghidra",
                ghidra,
                lambda: ghidra.deep_scan(binary, resource_tree=result.resource_tree),
                True,
                False,
            ))

        if capstone and result.resource_tree:
            def _capstone_run() -> dict[str, Any]:
                quick = result.quick_scan.get("radare2", {})
                info = quick.get("info", {}) if isinstance(quick, dict) else {}
                arch = info.get("bin", {}).get("arch") if isinstance(info.get("bin"), dict) else None
                entry = info.get("bin", {}).get("baddr") if isinstance(info.get("bin"), dict) else None
                return capstone.quick_scan(binary, arch=arch, entry=entry)

            tasks.append(("capstone", capstone, _capstone_run, False, True))

        if dwarf:
            tasks.append(("dwarf", dwarf, lambda: dwarf.deep_scan(binary), False, True))

        if angr:
            tasks.append(("angr", angr, lambda: angr.deep_scan(binary), False, True))

        if gef:
            tasks.append(("gef", gef, lambda: gef.deep_scan(binary), False, True))

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

        if adapter_name == "angr":
            cfg = payload.get("cfg", {})
            if isinstance(cfg, dict):
                summary["cfg_nodes"] = int(cfg.get("node_count") or 0)
                summary["cfg_edges"] = int(cfg.get("edge_count") or 0)
            names = extract_symbol_names(functions) if isinstance(functions, list) else []
            summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})

        if adapter_name == "ghidra":
            names = extract_symbol_names(functions) if isinstance(functions, list) else []
            summary["memory_allocations"] = sorted({n for n in names if n in alloc_symbols})

        if adapter_name == "capstone":
            summary["warnings"].append("Instruction-only output (no functions/CFG).")
            summary["status"] = "partial"

        if summary["functions_count"] == 0 and summary["cfg_nodes"] == 0 and adapter_name in {"radare2", "angr", "ghidra"}:
            summary["status"] = "partial"
            summary["warnings"].append("No functions/CFG extracted.")

        return summary

    def _build_evidence_coverage(self, result: AnalysisResult) -> dict[str, Any]:
        columns = ["functions", "cfg", "strings", "imports", "runtime", "allocs", "packer"]
        rows = ["radare2", "ghidra", "angr", "capstone", "dwarf", "readelf", "packer"]

        r2_quick = result.quick_scan.get("radare2", {}) if isinstance(result.quick_scan, dict) else {}
        r2_strings = r2_quick.get("strings", []) if isinstance(r2_quick, dict) else []
        r2_imports = r2_quick.get("imports", []) if isinstance(r2_quick, dict) else []

        runtime = result.quick_scan.get("runtime", {})
        readelf = result.quick_scan.get("readelf", {})
        packer = result.quick_scan.get("packer", {})

        def status_cell(value: bool | None) -> str:
            if value is None:
                return "missing"
            return "present" if value else "missing"

        matrix: dict[str, dict[str, str]] = {row: {col: "missing" for col in columns} for row in rows}

        tool_status = result.tool_status or {}
        for tool in ("radare2", "ghidra", "angr", "capstone", "dwarf"):
            summary = tool_status.get(tool, {})
            functions = (summary.get("functions_count") or 0) > 0
            cfg = (summary.get("cfg_nodes") or 0) > 0
            allocs = bool(summary.get("memory_allocations"))
            matrix[tool]["functions"] = status_cell(functions)
            matrix[tool]["cfg"] = "present" if cfg else ("partial" if summary.get("status") == "partial" else "missing")
            matrix[tool]["allocs"] = status_cell(allocs)

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
