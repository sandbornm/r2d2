"""Analysis orchestration pipeline."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, cast

from ..config import AppConfig
from ..environment import EnvironmentReport
from ..storage.dao import TrajectoryDAO
from ..storage.models import AnalysisTrajectory, TrajectoryAction
from .resource_tree import BinaryResource, FunctionResource, Resource
from ..adapters.base import AdapterRegistry, AdapterUnavailable, AnalyzerAdapter
from ..adapters import (
    AngrAdapter,
    CapstoneAdapter,
    DWARFAdapter,
    FridaAdapter,
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

        libmagic = self._registry.get("libmagic") if self._has_adapter("libmagic") else None
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None

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
        radare = self._registry.get("radare2") if self._has_adapter("radare2") else None
        ghidra = self._registry.get("ghidra") if self._has_adapter("ghidra") else None
        capstone = self._registry.get("capstone") if self._has_adapter("capstone") else None
        dwarf = self._registry.get("dwarf") if self._has_adapter("dwarf") else None
        # Only get angr adapter if run_angr is enabled in plan
        run_angr = plan.run_angr if plan else self._config.analysis.enable_angr
        angr = self._registry.get("angr") if self._has_adapter("angr") and run_angr else None
        frida = self._registry.get("frida") if self._has_adapter("frida") and self._config.analysis.enable_frida else None

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
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "radare2", "error": str(exc)},
                )

        if ghidra:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "ghidra"})
                ghidra_payload = ghidra.deep_scan(binary, resource_tree=result.resource_tree)
                result.deep_scan["ghidra"] = ghidra_payload
                self._record_action(trajectory, "ghidra.deep", ghidra_payload)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": "ghidra", "payload": ghidra_payload},
                )
            except AdapterUnavailable as exc:
                result.issues.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "ghidra", "error": str(exc)},
                )

        if capstone and result.resource_tree:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "capstone"})
                quick = result.quick_scan.get("radare2", {})
                info = quick.get("info", {}) if isinstance(quick, dict) else {}
                arch = info.get("bin", {}).get("arch") if isinstance(info.get("bin"), dict) else None
                entry = info.get("bin", {}).get("baddr") if isinstance(info.get("bin"), dict) else None
                capstone_payload = capstone.quick_scan(binary, arch=arch, entry=entry)
                result.deep_scan["capstone"] = capstone_payload
                self._record_action(trajectory, "capstone.quick", capstone_payload)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": "capstone", "payload": capstone_payload},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "capstone", "error": str(exc)},
                )

        if dwarf:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "dwarf"})
                dwarf_payload = dwarf.deep_scan(binary)
                result.deep_scan["dwarf"] = dwarf_payload
                self._record_action(trajectory, "dwarf.deep", dwarf_payload)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": "dwarf", "payload": dwarf_payload},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "dwarf", "error": str(exc)},
                )

        if angr:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "angr"})
                angr_payload = angr.deep_scan(binary)
                result.deep_scan["angr"] = angr_payload
                self._record_action(trajectory, "angr.deep", angr_payload)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": "angr", "payload": angr_payload},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "angr", "error": str(exc)},
                )

        if frida:
            try:
                self._emit_progress(progress_callback, "adapter_started", {"stage": "deep", "adapter": "frida"})
                frida_payload = frida.deep_scan(binary)
                result.deep_scan["frida"] = frida_payload
                self._record_action(trajectory, "frida.deep", frida_payload)
                self._emit_progress(
                    progress_callback,
                    "adapter_completed",
                    {"stage": "deep", "adapter": "frida", "payload": frida_payload},
                )
            except AdapterUnavailable as exc:
                result.notes.append(str(exc))
                self._emit_progress(
                    progress_callback,
                    "adapter_failed",
                    {"stage": "deep", "adapter": "frida", "error": str(exc)},
                )

        self._emit_progress(progress_callback, "stage_completed", {"stage": "deep"})

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
