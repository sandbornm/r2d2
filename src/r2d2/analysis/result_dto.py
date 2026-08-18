"""Single public AnalysisResult contract for SSE, chat attachments, and GET.

Live Flask used to serialize the dataclass with ``asdict`` (SSE) and a
hand-built attachment bag (chat). Those drifted. Every HTTP/CLI consumer
should go through ``analysis_result_to_public_dict``.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .briefing import build_briefing, extract_code_snippets
from .orchestrator import AnalysisResult

PUBLIC_ANALYSIS_TYPE = "analysis_result"


def analysis_result_to_public_dict(
    result: AnalysisResult,
    *,
    session_id: str | None = None,
    snippets: list[dict[str, Any]] | None = None,
    tool_scorecard: dict[str, Any] | None = None,
    briefing: dict[str, Any] | None = None,
    include_briefing: bool = True,
    record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Stable analysis payload shared by SSE, attachments, GET, and CLI JSON."""
    payload = analysis_result_core_dict(result)
    if session_id:
        payload["session_id"] = session_id
    extracted = snippets if snippets is not None else extract_code_snippets(result.deep_scan)
    payload["snippets"] = extracted
    payload["snippet_count"] = len(extracted)
    if tool_scorecard is not None:
        payload["tool_scorecard"] = tool_scorecard
    if include_briefing:
        payload["briefing"] = briefing if briefing is not None else build_briefing(payload)
    if record is not None:
        payload["record"] = record
    return payload


def analysis_result_core_dict(result: AnalysisResult) -> dict[str, Any]:
    """Core fields only. Omits resource_tree (internal, not part of the UI contract)."""
    plan = asdict(result.plan) if result.plan is not None else {}
    return {
        "type": PUBLIC_ANALYSIS_TYPE,
        "schema_version": "r2d2.analysis_result.v1",
        "binary": str(result.binary),
        "plan": plan,
        "quick_scan": result.quick_scan,
        "deep_scan": result.deep_scan,
        "notes": list(result.notes),
        "issues": list(result.issues),
        "trajectory_id": result.trajectory_id,
        "tool_availability": result.tool_availability,
        "tool_status": result.tool_status,
        "evidence_coverage": result.evidence_coverage,
        "analysis_graph": result.analysis_graph,
    }


def ensure_analysis_briefing(analysis: dict[str, Any]) -> dict[str, Any]:
    """Return a briefing, computing one if an older attachment omitted it."""
    existing = analysis.get("briefing")
    if isinstance(existing, dict) and existing.get("regions") is not None:
        return existing
    return build_briefing(analysis)


__all__ = [
    "PUBLIC_ANALYSIS_TYPE",
    "analysis_result_core_dict",
    "analysis_result_to_public_dict",
    "ensure_analysis_briefing",
]
