"""Investigation/provenance graph for analysis sessions.

This graph answers "where have we been and what did we do?" while
``analysis_graph`` answers "what did we find in the subject under test?".
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..storage.models import ChatMessage, ChatSession


INVESTIGATION_SCHEMA_VERSION = "r2d2.investigation_graph.v1"


class InvestigationNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    label: str
    actor: str | None = None
    timestamp: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class InvestigationEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    source: str
    target: str
    properties: dict[str, Any] = Field(default_factory=dict)


class InvestigationGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = INVESTIGATION_SCHEMA_VERSION
    session_id: str
    binary: str
    generated_at: str
    nodes: list[InvestigationNode] = Field(default_factory=list)
    edges: list[InvestigationEdge] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class _InvestigationAccumulator:
    def __init__(self, session: ChatSession) -> None:
        self.session = session
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.session_node_id = _node_id("session", session.session_id)
        self.binary_node_id = _node_id("subject", session.binary_path)

        self.add_node(
            self.session_node_id,
            kind="session",
            label=session.title or "Investigation",
            timestamp=session.created_at.isoformat(),
            properties={"session_id": session.session_id, "trajectory_id": session.trajectory_id},
        )
        self.add_node(
            self.binary_node_id,
            kind="subject",
            label=session.binary_path.split("/")[-1] or session.binary_path,
            properties={"binary_path": session.binary_path},
        )
        self.add_edge("investigates", self.session_node_id, self.binary_node_id)

    def add_node(
        self,
        node_id: str,
        *,
        kind: str,
        label: str,
        actor: str | None = None,
        timestamp: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "kind": kind,
                "label": label,
                "actor": actor,
                "timestamp": timestamp,
                "properties": _json_dict(properties or {}),
            }
            return node_id
        existing = self.nodes[node_id]
        existing["properties"].update(
            {key: value for key, value in _json_dict(properties or {}).items() if key not in existing["properties"]}
        )
        if timestamp and not existing.get("timestamp"):
            existing["timestamp"] = timestamp
        return node_id

    def add_edge(self, kind: str, source: str, target: str, properties: dict[str, Any] | None = None) -> str:
        edge_id = _stable_id("edge", kind, source, target)
        if edge_id not in self.edges:
            self.edges[edge_id] = {
                "id": edge_id,
                "kind": kind,
                "source": source,
                "target": target,
                "properties": _json_dict(properties or {}),
            }
        return edge_id

    def to_graph(self) -> dict[str, Any]:
        nodes = [InvestigationNode.model_validate(node) for node in self.nodes.values()]
        edges = [InvestigationEdge.model_validate(edge) for edge in self.edges.values()]
        graph = InvestigationGraph(
            session_id=self.session.session_id,
            binary=self.session.binary_path,
            generated_at=datetime.now(timezone.utc).isoformat(),
            nodes=nodes,
            edges=edges,
            summary=_build_summary(nodes, edges),
        )
        return graph.model_dump(mode="json")


def build_investigation_graph(
    session: ChatSession,
    *,
    messages: Iterable[ChatMessage] = (),
    activities: Iterable[dict[str, Any]] = (),
    trajectory_actions: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Build a graph of human/model/agent/tool actions for one session."""

    acc = _InvestigationAccumulator(session)
    actor_nodes = {
        "human": acc.add_node("actor:human", kind="actor", label="Human", actor="human"),
        "agent": acc.add_node("actor:agent", kind="actor", label="r2d2 Agent", actor="agent"),
        "model": acc.add_node("actor:model", kind="actor", label="Model", actor="model"),
        "tool": acc.add_node("actor:tool", kind="actor", label="Tooling", actor="tool"),
    }

    event_nodes: list[tuple[str | None, str]] = []

    for row in trajectory_actions:
        event_id, timestamp = _trajectory_event(acc, row)
        event_nodes.append((timestamp, event_id))
        acc.add_edge("performed_by", actor_nodes["tool"], event_id)
        acc.add_edge("acted_on", event_id, acc.binary_node_id)

    for activity in activities:
        event_id, timestamp = _activity_event(acc, activity)
        event_nodes.append((timestamp, event_id))
        acc.add_edge("performed_by", actor_nodes["human"], event_id)
        acc.add_edge("acted_on", event_id, acc.binary_node_id)

    for message in messages:
        event_id, timestamp, actor_key = _message_event(acc, message)
        event_nodes.append((timestamp, event_id))
        acc.add_edge("performed_by", actor_nodes[actor_key], event_id)
        for attachment in message.attachments or []:
            if isinstance(attachment, dict):
                _attach_message_artifact(acc, event_id, attachment)

    ordered = sorted(
        event_nodes,
        key=lambda item: item[0] or "",
    )
    previous = acc.session_node_id
    for index, (_, node_id) in enumerate(ordered, start=1):
        acc.add_edge("then", previous, node_id, {"step": index})
        previous = node_id

    return acc.to_graph()


def _trajectory_event(acc: _InvestigationAccumulator, row: dict[str, Any]) -> tuple[str, str | None]:
    action = _row_get(row, "action", "tool.action")
    seq = _row_get(row, "seq")
    timestamp = _row_get(row, "created_at")
    payload = _decode_payload(_row_get(row, "payload"))
    event_id = _node_id("trajectory", f"{seq}:{action}")
    acc.add_node(
        event_id,
        kind="tool_action",
        label=_humanize_action(action),
        actor="tool",
        timestamp=timestamp,
        properties={"action": action, "seq": seq, "payload_preview": _preview(payload)},
    )
    tool_name = str(action).split(".", 1)[0]
    if tool_name and tool_name != action:
        tool_id = _node_id("tool", tool_name)
        acc.add_node(tool_id, kind="tool", label=tool_name, actor="tool")
        acc.add_edge("used_tool", event_id, tool_id)
    return event_id, timestamp


def _activity_event(acc: _InvestigationAccumulator, activity: dict[str, Any]) -> tuple[str, str | None]:
    event_type = _row_get(activity, "event_type", "activity")
    event_data = _decode_payload(_row_get(activity, "event_data")) or {}
    timestamp = _row_get(activity, "created_at")
    event_id = _node_id("activity", _row_get(activity, "event_id", _stable_id("activity", event_type, timestamp)))
    acc.add_node(
        event_id,
        kind="human_action",
        label=_humanize_action(event_type),
        actor="human",
        timestamp=timestamp,
        properties={"event_type": event_type, "event_data": event_data},
    )
    address = event_data.get("address") if isinstance(event_data, dict) else None
    if address:
        artifact_id = _node_id("address", address)
        acc.add_node(artifact_id, kind="address", label=str(address), properties={"address": address})
        acc.add_edge("inspected", event_id, artifact_id)
    return event_id, timestamp


def _message_event(acc: _InvestigationAccumulator, message: ChatMessage) -> tuple[str, str | None, str]:
    actor_key = "model" if message.role == "assistant" else "human" if message.role == "user" else "agent"
    event_id = _node_id("message", message.message_id)
    label = f"{message.role.title()} message"
    if message.content:
        label = message.content.strip().splitlines()[0][:80] or label
    acc.add_node(
        event_id,
        kind="message",
        label=label,
        actor=actor_key,
        timestamp=message.created_at.isoformat(),
        properties={
            "role": message.role,
            "message_id": message.message_id,
            "content_preview": message.content[:800],
            "attachment_count": len(message.attachments or []),
        },
    )
    return event_id, message.created_at.isoformat(), actor_key


def _attach_message_artifact(
    acc: _InvestigationAccumulator,
    event_id: str,
    attachment: dict[str, Any],
) -> None:
    attachment_type = str(attachment.get("type") or "attachment")
    artifact_id = _node_id("artifact", f"{event_id}:{attachment_type}")
    label = attachment_type.replace("_", " ").title()
    acc.add_node(
        artifact_id,
        kind="artifact",
        label=label,
        properties={
            "type": attachment_type,
            "keys": sorted(str(key) for key in attachment.keys())[:30],
        },
    )
    edge_kind = "produced" if attachment_type in {"analysis_result", "llm_response_meta"} else "attached"
    acc.add_edge(edge_kind, event_id, artifact_id)

    if attachment_type == "analysis_result":
        for graph_key in ("analysis_graph", "investigation_graph"):
            graph = attachment.get(graph_key)
            if isinstance(graph, dict):
                graph_id = _node_id("graph", f"{event_id}:{graph_key}")
                summary = graph.get("summary") or {}
                acc.add_node(
                    graph_id,
                    kind="graph_artifact",
                    label=graph_key.replace("_", " ").title(),
                    properties={"schema_version": graph.get("schema_version"), "summary": summary},
                )
                acc.add_edge("summarized_as", artifact_id, graph_id)


def _build_summary(nodes: list[InvestigationNode], edges: list[InvestigationEdge]) -> dict[str, Any]:
    node_kinds = Counter(node.kind for node in nodes)
    edge_kinds = Counter(edge.kind for edge in edges)
    actor_counts = Counter(node.actor for node in nodes if node.actor)
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_kinds": dict(sorted(node_kinds.items())),
        "edge_kinds": dict(sorted(edge_kinds.items())),
        "actor_counts": dict(sorted(actor_counts.items())),
        "event_count": sum(node_kinds[kind] for kind in ("tool_action", "human_action", "message")),
    }


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return getattr(row, key, default)


def _decode_payload(value: Any) -> Any:
    if value is None or isinstance(value, dict | list):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _preview(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _preview(val) for key, val in list(value.items())[:20]}
    if isinstance(value, list):
        return [_preview(item) for item in value[:10]]
    if isinstance(value, str):
        return value[:800]
    return value


def _humanize_action(value: Any) -> str:
    text = str(value).replace("_", " ").replace(".", " / ").strip()
    return text[:1].upper() + text[1:] if text else "Action"


def _node_id(kind: str, key: Any) -> str:
    text = str(key)
    safe = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", text).strip("_")[:96]
    if safe:
        return f"{kind}:{safe}"
    return _stable_id(kind, text)


def _stable_id(prefix: str, *parts: Any) -> str:
    digest = hashlib.sha1("|".join(str(part) for part in parts).encode()).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _json_dict(payload: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _json_value(value) for key, value in payload.items() if value is not None}


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value[:4000]
    if isinstance(value, dict):
        return {str(key): _json_value(val) for key, val in value.items() if val is not None}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in list(value)[:200]]
    return str(value)


__all__ = [
    "INVESTIGATION_SCHEMA_VERSION",
    "InvestigationEdge",
    "InvestigationGraph",
    "InvestigationNode",
    "build_investigation_graph",
]
