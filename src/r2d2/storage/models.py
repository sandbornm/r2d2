"""Domain models for persisted trajectories and analysis artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Sequence
import uuid


@dataclass(slots=True)
class CodeSnippet:
    """A single disassembly snippet from a binary block."""
    
    address: str
    function_name: str | None = None
    function_addr: str | None = None
    bytes_hex: str | None = None
    instructions: list[dict[str, str]] = field(default_factory=list)
    source: str = "unknown"  # "angr" | "radare2" | "capstone"
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "function_name": self.function_name,
            "function_addr": self.function_addr,
            "bytes_hex": self.bytes_hex,
            "instructions": self.instructions,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeSnippet":
        created = data.get("created_at")
        if isinstance(created, str):
            created = datetime.fromisoformat(created)
        elif not isinstance(created, datetime):
            created = datetime.utcnow()
            
        return cls(
            address=data.get("address", "0x0"),
            function_name=data.get("function_name"),
            function_addr=data.get("function_addr"),
            bytes_hex=data.get("bytes_hex"),
            instructions=data.get("instructions", []),
            source=data.get("source", "unknown"),
            created_at=created,
        )


@dataclass(slots=True)
class SnippetStore:
    """Collection of code snippets from an analysis session."""
    
    session_id: str
    binary_path: str
    snippets: list[CodeSnippet] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_snippet(self, snippet: CodeSnippet) -> None:
        self.snippets.append(snippet)
        self.updated_at = datetime.utcnow()
    
    def add_from_angr(self, block_data: dict[str, Any]) -> None:
        """Add snippets from angr CFG block data."""
        instructions = []
        for insn in block_data.get("instructions", []):
            instructions.append({
                "addr": insn.get("addr", ""),
                "mnemonic": insn.get("mnemonic", ""),
                "op_str": insn.get("op_str", ""),
                "bytes": insn.get("bytes", ""),
            })
        
        if instructions:
            self.add_snippet(CodeSnippet(
                address=block_data.get("addr", "0x0"),
                function_name=block_data.get("function_name"),
                function_addr=block_data.get("function"),
                bytes_hex=block_data.get("bytes"),
                instructions=instructions,
                source="angr",
            ))
    
    def add_from_radare2(self, block_data: dict[str, Any]) -> None:
        """Add snippets from radare2 function CFG block data."""
        instructions = []
        for insn in block_data.get("disassembly", []):
            instructions.append({
                "addr": insn.get("addr", ""),
                "opcode": insn.get("opcode", ""),
                "bytes": insn.get("bytes", ""),
            })
        
        if instructions:
            self.add_snippet(CodeSnippet(
                address=block_data.get("offset", "0x0"),
                function_name=block_data.get("function"),
                bytes_hex=None,
                instructions=instructions,
                source="radare2",
            ))
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "binary_path": self.binary_path,
            "snippets": [s.to_dict() for s in self.snippets],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "snippet_count": len(self.snippets),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SnippetStore":
        created = data.get("created_at")
        updated = data.get("updated_at")
        
        if isinstance(created, str):
            created = datetime.fromisoformat(created)
        elif not isinstance(created, datetime):
            created = datetime.utcnow()
            
        if isinstance(updated, str):
            updated = datetime.fromisoformat(updated)
        elif not isinstance(updated, datetime):
            updated = datetime.utcnow()
        
        store = cls(
            session_id=data.get("session_id", ""),
            binary_path=data.get("binary_path", ""),
            created_at=created,
            updated_at=updated,
        )
        
        for snippet_data in data.get("snippets", []):
            store.snippets.append(CodeSnippet.from_dict(snippet_data))
        
        return store


@dataclass(slots=True)
class TrajectoryAction:
    action: str
    payload: Any
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(slots=True)
class AnalysisTrajectory:
    binary_path: str
    trajectory_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    actions: list[TrajectoryAction] = field(default_factory=list)

    def append(self, action: TrajectoryAction) -> None:
        self.actions.append(action)


@dataclass(slots=True)
class ChatSession:
    binary_path: str
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trajectory_id: str | None = None
    title: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    message_count: int = 0


AttachmentType = dict[str, Any]


@dataclass(slots=True)
class ChatMessage:
    session_id: str
    role: str
    content: str
    attachments: Sequence[AttachmentType] = field(default_factory=list)
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=datetime.utcnow)
