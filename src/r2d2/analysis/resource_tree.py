"""Resource tree modelling inspired by OFRAK."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(slots=True)
class Resource:
    """Generic node in the resource tree."""

    kind: str
    name: str
    metadata: dict[str, object] = field(default_factory=dict)
    resource_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    children: list["Resource"] = field(default_factory=list)

    def add_child(self, child: "Resource") -> None:
        self.children.append(child)

    def iter(self) -> Iterable["Resource"]:
        yield self
        for child in self.children:
            yield from child.iter()


@dataclass(slots=True)
class BinaryResource(Resource):
    path: str = ""
    architecture: str | None = None


@dataclass(slots=True)
class FunctionResource(Resource):
    address: int | None = None
    size: int | None = None


@dataclass(slots=True)
class InstructionResource(Resource):
    address: int | None = None
    bytes_: bytes | None = None
    mnemonic: str | None = None


__all__ = [
    "Resource",
    "BinaryResource",
    "FunctionResource",
    "InstructionResource",
]
