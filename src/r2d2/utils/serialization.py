"""Serialization helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def to_json(payload: Any, *, indent: int = 2) -> str:
    def _default(obj: Any) -> Any:
        if is_dataclass(obj):
            return asdict(obj)
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        return str(obj)

    return json.dumps(payload, indent=indent, default=_default)
