"""Progress rendering utilities."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from rich.progress import Progress


@contextmanager
def progress_bar(description: str) -> Iterator[Progress]:
    with Progress() as progress:
        task = progress.add_task(description, total=None)
        try:
            yield progress
        finally:
            progress.update(task, completed=True)
