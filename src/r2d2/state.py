"""Shared application state helpers for CLI and web entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .analysis import AnalysisOrchestrator
from .config import AppConfig, load_config
from .environment import EnvironmentReport, detect_environment
from .logging import configure_logging
from .storage import ChatDAO, Database, TrajectoryDAO


@dataclass(slots=True)
class AppState:
    config: AppConfig
    env: EnvironmentReport
    dao: TrajectoryDAO | None
    chat_dao: ChatDAO | None
    orchestrator: AnalysisOrchestrator


def build_state(config_path: Optional[Path]) -> AppState:
    """Construct an application state bundle.

    Reuses CLI configuration loading logic so other interfaces (web UI,
    tests) can spin up orchestrator instances with a single call.
    """

    config = load_config(config_path)
    configure_logging(config.verbosity)  # type: ignore[arg-type]

    env = detect_environment(config)

    dao: TrajectoryDAO | None = None
    chat_dao: ChatDAO | None = None
    if config.storage.auto_migrate:
        database = Database(config.storage.database_path)
        dao = TrajectoryDAO(database)
        chat_dao = ChatDAO(database)

    orchestrator = AnalysisOrchestrator(config, env, trajectory_dao=dao)
    return AppState(config=config, env=env, dao=dao, chat_dao=chat_dao, orchestrator=orchestrator)
