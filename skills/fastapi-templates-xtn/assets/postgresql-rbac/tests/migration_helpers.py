import importlib.util
from pathlib import Path
from types import ModuleType

from alembic.config import Config

MIGRATION_VERSIONS = Path(__file__).resolve().parents[1] / "alembic" / "versions"


def alembic_config() -> Config:
    """Let the embedding test process retain ownership of its logging setup."""
    root = MIGRATION_VERSIONS.parent.parent
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    config.attributes["configure_logger"] = False
    return config


def load_migration(filename: str) -> ModuleType:
    """Execute a fresh revision module so tests never share patched module state."""
    migration_path = MIGRATION_VERSIONS / filename
    spec = importlib.util.spec_from_file_location(
        f"test_{migration_path.stem}",
        migration_path,
    )
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration
