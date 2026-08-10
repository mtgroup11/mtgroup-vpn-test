"""
Alembic environment for MTGroup VPN Ultimate.

Wired to the application's own config and models rather than to
`alembic.ini`, so there is exactly one source of truth for the database
URL (`settings.DATABASE_URL`) and one for the schema
(`backend.app.models.Base.metadata`). `alembic.ini`'s `sqlalchemy.url`
is deliberately left blank — if it were set, it could silently disagree
with what the running app uses and migrate the wrong database.
"""

import asyncio
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Make the repo root importable when alembic is invoked from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.core.config import settings  # noqa: E402
from backend.app.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    """
    Resolve which database to migrate.

    An explicitly-supplied `sqlalchemy.url` wins — that's how callers
    target a specific database (tests against a temp file, a one-off
    `alembic -x`, a maintenance script). `alembic.ini` deliberately
    leaves it blank, so in normal operation this falls through to the
    application's own configured URL and there is exactly one source of
    truth.
    """
    configured = config.get_main_option("sqlalchemy.url")
    if configured:
        return configured
    return settings.DATABASE_URL


def render_item(type_, obj, autogen_context):
    """
    Render `EncryptedType` columns as plain `sa.Text()` in migrations.

    `EncryptedType` is a `TypeDecorator` whose `impl` is `Text` — the
    encryption is applied in Python on the way in and out, so at the
    database level the column genuinely is TEXT. Emitting the decorator
    class here would force every migration to import application code
    (and autogenerate emits it unqualified, which doesn't even import),
    coupling the migration history to a class that may later move or be
    renamed. Migrations should describe the database, not the ORM.
    """
    if type_ == "type" and obj.__class__.__name__ == "EncryptedType":
        return "sa.Text()"
    return False


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it (`alembic upgrade --sql`)."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_item=render_item,
        # SQLite cannot ALTER most column properties in place; batch mode
        # rewrites the table instead. Harmless on other backends.
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
        render_item=render_item,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = get_url()

    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    # When the app calls Alembic during startup (models.init_db) it hands us
    # its already-open connection via config.attributes. Reuse it rather than
    # opening a second one: on SQLite a second connection would block on the
    # first one's write lock, and it would also run the migration outside the
    # caller's transaction.
    existing_connection = config.attributes.get("connection")
    if existing_connection is not None:
        do_run_migrations(existing_connection)
        return

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
