"""
Alembic environment for kite-controller.

The connection comes from app.db's engine rather than alembic.ini's
sqlalchemy.url, so the CLI and the app can never end up pointed at
different databases — KITE_DB is the single source of truth for
where the DB lives, exactly as it was before migrations existed.

render_as_batch=True matters on SQLite specifically: SQLite has no real
ALTER for dropping or altering a column, so alembic emulates it by
creating a new table, copying rows, and swapping. Without this, any
future migration that isn't a plain ADD COLUMN would simply fail on the
default database this project ships with.
"""
from alembic import context

from app.db import engine
from app.models import Base

target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(
        url=str(engine.url),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
