import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Load Alembic Config
config = context.config

# Set up logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Use DATABASE_URL from environment variables, with a fallback
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://aip:aip_password@db:5432/aip_db")
DATABASE_URL = DATABASE_URL.replace("postgresql+asyncpg", "postgresql+psycopg2")

# Override sqlalchemy.url in Alembic config dynamically
config.set_main_option("sqlalchemy.url", DATABASE_URL)

# Metadata for migrations (update if needed)
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    context.configure(
        url=DATABASE_URL,  # Use the dynamic URL here
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
