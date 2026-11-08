import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Tests pass the URL in config attributes; deployments use the environment (owner role).
url = config.attributes.get("url") or os.environ["VULNEX_MIGRATION_DATABASE_URL"]

with create_engine(url).connect() as connection:
    context.configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()
