#!/bin/sh
# Runs once, on first start of an empty data volume (postgres image init hook).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	-v owner_password="$VULNEX_OWNER_PASSWORD" \
	-v app_password="$VULNEX_APP_PASSWORD" \
	-f /vulnex/roles.psql
