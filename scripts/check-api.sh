#!/bin/sh
# Run the Python check suite (ruff, mypy, pytest incl. database tests) inside a Linux container.
#
# Why a container: Windows Smart App Control blocks unsigned compiled Python extensions
# (SQLAlchemy's Cython modules, mypy's mypyc core) in the host .venv. The container also
# matches CI (Linux, Python 3.13) more closely than the Windows host does.
#
# Needs: the compose `db` service running and deploy/compose/.env filled in.
#   docker compose -f deploy/compose/compose.yaml up -d db
#   sh scripts/check-api.sh            # all checks
#   sh scripts/check-api.sh pytest -k tenant   # any single command, run via `uv run`
set -eu
cd "$(dirname "$0")/.."

ENV_FILE=deploy/compose/.env
[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE (copy .env.example)"; exit 1; }
# shellcheck disable=SC1090
. "./$ENV_FILE"

# Git Bash on Windows rewrites /paths in arguments; turn that off and give Docker a Windows path.
export MSYS_NO_PATHCONV=1
SRC=$(pwd -W 2>/dev/null || pwd)

if [ $# -gt 0 ]; then
	CMD="uv sync --locked --all-packages --quiet && uv run $*"
else
	CMD="uv sync --locked --all-packages --quiet && uv run ruff check && uv run ruff format --check \
		&& uv run mypy engines packages && uv run pytest"
fi

exec docker run --rm \
	--network vulnex_default \
	-v "$SRC:/src" -w /src \
	-v vulnex-check-venv:/opt/venv \
	-v vulnex-check-uvcache:/root/.cache/uv \
	-e UV_PROJECT_ENVIRONMENT=/opt/venv \
	-e UV_LINK_MODE=copy \
	-e MYPY_CACHE_DIR=/tmp/mypy \
	-e VULNEX_TEST_OWNER_URL="postgresql+psycopg://vulnex_owner:${VULNEX_OWNER_PASSWORD}@db:5432/vulnex_test" \
	-e VULNEX_TEST_APP_URL="postgresql+psycopg://vulnex_app:${VULNEX_APP_PASSWORD}@db:5432/vulnex_test" \
	ghcr.io/astral-sh/uv:0.13.3-python3.13-trixie-slim \
	sh -c "$CMD"
