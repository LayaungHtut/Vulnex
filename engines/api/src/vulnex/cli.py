"""Operator commands for self-hosted installs: worker PKI and controlled account provisioning.

    python -m vulnex.cli init-pki --out deploy/compose/pki --server-name localhost

    python -m vulnex.cli create-organization --name "Acme" --owner-email a@acme.test \
        --owner-name "Ada Admin"

The password is read from VULNEX_BOOTSTRAP_PASSWORD if set, otherwise prompted for twice.
Runs as the application role (VULNEX_DATABASE_URL), under the same RLS rules as the API.
With Compose: docker compose -f deploy/compose/compose.yaml run --rm -it api \
    python -m vulnex.cli create-organization ...
"""

import argparse
import getpass
import json
import os
import sys
import uuid
from pathlib import Path

from sqlalchemy import Engine, text

from vulnex import security
from vulnex.db import make_engine
from vulnex.pki import init_pki
from vulnex.settings import Settings


def create_organization(
    engine: Engine, name: str, owner_email: str, owner_name: str, password: str
) -> tuple[uuid.UUID, uuid.UUID]:
    """Create an organization whose first owner is the given account (created if new).

    If the email already has an account, it keeps its password and simply becomes an owner.
    Returns (organization_id, user_id).
    """
    if not security.PASSWORD_MIN <= len(password) <= security.PASSWORD_MAX:
        raise ValueError(
            f"password must be {security.PASSWORD_MIN}-{security.PASSWORD_MAX} characters"
        )
    tenant_id = uuid.uuid4()
    password_hash = security.hash_password(password)
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
        conn.execute(
            text("INSERT INTO app.tenant (id, name) VALUES (:t, :name)"),
            {"t": tenant_id, "name": name},
        )
        user_id: uuid.UUID = conn.execute(
            text("SELECT user_id FROM auth.create_user(:email, :name, :hash)"),
            {"email": owner_email.strip().lower(), "name": owner_name, "hash": password_hash},
        ).scalar_one()
        conn.execute(
            text("INSERT INTO app.membership (tenant_id, user_id, role) VALUES (:t, :u, 'owner')"),
            {"t": tenant_id, "u": user_id},
        )
        conn.execute(
            text(
                "INSERT INTO app.audit_event (tenant_id, action, target_type, target_id, detail) "
                "VALUES (:t, 'organization.created', 'user', :u, CAST(:d AS jsonb))"
            ),
            {"t": tenant_id, "u": str(user_id), "d": json.dumps({"via": "cli", "role": "owner"})},
        )
    return tenant_id, user_id


def _password() -> str:
    env = os.environ.get("VULNEX_BOOTSTRAP_PASSWORD")
    if env:
        return env
    first = getpass.getpass("Owner password (12-128 characters): ")
    if first != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match")
    return first


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="vulnex.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    org = sub.add_parser("create-organization", help="create an organization and its owner")
    org.add_argument("--name", required=True)
    org.add_argument("--owner-email", required=True)
    org.add_argument("--owner-name", required=True)
    pki = sub.add_parser("init-pki", help="create the worker CA, endpoint TLS and signing keys")
    pki.add_argument("--out", required=True, type=Path)
    pki.add_argument(
        "--server-name",
        action="append",
        required=True,
        help="DNS name or IP address of the worker endpoint (repeat for several)",
    )
    args = parser.parse_args(argv)

    if args.command == "init-pki":
        try:
            init_pki(args.out, args.server_name)
        except FileExistsError as e:
            sys.exit(str(e))
        print(f"worker PKI written to {args.out}; keep the .key files secret")
        return

    settings = Settings()  # pyright: ignore[reportCallIssue]  # values come from env
    engine = make_engine(settings.database_url.get_secret_value())
    try:
        tenant_id, user_id = create_organization(
            engine, args.name, args.owner_email, args.owner_name, _password()
        )
    except ValueError as e:
        sys.exit(str(e))
    finally:
        engine.dispose()
    print(f"organization {tenant_id}\nowner        {user_id} ({args.owner_email.lower()})")


if __name__ == "__main__":
    main()
