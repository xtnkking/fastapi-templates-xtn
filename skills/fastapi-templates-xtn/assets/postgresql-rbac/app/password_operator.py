from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import uuid

from app.authentication_service import get_local_authentication_service
from app.database import engine
from app.rbac.errors import RbacError


def _uuid4(value: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("user ID must be a UUIDv4") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise argparse.ArgumentTypeError("user ID must be a canonical UUIDv4")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Set a temporary password for the existing sole super administrator."
        )
    )
    parser.add_argument(
        "--user-id",
        required=True,
        type=_uuid4,
        help="immutable users.id of the sole super administrator",
    )
    return parser


async def _run(user_id: uuid.UUID, temporary_password: str) -> None:
    try:
        await get_local_authentication_service().operator_reset_super_admin_password(
            user_id=user_id,
            temporary_password=temporary_password,
            request_id=f"operator:{uuid.uuid4()}",
        )
    finally:
        await engine.dispose()


def main() -> int:
    args = _parser().parse_args()
    temporary_password = getpass.getpass("New temporary password: ")
    confirmation = getpass.getpass("Repeat temporary password: ")
    if temporary_password != confirmation:
        print("The two password entries do not match.", file=sys.stderr)
        return 2

    try:
        asyncio.run(_run(args.user_id, temporary_password))
    except RbacError:
        print(
            "Password reset failed. Check the user ID, account state, "
            "and password policy.",
            file=sys.stderr,
        )
        return 1
    print(
        "Temporary password set. The account must complete password reset before login."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
