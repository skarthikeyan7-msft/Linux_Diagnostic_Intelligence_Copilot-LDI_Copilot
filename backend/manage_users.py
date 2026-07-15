#!/usr/bin/env python
"""
Manage LDI Copilot's per-user local accounts (the "accounts" auth mode -
see backend/auth.py, backend/users.py, SECURITY.md's "Running one shared
instance instead" section).

Run this ON THE MACHINE hosting the server; it edits
backend/data/users.json directly (gitignored - never commit it).
Changes take effect immediately for anyone already using accounts mode
(logins re-read this file on every attempt) - a restart is only needed
the very first time you go from zero accounts to one, since that's what
decides which auth gate the server selects at startup (see
backend/app.py's main()).

Usage:
    python backend/manage_users.py add <username>
    python backend/manage_users.py add <username> --overwrite   # reset an existing user's password
    python backend/manage_users.py remove <username>
    python backend/manage_users.py list
"""
import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from users import UserStore  # noqa: E402

USERS_PATH = Path(__file__).resolve().parent / "data" / "users.json"


def _prompt_password() -> str:
    password = getpass.getpass("New password (min 8 characters): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("ERROR: passwords did not match.", file=sys.stderr)
        sys.exit(1)
    return password


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    add_p = sub.add_parser("add", help="Add a new user, or reset an existing one's password with --overwrite")
    add_p.add_argument("username")
    add_p.add_argument("--overwrite", action="store_true", help="Reset the password if the user already exists")

    rm_p = sub.add_parser("remove", help="Remove a user")
    rm_p.add_argument("username")

    sub.add_parser("list", help="List configured usernames")

    args = ap.parse_args()
    store = UserStore(USERS_PATH)

    if args.command == "add":
        was_empty = store.count() == 0
        password = _prompt_password()
        try:
            store.add_user(args.username, password, overwrite=args.overwrite)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        action = "updated" if args.overwrite else "added"
        print(f"User {args.username!r} {action}.")
        if was_empty:
            print("This is the first account - restart the server so it switches into accounts mode.")
        else:
            print("Takes effect immediately - no server restart needed.")

    elif args.command == "remove":
        if store.remove_user(args.username):
            print(f"User {args.username!r} removed. Takes effect immediately - no server restart needed.")
            if store.count() == 0:
                print("No accounts remain - restart the server if you want it to fall back to --auth-token/--no-auth behavior.")
        else:
            print(f"No such user: {args.username!r}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "list":
        usernames = store.list_usernames()
        if not usernames:
            print("No users configured yet. Add one with: python backend/manage_users.py add <username>")
        else:
            for u in usernames:
                print(u)


if __name__ == "__main__":
    main()
