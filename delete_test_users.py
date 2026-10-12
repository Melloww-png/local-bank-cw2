"""Delete only user1/user2 after stopping the local Flask server."""

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "vulnerable" / "bank.db"
BACKUP_DIRECTORY = ROOT / "backups"


def delete_test_users():
    if not DATABASE.is_file():
        raise SystemExit("bank.db was not found. Start the bank once first.")

    query = """
        SELECT id, username FROM users
        WHERE role = 'customer' AND username IN (?, ?)
        ORDER BY id
    """
    names = ("user1", "user2")

    with closing(sqlite3.connect(DATABASE)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")

        if not db.execute(query, names).fetchall():
            return [], None

        BACKUP_DIRECTORY.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        backup = BACKUP_DIRECTORY / f"bank-before-user-cleanup-{timestamp}.db"

        # Back up the existing database before changing it.
        with closing(sqlite3.connect(backup)) as destination:
            db.backup(destination)

        try:
            db.execute("BEGIN IMMEDIATE")
            users = db.execute(query, names).fetchall()

            for user in users:
                user_id = user["id"]

                db.execute(
                    "DELETE FROM transfers WHERE sender_id = ? OR recipient_id = ?",
                    (user_id, user_id),
                )
                db.execute(
                    "DELETE FROM support_messages WHERE user_id = ?",
                    (user_id,),
                )
                db.execute(
                    "DELETE FROM account_extras WHERE user_id = ?",
                    (user_id,),
                )
                db.execute(
                    "DELETE FROM users WHERE id = ?",
                    (user_id,),
                )

            db.commit()

        except Exception:
            db.rollback()
            raise

    return [user["username"] for user in users], backup


if __name__ == "__main__":
    removed, backup_path = delete_test_users()

    if removed:
        print("Deleted customer accounts: " + ", ".join(removed))
        print(f"Database backup saved to: {backup_path}")
        print("The admin account and other customer balances are preserved.")
        print("Start the bank and register these customers again with full names.")
    else:
        print("No customer accounts named user1 or user2 were found.")