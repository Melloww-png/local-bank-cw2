"""Reset this local coursework database after stopping the Flask server."""

import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from vulnerable import app as bank


def reset_database():
    database = Path(bank.DATABASE)
    backup = None

    if database.exists():
        backup_dir = database.parent.parent / "backups"
        backup_dir.mkdir(exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        backup = backup_dir / f"bank-before-reset-{timestamp}.db"

        # Includes committed changes from SQLite journal/WAL files.
        with closing(sqlite3.connect(database)) as source:
            with closing(sqlite3.connect(backup)) as destination:
                source.backup(destination)

        database.unlink()

    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(database) + suffix).unlink(missing_ok=True)

    secret = secrets.token_hex(32)
    bank.SECRET_FILE.write_text(secret, encoding="utf-8")
    bank.app.config["SECRET_KEY"] = secret
    bank.init_db()
    return backup


if __name__ == "__main__":
    print("Run this only after stopping the Flask server with Ctrl+C.")
    backup_path = reset_database()

    if backup_path is not None:
        print(f"Old database backed up to: {backup_path}")

    print(
        "Fresh database created. Old customer accounts, loans, "
        "messages, and tickets removed."
    )
    print("Previous browser sessions invalidated.")
    print("Admin login: lab_admin / AdminDemo123!")
    print("Register new fictional customer accounts before testing.")