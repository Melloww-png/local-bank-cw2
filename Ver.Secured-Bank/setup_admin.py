"""Create the secured copy's first admin without shipping a default password."""
from contextlib import closing
from getpass import getpass

from werkzeug.security import generate_password_hash

from app import ADMIN_USERNAME, get_db_connection, init_db


def main():
    init_db()
    with closing(get_db_connection()) as db:
        if db.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
            print("An administrator already exists. Its password has not been changed.")
            return
        print(f"Create the local administrator: {ADMIN_USERNAME}")
        password = getpass("Choose an admin password (12-128 characters): ")
        confirmation = getpass("Repeat that password: ")
        if not 12 <= len(password) <= 128:
            raise SystemExit("Use 12-128 characters. Run setup_admin.py again.")
        if password != confirmation:
            raise SystemExit("Passwords do not match. Run setup_admin.py again.")
        db.execute(
            """INSERT INTO users (username, full_name, email, password_hash, role)
               VALUES (?, ?, ?, ?, 'admin')""",
            (ADMIN_USERNAME, "Lab Administrator", "admin@example.test",
             generate_password_hash(password, method="scrypt")),
        )
        db.commit()
    print("Administrator created. Start the bank with: python app.py")


if __name__ == "__main__":
    main()
