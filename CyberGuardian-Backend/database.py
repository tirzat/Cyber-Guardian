
import sqlite3


DATABASE_NAME = "cyberguardian.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            score INTEGER,
            rating TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def save_scan(domain, score, rating):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO scan_history (domain, score, rating)
        VALUES (?, ?, ?)
        """,
        (domain, score, rating)
    )

    connection.commit()
    connection.close()


def get_scan_history():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM scan_history
        ORDER BY scanned_at DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]

