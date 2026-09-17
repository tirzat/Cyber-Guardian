import sqlite3
from datetime import datetime

DATABASE_NAME = "cyberguardian.db"


def create_database():
    conn = sqlite3.connect(DATABASE_NAME)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            score INTEGER NOT NULL,
            rating TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_scan(domain: str, score: int, rating: str):
    conn = sqlite3.connect(DATABASE_NAME)

    cursor = conn.cursor()

    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO scan_history
        (domain, score, rating, scanned_at)
        VALUES (?, ?, ?, ?)
    """, (domain, score, rating, scanned_at))

    conn.commit()
    conn.close()


def get_scan_history():
    conn = sqlite3.connect(DATABASE_NAME)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, domain, score, rating, scanned_at
        FROM scan_history
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    history = []

    for row in rows:
        history.append({
            "id": row[0],
            "domain": row[1],
            "score": row[2],
            "rating": row[3],
            "scanned_at": row[4]
        })

    return history