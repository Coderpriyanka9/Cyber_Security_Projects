import sqlite3

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pulse_name TEXT,
            ioc TEXT,
            type TEXT,
            risk_score INTEGER,
            enrichment TEXT
        )
    """)
    conn.commit()
    conn.close()

def store_records(db_path, records):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    for r in records:
        cur.execute("""
            INSERT INTO intel (pulse_name, ioc, type, risk_score, enrichment)
            VALUES (?, ?, ?, ?, ?)
        """, (r["pulse_name"], r["ioc"], r["type"], r["risk_score"], str(r["enrichment"])))
    conn.commit()
    conn.close()
