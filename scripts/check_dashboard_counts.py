import os
import sqlite3
import sys

BASE_DIR = r"d:\INTERN\File-Transfer-Management-System-main"
DB_PATH = os.path.join(BASE_DIR, "server", "database", "monitoring.db")

if os.path.exists(DB_PATH):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get counts by risk level
        cursor.execute("SELECT risk_level, COUNT(*) as count FROM logs GROUP BY risk_level")
        rows = cursor.fetchall()
        
        counts = {row['risk_level']: row['count'] for row in rows}
        total = sum(counts.values())
        
        print("Log Counts by Risk Level:")
        for level, count in counts.items():
            print(f"{level}: {count}")
        print(f"TOTAL: {total}")
        
        conn.close()
    except Exception as e:
        print(f"Error: {e}")
else:
    print("Database not found.")
