import sqlite3
import os
import sys

# Add project root to path to import config
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

try:
    from flask_bcrypt import Bcrypt
    from flask import Flask
    import datetime
    from datetime import timezone
except ImportError:
    print("Required libraries (Flask, Flask-Bcrypt) not found. Please install them first.")
    sys.exit(1)

def get_ist_time():
    """Returns the current time in Indian Standard Time (IST)."""
    ist_offset = datetime.timedelta(hours=5, minutes=30)
    return (datetime.datetime.now(timezone.utc) + ist_offset).strftime("%Y-%m-%d %H:%M:%S")

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Dynamic DB Path placement
db_path = os.path.join(BASE_DIR, 'server', 'database', 'monitoring.db')

if os.path.exists(db_path):
    try:
        conn = sqlite3.connect(db_path)
        hashed = bcrypt.generate_password_hash('password123').decode('utf-8')
        with conn:
            # Create or Update common users
            conn.execute("INSERT OR REPLACE INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)", 
                         ('admin', hashed, 'admin', get_ist_time()))
            conn.execute("INSERT OR REPLACE INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)", 
                         ('ashwin', hashed, 'user', get_ist_time()))
        print(f"Success: Passwords set for 'admin' and 'ashwin' to 'password123'")
        print(f"Database location: {db_path}")
        conn.close()
    except Exception as e:
        print(f"Error accessing database: {e}")
else:
    print(f"Error: Database not found at {db_path}")
    print("Please ensure the project is initialized correctly.")
