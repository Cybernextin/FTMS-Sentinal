from flask_login import UserMixin
import sqlite3
import datetime
from datetime import timezone
import os
import shutil
import logging

# Configure logging for database operations
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DATABASE_FILE = os.path.join(DB_DIR, "monitoring.db")

class User(UserMixin):
    """
    Standard User Model for FTMS.
    Attributes:
        id (int): Primary Key
        username (str): Unique Username
        role (str): 'admin' or 'user'
    """
    def __init__(self, id, username, role, login_attempts=0, workspace_visibility="public"):
        self.id = id
        self.username = username
        self.role = role
        self.login_attempts = login_attempts
        self.workspace_visibility = workspace_visibility

# FileFolder class removed as requested - consolidated into dictionary-based metadata for flexibility

def get_ist_time():
    """Returns the current time in Indian Standard Time (IST)."""
    ist_offset = datetime.timedelta(hours=5, minutes=30)
    return (datetime.datetime.now(timezone.utc) + ist_offset).strftime("%Y-%m-%d %H:%M:%S")

def ensure_db_dir():
    """Ensure the database directory exists."""
    if not os.path.exists(DB_DIR):
        try:
            os.makedirs(DB_DIR, exist_ok=True)
            logger.info(f"Created database directory at {DB_DIR}")
        except Exception as e:
            logger.error(f"Failed to create database directory: {e}")
            raise

def backup_corrupt_db():
    """Backups the corrupted database file."""
    if os.path.exists(DATABASE_FILE):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(DB_DIR, f"logs_corrupted_backup_{timestamp}.db")
        try:
            shutil.copy2(DATABASE_FILE, backup_path)
            logger.warning(f"Corrupted database backed up to: {backup_path}")
            try:
                os.remove(DATABASE_FILE)
                logger.info("Corrupted database file removed.")
            except PermissionError:
                logger.error("Could not remove corrupted file (in use?). Rename attempt...")
                os.rename(DATABASE_FILE, DATABASE_FILE + ".old_" + timestamp)
        except Exception as e:
            logger.error(f"Failed to backup corrupted database: {e}")

def check_integrity():
    """Checks the SQLite database integrity."""
    if not os.path.exists(DATABASE_FILE):
        return True

    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        result = cursor.execute("PRAGMA integrity_check;").fetchone()
        return result and result[0] == "ok"
    except (sqlite3.DatabaseError, Exception) as e:
        logger.error(f"Integrity check failed: {e}")
        return False
    finally:
        conn.close()

def init_db():
    """Initializes the database with integrity checks and schema creation."""
    try:
        ensure_db_dir()
        if not check_integrity():
            logger.warning("Database corruption detected. Initiating recovery...")
            backup_corrupt_db()
        
        conn = sqlite3.connect(DATABASE_FILE)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            
            # Users Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    login_attempts INTEGER DEFAULT 0,
                    delete_attempts INTEGER DEFAULT 0,
                    last_delete_attempt TEXT,
                    owner_delete_password_hash TEXT,
                    owner_delete_password_created_at TEXT,
                    created_at TEXT,
                    workspace_visibility TEXT DEFAULT 'public',
                    lock_attempts INTEGER DEFAULT 0
                )
            ''')
            
            # Files Metadata Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    file_path TEXT UNIQUE NOT NULL,
                    parent_id INTEGER,
                    owner_id INTEGER,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    visibility TEXT NOT NULL DEFAULT 'public',
                    sha256_hash TEXT,
                    FOREIGN KEY (owner_id) REFERENCES users(id),
                    FOREIGN KEY (parent_id) REFERENCES files(id)
                )
            ''')

            # File Access Table (Multiple users per folder)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_access (
                    file_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    PRIMARY KEY (file_id, user_id),
                    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            # Logs Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    file_path TEXT,
                    destination TEXT,
                    risk_level TEXT NOT NULL,
                    ip_address TEXT,
                    timestamp TEXT NOT NULL,
                    pid INTEGER,
                    process_name TEXT,
                    parent_process TEXT
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully.")
        finally:
            conn.close()
            
    except Exception as e:
        logger.critical(f"Database initialization failed: {e}")
        import sys
        sys.exit(1)
    
    update_schema()

def get_db_connection():
    """Establishes a connection to the database."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.DatabaseError:
        logger.error("Connection failed: Database malformed. Attempting reset...")
        backup_corrupt_db()
        init_db()
        return sqlite3.connect(DATABASE_FILE)

def add_log_entry(username, action, risk_level, file_path=None, destination=None, ip_address="Unknown", pid=None, process_name=None, parent_process=None):
    conn = get_db_connection()
    try:
        timestamp = get_ist_time()
        with conn:
            conn.execute('''
                INSERT INTO logs (username, action, file_path, destination, risk_level, ip_address, timestamp, pid, process_name, parent_process)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, action, file_path, destination, risk_level, ip_address, timestamp, pid, process_name, parent_process))
        
        if risk_level == "CRITICAL":
            print(f"\n🚨 CRITICAL SECURITY ALERT: {action} by {username} ({process_name if process_name else 'Unknown Process'}) at {timestamp}\n")
    except Exception as e:
        logger.error(f"Failed to add log entry: {e}")
    finally:
        conn.close()

def get_user_by_username(username):
    conn = get_db_connection()
    try:
        user_data = conn.execute('SELECT * FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['role'], user_data['login_attempts'], user_data['workspace_visibility'])
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
    finally:
        conn.close()
    return None

def get_user_by_id(user_id):
    conn = get_db_connection()
    try:
        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['role'], user_data['login_attempts'], user_data['workspace_visibility'])
    except Exception as e:
        logger.error(f"Error fetching user by ID: {e}")
    finally:
        conn.close()
    return None

def increment_login_attempts(username):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ? COLLATE NOCASE', (username,))
        return True
    except Exception as e:
        logger.error(f"Error incrementing login attempts: {e}")
    finally:
        conn.close()
    return False

def reset_login_attempts(username):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('UPDATE users SET login_attempts = 0 WHERE username = ? COLLATE NOCASE', (username,))
        return True
    except Exception as e:
        logger.error(f"Error resetting login attempts: {e}")
    finally:
        conn.close()
    return False

def get_login_attempts(username):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT login_attempts FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        return row['login_attempts'] if row else 0
    except Exception as e:
        logger.error(f"Error getting login attempts: {e}")
    finally:
        conn.close()
    return 0

def increment_delete_attempts(username):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('UPDATE users SET delete_attempts = delete_attempts + 1, last_delete_attempt = ? WHERE username = ? COLLATE NOCASE', 
                         (datetime.datetime.now().isoformat(), username))
        return True
    except Exception as e:
        logger.error(f"Error incrementing delete attempts: {e}")
    finally:
        conn.close()
    return False

def reset_delete_attempts(username):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('UPDATE users SET delete_attempts = 0 WHERE username = ? COLLATE NOCASE', (username,))
        return True
    except Exception as e:
        logger.error(f"Error resetting delete attempts: {e}")
    finally:
        conn.close()
    return False

def delete_user(username):
    """Deletes a user from the system. Prevents deleting the last admin."""
    import config
    STORAGE_ROOT = config.STORAGE_ROOT
    conn = get_db_connection()
    try:
        # Check if it's an admin
        user = conn.execute('SELECT id, role FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        if not user:
            return False, "User not found."
            
        if user['role'] == 'admin':
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
            if admin_count <= 1:
                return False, "Cannot delete the last administrator."
                
        user_id = user['id']
        
        # Physical File Deletion (Hard delete)
        import os
        import shutil
        user_root_path = os.path.join(STORAGE_ROOT, username.lower())
        if os.path.exists(user_root_path):
            try:
                shutil.rmtree(user_root_path)
            except Exception as e:
                logger.error(f"Failed to remove physical files for {username}: {e}")
        
        with conn:
            # 1. Delete ALL files records that start with this user's path (Case-insensitive catch)
            prefix = username.lower() + '/'
            conn.execute("DELETE FROM files WHERE file_path = ? COLLATE NOCASE OR file_path LIKE ? || '%' COLLATE NOCASE", (username.lower(), prefix))
            
            # 2. Delete access control mappings related to this user (both given and received)
            conn.execute('DELETE FROM file_access WHERE user_id = ?', (user_id,))
            conn.execute('DELETE FROM file_access WHERE file_id NOT IN (SELECT id FROM files)')
            
            # 3. Delete audit logs related to that user
            conn.execute('DELETE FROM logs WHERE username = ? COLLATE NOCASE', (username,))
            
            # 4. Delete user account record
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            
        return True, f"User {username} and all associated data deleted successfully."
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return False, str(e)
    finally:
        conn.close()

def get_delete_attempts(username):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT delete_attempts, last_delete_attempt FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        return row if row else {'delete_attempts': 0, 'last_delete_attempt': None}
    except Exception as e:
        logger.error(f"Error getting delete attempts: {e}")
    finally:
        conn.close()
    return {'delete_attempts': 0, 'last_delete_attempt': None}

def increment_lock_attempts(username):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('UPDATE users SET lock_attempts = lock_attempts + 1 WHERE username = ? COLLATE NOCASE', (username,))
        return True
    except Exception as e:
        logger.error(f"Error incrementing lock attempts: {e}")
    finally:
        conn.close()
    return False

def reset_lock_attempts(username):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('UPDATE users SET lock_attempts = 0 WHERE username = ? COLLATE NOCASE', (username,))
        return True
    except Exception as e:
        logger.error(f"Error resetting lock attempts: {e}")
    finally:
        conn.close()
    return False

def get_lock_attempts(username):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT lock_attempts FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        return row['lock_attempts'] if row else 0
    except Exception as e:
        logger.error(f"Error getting lock attempts: {e}")
    finally:
        conn.close()
    return 0


def set_owner_password_hash(username, password_hash):
    conn = get_db_connection()
    try:
        timestamp = get_ist_time()
        with conn:
            conn.execute('UPDATE users SET owner_delete_password_hash = ?, owner_delete_password_created_at = ? WHERE username = ? COLLATE NOCASE', 
                         (password_hash, timestamp, username))
        return True
    except Exception as e:
        logger.error(f"Error setting owner password for {username}: {e}")
    finally:
        conn.close()
    return False

def delete_owner_password_hash(username):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('UPDATE users SET owner_delete_password_hash = NULL, owner_delete_password_created_at = NULL WHERE username = ? COLLATE NOCASE', 
                         (username,))
        return True
    except Exception as e:
        logger.error(f"Error deleting owner password for {username}: {e}")
    finally:
        conn.close()
    return False


def get_file_owner(file_path):
    """Fetches just the username of the owner."""
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT created_by FROM files WHERE file_path = ?', (file_path,)).fetchone()
        return row['created_by'] if row else None
    except Exception as e:
        logger.error(f"Error fetching file owner: {e}")
    finally:
        conn.close()
    return None

def register_file(file_name, file_path, username, visibility='public'):
    """Logs the creation/upload of a file for ownership tracking."""
    conn = get_db_connection()
    try:
        user = get_user_by_username(username)
        owner_id = user.id if user else None
        timestamp = get_ist_time()
        
        # Calculate parent_id
        parent_path = os.path.dirname(file_path).replace("\\", "/")
        parent_id = None
        if parent_path:
            p_row = conn.execute('SELECT id FROM files WHERE file_path = ?', (parent_path,)).fetchone()
            if p_row: parent_id = p_row['id']

        # Enforce strict visibility enum
        if visibility not in ['public', 'private']:
            visibility = 'public'

        file_path = file_path.replace("\\", "/")
        with conn:
            conn.execute('''
                INSERT OR REPLACE INTO files (file_name, file_path, parent_id, owner_id, created_by, created_at, visibility)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (file_name, file_path, parent_id, owner_id, username, timestamp, visibility))
    except Exception as e:
        logger.error(f"Failed to register file: {e}")
    finally:
        conn.close()

def get_file_by_path(file_path):
    """Retrieves file record by its path."""
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT * FROM files WHERE file_path = ?', (file_path,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching file by path: {e}")
    finally:
        conn.close()
    return None



def get_file_owner_info(file_path):
    """Fetches the username, ID, and visibility of the owner/file."""
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT id, created_by, owner_id, visibility FROM files WHERE file_path = ?', (file_path,)).fetchone()
        if row:
            return {
                "username": row['created_by'], 
                "owner_id": row['owner_id'], 
                "record_id": row['id'], 
                "visibility": row['visibility'] or 'public'
            }
    except Exception as e:
        logger.error(f"Error fetching file owner info: {e}")
    finally:
        conn.close()
    return None

def set_file_visibility(file_path, visibility):
    """Updates visibility for a file and all its children.
    
    SECURITY RULE: If the file's owner has workspace_visibility == 'private',
    any attempt to switch to 'public' is silently overridden to 'private'.
    This enforces the root-lock rule at the deepest possible layer.
    """
    if visibility not in ['public', 'private']:
        return False

    conn = get_db_connection()
    try:
        # Removed legacy backend enforcement logic here so real changes can persist
        with conn:
            # Update item itself
            conn.execute('UPDATE files SET visibility = ? WHERE file_path = ?', (visibility, file_path))
            # Recursively update children
            conn.execute('UPDATE files SET visibility = ? WHERE file_path LIKE ? || "/%"', (visibility, file_path))
        return True
    except Exception as e:
        logger.error(f"Error setting visibility: {e}")
    finally:
        conn.close()
    return False

def get_allowed_users(file_id):
    """Returns list of usernames allowed to access a private file."""
    conn = get_db_connection()
    try:
        rows = conn.execute('''
            SELECT u.username FROM users u
            JOIN file_access fa ON u.id = fa.user_id
            WHERE fa.file_id = ?
        ''', (file_id,)).fetchall()
        return [r['username'] for r in rows]
    except Exception as e:
        logger.error(f"Error fetching allowed users: {e}")
    finally:
        conn.close()
    return []

def set_allowed_users(file_id, usernames):
    """Updates the sharing list for a file."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('DELETE FROM file_access WHERE file_id = ?', (file_id,))
            for uname in usernames:
                user = conn.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (uname,)).fetchone()
                if user:
                    conn.execute('INSERT INTO file_access (file_id, user_id) VALUES (?, ?)', (file_id, user['id']))
        return True
    except Exception as e:
        logger.error(f"Error setting allowed users: {e}")
    finally:
        conn.close()
    return False

def get_all_normal_users():
    """Returns all users with 'user' role."""
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT id, username FROM users WHERE role = 'user'").fetchall()
        return [{"id": r['id'], "username": r['username']} for r in rows]
    except Exception as e:
        logger.error(f"Error getting users: {e}")
    finally:
        conn.close()
    return []

def get_file_by_id(file_id):
    """Retrieves file metadata by database ID."""
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching file by ID: {e}")
    finally:
        conn.close()
    return None

def update_file_metadata(old_path, new_name, new_path, new_parent_id=None):
    """Updates file metadata recursively during rename/move operations."""
    conn = get_db_connection()
    try:
        with conn:
            # Update the specific item being renamed/moved
            if new_parent_id is not None:
                conn.execute('''
                    UPDATE files SET file_name = ?, file_path = ?, parent_id = ? WHERE file_path = ?
                ''', (new_name, new_path, new_parent_id, old_path))
            else:
                 conn.execute('''
                    UPDATE files SET file_name = ?, file_path = ? WHERE file_path = ?
                ''', (new_name, new_path, old_path))
            
            # Recursively update all children if it's a directory
            conn.execute('''
                UPDATE files 
                SET file_path = ? || substr(file_path, length(?) + 1) 
                WHERE file_path LIKE ? || '/%'
            ''', (new_path, old_path, old_path))
    except Exception as e:
        logger.error(f"Error updating file metadata: {e}")
    finally:
        conn.close()

def remove_file_metadata(file_path):
    """Removes metadata when a file is deleted."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute('DELETE FROM files WHERE file_path = ? OR file_path LIKE ?', (file_path, file_path + "/%"))
    except Exception as e:
        logger.error(f"Error removing file metadata: {e}")
    finally:
        conn.close()

def get_owner_password_info(username):
    """Retrieves owner password hash and creation timestamp."""
    if not username: return None
    conn = get_db_connection()
    try:
        row = conn.execute(
            'SELECT owner_delete_password_hash, owner_delete_password_created_at FROM users WHERE username = ? COLLATE NOCASE',
            (username,)
        ).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching owner password info: {e}")
    finally:
        conn.close()
    return None

def is_owner_password_valid(username):
    """Checks if owner password is set and not expired (24h)."""
    info = get_owner_password_info(username)
    if not info or not info.get('owner_delete_password_hash') or not info.get('owner_delete_password_created_at'):
        return False, "NOT_CONFIGURED"
    
    try:
        created_at = datetime.datetime.strptime(info['owner_delete_password_created_at'], "%Y-%m-%d %H:%M:%S")
        if (datetime.datetime.now() - created_at).total_seconds() > 86400:
            delete_owner_password_hash(username)
            return False, "EXPIRED"
        return True, "VALID"
    except Exception as e:
        logger.error(f"Error checking password validity: {e}")
        return False, "ERROR"

def update_schema():
    """Applies necessary schema updates for existing databases."""
    conn = get_db_connection()
    try:
        with conn:

            # Check for parent_id column
            try:
                conn.execute('SELECT parent_id FROM files LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute('ALTER TABLE files ADD COLUMN parent_id INTEGER')
                # Back-fill parent_id for existing files
                rows = conn.execute('SELECT id, file_path FROM files WHERE parent_id IS NULL').fetchall()
                for r in rows:
                    p_path = os.path.dirname(r['file_path']).replace("\\", "/")
                    if p_path:
                        p_row = conn.execute('SELECT id FROM files WHERE file_path = ?', (p_path,)).fetchone()
                        if p_row:
                            conn.execute('UPDATE files SET parent_id = ? WHERE id = ?', (p_row['id'], r['id']))

            # Check for owner_delete_password_hash column
            try:
                conn.execute('SELECT owner_delete_password_hash FROM users LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute('ALTER TABLE users ADD COLUMN owner_delete_password_hash TEXT')
                conn.execute('ALTER TABLE users ADD COLUMN owner_delete_password_created_at TEXT')



            # Check for visibility column in files
            try:
                conn.execute('SELECT visibility FROM files LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE files ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'")

            # Check for owner_id backfill
            rows = conn.execute('SELECT id, created_by FROM files WHERE owner_id IS NULL').fetchall()
            for r in rows:
                user = conn.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (r['created_by'],)).fetchone()
                if user:
                    conn.execute('UPDATE files SET owner_id = ? WHERE id = ?', (user['id'], r['id']))

            # Check for file_access table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_access (
                    file_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    PRIMARY KEY (file_id, user_id),
                    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            # Check for created_at column in users
            try:
                conn.execute('SELECT created_at FROM users LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute('ALTER TABLE users ADD COLUMN created_at TEXT')

            # Check for ip_address column in logs
            try:
                conn.execute('SELECT ip_address FROM logs LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute('ALTER TABLE logs ADD COLUMN ip_address TEXT')

            # Check for destination column in logs
            try:
                conn.execute('SELECT destination FROM logs LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute('ALTER TABLE logs ADD COLUMN destination TEXT')

            # Check for workspace_visibility column in users
            try:
                conn.execute('SELECT workspace_visibility FROM users LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE users ADD COLUMN workspace_visibility TEXT DEFAULT 'public'")

            # Check for lock_attempts column in users
            try:
                conn.execute('SELECT lock_attempts FROM users LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE users ADD COLUMN lock_attempts INTEGER DEFAULT 0")

            # Check for encryption/process/hash columns
            try:
                conn.execute('SELECT sha256_hash FROM files LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE files ADD COLUMN sha256_hash TEXT")

            try:
                conn.execute('SELECT pid FROM logs LIMIT 1')
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE logs ADD COLUMN pid INTEGER")
                conn.execute("ALTER TABLE logs ADD COLUMN process_name TEXT")
                conn.execute("ALTER TABLE logs ADD COLUMN parent_process TEXT")

    except Exception as e:
        logger.error(f"Schema update failed: {e}")
    finally:
        conn.close()


def create_user(username, password_hash, role='user'):
    conn = get_db_connection()
    try:
        created_at = get_ist_time()
        with conn:
            conn.execute('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)', 
                         (username, password_hash, role, created_at))
        return True
    except Exception as e:
        logger.error(f"Error creating user {username}: {e}")
        return False
    finally:
        conn.close()

def get_log_by_id(log_id):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT * FROM logs WHERE id = ?', (log_id,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching log by ID: {e}")
    finally:
        conn.close()
    return None

def delete_logs_by_ids(ids):
    conn = get_db_connection()
    try:
        with conn:
            query = f"DELETE FROM logs WHERE id IN ({','.join(['?']*len(ids))})"
            conn.execute(query, ids)
        return True
    except Exception as e:
        logger.error(f"Error deleting logs: {e}")
    finally:
        conn.close()
    return False

def purge_logs_v2(data):
    """
    Advanced purge logic handling various criteria from the Admin Command Center.
    'data' is a dict containing 'type' and 'value'.
    """
    conn = get_db_connection()
    try:
        p_type = data.get('type')
        p_val = data.get('value')
        
        with conn:
            if p_type == 'severity':
                conn.execute("DELETE FROM logs WHERE risk_level = ?", (p_val,))
                
            elif p_type == 'type':
                if p_val == 'AUTH':
                    conn.execute("DELETE FROM logs WHERE action LIKE '%LOGIN%' OR action LIKE '%LOGOUT%'")
                elif p_val == 'FILE_UPLOAD':
                    # Catch both FILE_UPLOAD and UPLOAD and CREATED events
                    conn.execute("DELETE FROM logs WHERE action IN ('FILE_UPLOAD', 'UPLOAD', 'FILE_CREATED', 'DIRECTORY_CREATED')")
                elif p_val == 'DOWNLOAD':
                    conn.execute("DELETE FROM logs WHERE action LIKE '%DOWNLOAD%' OR action = 'VIEW'")
                elif p_val == 'DELETE':
                    # Fix capitalization and handle directory delete
                    conn.execute("DELETE FROM logs WHERE action LIKE '%DELETED%' OR action LIKE '%DELETE%'")
                elif p_val == 'FILE_MODIFIED':
                    conn.execute("DELETE FROM logs WHERE action = 'FILE_MODIFIED'")
                elif p_val == 'DIR_EVENT':
                    conn.execute("DELETE FROM logs WHERE action LIKE 'DIRECTORY_%'")
                elif p_val == 'ENV_CHANGE':
                    # Catch the actual ENV_CHANGE action and user/password changes
                    conn.execute("DELETE FROM logs WHERE action IN ('ENV_CHANGE', 'ACCESS_UPDATE', 'USER_CREATED', 'USER_DELETED', 'OWNER_PASSWORD_SET', 'PASSWORD_CHANGED', 'ADMIN_PASSWORD_CHANGE', 'USER_PASSWORD_CHANGE')")
                    
            elif p_type == 'time':
                if p_val == '24h':
                    # Note: Using IST strings in DB, so this is an approximation but standard for this project's current architecture
                    conn.execute("DELETE FROM logs WHERE timestamp < datetime('now', '+5 hours', '30 minutes', '-24 hours')")
                elif p_val == '7d':
                    conn.execute("DELETE FROM logs WHERE timestamp < datetime('now', '+5 hours', '30 minutes', '-7 days')")
                elif p_val == '30d':
                    conn.execute("DELETE FROM logs WHERE timestamp < datetime('now', '+5 hours', '30 minutes', '-30 days')")
                    
            elif p_type == 'range':
                # Map value: {start: 'YYYY-MM-DD', end: 'YYYY-MM-DD'}
                start = p_val.get('start')
                end = p_val.get('end')
                # Use date() function to compare just the date part of the timestamp
                conn.execute("DELETE FROM logs WHERE date(timestamp) BETWEEN ? AND ?", (start, end))
                
            elif p_type == 'advanced':
                if p_val == 'non_critical':
                    conn.execute("DELETE FROM logs WHERE risk_level NOT IN ('HIGH', 'CRITICAL')")
                elif p_val == 'resolved':
                    # Assuming we might have a resolved flag in future, for now delete INFO which are informational
                    conn.execute("DELETE FROM logs WHERE risk_level = 'INFO'")
                elif p_val == 'user_activity':
                    conn.execute("DELETE FROM logs WHERE username != 'System' AND risk_level IN ('LOW', 'INFO')")
                elif p_val == 'all':
                    conn.execute("DELETE FROM logs")
                    
        return True
    except Exception as e:
        logger.error(f"Error in Advanced Purge: {e}")
    finally:
        conn.close()
    return False

def get_user_password_hash(username):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT password_hash FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        return row['password_hash'] if row else None
    except Exception as e:
        logger.error(f"Error fetching password hash: {e}")
    finally:
        conn.close()
    return None

def update_file_hash(file_path, sha256_hash):
    """Updates the SHA256 hash for a specific file record."""
    conn = get_db_connection()
    try:
        # Standardize path
        file_path = file_path.replace("\\", "/")
        with conn:
            conn.execute('UPDATE files SET sha256_hash = ? WHERE file_path = ?', (sha256_hash, file_path))
    except Exception as e:
        logger.error(f"Error updating file hash: {e}")
    finally:
        conn.close()

def get_file_hash(file_path):
    """Retrieves the stored SHA256 hash for a file."""
    conn = get_db_connection()
    try:
        file_path = file_path.replace("\\", "/")
        row = conn.execute('SELECT sha256_hash FROM files WHERE file_path = ?', (file_path,)).fetchone()
        return row['sha256_hash'] if row else None
    except Exception as e:
        logger.error(f"Error fetching file hash: {e}")
    finally:
        conn.close()
    return None
