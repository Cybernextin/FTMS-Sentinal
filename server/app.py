import os
import shutil
import datetime
import re
import signal
import sys
from functools import wraps
from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask_wtf.csrf import CSRFProtect
from server import database_manager
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import generate_report
import config
from core.severity_engine import SeverityEngine

severity_engine = SeverityEngine()

# --- CONFIGURATION ---
STORAGE_ROOT = config.STORAGE_ROOT
SECRET_KEY = os.environ.get('FTMS_SECRET_KEY', 'FTMS_Sentinel_Secure_Vault_Key_2026')
API_KEY = config.API_KEY

app = Flask(__name__)
bcrypt = Bcrypt(app)
# Security layers disabled for universal browser compatibility
app.config['WTF_CSRF_ENABLED'] = False 
csrf = CSRFProtect(app)

# --- SECURITY HARDENING CONFIG ---
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30) # 30 min timeout
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 200 * 1024 * 1024))

# NETWORK ACCESSIBILITY CONFIG
app.config['SESSION_COOKIE_SECURE'] = False # Allow login over plain HTTP for local network access
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Changed from Strict to allow transitions from dashboard to report more reliably on slow networks
app.config['REMEMBER_COOKIE_SECURE'] = False
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'

# --- SIGNAL HANDLERS ---
def shutdown_handler(sig, frame):
    """Gracefully shuts down the FTMS server."""
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# --- DECORATORS ---
def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login_page'))
            if current_user.role != required_role:
                # Log unauthorized access attempt
                risk = "CRITICAL" if required_role == 'admin' else "HIGH"
                log_security_event(
                    "UNAUTHORIZED_ACCESS", 
                    risk_level=risk, 
                    destination=request.path,
                    message=f"Privilege escalation attempt: {current_user.username} tried to access {request.path}"
                )
                flash("Access Denied: Insufficient permissions.", "error")
                return redirect(url_for('user_dashboard'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# --- HELPER FUNCTIONS ---
def last_modified_time(path):
    """Returns formatted last modification time of a file/folder."""
    try:
        if os.path.exists(path):
            mtime = os.path.getmtime(path)
            return datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
    except:
        pass
    return "N/A"

def validate_path(subpath):
    """
    Standardized path validation and traversal prevention.
    Allows all users to access the STORAGE_ROOT grid, while RBAC 
    subsequently controls entry into specific sectors.
    """
    if not subpath:
        return STORAGE_ROOT
    
    # Secure path joining
    subpath = subpath.lstrip(r'\/')
    safe_path = os.path.normpath(os.path.join(STORAGE_ROOT, subpath))
    
    if not safe_path.startswith(os.path.abspath(STORAGE_ROOT)):
        return None
    return safe_path

def std_response(success=True, message="", data=None, status_code=200):
    """
    Standardized response format:
    {
       "success": true/false,
       "message": "description",
       "data": {}
    }
    """
    response = {
        "success": success,
        "message": message,
        "data": data or {}
    }
    # For backward compatibility with some JS that might use 'status'
    response["status"] = "success" if success else "error"
    return jsonify(response), status_code

def is_path_accessible(subpath, action_type='read'):
    """
    Role-Based Access Control:
    - Admin: Full override.
    - Owner: Full access to own files/folders.
    - Non-Owner: Access if 'public' OR in 'allowedUsers'.
    """
    if not current_user.is_authenticated:
        return False
    if current_user.role == 'admin':
        return True
        
    subpath = subpath.strip('/')
    if not subpath:
        return True # Root level access allowed

    # Section 3: Folder-level permission overrides file-level ownership.
    # We check each segment of the path; if any parent folder grants access, the whole path is accessible.
    parts = subpath.split('/')
    current_check = ""
    
    for part in parts:
        current_check = f"{current_check}/{part}" if current_check else part
        
        # Implicit top-level owner access check
        if current_check.lower() == current_user.username.lower():
            return True
            
        p_info = database_manager.get_file_owner_info(current_check)
        if p_info:
            if p_info['username'].lower() == current_user.username.lower():
                return True
            if p_info['visibility'] == 'public':
                return True
            allowed = database_manager.get_allowed_users(p_info['record_id'])
            if current_user.username.lower() in [u.lower() for u in allowed]:
                return True
        else:
            # Fallback: if no DB record, check if this is a user root and if that user is 'public'
            owner_name = current_check.split('/')[0]
            owner_obj = database_manager.get_user_by_username(owner_name)
            if owner_obj and owner_obj.workspace_visibility == 'public':
                return True
                
    return False

from werkzeug.exceptions import HTTPException

@app.errorhandler(403)
def forbidden(e):
    if request.is_json or request.path == '/upload':
        return jsonify({"success": False, "message": "Access Denied: Level 4 Clearance Required"}), 403
    flash("Access Denied: Restricted Sector", "error")
    return redirect(url_for('login_page'))

@app.errorhandler(404)
def not_found(e):
    if request.is_json:
        return std_response(False, "Sector Missing: Resource not found", status_code=404)
    # Redirect to dashboard if logged in, otherwise login
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login_page'))

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({
        "success": False,
        "message": "File too large"
    }), 413

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    if isinstance(e, HTTPException):
        return e
    app.logger.error(f"SYSTEM FATAL: {str(e)}")
    if request.is_json or request.path == '/upload':
        return jsonify({"success": False, "message": "System Entropy Detected: Stabilizing components"}), 500
    flash("System oscillation detected. Session stabilized.", "error")
    return redirect(url_for('login_page'))

def calculate_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total_size = 0
    try:
        for dirpath, _, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)
    except:
        pass
    return total_size

def count_files_recursive(rel_path):
    """Helper to count files in a directory recursively for bulk detection."""
    full_path = validate_path(rel_path)
    if not full_path or not os.path.exists(full_path):
        return 1
    if not os.path.isdir(full_path):
        return 1
    
    count = 0
    for _, _, files in os.walk(full_path):
        count += len(files)
    return count

def log_security_event(action, file_path=None, destination=None, risk_level=None, count=1, **kwargs):
    """
    Centralized logging helper that dynamically calculates severity.
    """
    try:
        from flask import request
        ip_addr = request.remote_addr if request else "127.0.0.1"
    except:
        ip_addr = "127.0.0.1"

    username = "System"
    role = "user"
    if current_user and current_user.is_authenticated:
        username = current_user.username
        role = current_user.role
    
    # Dynamically determine risk level if not explicitly provided or if it's a generic LOW/INFO/MEDIUM
    if not risk_level or risk_level in ["LOW", "INFO", "MEDIUM"]:
        # The engine handles the heavy lifting of the new patterns
        risk_level = severity_engine.get_severity(action, username, role, file_path, destination, count=count)
    
    database_manager.add_log_entry(
        username, action, risk_level, file_path, destination, ip_addr,
        pid=kwargs.get('pid'),
        process_name=kwargs.get('process_name'),
        parent_process=kwargs.get('parent_process')
    )

# SECURITY HOOKS REMOVED

# --- SECURITY HELPERS ---
def secure_password_check(stored_hash, password):
    """
    Standardized verifier for both Werkzeug and Bcrypt hashes.
    Ensures compatibility across the authentication ecosystem.
    """
    if not stored_hash or not password:
        return False
    
    try:
        if stored_hash.startswith(('$2b$', '$2a$')):
            return bcrypt.check_password_hash(stored_hash, password)
        return check_password_hash(stored_hash, password)
    except Exception:
        return False

@app.after_request
def add_security_headers(response):
    # Security headers removed as requested for universal browser access
    return response

# --- FLASK-LOGIN SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.session_protection = "strong" # Hardened from "basic"

@login_manager.user_loader
def load_user(user_id):
    return database_manager.get_user_by_id(user_id)

# --- CONTEXT PROCESSORS ---
@app.context_processor
def inject_globals():
    return dict(
        database_manager=database_manager, 
        is_admin=(lambda: current_user.is_authenticated and current_user.role == 'admin'),
        last_modified_time=last_modified_time
    )

# --- DB INIT ---
with app.app_context():
    database_manager.init_db()

# --- ROUTES: AUTHENTICATION ---

@app.route('/')
def root_route():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
@app.route('/user/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        if current_user.is_authenticated:
            logout_user()
            session.clear()
        return render_template('login.html', mode='user', action_url=url_for('login_page'))

    return perform_login(is_admin_portal=False)

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        if current_user.is_authenticated and current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html')

    return perform_login(is_admin_portal=True)

def perform_login(is_admin_portal=False):
    raw_username = request.form.get('username', '').strip()
    username = raw_username.lower()
    password = request.form.get('password', '')
    ip_addr = request.remote_addr
    
    if not username or not password:
        flash("Credentials required", "error")
        return redirect(url_for('admin_login' if is_admin_portal else 'login_page'))

    try:
        user_obj = database_manager.get_user_by_username(username)
        if user_obj:
            stored_hash = database_manager.get_user_password_hash(username)
            is_valid = secure_password_check(stored_hash, password)

            if is_valid:
                # Security Restriction: Admins are barred from standard user portals
                if user_obj.role == 'admin' and not is_admin_portal:
                    flash("Access Denied: Administrative accounts must use the secure command portal.", "error")
                    return redirect(url_for('admin_login'))

                # Prevent Session Fixation: Regerate session ID on login
                session.clear()
                session.permanent = True 
                database_manager.reset_login_attempts(username)
                login_user(user_obj)
                
                log_security_event("LOGIN_SUCCESS", risk_level="LOW")
                
                if user_obj.role == 'admin' and is_admin_portal:
                    return redirect(url_for('admin_dashboard'))
                
                return redirect(url_for('user_dashboard'))


        
        # Log failed attempt
        log_security_event("LOGIN_FAILURE", risk_level="MEDIUM", message=f"Failed login attempt for {username}")
        database_manager.increment_login_attempts(username)
        attempts = database_manager.get_login_attempts(username)
        flash(f"Invalid credentials (Attempt {attempts})", "error")
        return redirect(url_for('admin_login' if is_admin_portal else 'login_page'))

    except Exception as e:
        app.logger.error(f"Auth Error: {str(e)}")
        flash("Authentication system oscillation. Contact Administrator.", "error")
        return redirect(url_for('admin_login' if is_admin_portal else 'login_page'))

@app.route('/logout')
def logout():
    """
    Secure Logout Protocol:
    1. Log the event
    2. Destroy standard session
    3. Clear Flask-Login state
    4. Force clear all session data/cookies
    """
    if current_user.is_authenticated:
        log_security_event("LOGOUT", risk_level="INFO")
    
    logout_user()
    session.clear()
    
    # Create response to clear cookies explicitly if needed
    response = redirect(url_for('login_page'))
    response.set_cookie('session', '', expires=0)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    
    flash('Security session terminated.', 'info')
    return response

# --- ROUTES: USER FILE MANAGER ---

@app.route('/user/dashboard')
@app.route('/user/dashboard/<path:subpath>')
@login_required
def user_dashboard(subpath=''):
    subpath = subpath.strip('/')
    full_path = validate_path(subpath)
    if not full_path: abort(404)

    if not is_path_accessible(subpath):
        abort(403)

    if os.path.isfile(full_path):
        return serve_file(subpath)

    try:
        items = []
        for item in os.listdir(full_path):
            item_rel_path = os.path.join(subpath, item).replace("\\", "/")
            item_full_path = os.path.join(full_path, item)
            is_dir = os.path.isdir(item_full_path)

            # Root-level restriction removed to allow global visibility of all folders


            
            can_access = is_path_accessible(item_rel_path, 'read')
            
            # Fallback for visibility: use database record if exists, 
            # otherwise infer from owner's global workspace preference
            owner_info = database_manager.get_file_owner_info(item_rel_path)
            allowed_users = []
            if owner_info:
                visibility_val = owner_info['visibility']
                owner_name = owner_info['username']
                record_id = owner_info['record_id']
                allowed_users = database_manager.get_allowed_users(owner_info['record_id'])
            else:
                owner_name = item_rel_path.split('/')[0]
                owner_obj = database_manager.get_user_by_username(owner_name)
                # If owner is public, folder is public. Otherwise default to private for system safety.
                visibility_val = owner_obj.workspace_visibility if owner_obj else 'private'
                owner_name = owner_obj.username if owner_obj else 'System'
                record_id = None

            items.append({
                'name': item,
                'path': item_rel_path,
                'is_folder': is_dir,
                'size': "CORE" if is_dir else f"{os.path.getsize(item_full_path) / 1024:.1f} KB",
                'modified': last_modified_time(item_full_path),
                'owner': owner_name,
                'can_access': can_access,
                'visibility': visibility_val,
                'id': record_id,
                'allowed_users': allowed_users
            })

        # Calculate environment state for this user/view
        # Single Source of Truth: user's workspace_visibility preference
        is_all_public = (current_user.workspace_visibility == 'public')

        # Emergency override: if ANY item OWNED BY USER in current view is private, force private toggle state
        if is_all_public:
            for item in items:
                if item['owner'].lower() == current_user.username.lower() and item['visibility'] == 'private':
                    is_all_public = False
                    break

        is_valid_pass, _ = database_manager.is_owner_password_valid(current_user.username)
        return render_template('user_dashboard.html', 
                             items=items, 
                             current_path=subpath, 
                             is_all_public=is_all_public,
                             has_password=is_valid_pass)
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return render_template('user_dashboard.html', items=[], current_path=subpath, is_all_public=True, has_password=False)

@app.route('/view/<path:filepath>')
@app.route('/download/<path:filepath>')
@login_required
def serve_file(filepath):
    filepath = filepath.replace('\\', '/').strip('/')
    full_path = validate_path(filepath)
    
    if not full_path or not os.path.exists(full_path):
        app.logger.warning(f"File not found: {filepath}")
        abort(404)
    
    if not is_path_accessible(filepath, 'read'):
        app.logger.warning(f"Access denied to file: {filepath}")
        abort(403)
        
    as_attachment = request.path.startswith('/download/')
    
    if os.path.isdir(full_path) and not as_attachment:
        app.logger.warning(f"Cannot view directory: {filepath}")
        abort(400)
    
    # Log the access/download event
    action = "DOWNLOAD" if as_attachment else "VIEW"
    log_security_event(action, filepath)

    if os.path.isdir(full_path):
        import shutil, tempfile, uuid
        from flask import send_file, after_this_request
        
        temp_dir = tempfile.gettempdir()
        zip_base_name = f"ftms_{uuid.uuid4().hex}"
        zip_base_path = os.path.join(temp_dir, zip_base_name)
        shutil.make_archive(zip_base_path, 'zip', full_path)
        zip_filepath = f"{zip_base_path}.zip"
        
        folder_name = os.path.basename(full_path)
        if not folder_name:
            folder_name = "archive"
        download_name = f"{folder_name}.zip"
        
        @after_this_request
        def cleanup(response):
            try:
                os.remove(zip_filepath)
            except Exception:
                pass
            return response
            
        try:
            return send_file(zip_filepath, as_attachment=True, download_name=download_name)
        except TypeError:
            return send_file(zip_filepath, as_attachment=True, attachment_filename=download_name)
        except Exception as dir_err:
            app.logger.error(f"ZIP DOWNLOAD FAIL: {dir_err}")
            raise

    # Force PDF mime type if extension matches to help some browsers
    mimetype = None
    if filepath.lower().endswith('.pdf'):
        mimetype = 'application/pdf'

    return send_from_directory(
        os.path.dirname(full_path), 
        os.path.basename(full_path), 
        as_attachment=as_attachment,
        mimetype=mimetype
    )

def verify_operation_auth(item_path, provided_password=None):
    """
    Standard Security Policy:
    - Admin: Full override (can delete/modify anything anywhere).
    - Workspace Owner: The user whose root folder name matches the FIRST segment
      of the item path has FULL unconditional authority over every file and folder
      inside their workspace — regardless of who created those items (including admin).
      Example: 'alice' owns and can delete ALL of 'alice/anything/created_by_admin.pdf'
    - Non-Owner: Requires the workspace owner's security key (if set) to modify resources.
    """
    if current_user.role == 'admin':
        return True, "Admin authorized", 200

    # Workspace Ownership Check:
    # The FIRST path segment always identifies the workspace root owner.
    # This grants the account holder unconditional delete/modify rights over their entire
    # namespace — even for files/folders created by admin or transferred from other users.
    workspace_owner = item_path.strip('/').split('/')[0]
    if workspace_owner.lower() == current_user.username.lower():
        return True, "Workspace owner authorized", 200

    # From here: current user is accessing ANOTHER user's workspace
    # Use DB owner info for the security key check; fallback to path-derived owner
    owner_info = database_manager.get_file_owner_info(item_path)
    owner_name = owner_info['username'] if owner_info else workspace_owner

    # Non-owner modification: requires valid, unexpired security key from the workspace owner
    is_p_valid, p_status = database_manager.is_owner_password_valid(owner_name)
    
    if p_status == "NOT_CONFIGURED":
        return False, f"Access Denied: {owner_name} has not enabled security keys for cross-user modifications.", 403
    
    if p_status == "EXPIRED":
        return False, "Security key has expired. Owner must refresh protection.", 401

    # Brute-force protection: check for locked state
    attempts = database_manager.get_lock_attempts(owner_name)
    if attempts >= 5:
        # Check if the lock is historical or recent? For now, we enforce a total lockout until reset.
        log_security_event("LOCK_EXHAUSTION", risk_level="CRITICAL", message=f"Lockout active for {owner_name} (5+ failed attempts)")
        return False, "Security Lockout: Too many failed attempts. Resource is frozen.", 403

    if not provided_password:
        return False, "Security key required for modification.", 401

    owner_pass_info = database_manager.get_owner_password_info(owner_name)
    stored_hash = owner_pass_info.get('owner_delete_password_hash')
    
    if secure_password_check(stored_hash, provided_password):
        database_manager.reset_lock_attempts(owner_name)
        return True, "Security key verified", 200
    
    # Track failed attempt
    database_manager.increment_lock_attempts(owner_name)
    current_attempts = attempts + 1
    log_security_event("INVALID_SECURITY_KEY", risk_level="HIGH", message=f"Failed lock attempt {current_attempts}/5 for {owner_name}")
    
    return False, f"Invalid security key. ({current_attempts}/5 attempts used)", 401

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt', 'png', 'jpg', 'jpeg', 'zip', 'xls', 'xlsx', 'py', 'js', 'html', 'csv'}

def allowed_file(filename):
    return True # Allow all file types

# --- ROUTES: FILE OPERATIONS ---

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files.get('file')
    current_path = request.form.get('current_path', '').strip('/')
    parent_path = request.form.get('parent_path', current_path).strip('/')
    
    # Policy enforcement: nothing allowed to upload in root except admin privilege
    if not parent_path and current_user.role != 'admin':
        app.logger.warning(f"Unauthorized root upload attempt by {current_user.username}")
        return jsonify({"success": False, "message": "Access Denied: Level 4 Clearance Required for root asset deployment"}), 403

    
    app.logger.info(f"--- UPLOAD INITIATED ---")
    app.logger.info(f"Headers: {request.headers}")
    app.logger.info(f"Content-Length: {request.content_length}")
    app.logger.info(f"Target Parent: {parent_path}")
    
    # Step 5 - Debug Logging Equivalent
    app.logger.info(f"req.file: {file}")

    if not file:
        app.logger.warning("Upload failed: No file found in request -> Multer/File attachment issue on frontend")
        return jsonify({"success": False, "message": "File missing from transmission"}), 400
    
    app.logger.info(f"Original Filename: {file.filename}")
    
    if not allowed_file(file.filename):
        app.logger.warning(f"Upload failed: File type restricted for {file.filename}")
        return jsonify({"success": False, "message": "File type restricted"}), 400
    
    # sanitize filename strictly
    import time
    name_only, ext = os.path.splitext(file.filename)
    safe_name = re.sub(r'[\'\"\[\]\(\)]', '', name_only)
    safe_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', safe_name)
    final_name = secure_filename(f"{safe_name}{ext}")

    rel_path = os.path.join(parent_path, final_name).replace("\\", "/")
    full_path = validate_path(rel_path)
    
    if not full_path:
        app.logger.warning(f"Upload failed: Invalid deployment path for {final_name}")
        return jsonify({"success": False, "message": "Invalid deployment path"}), 403
    
    # prevent file overwrite
    if os.path.exists(full_path):
        final_name = f"{int(time.time())}_{final_name}"
        rel_path = os.path.join(parent_path, final_name).replace("\\", "/")
        full_path = validate_path(rel_path)

    try:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        file.save(full_path)
        app.logger.info(f"File saved dynamically to diskStorage at: {full_path}")
        
        database_manager.register_file(final_name, rel_path, current_user.username, visibility=current_user.workspace_visibility)
        log_security_event("FILE_UPLOAD", risk_level="LOW", file_path=rel_path)
        
        return jsonify({
            "success": True,
            "fileUrl": rel_path,
            "message": "Upload successful"
        }), 200
        
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({
            "success": False,
            "message": "Server error during upload"
        }), 500

@app.route('/user/folder/create', methods=['POST'])
@login_required
def unified_create_folder():
    """
    Creates a new directory with cross-user safety checks.
    """
    data = request.get_json() if request.is_json else request.form
    name = secure_filename(data.get('folder_name', data.get('name', '')))
    current_path = data.get('current_path', data.get('parent', '')).strip('/')
    
    if not name: return std_response(False, "Invalid designation", status_code=400)
    
    rel_path = os.path.join(current_path, name).replace("\\", "/")
    full_path = validate_path(rel_path)
    
    # Policy enforcement: root creation restricted to admin privilege
    if not current_path and current_user.role != 'admin':
        return std_response(False, "Folder creation restricted at the network root", status_code=403)
    
    if not full_path: abort(403)

    
    if os.path.exists(full_path):
        return std_response(False, "Sector already exists", status_code=400)
        
    os.makedirs(full_path, exist_ok=True)
    database_manager.register_file(name, rel_path, current_user.username, visibility=current_user.workspace_visibility)
    log_security_event("DIRECTORY_CREATED", risk_level="LOW", file_path=rel_path)
    
    return std_response(True, "New sector initialized", {"name": name, "path": rel_path})

@app.route('/folder/rename/<int:item_id>', methods=['POST'])
@login_required
def rename_by_id(item_id):
    file_info = database_manager.get_file_by_id(item_id)
    if not file_info: return std_response(False, "Resource not found", status_code=404)
    
    if not is_path_accessible(file_info['file_path'], 'write'):
        return std_response(False, "Unauthorized access", status_code=403)
        
    data = request.get_json()
    new_name = secure_filename(data.get('new_name', ''))
    if not new_name: return std_response(False, "Invalid designation", status_code=400)
    
    old_path = file_info['file_path']
    parent_dir = os.path.dirname(old_path)
    new_path = os.path.join(parent_dir, new_name).replace("\\", "/")
    
    old_full = validate_path(old_path)
    new_full = validate_path(new_path)
    
    if os.path.exists(new_full): return std_response(False, "Collision at destination", status_code=400)
    
    try:
        os.rename(old_full, new_full)
        database_manager.update_file_metadata(old_path, new_name, new_path)
        log_security_event("RENAME", risk_level="MEDIUM", file_path=old_path, destination=new_path)
        return std_response(True, "Resource recataloged")
    except Exception as e:
        return std_response(False, str(e), status_code=500)

@app.route('/folder/back/<int:folder_id>')
@login_required
def folder_back_by_id(folder_id):
    item = database_manager.get_file_by_id(folder_id)
    if not item: return redirect(url_for('user_dashboard'))
    
    parent_path = ""
    if item['parent_id']:
        parent = database_manager.get_file_by_id(item['parent_id'])
        if parent: parent_path = parent['file_path']
        
    if current_user.role == 'admin':
        return redirect(url_for('admin_file_explorer') + "?path=" + parent_path)
    return redirect(url_for('user_dashboard', subpath=parent_path))

@app.route('/folder/move/<int:item_id>', methods=['POST'])
@login_required
def move_by_id(item_id):
    item = database_manager.get_file_by_id(item_id)
    if not item: return std_response(False, "Item not found", 404)
    
    data = request.get_json()
    password = data.get('password')
    
    authorized, msg, code = verify_operation_auth(item['file_path'], password)
    if not authorized:
        return std_response(False, msg, code)
        
    dest_path = data.get('dest_path', '').strip('/')
    if not dest_path:
        dest_path = current_user.username
    
    # Validation Rules
    full_dest = validate_path(dest_path)
    if not full_dest or not os.path.exists(full_dest) or not os.path.isdir(full_dest):
        return std_response(False, "Invalid destination", 400)

    # Destination permission check (Must have read/write access to destination)
    # Actually, moving into something usually requires it to be yours or public.
    # However, for simplicity, we allow moving into any valid path that is not restricted by root rules.
    pass

    src_path = item['file_path']
    if dest_path == src_path or dest_path.startswith(src_path + '/'):
        return std_response(False, "Circular move denied", 400)
        
    src_full = validate_path(src_path)
    target_full = os.path.join(full_dest, os.path.basename(src_path))
    
    if os.path.exists(target_full):
        return std_response(False, "Name collision in destination", 400)
        
    shutil.move(src_full, target_full)
    new_path = os.path.join(dest_path, os.path.basename(src_path)).replace("\\", "/")
    
    # Find new parent ID
    new_parent_id = None
    p_row = database_manager.get_file_by_path(dest_path)
    if p_row: new_parent_id = p_row['id']

    database_manager.update_file_metadata(src_path, os.path.basename(src_path), new_path, new_parent_id=new_parent_id)
    # Calculate bulk count for escalation
    count = count_files_recursive(src_path)
    log_security_event("MOVE", risk_level="MEDIUM", file_path=src_path, destination=new_path, count=count)
    
    return std_response(True, "Moved successfully", {"new_path": new_path})

@app.route('/user/folder/move', methods=['POST'])
@login_required
def user_api_move():
    data = request.json
    src_path = data.get('src_path', '').strip('/')
    dest_dir = data.get('dest_path', '').strip('/')
    password = data.get('password')

    if not src_path: return std_response(False, "Source required", status_code=400)
    
    # Auth Check
    authorized, msg, code = verify_operation_auth(src_path, password)
    if not authorized: return std_response(False, msg, code)

    src_full = validate_path(src_path)
    dest_full_dir = validate_path(dest_dir)
    if not src_full or not dest_full_dir: abort(403)
    
    if dest_full_dir == src_full or dest_full_dir.startswith(src_full + '/') or dest_full_dir.startswith(src_full + '\\'):
        return std_response(False, "Circular move denied", status_code=400)
    
    filename = os.path.basename(src_path)
    target_rel = os.path.join(dest_dir, filename).replace("\\", "/")
    target_full = validate_path(target_rel)
    
    if os.path.exists(target_full):
        return std_response(False, "Collision at destination", status_code=400)
        
    shutil.move(src_full, target_full)
    
    # Update DB
    new_parent_id = None
    p_info = database_manager.get_file_by_path(dest_dir)
    if p_info: new_parent_id = p_info['id']
    
    # Calculate bulk count for escalation
    count = count_files_recursive(src_path)
    database_manager.update_file_metadata(src_path, filename, target_rel, new_parent_id=new_parent_id)
    log_security_event("MOVE", risk_level="MEDIUM", file_path=src_path, destination=target_rel, count=count)
    return std_response(True, "Resource relocated")

@app.route('/api/folders/move-targets')
@login_required
def api_get_move_targets():
    """
    Returns a list of sectors suitable for tree rendering.
    Forces orphans to be children of ROOT (id=0).
    """
    targets = [{"id": 0, "parent_id": None, "name": "ROOT", "path": "", "owner": "System", "is_folder": True}]
    
    conn = database_manager.get_db_connection()
    try:
        if current_user.role == 'admin':
            rows = conn.execute("SELECT id, parent_id, file_path, file_name, created_by FROM files").fetchall()
        else:
            rows = conn.execute("""
                SELECT id, parent_id, file_path, file_name, created_by FROM files 
                WHERE (owner_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE) OR visibility = 'public')
            """, (current_user.username,)).fetchall()
            
        # Build Tree
        items_map = {}
        # Initialize map with ROOT (targets[0])
        # targets[0] is ROOT with id=0.
        root_node = targets[0]
        root_node['children'] = []
        items_map[0] = root_node
        
        # Add all file rows to map
        for r in rows:
            path_val = validate_path(r['file_path'])
            if path_val and os.path.exists(path_val) and os.path.isdir(path_val):
                pid = r['parent_id']
                if pid is None: pid = 0
                
                item = {
                    "id": r['id'],
                    "parent_id": pid,
                    "name": r['file_name'],
                    "path": r['file_path'],
                    "owner": r['created_by'],
                    "is_folder": True,
                    "children": []
                }
                items_map[item['id']] = item

        # Assign children (Iterate over map items, skipping ROOT initially)
        # We need to list IDs to avoid runtime error if map changes (it won't, but safer)
        all_ids = list(items_map.keys())
        for i_id in all_ids:
            if i_id == 0: continue
            
            item = items_map[i_id]
            pid = item['parent_id']
            
            if pid in items_map:
                items_map[pid]['children'].append(item)
            else:
                # If parent not allowed/found, attach to ROOT
                items_map[0]['children'].append(item)
                
        # Return only the ROOT node (or list of roots if valid)
        # Since we forced everything under ROOT(0), we should ideally just return [root_node]
        # But for UI versatility we'll return list containing ROOT
        
        final_roots = [items_map[0]]
        
        def sort_recursive(node):
            node['children'].sort(key=lambda x: x['name'].lower())
            for c in node['children']:
                sort_recursive(c)
                
        sort_recursive(items_map[0])
        
        return std_response(True, "Tree structure acquired", {"targets": final_roots})
    finally:
        conn.close()

@app.route('/folder/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_by_id(item_id):
    file_info = database_manager.get_file_by_id(item_id)
    if not file_info: return std_response(False, "Resource not found", status_code=404)
    
    # Security Policy: 
    # Must be owner OR admin to delete without key if no key set.
    # If key set, any authorized writer must provide it.
    
    # Safely parse JSON body — body may be absent or non-JSON
    try:
        body = request.get_json(silent=True) or {}
        provided_password = body.get('password')
    except Exception:
        provided_password = None

    auth_success, auth_msg, auth_code = verify_operation_auth(file_info['file_path'], provided_password)
    if not auth_success: return std_response(False, auth_msg, status_code=auth_code)
    
    full_path = validate_path(file_info['file_path'])
    if not full_path or not os.path.exists(full_path):
        return std_response(False, "Physical asset missing", status_code=404)
        
    try:
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)
        else:
            os.remove(full_path)
            
        # Calculate bulk count before deletion for escalation
        count = count_files_recursive(file_info['file_path'])
        database_manager.remove_file_metadata(file_info['file_path'])
        log_security_event("DELETE", file_path=file_info['file_path'], count=count)
        return std_response(True, "Resource incinerated")
    except Exception as e:
        return std_response(False, f"Incineration failure: {str(e)}", status_code=500)

@app.route('/user/folder/rename', methods=['POST'])
@login_required
def rename_item_path():
    data = request.get_json()
    old_path = data.get('old_path', '').strip('/')
    new_name = secure_filename(data.get('new_name', ''))
    password = data.get('password')

    if not old_path or not new_name:
        return std_response(False, "Insufficient metadata for recataloging", 400)

    authorized, msg, code = verify_operation_auth(old_path, password)
    if not authorized: return std_response(False, msg, code)

    parent_dir = os.path.dirname(old_path)
    new_path = os.path.join(parent_dir, new_name).replace("\\", "/")
    
    old_full = validate_path(old_path)
    new_full = validate_path(new_path)
    
    if os.path.exists(new_full): return std_response(False, "Collision at destination", 400)
    
    try:
        os.rename(old_full, new_full)
        database_manager.update_file_metadata(old_path, new_name, new_path)
        log_security_event("RENAME", risk_level="MEDIUM", file_path=old_path, destination=new_path)
        return std_response(True, "Resource recataloged")
    except Exception as e:
        return std_response(False, str(e), 500)

@app.route('/user/folder/move', methods=['POST'])
@login_required
def move_item_path():
    data = request.get_json()
    src_path = data.get('src_path', '').strip('/')
    dest_path = data.get('dest_path', '').strip('/')
    password = data.get('password')

    if not src_path or dest_path is None:
        return std_response(False, "Relocation parameters insufficient", 400)

    authorized, msg, code = verify_operation_auth(src_path, password)
    if not authorized: return std_response(False, msg, code)

    full_dest = validate_path(dest_path)
    if not full_dest or not os.path.exists(full_dest) or not os.path.isdir(full_dest):
        return std_response(False, "Invalid destination sector", 400)

    src_full = validate_path(src_path)
    target_full = os.path.join(full_dest, os.path.basename(src_path))
    
    if os.path.exists(target_full):
        return std_response(False, "Name collision in destination", 400)
        
    shutil.move(src_full, target_full)
    new_path = os.path.join(dest_path, os.path.basename(src_path)).replace("\\", "/")
    
    new_parent_id = None
    p_row = database_manager.get_file_by_path(dest_path)
    if p_row: new_parent_id = p_row['id']

    database_manager.update_file_metadata(src_path, os.path.basename(src_path), new_path, new_parent_id=new_parent_id)
    # Calculate bulk count for escalation
    count = count_files_recursive(src_path)
    log_security_event("MOVE", risk_level="MEDIUM", file_path=src_path, destination=new_path, count=count)
    
    return std_response(True, "Resource relocated", {"new_path": new_path})

@app.route('/delete-file', methods=['POST'])
@app.route('/delete_item', methods=['POST'])
@app.route('/user/folder/delete', methods=['POST'])
@login_required
def delete_item():
    data = request.get_json() if request.is_json else request.form
    item_path = (data.get('path') or data.get('item_path', '')).strip('/')
    password = data.get('password') or data.get('owner_password')

    if not item_path:
        return std_response(False, "Path required", 400)

    authorized, msg, code = verify_operation_auth(item_path, password)
    if not authorized:
        return std_response(False, msg, code)

    full_path = validate_path(item_path)
    if not full_path or not os.path.exists(full_path):
        # Even if file is gone, cleanup DB metadata
        database_manager.remove_file_metadata(item_path)
        return std_response(True, "Metadata purged")

    try:
        if os.path.isdir(full_path): 
            shutil.rmtree(full_path)
        else: 
            os.remove(full_path)
        
        # Calculate bulk count for escalation
        count = count_files_recursive(item_path)
        database_manager.remove_file_metadata(item_path)
        log_security_event("DELETE", risk_level="LOW", file_path=item_path, count=count)
        return std_response(True, "Resource incinerated successfully")
    except Exception as e:
        app.logger.error(f"Deletion failure: {e}")
        return std_response(False, "Internal deletion failure", 500)



# --- ROUTES: ADMIN ---

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    conn = database_manager.get_db_connection()
    try:
        logs = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 500").fetchall()
        # FTMS Scope Filtering for stats
        transfer_actions = ['FILE_UPLOAD', 'UPLOAD', 'FILE_CREATED', 'DIRECTORY_CREATED', 'DOWNLOAD', 'FILE_DOWNLOAD', 'VIEW', 'DELETE', 'ADMIN_DELETE', 'FILE_DELETED', 'DIRECTORY_DELETED', 'RENAME', 'ADMIN_RENAME', 'FILE_MODIFIED', 'MOVE', 'ADMIN_MOVE', 'FILE_MOVED', 'ACCESS_UPDATE', 'ENV_CHANGE', 'UNAUTHORIZED_EXECUTABLE', 'RANSOMWARE_INDICATOR', 'SENSITIVE_EXIT', 'STORAGE_EXIT', 'EXTENSION_MASKING', 'SENSITIVE_KEYWORD', 'USER_CREATED', 'USER_DELETED', 'OWNER_PASSWORD_SET', 'PASSWORD_CHANGED', 'ADMIN_PASSWORD_CHANGE', 'USER_PASSWORD_CHANGE']
        placeholders = ','.join(['?'] * len(transfer_actions))
        stats = {
            "total_events": conn.execute(f"SELECT COUNT(*) FROM logs WHERE action IN ({placeholders})", transfer_actions).fetchone()[0],
            "critical_events": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'CRITICAL' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "high_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'HIGH' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "medium_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'MEDIUM' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "low_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'LOW' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "info_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'INFO' AND action IN ({placeholders})", transfer_actions).fetchone()[0]
        }
        usernames = [r[0] for r in conn.execute("SELECT username FROM users").fetchall()]
    finally: conn.close()
    return render_template('admin.html', logs=logs, stats=stats, usernames=usernames)

@app.route('/api/logs')
@login_required
@role_required('admin')
def api_get_logs():
    conn = database_manager.get_db_connection()
    try:
        logs = [dict(row) for row in conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 500").fetchall()]
        # FTMS Scope Filtering for stats
        transfer_actions = ['FILE_UPLOAD', 'UPLOAD', 'FILE_CREATED', 'DIRECTORY_CREATED', 'DOWNLOAD', 'FILE_DOWNLOAD', 'VIEW', 'DELETE', 'ADMIN_DELETE', 'FILE_DELETED', 'DIRECTORY_DELETED', 'RENAME', 'ADMIN_RENAME', 'FILE_MODIFIED', 'MOVE', 'ADMIN_MOVE', 'FILE_MOVED', 'ACCESS_UPDATE', 'ENV_CHANGE', 'UNAUTHORIZED_EXECUTABLE', 'RANSOMWARE_INDICATOR', 'SENSITIVE_EXIT', 'STORAGE_EXIT', 'EXTENSION_MASKING', 'SENSITIVE_KEYWORD', 'USER_CREATED', 'USER_DELETED', 'OWNER_PASSWORD_SET', 'PASSWORD_CHANGED', 'ADMIN_PASSWORD_CHANGE', 'USER_PASSWORD_CHANGE']
        placeholders = ','.join(['?'] * len(transfer_actions))
        stats = {
            "total_events": conn.execute(f"SELECT COUNT(*) FROM logs WHERE action IN ({placeholders})", transfer_actions).fetchone()[0],
            "critical_events": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'CRITICAL' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "high_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'HIGH' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "medium_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'MEDIUM' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "low_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'LOW' AND action IN ({placeholders})", transfer_actions).fetchone()[0],
            "info_risk": conn.execute(f"SELECT COUNT(*) FROM logs WHERE risk_level = 'INFO' AND action IN ({placeholders})", transfer_actions).fetchone()[0]
        }
    finally: conn.close()
    return std_response(True, "Logs retrieved", {"logs": logs, "stats": stats})

@app.route('/api/logs/delete_selected', methods=['POST'])
@login_required
@role_required('admin')
def api_delete_selected_logs():
    ids = request.get_json().get('ids', [])
    if ids and database_manager.delete_logs_by_ids(ids):
        return std_response(True, "Logs deleted", {"count": len(ids)})
    return std_response(False, "Failed to delete logs", 400)

@app.route('/api/logs/purge', methods=['POST'])
@login_required
@role_required('admin')
def api_purge_logs():
    data = request.get_json()
    purge_type = data.get('type')
    purge_value = data.get('value')
    
    # Security: Nuclear purge requires password confirmation
    if purge_type == 'advanced' and purge_value == 'all':
        password = data.get('password')
        actual_hash = database_manager.get_user_password_hash(current_user.username)
        is_valid = False
        if actual_hash:
            if actual_hash.startswith(('$2b$', '$2a$')):
                is_valid = bcrypt.check_password_hash(actual_hash, password)
            else:
                is_valid = check_password_hash(actual_hash, password)
        
        if not is_valid:
            return std_response(False, "Authentication failed. Nuclear purge aborted.", 401)
    
    if database_manager.purge_logs_v2(data):
        return std_response(True, "Log incineration successful.")
    return std_response(False, "System error during log purge process.", 400)

@app.route('/admin/logs/override')
@login_required
@role_required('admin')
def admin_logs_override():
    """Nuclear purge override (now handled in dashboard directly)."""
    return redirect(url_for('admin_dashboard') + '?openModal=purgeModal')

@app.route('/report')
@login_required
def report():
    # Role-based validation
    if current_user.role != 'admin':
        # Generic check: Users are allowed but restricted to their own data below
        pass

    import socket
    log_id = request.args.get('id')
    ids_raw = request.args.get('ids')
    ranks_raw = request.args.get('ranks')
    rank_single = request.args.get('rank')
    count = request.args.get('count', type=int)
    range_limits = request.args.get('range')
    logs = []
    log = None
    ranks_map = {}
    
    conn = database_manager.get_db_connection()
    try:
        if log_id:
            # Single log view
            log_data = database_manager.get_log_by_id(log_id)
            if log_data:
                # Security: Prevent unauthorized access
                if current_user.role != 'admin' and log_data.get('username').lower() != current_user.username.lower():
                    abort(403)
                log = log_data
                logs = [log]
        elif ids_raw:
            # Specific selection batch view
            id_list = [i.strip() for i in ids_raw.split(',') if i.strip().isdigit()]
            if id_list:
                placeholders = ','.join(['?'] * len(id_list))
                query = f"SELECT * FROM logs WHERE id IN ({placeholders}) ORDER BY timestamp DESC"
                if current_user.role == 'admin':
                    logs = conn.execute(query, id_list).fetchall()
                else:
                    query = f"SELECT * FROM logs WHERE username = ? AND id IN ({placeholders}) ORDER BY timestamp DESC"
                    logs = conn.execute(query, [current_user.username] + id_list).fetchall()
                logs = [dict(l) for l in logs]
                if logs: log = logs[0]
        elif range_limits:
            try:
                f, t = map(int, range_limits.split('-'))
                if current_user.role == 'admin':
                    logs = conn.execute("SELECT * FROM logs WHERE id >= ? AND id <= ? ORDER BY timestamp DESC", (f, t)).fetchall()
                else:
                    logs = conn.execute("SELECT * FROM logs WHERE username = ? AND id >= ? AND id <= ? ORDER BY timestamp DESC", (current_user.username, f, t)).fetchall()
                logs = [dict(l) for l in logs]
                if logs: log = logs[0]
            except ValueError:
                pass
        elif count:
            # Multi-log batch view
            if current_user.role == 'admin':
                logs = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (count,)).fetchall()
            else:
                logs = conn.execute("SELECT * FROM logs WHERE username = ? ORDER BY timestamp DESC LIMIT ?", (current_user.username, count)).fetchall()
            logs = [dict(l) for l in logs]
            if logs: log = logs[0] # Primary log for headers
        
        # Fallback to latest log if nothing else provides data
        if not log and not logs:
            if current_user.role == 'admin':
                log_data = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 1").fetchone()
            else:
                log_data = conn.execute("SELECT * FROM logs WHERE username = ? ORDER BY timestamp DESC LIMIT 1", (current_user.username,)).fetchone()
            if log_data:
                log = dict(log_data)
                logs = [log]
    finally:
        conn.close()

    # Build ranks map for the template
    if rank_single and log_id:
        ranks_map[str(log_id)] = rank_single
    elif ranks_raw and ids_raw:
        r_list = [r.strip() for r in ranks_raw.split(',')]
        i_list = [i.strip() for i in ids_raw.split(',')]
        for i, r in zip(i_list, r_list):
            ranks_map[i] = r

    return render_template('report_ai.html', log=log, logs=logs, ranks=ranks_map)

@app.route('/api/audit/generate', methods=['POST'])
@login_required
@role_required('admin')
def api_audit_generate():
    data = request.get_json()
    gen_type = data.get('type')
    
    if gen_type == 'selected':
        items = data.get('selectedItems', [])
        if not items:
            return std_response(False, "No identifiers provided", 400)
        ids_str = ",".join([str(i['id']) for i in items])
        ranks_str = ",".join([str(i['rank']) for i in items])
        return std_response(True, "Report request successful", {
            "redirect_url": url_for('report', ids=ids_str, ranks=ranks_str)
        })
    elif gen_type == 'range':
        from_val = data.get('from')
        to_val = data.get('to')
        if from_val is None or to_val is None or from_val > to_val:
            return std_response(False, "Invalid range parameters", 400)
        return std_response(True, "Report request successful", {
            "redirect_url": url_for('report', range=f"{from_val}-{to_val}")
        })
    
    return std_response(False, "Invalid generation mode", 400)

@app.route('/add-user', methods=['POST'])
@login_required
@role_required('admin')
def add_user():
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password: return std_response(False, "Missing credentials", 400)

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    if database_manager.create_user(username, hashed):
        user_dir = os.path.join(STORAGE_ROOT, username)
        os.makedirs(user_dir, exist_ok=True)
        # Register user root in metadata
        database_manager.register_file(username, username, username, visibility='private')
        log_security_event("USER_CREATED", risk_level="INFO", file_path=username)
        return std_response(True, "User created")
    return std_response(False, "User exists", 400)

@app.route('/admin/change-password', methods=['POST'])
@login_required
@role_required('admin')
def admin_change_password():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password')
    
    if not username or not password: 
        return std_response(False, "Missing data", 400)
    
    if len(password) < 6: 
        return std_response(False, "Password must be at least 6 characters.", 400)

    # Use Bcrypt for consistency with add_user
    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    
    conn = database_manager.get_db_connection()
    try:
        with conn:
            cursor = conn.execute('UPDATE users SET password_hash = ? WHERE username = ? COLLATE NOCASE', (hashed, username))
            if cursor.rowcount == 0:
                return std_response(False, f"User '{username}' not found in the manifest.", 404)
                
        log_security_event("ADMIN_PASSWORD_CHANGE", risk_level="HIGH", file_path=username)
        return std_response(True, "User credentials successfully updated.")
    except Exception as e:
        app.logger.error(f"Error changing password: {e}")
        return std_response(False, f"Internal error: {str(e)}", 500)
    finally:
        conn.close()

@app.route('/delete-user', methods=['POST'])
@login_required
@role_required('admin')
def admin_delete_user():
    data = request.get_json()
    username = data.get('username')
    if not username: return std_response(False, "Username required", 400)
    
    success, message = database_manager.delete_user(username)
    if success:
        log_security_event("USER_DELETED", risk_level="HIGH", file_path=username)
        return std_response(True, message)
    return std_response(False, message, 400)

# --- ADMIN API: FILE EXPLORER ---

@app.route('/admin/file-explorer')
@login_required
@role_required('admin')
def admin_file_explorer():
    # Check global visibility state
    # Single source of truth for admin toggle
    is_global_public = (current_user.workspace_visibility == 'public')
    
    # Force private if any private files exist to maintain consistency
    if is_global_public:
        conn = database_manager.get_db_connection()
        private_count = conn.execute("SELECT COUNT(*) FROM files WHERE visibility = 'private'").fetchone()[0]
        conn.close()
        if private_count > 0:
            is_global_public = False
            
    return render_template('admin_file_manager.html', is_global_public=is_global_public)

@app.route('/admin/file-api/list')
@login_required
@role_required('admin')
def admin_api_list():
    subpath = request.args.get('subpath', '').strip('/')
    full_path = validate_path(subpath)
    
    if not full_path or not os.path.exists(full_path):
        return std_response(False, "Sector not found", status_code=404)
        
    items = []
    try:
        # If accessing root, ensure we see all physical user directories even if not in DB
        # But we primarily rely on os.scandir which sees the filesystem
        with os.scandir(full_path) as it:
            for entry in it:
                rel_path = os.path.join(subpath, entry.name).replace("\\", "/")
                stat = entry.stat()
                is_dir = entry.is_dir()
                
                if subpath == '':
                    app.logger.info(f"SCAN_ROOT: entry={entry.name} is_dir={is_dir}")
                
                # Admin Root View: Only show folders belonging to actual registered users
                if subpath == '':
                    if not is_dir: continue # Hide files at root
                    
                    # Logic: Allow if it's a registered user OR a known system folder
                    is_registered_user = database_manager.get_user_by_username(entry.name) is not None
                    is_system_folder = entry.name.lower() in ['.quarantine', 'admin', 'logs', 'storage']
                    
                    if not (is_registered_user or is_system_folder):
                        continue # Hide other non-user folders at root

                
                # Fetch metadata
                owner_info = database_manager.get_file_owner_info(rel_path)
                
                # Robust owner fallback
                if owner_info:
                    owner = owner_info['username']
                    visibility = owner_info['visibility']
                    record_id = owner_info['record_id']
                elif entry.name.lower() in ['.quarantine', 'admin', 'logs']:
                    # Force system folders to be visible and attributed to System
                    owner = "System"
                    visibility = "public"
                    record_id = None
                else:
                    # If no record, infer from path structure
                    parts = rel_path.split('/')
                    owner_name = parts[0] if parts else "System"
                    owner_obj = database_manager.get_user_by_username(owner_name)
                    
                    owner = owner_obj.username if owner_obj else "System"
                    # Use owner's visibility preference as the fallback source of truth
                    visibility = owner_obj.workspace_visibility if owner_obj else "private"
                    record_id = None
                
                # Admin View: Show everything
                items.append({
                    "id": record_id if record_id is not None else "",
                    "name": entry.name,
                    "path": rel_path,
                    "type": "folder" if is_dir else "file",
                    "size": stat.st_size,
                    "modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    "owner": owner,
                    "visibility": visibility,
                    "is_folder": is_dir # Redundant helper for some JS
                })
        
        return std_response(True, "Sectors listed", {"items": items})
    except Exception as e:
        return std_response(False, str(e), status_code=500)

@app.route('/admin/file-api/create-folder', methods=['POST'])
@login_required
@role_required('admin')
def admin_api_create_folder():
    data = request.json
    parent = data.get('parent', '').strip('/')
    name = secure_filename(data.get('name', ''))
    if not name: return std_response(False, "Invalid designation", status_code=400)
    
    rel_path = os.path.join(parent, name).replace("\\", "/")
    full_path = validate_path(rel_path)
    if not full_path: abort(403)
    
    if os.path.exists(full_path):
        return std_response(False, "Sector already exists", status_code=400)
        
    os.makedirs(full_path, exist_ok=True)
    database_manager.register_file(name, rel_path, current_user.username)
    log_security_event("ADMIN_CREATE_FOLDER", risk_level="LOW", file_path=rel_path)
    return std_response(True, "Sector initialized", {"path": rel_path})

@app.route('/admin/file-api/rename', methods=['POST'])
@login_required
@role_required('admin')
def admin_api_rename():
    data = request.json
    old_path = data.get('old_path', '').strip('/')
    new_name = secure_filename(data.get('new_name', ''))
    if not old_path or not new_name: return std_response(False, "Missing criteria", status_code=400)
    
    old_full = validate_path(old_path)
    new_rel = os.path.join(os.path.dirname(old_path), new_name).replace("\\", "/")
    new_full = validate_path(new_rel)
    
    if os.path.exists(new_full): return std_response(False, "Collision detected", status_code=400)
    
    os.rename(old_full, new_full)
    database_manager.update_file_metadata(old_path, new_name, new_rel)
    log_security_event("ADMIN_RENAME", risk_level="MEDIUM", file_path=old_path, destination=new_rel)
    return std_response(True, "Resource recataloged")

@app.route('/admin/file-api/delete', methods=['POST'])
@login_required
@role_required('admin')
def admin_api_delete():
    path = request.json.get('path', '').strip('/')
    full_path = validate_path(path)
    if not full_path or not os.path.exists(full_path):
        return std_response(False, "Resource missing", status_code=404)
    
    if os.path.isdir(full_path): shutil.rmtree(full_path)
    else: os.remove(full_path)
    
    # Calculate bulk count before deletion for escalation
    count = count_files_recursive(path)
    database_manager.remove_file_metadata(path)
    log_security_event("ADMIN_DELETE", risk_level="HIGH", file_path=path, count=count)
    return std_response(True, "Resource incinerated")

@app.route('/admin/file-api/move', methods=['POST'])
@login_required
@role_required('admin')
def admin_api_move():
    data = request.json
    src_path = data.get('src_path', '').strip('/')
    dest_dir = data.get('dest_dir', '').strip('/')
    
    if not src_path: return std_response(False, "Source required", status_code=400)
    
    src_full = validate_path(src_path)
    dest_full_dir = validate_path(dest_dir)
    if not src_full or not dest_full_dir: abort(403)
    
    if dest_full_dir == src_full or dest_full_dir.startswith(src_full + os.sep) or dest_full_dir.startswith(src_full + '/'):
        return std_response(False, "Circular move denied", status_code=400)
    
    filename = os.path.basename(src_path)
    target_rel = os.path.join(dest_dir, filename).replace("\\", "/")
    target_full = validate_path(target_rel)
    
    if os.path.exists(target_full):
        return std_response(False, "Collision at destination", status_code=400)
        
    shutil.move(src_full, target_full)
    
    # Update DB
    new_parent_id = None
    p_info = database_manager.get_file_by_path(dest_dir)
    if p_info: new_parent_id = p_info['id']
    
    # Calculate bulk count for escalation
    count = count_files_recursive(src_path)
    database_manager.update_file_metadata(src_path, filename, target_rel, new_parent_id=new_parent_id)
    log_security_event("ADMIN_MOVE", risk_level="MEDIUM", file_path=src_path, destination=target_rel, count=count)
    return std_response(True, "Resource relocated")


@app.route('/admin/file-api/download')
@login_required
@role_required('admin')
def admin_api_download():
    path = request.args.get('path', '').strip('/')
    full_path = validate_path(path)
    if not full_path or not os.path.exists(full_path):
        abort(404)
        
    log_security_event("ADMIN_DOWNLOAD", risk_level="INFO", file_path=path, ip_address=request.remote_addr)

    if os.path.isdir(full_path):
        import shutil, tempfile, uuid
        from flask import send_file, after_this_request
        
        temp_dir = tempfile.gettempdir()
        zip_base_name = f"ftms_{uuid.uuid4().hex}"
        zip_base_path = os.path.join(temp_dir, zip_base_name)
        shutil.make_archive(zip_base_path, 'zip', full_path)
        zip_filepath = f"{zip_base_path}.zip"
        
        folder_name = os.path.basename(full_path)
        if not folder_name:
            folder_name = "archive"
        download_name = f"{folder_name}.zip"
        
        @after_this_request
        def cleanup(response):
            try:
                os.remove(zip_filepath)
            except Exception:
                pass
            return response
            
        try:
            return send_file(zip_filepath, as_attachment=True, download_name=download_name)
        except TypeError:
            return send_file(zip_filepath, as_attachment=True, attachment_filename=download_name)
            
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=True)




# --- MONITOR API ---

@app.route('/api/log', methods=['POST'])
def receive_log_api():
    if request.headers.get("X-API-KEY") != API_KEY: abort(401)
    data = request.json
    if not data: abort(400)

    action = data.get('action', 'UNKNOWN').upper()
    file_path = data.get('file_path')
    
    # FTMS Scope Filtering
    FTMS_ACTIONS = [
        'FILE_UPLOAD', 'UPLOAD', 'DOWNLOAD', 'FILE_DOWNLOAD', 'VIEW',
        'DELETE', 'ADMIN_DELETE', 'FILE_DELETED', 'DIRECTORY_DELETED',
        'RENAME', 'ADMIN_RENAME', 'FILE_MODIFIED', 
        'MOVE', 'ADMIN_MOVE', 'FILE_MOVED',
        'FILE_CREATED', 'DIRECTORY_CREATED',
        'ACCESS_UPDATE', 'ENV_CHANGE', 
        'UNAUTHORIZED_EXECUTABLE', 'RANSOMWARE_INDICATOR', 'SENSITIVE_EXIT', 'STORAGE_EXIT',
        'EXTENSION_MASKING', 'SENSITIVE_KEYWORD', 'USER_CREATED', 'USER_DELETED',
        'INTEGRITY_VIOLATION', 'FILE_QUARANTINED'
    ]
    
    if action not in FTMS_ACTIONS:
        return std_response(True, f"Log suppressed: {action} is non-FTMS activity")
    
    # Sync reality with metadata
    if action in ["FILE_DELETED", "DIRECTORY_DELETED"] and file_path:
        # Convert absolute path to relative if needed
        rel_path = file_path
        if os.path.isabs(file_path):
            try:
                rel_path = os.path.relpath(file_path, STORAGE_ROOT).replace("\\", "/")
            except ValueError:
                pass
        database_manager.remove_file_metadata(rel_path)

    log_security_event(
        action=action,
        risk_level=data.get('risk_level'),
        file_path=file_path,
        destination=data.get('destination') or data.get('reason'),
        pid=data.get('pid'),
        process_name=data.get('process_name'),
        parent_process=data.get('parent_process')
    )
    return std_response(True, "Event cataloged", status_code=201)


# --- REPORTING ---

@app.route('/generate-report', methods=['POST'])
@login_required
@role_required('admin')
def flask_generate_report():
    """
    Handles report generation triggered from admin.js.
    admin.js sends: {type: 'count'|'selection', count: N, files: [...]}
    admin.js expects back: {success: bool, data: {redirect_url: str}, message: str}
    """
    data = request.json or {}
    gen_type = data.get('type', 'count')
    
    try:
        if gen_type == 'count':
            count = data.get('count')
            if not count or not str(count).isdigit() or int(count) <= 0:
                return std_response(False, "Invalid count: must be a positive integer", status_code=400)
            # Use the inline HTML report viewer
            return std_response(True, "Report ready", {
                "redirect_url": url_for('report', count=int(count))
            })
            
        elif gen_type == 'selection':
            files = data.get('files', [])
            if not files or not isinstance(files, list):
                return std_response(False, "No log entries selected", status_code=400)
            ids = ",".join([str(f) for f in files if str(f).isdigit()])
            if not ids:
                return std_response(False, "Invalid selection — no valid IDs", status_code=400)
            return std_response(True, "Report ready", {
                "redirect_url": url_for('report', ids=ids)
            })
            
        elif gen_type == 'pdf':
            # Full PDF generation via generate_report module
            res = generate_report.generate({'username': current_user.username})
            if res.get('status') == 'success':
                return std_response(True, "PDF report generated", {
                    "redirect_url": res.get('file_url', '/downloads/')
                })
            return std_response(False, res.get('message', 'PDF generation failed'), status_code=500)
            
        return std_response(False, "Unknown generation mode", status_code=400)
        
    except Exception as e:
        app.logger.error(f"Report generation error: {e}")
        return std_response(False, f"Report engine failure: {str(e)}", status_code=500)

@app.route('/downloads/<path:filename>')
@login_required
@role_required('admin')
def download_report(filename):
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
    return send_from_directory(report_dir, filename)

# --- SYSTEM ---

@app.route('/security-status')
@login_required
def security_status():
    user = request.args.get('username', current_user.username)
    is_valid, status = database_manager.is_owner_password_valid(user)
    return std_response(True, "Security readout", {"has_password": is_valid, "status": status, "username": user})


@app.route('/set-password', methods=['POST'])
@login_required
def set_owner_password():
    password = request.get_json().get('password')
    if not password or len(password) < 6: return std_response(False, "Min 6 chars", status_code=400)
    database_manager.set_owner_password_hash(current_user.username, bcrypt.generate_password_hash(password).decode('utf-8'))
    database_manager.reset_lock_attempts(current_user.username)
    log_security_event("OWNER_PASSWORD_SET", risk_level="LOW")
    return std_response(True, "Master key established")

@app.route('/delete-password', methods=['POST'])
@login_required
def delete_owner_password():
    """
    Deactivates the deletion protection by clearing the owner_delete_password_hash.
    """
    if database_manager.delete_owner_password_hash(current_user.username):
        log_security_event("OWNER_PASSWORD_DELETED", risk_level="LOW")
        return std_response(True, "Security protection removed.")
    return std_response(False, "Failed to remove password from secure vault.", status_code=500)

@app.route('/api/environment', methods=['PUT'])
@login_required
def api_update_environment():
    data = request.get_json()
    new_visibility = data.get('visibility', '').lower()
    
    if new_visibility not in ['public', 'private']:
        return std_response(False, "Invalid visibility state", status_code=400)
    
    conn = database_manager.get_db_connection()
    try:
        with conn:
            if current_user.role == 'admin':
                # 1. Global Override: Update ALL files/folders in the system
                conn.execute('UPDATE files SET visibility = ?', (new_visibility,))
                # 2. Synchronize ALL users to this state
                conn.execute('UPDATE users SET workspace_visibility = ?', (new_visibility,))
                msg = f"GLOBAL ENVIRONMENT LOCKED TO {new_visibility.upper()}"
            else:
                # 1. Update all files owned by user OR within their directory
                user_root = current_user.username.lower()
                conn.execute('''
                    UPDATE files SET visibility = ? 
                    WHERE owner_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)
                    OR file_path = ? COLLATE NOCASE
                    OR file_path LIKE ? || '/%' COLLATE NOCASE
                ''', (new_visibility, current_user.username, user_root, user_root))
                
                # 2. Update user workspace preference
                conn.execute('UPDATE users SET workspace_visibility = ? WHERE id = ?', (new_visibility, current_user.id))
                msg = f"USER ENVIRONMENT SYNCED TO {new_visibility.upper()}"
                
            # Verify the update happened
            updated_count = conn.execute('SELECT COUNT(*) FROM files WHERE visibility = ?', (new_visibility,)).fetchone()[0]
            app.logger.info(f"Environment update: {updated_count} items now {new_visibility}")

        log_security_event("ENV_CHANGE", risk_level="MEDIUM", destination=msg)
        return std_response(True, msg, {
            "permission": new_visibility, 
            "visibility": new_visibility,
            "status": "synchronized"
        })
    except Exception as e:
        app.logger.error(f"FATAL: Environment sync failure: {e}")
        return std_response(False, "Database synchronization failure", status_code=500)
    finally:
        conn.close()



@app.route('/api/files/visibility', methods=['PUT'])
@login_required
def api_files_visibility():
    data = request.get_json()
    subpath = data.get('path', '').strip('/')
    new_visibility = data.get('visibility', '').lower()

    if new_visibility not in ['public', 'private']:
        return std_response(False, "Invalid state configuration", status_code=400)

    # Check permission
    file_info = database_manager.get_file_by_path(subpath)
    if not file_info:
        return std_response(False, "Resource record not found in system", status_code=404)

    # Only owners or admins can toggle visibility
    if current_user.role != 'admin' and file_info['created_by'].lower() != current_user.username.lower():
        # Fallback: check if subpath STARTS with username prefix
        if not subpath.lower().startswith(current_user.username.lower() + '/'):
            return std_response(False, "Unauthorized: Ownership verification failed", status_code=403)

    if database_manager.set_file_visibility(subpath, new_visibility):
        log_security_event("VISIBILITY_RECURSIVE_UPDATE", risk_level="MEDIUM", file_path=subpath, destination=new_visibility.upper())
        return std_response(True, f"Cascading visibility applied: {new_visibility.upper()}")
    
    return std_response(False, "Cascading synchronization failed", status_code=500)

@app.route('/api/users', methods=['GET'])
@login_required
def api_get_users():
    users = database_manager.get_all_normal_users()
    # Filter out current user
    users = [u for u in users if u['username'].lower() != current_user.username.lower()]
    return std_response(True, "Users found", {"users": users})

@app.route('/api/folders/<int:file_id>/access', methods=['PUT'])
@login_required
def api_update_folder_access(file_id):
    # Check if user owns the folder or is admin
    file_info = database_manager.get_file_by_id(file_id)
    if not file_info:
        return std_response(False, "Folder not found", status_code=404)
        
    if current_user.role != 'admin' and file_info['created_by'].lower() != current_user.username.lower():
        return std_response(False, "Unauthorized", status_code=403)
        
    data = request.get_json()
    allowed_users = data.get('allowedUsers', [])
    
    if database_manager.set_allowed_users(file_id, allowed_users):
        log_security_event("ACCESS_UPDATE", risk_level="INFO", file_path=file_info['file_path'], destination=str(allowed_users))
        return std_response(True, "Access permission updated")
        
    return std_response(False, "Failed to update access", status_code=500)

def run_server(quiet=False):
    os.makedirs(STORAGE_ROOT, exist_ok=True)
    database_manager.update_schema()
    
    # Secret key should remain stable across restarts for session persistence
    app.config['SECRET_KEY'] = SECRET_KEY
    
    if not quiet:
        print("\n" + "="*50)
        print("🚀 SENTINEL FTMS SERVER INITIATED")
        print("="*50)
        print(f"📡 Local Access:      http://localhost:{config.SERVER_PORT}")
        
        # Format the primary IP for display (wrap IPv6 in brackets)
        display_ip = config.MACHINE_IP
        if ":" in display_ip:
            print(f"🌐 Network Access:    http://[{display_ip}]:{config.SERVER_PORT}")
        else:
            print(f"🌐 Network Access:    http://{display_ip}:{config.SERVER_PORT}")
            
        print("="*50 + "\n")
    
    # Suppress Flask CLI banner for integrated mode
    if quiet:
        import logging
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        # Disable the default click-based banner printing if possible 
        # but keep it basic for max compatibility
        cli = sys.modules.get('flask.cli')
        if cli:
            cli.show_server_banner = lambda *args, **kwargs: None

    # When run via monitor.py, the server is in a side thread.
    # The Flask reloader (signal handler) ONLY works in the main thread.
    import threading
    is_main_thread = (threading.current_thread() is threading.main_thread())
    
    # Enable debug mode if not quiet, but only use reloader in the main thread.
    use_debug = not quiet
    use_reloader = use_debug and is_main_thread

    app.run(host=config.SERVER_HOST, port=config.SERVER_PORT, debug=use_debug, use_reloader=use_reloader, threaded=True)

if __name__ == '__main__':
    run_server()
