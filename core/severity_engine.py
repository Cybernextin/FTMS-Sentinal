import os
import datetime
import config

class SeverityEngine:
    def __init__(self):
        self.risk_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def _is_sensitive(self, path):
        if not path: return False
        path = path.lower()
        # Check against sensitive root
        if config.SENSITIVE_ROOT.lower() in path:
            return True
        # Check against sensitive extensions
        for ext in config.SENSITIVE_EXTENSIONS:
            if path.endswith(ext.lower()):
                return True
        # Check against keywords
        for kw in config.SENSITIVE_KEYWORDS:
            if kw.lower() in os.path.basename(path).lower():
                return True
        return False

    def _is_external_or_public(self, path):
        if not path: return False
        path = path.lower().replace('\\', '/')
        if 'external' in path or 'public' in path or 'shared' in path:
            return True
        if config.USB_ROOT.lower() in path:
            return True
        return False

    def _get_role(self, username):
        # This might need a database call or session check
        # For now, we assume this is passed or we infer 'admin' if name is 'admin'
        # In app.py we have current_user.role, so we should pass role to evaluate_severity
        return 'admin' if username.lower() == 'admin' else 'user'

    def _is_outside_working_hours(self):
        now = datetime.datetime.now()
        hour = now.hour
        start, end = config.WORKING_HOURS
        # Check if weekday
        if now.weekday() >= 5: # Saturday or Sunday
            return True
        if hour < start or hour >= end:
            return True
        return False

    def get_severity(self, action, username, role, file_path=None, destination=None, is_bulk=False, count=1):
        """
        Dynamically calculates severity based on the provided rules.
        """
        severity = "INFO" # Default

        action = action.upper()
        role = role.lower()
        
        # 1. FILE MOVE
        if action in ["MOVE", "ADMIN_MOVE", "FILE_MOVED"]:
            severity = "MEDIUM" # User moves file within own folder (default)
            if self._is_sensitive(file_path) and self._is_external_or_public(destination):
                severity = "CRITICAL"
            elif is_bulk or count > config.BULK_THRESHOLD:
                severity = "HIGH"
            elif self._is_cross_department(file_path, destination):
                severity = "HIGH"
            elif self._is_same_directory(file_path, destination):
                severity = "LOW"
            elif "SYSTEM" in action:
                severity = "INFO"

        # 2. FILE DELETE
        elif action in ["DELETE", "ADMIN_DELETE", "FILE_DELETED", "DIRECTORY_DELETED"]:
            severity = "MEDIUM" # User deletes own uploaded file
            if self._is_sensitive(file_path) or (is_bulk or count > config.BULK_THRESHOLD):
                severity = "CRITICAL"
            elif role == 'admin' and not self._is_own_file(username, file_path):
                severity = "HIGH"
            elif self._is_shared(file_path):
                severity = "HIGH"
            elif self._is_temp(file_path):
                severity = "LOW"
            elif "CLEANUP" in action or "SYSTEM" in action:
                severity = "INFO"

        # 3. FILE RENAME
        elif action in ["RENAME", "ADMIN_RENAME"]:
            severity = "LOW" # Renaming personal file
            if self._is_sensitive(file_path) and (self._is_misleading(destination) or self._is_hidden(destination)):
                severity = "CRITICAL"
            elif self._is_bypass_rename(file_path, destination):
                severity = "CRITICAL"
            elif self._is_frequent_activity(username, action): # Placeholder
                severity = "HIGH"
            elif self._is_shared(file_path):
                severity = "MEDIUM"
            elif "SYSTEM" in action:
                severity = "INFO"

        # 4. FILE DOWNLOAD
        elif action in ["DOWNLOAD", "FILE_DOWNLOAD"]:
            severity = "LOW" # Normal file download
            if (is_bulk or count > config.BULK_THRESHOLD) and self._is_sensitive(file_path):
                severity = "CRITICAL"
            elif self._is_restricted_folder(file_path):
                severity = "CRITICAL"
            elif (is_bulk or count > config.BULK_THRESHOLD) and self._is_outside_working_hours():
                severity = "HIGH"
            elif self._is_repeated_download(username, file_path): # Placeholder
                severity = "HIGH"
            elif self._is_shared(file_path):
                severity = "MEDIUM"
            elif "SYSTEM" in action:
                severity = "INFO"

        # 5. FILE VIEW
        elif action in ["VIEW", "FILE_VIEW"]:
            severity = "LOW" # Viewing own file
            if self._is_highly_restricted(file_path) and not self._is_authorized(username, file_path):
                severity = "CRITICAL"
            elif self._is_repeated_view(username, file_path): # Placeholder
                severity = "HIGH"
            elif not self._is_authorized_role(role, file_path):
                severity = "HIGH"
            elif self._is_shared(file_path):
                severity = "MEDIUM"
            elif "SYSTEM" in action:
                severity = "INFO"

        # 6. PASSWORD CHANGE
        elif action in ["ADMIN_PASSWORD_CHANGE", "USER_PASSWORD_CHANGE", "PASSWORD_CHANGED", "OWNER_PASSWORD_SET"]:
            severity = "LOW" # default for own password change during hours
            
            if action == "OWNER_PASSWORD_SET":
                severity = "LOW"
            elif role == 'admin':
                severity = "MEDIUM"
                if self._is_outside_working_hours() or self._is_rapid_change(username):
                    severity = "HIGH"
            else:
                # User changing own password or someone else's? 
                if self._is_outside_working_hours():
                    severity = "HIGH"
                
                target_user = (file_path or "").lower()
                if target_user and target_user != username.lower():
                    if target_user == 'admin' or self._is_admin_account(target_user):
                        severity = "CRITICAL"
                    else:
                        severity = "HIGH"

        # 7. Threat Engine Detections (Direct mapping)
        elif action in ["RANSOMWARE_INDICATOR", "SENSITIVE_EXIT"]:
            severity = "CRITICAL"
        elif action in ["UNAUTHORIZED_EXECUTABLE", "EXTENSION_MASKING", "STORAGE_EXIT"]:
            severity = "HIGH"
        elif action == "SENSITIVE_KEYWORD":
            severity = "MEDIUM"
        
        # Cross-Role Transitions & Escalations
        if role == 'user' and (file_path and 'admin' in file_path.lower() or destination and 'admin' in destination.lower()):
            severity = "CRITICAL"

        if self._is_outside_working_hours() and severity in ["LOW", "INFO"]:
            # Only escalate if it's not a system action
            if "SYSTEM" not in action and "AUTO" not in action:
                severity = "MEDIUM"

        return severity

    # Helper methods
    def _is_cross_department(self, src, dest):
        if not src or not dest: return False
        s_parts = src.strip('/').replace('\\', '/').split('/')
        d_parts = dest.strip('/').replace('\\', '/').split('/')
        if len(s_parts) > 1 and len(d_parts) > 1:
            # Check the second part (e.g. storage/USER_A/...) 
            # If the top level is 'storage', we compare the user folders
            if s_parts[0] == d_parts[0]:
                return s_parts[1] != d_parts[1]
        return False

    def _is_same_directory(self, src, dest):
        if not src or not dest: return False
        return os.path.dirname(src).replace('\\', '/') == os.path.dirname(dest).replace('\\', '/')

    def _is_own_file(self, username, path):
        if not path: return True
        return path.lower().replace('\\', '/').startswith(username.lower())

    def _is_shared(self, path):
        p = (path or '').lower()
        return 'shared' in p or 'team' in p or 'public' in p

    def _is_temp(self, path):
        p = (path or '').lower()
        return 'temp' in p or '.tmp' in p or 'cache' in p

    def _is_misleading(self, path):
        basename = os.path.basename(path or '').lower()
        misleading = ['sys_cache', 'driver_backup', 'config_old', 'update_bin']
        return any(m in basename for m in misleading)

    def _is_hidden(self, path):
        basename = os.path.basename(path or '').lower()
        return basename.startswith('.')

    def _is_bypass_rename(self, old, new):
        if not old or not new: return False
        _, old_ext = os.path.splitext(old)
        _, new_ext = os.path.splitext(new)
        # Bypassing binary detection
        if old_ext.lower() in config.SUSPICIOUS_EXECUTABLES and new_ext.lower() not in config.SUSPICIOUS_EXECUTABLES:
            return True
        # Bypassing sensitive masking
        if old_ext.lower() in config.SENSITIVE_EXTENSIONS and new_ext.lower() == '.txt':
            return True
        return False

    def _is_frequent_activity(self, username, action):
        return False

    def _is_restricted_folder(self, path):
        p = (path or '').lower().replace('\\', '/')
        return 'admin/sensitive' in p or 'vault' in p or 'restricted' in p

    def _is_repeated_download(self, username, path):
        return False

    def _is_highly_restricted(self, path):
        return self._is_restricted_folder(path)

    def _is_authorized(self, username, path):
        if username.lower() == 'admin': return True
        return path.lower().replace('\\', '/').startswith(username.lower())

    def _is_authorized_role(self, role, path):
        if role == 'admin': return True
        return 'admin' not in (path or '').lower()

    def _is_repeated_view(self, username, path):
        return False

    def _is_rapid_change(self, username):
        return False

    def _is_admin_account(self, username):
        return username.lower() == 'admin'

    def _get_path_owner(self, path):
        if not path: return None
        parts = path.strip('/').replace('\\', '/').split('/')
        return parts[0].lower() if parts else None
