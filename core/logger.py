import logging
import os
from datetime import datetime, timezone
from core.crypto_utils import crypto_manager

# Define standard log format
# | Timestamp | Event Type | File Path | Reason | Risk Level |

class SecurityFormatter(logging.Formatter):
    def format(self, record):
        return record.msg  # Message is pre-formatted in log_security_event

class RotatingMonthBasedFileHandler(logging.FileHandler):
    """
    Custom FileHandler that:
    1. Handles month-based directory structures (logs/feb/security_events.log).
    2. checks date on every emit for month rotation.
    3. Implements file size rotation (Log Rotation).
    """
    def __init__(self, base_log_dir, max_bytes=10*1024*1024, backup_count=5):
        self.base_log_dir = base_log_dir
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.current_filepath = self._get_target_filepath()
        
        # Ensure initial directory exists
        os.makedirs(os.path.dirname(self.current_filepath), exist_ok=True)
        
        # Initialize standard FileHandler
        super().__init__(self.current_filepath)
        
        # Check if we need to write a header for a new file
        if os.path.exists(self.current_filepath) and os.path.getsize(self.current_filepath) == 0:
            self._write_header()

    def _get_target_filepath(self):
        """Calculates the dynamic path: logs/month_abbr/security_events.log using UTC."""
        # Use UTC for standard security logging
        now = datetime.now(timezone.utc)
        month_str = now.strftime("%b").lower() # e.g. 'feb', 'mar'
        
        # Folder: logs/feb/
        month_dir = os.path.join(self.base_log_dir, month_str)
        
        # File: logs/feb/security_events.log
        return os.path.join(month_dir, "security_events.log")

    def _write_header(self):
        """Writes the column headers to the log file."""
        header = (
            f"| {'TIMESTAMP (UTC)':<19} | {'EVENT TYPE':<25} | {'FILE PATH'} | {'REASON':<35} | {'RISK':<10} |\n"
            f"{'-' * 120}\n"
        )
        if self.stream:
            try:
                self.stream.write(header)
                self.flush()
            except Exception:
                pass

    def _do_rollover(self):
        """
        Do a rollover, as described in __init__().
        """
        if self.stream:
            self.stream.close()
            self.stream = None
        
        if self.backup_count > 0:
            for i in range(self.backup_count - 1, 0, -1):
                sfn = f"{self.baseFilename}.{i}"
                dfn = f"{self.baseFilename}.{i + 1}"
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            dfn = f"{self.baseFilename}.1"
            if os.path.exists(dfn):
                os.remove(dfn)
            if os.path.exists(self.baseFilename):
                os.rename(self.baseFilename, dfn)
        
        self.stream = self._open()
        self._write_header()

    def emit(self, record):
        """Overridden emit to check for month changes and file size before logging."""
        try:
            # 1. Check Month Change
            new_filepath = self._get_target_filepath()
            if new_filepath != self.baseFilename:
                self.close()
                os.makedirs(os.path.dirname(new_filepath), exist_ok=True)
                self.baseFilename = new_filepath
                self.stream = self._open()
                if os.path.getsize(new_filepath) == 0:
                    self._write_header()
            
            # 2. Check File Size (Rotation)
            if self.max_bytes > 0:
                self.stream.seek(0, 2)  # Go to end
                if self.stream.tell() + len(self.format(record)) >= self.max_bytes:
                    self._do_rollover()
            
            super().emit(record)
        except Exception:
            self.handleError(record)

def setup_logger(base_log_dir):
    """
    Sets up the logger with the RotatingMonthBasedFileHandler.
    """
    logger = logging.getLogger("SecureMonitor")
    logger.setLevel(logging.INFO)
    
    # Clean up existing handlers to prevent duplicates
    if logger.handlers:
        logger.handlers = []

    # Add our custom dynamic handler with 10MB limit and 5 backups
    handler = RotatingMonthBasedFileHandler(base_log_dir, max_bytes=10*1024*1024, backup_count=5)
    handler.setLevel(logging.INFO)
    handler.setFormatter(SecurityFormatter())
    
    logger.addHandler(handler)
    
    return logger

def log_security_event(logger, timestamp, event_type, file_path, reason, risk_level):
    """
    Logs the event using the configured logger.
    The entry is encrypted before being stored to prevent tampering.
    """
    # Format: | Timestamp | Event Type | File Path | Reason | Risk Level |
    log_message = f"| {timestamp:<19} | {event_type:<25} | {file_path} | {reason:<35} | {risk_level:<10} |"
    
    # Encrypt the audit line
    encrypted_log = crypto_manager.encrypt_data(log_message)
    
    logger.info(encrypted_log)

def decrypt_audit_logs(log_file_path):
    """Utility to decrypt an entire encrypted log file for forensic review."""
    if not os.path.exists(log_file_path):
        return "Log file not found."
    
    decrypted_lines = []
    with open(log_file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('|') or line.startswith('-'):
                # Pass through headers
                decrypted_lines.append(line)
                continue
            
            decrypted_lines.append(crypto_manager.decrypt_data(line))
    
    return "\n".join(decrypted_lines)

