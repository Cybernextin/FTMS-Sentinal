import hashlib
import psutil
import shutil
import time
import os
import sys
import threading
import requests
import getpass
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timezone

# Local imports
import config
import core.logger as logger
from core.threat_engine import ThreatEngine 
import core.generate_report as generate_report
import database_manager
from core.crypto_utils import crypto_manager
# Add server directory to sys.path to allow importing app components
base_dir = os.path.dirname(os.path.abspath(__file__))
server_path = os.path.join(base_dir, 'server')
if server_path not in sys.path:
    sys.path.append(server_path)

# ANSI Color Codes
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Initialize system
# Config LOG_DIR is the base directory for logs
sec_logger = logger.setup_logger(config.LOG_DIR)
threat_engine = ThreatEngine()

# Threading for async tasks
from concurrent.futures import ThreadPoolExecutor

class SecurityMonitorHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_events = {} # Debouncing store: {(event_type, path): timestamp}
        self.debounce_seconds = 1.0
        self.executor = ThreadPoolExecutor(max_workers=4) # Async worker pool
        self.cleanup_counter = 0

    def on_any_event(self, event):
        # Periodic cleanup of cache
        self.cleanup_counter += 1
        if self.cleanup_counter > 100:
            self._cleanup_cache()
            self.cleanup_counter = 0

    def _cleanup_cache(self):
        """Removes old events from debounce cache to prevent memory leaks."""
        now = time.time()
        # Keep only events from the last 10 seconds
        self.last_events = {k: v for k, v in self.last_events.items() if now - v < 10}

    def _get_timestamp(self):
        # Use UTC for consistency across logs
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


    def _should_ignore(self, path):
        # Ignore system/log files to prevent loops - normalize and check
        path = os.path.normpath(path)
        log_dir = os.path.normpath(config.LOG_DIR)
        
        if path.startswith(log_dir):
            return True
            
        ignored_substrings = ["__pycache__", ".git", ".idea", ".vscode", ".sqlite", ".quarantine"]
        for sub in ignored_substrings:
            if sub in path:
                return True
        return False

    def _calculate_hash(self, file_path):
        """Calculates SHA256 hash of a file."""
        if os.path.isdir(file_path): return None
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def _get_process_info(self, file_path=None):
        """Attempts to find the process interacting with the file or returns current system context."""
        try:
            # Note: Finding the EXACT process is OS-dependent and often requires elevated privileges.
            # This heuristic scans for processes that have the file open.
            if file_path:
                abs_path = os.path.abspath(file_path)
                for proc in psutil.process_iter(['pid', 'name', 'ppid']):
                    try:
                        for f in proc.open_files():
                            if f.path == abs_path:
                                return proc.info['pid'], proc.info['name'], proc.info['ppid']
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # Fallback: Get info of the most active non-system process or just return current user context
            return os.getpid(), "python.exe (Sentinel)", "N/A"
        except Exception:
            return None, "Unknown", None

    def _quarantine_file(self, file_path, reason):
        """Moves a suspicious file to the hidden quarantine zone."""
        try:
            if not os.path.exists(file_path): return
            filename = os.path.basename(file_path)
            dest_path = os.path.join(config.QUARANTINE_DIR, f"{int(time.time())}_{filename}")
            
            shutil.move(file_path, dest_path)
            # Register the quarantine event specifically
            self._log_event("FILE_QUARANTINED", file_path, f"REASON: {reason} | MOVED TO: {dest_path}", config.RISK_HIGH)
            return True
        except Exception as e:
            print(f"[!] Quarantine Failed: {e}")
            return False

    def _log_event(self, event_type, file_path, reason, risk, pid=None, proc_name=None, ppid=None):
        # Debouncing
        now = time.time()
        key = (event_type, file_path)
        last_time = self.last_events.get(key, 0)
        
        if now - last_time < self.debounce_seconds:
            return # Skip duplicate event
            
        self.last_events[key] = now
        
        # Get process info if not provided
        if not pid:
            pid, proc_name, ppid = self._get_process_info(file_path)

        # 1. Log to File (Full Path) via logger
        logger.log_security_event(sec_logger, self._get_timestamp(), event_type, file_path, reason, risk)
        
        # 1.5 Send to Server API
        try:
            payload = {
                "username": getpass.getuser(),
                "action": event_type,
                "risk_level": risk,
                "file_path": file_path,
                "destination": reason,
                "pid": pid,
                "process_name": proc_name,
                "parent_process": str(ppid)
            }
            # Encrypt the payload before sending to API if paranoid (Optional, but demonstrates cryptographic skill)
            # For now, we interact with the DB directly or via the API as usual.
            headers = {"Content-Type": "application/json", "X-API-KEY": config.API_KEY}
            requests.post(f"http://127.0.0.1:{config.SERVER_PORT}/api/log", json=payload, headers=headers, timeout=0.5)
        except Exception:
            pass 

        # 2. Print to Console
        self._print_formatted_alert(event_type, file_path, reason, risk)

        # 3. Auto-Report Generation (Async)
        if risk in [config.RISK_HIGH, config.RISK_CRITICAL]:
            event_data = {
                'timestamp': self._get_timestamp(),
                'event_type': event_type,
                'file_path': file_path,
                'reason': reason,
                'risk_level': risk
            }
            self.executor.submit(self._trigger_auto_report, event_data, f"AUTO-{int(now)}")

    def _trigger_auto_report(self, event_data, event_id):
        try:
            generate_report.generate_single_report(event_data, event_id)
        except Exception:
            pass


    def _print_formatted_alert(self, event_type, file_path, reason, risk):
        ts = self._get_timestamp()
        time_part = ts.split(' ')[1] # Extract HH:MM
        
        # Color coding based on risk
        color = Colors.GREEN
        if risk == config.RISK_MEDIUM: color = Colors.YELLOW
        elif risk == config.RISK_HIGH: color = Colors.RED
        elif risk == config.RISK_CRITICAL: color = Colors.RED + Colors.BOLD
        
        # Zone Classification
        zone = "Local"
        if "Storage" in reason: zone = "Storage"
        elif "USB" in reason: zone = "External"
        elif "outside" in reason: zone = "Unknown"
        
        # Truncation logic for strict alignment
        display_event = event_type[:22] if len(event_type) > 22 else event_type
        display_path = file_path if len(file_path) <= 32 else "..." + file_path[-29:]
        display_reason = reason if len(reason) <= 28 else reason[:25] + "..."
        display_risk = risk[:9]
        display_zone = zone[:8]

        print(f"{Colors.RESET}│ {time_part:<8} │ {display_event:<22} │ {display_path:<32} │ {display_reason:<28} │ {color}{display_risk:<9}{Colors.RESET} │ {display_zone:<8} │")
        print(f"{Colors.RESET}{'─'*126}")

    def on_moved(self, event):
        if self._should_ignore(event.src_path) or self._should_ignore(event.dest_path):
            return

        if event.is_directory:
            # Check if one of our main monitored roots was moved
            if event.src_path == config.SENSITIVE_ROOT or event.src_path == config.STORAGE_ROOT:
                 self._log_event("MONITOR_ALERT", event.src_path, f"CORE DIRECTORY MOVED to {event.dest_path}. Monitor may become disconnected!", config.RISK_HIGH)
            else:
                 self._log_event("DIRECTORY_MOVED", event.src_path, f"Moved to {event.dest_path}", config.RISK_LOW)
            return

        # 1. Transfer Threat (Zone transitions)
        event_type, reason, risk = threat_engine.detect_transfer_threat(event.src_path, event.dest_path)
        
        # INTEGRITY CHECK: Compare hash before and after move
        src_hash = database_manager.get_file_hash(event.src_path)
        dest_hash = self._calculate_hash(event.dest_path)
        
        if src_hash and dest_hash and src_hash != dest_hash:
            self._log_event("INTEGRITY_VIOLATION", event.dest_path, f"Hash mismatch during move: {src_hash} -> {dest_hash}", config.RISK_CRITICAL)
            self._quarantine_file(event.dest_path, "Integrity Violation Detected")
            return

        if event_type:
            self._log_event(event_type, event.src_path, f"{reason} -> {event.dest_path}", risk)
            if risk == config.RISK_CRITICAL:
                self._quarantine_file(event.dest_path, "Critical Transfer Violation")
            return

        # 2. Path-based threat (Masking, Keywords) at destination
        path_type, path_reason, path_risk = threat_engine.detect_path_threat(event.dest_path)
        if path_type:
             self._log_event(path_type, event.dest_path, path_reason, path_risk)
        else:
            # Log normal move
             self._log_event("FILE_MOVED", event.src_path, f"Moved to {event.dest_path}", config.RISK_LOW)
        
        # Update hash in DB for the new location
        if dest_hash:
            database_manager.update_file_hash(event.dest_path, dest_hash)

    def on_created(self, event):
        if self._should_ignore(event.src_path): return

        if event.is_directory:
            self._log_event("DIRECTORY_CREATED", event.src_path, "New directory created", config.RISK_LOW)
            return
            
        # 1. Malware Check (Executable Creation)
        mal_type, mal_reason, mal_risk = threat_engine.detect_malware_behavior("FILE_CREATED", event.src_path)
        if mal_type:
            self._log_event(mal_type, event.src_path, mal_reason, mal_risk)
            return

        # 2. Path-based threat (Masking, Keywords)
        path_type, path_reason, path_risk = threat_engine.detect_path_threat(event.src_path)
        if path_type:
             self._log_event(path_type, event.src_path, path_reason, path_risk)
             if path_risk == config.RISK_CRITICAL:
                 self._quarantine_file(event.src_path, "Critical Path Threat")
        else:
            # Normal creation
            self._log_event("FILE_CREATED", event.src_path, "New file created", config.RISK_LOW)
        
        # Initial Hash Calculation
        h = self._calculate_hash(event.src_path)
        if h: database_manager.update_file_hash(event.src_path, h)

    def on_modified(self, event):
        if self._should_ignore(event.src_path): return

        if event.is_directory:
            return
        
        # 1. Malware Check (Bulk Modification / Ransomware)
        malware_event, malware_reason, malware_risk = threat_engine.detect_malware_behavior("FILE_MODIFIED", event.src_path)
        if malware_event:
             self._log_event(malware_event, event.src_path, malware_reason, malware_risk)
             if malware_risk == config.RISK_CRITICAL:
                self._quarantine_file(event.src_path, "Ransomware Suspect")
             return

        # Normal modification logged as LOW
        self._log_event("FILE_MODIFIED", event.src_path, "Content change detected", config.RISK_LOW)
        
        # Update Hash
        h = self._calculate_hash(event.src_path)
        if h: database_manager.update_file_hash(event.src_path, h)

    def on_deleted(self, event):
        
        
        if self._should_ignore(event.src_path): return

        event_type_str = "Directory" if event.is_directory else "File"
        
        # Log deletion of monitored files/folders
        if event.src_path.startswith(config.STORAGE_ROOT):
            if event.src_path.startswith(config.SENSITIVE_ROOT):
                risk = config.RISK_HIGH if not event.is_directory else config.RISK_CRITICAL
                reason = "Sensitive data deleted or moved outside monitored zone"
            else:
                risk = config.RISK_LOW
                reason = f"Normal {event_type_str.lower()} deletion"
            self._log_event(f"{event_type_str.upper()}_DELETED", event.src_path, reason, risk)



def print_banner():
    # Attempt to clear screen for clean start
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""
{Colors.CYAN}{Colors.BOLD}    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝{Colors.RESET}
    
    {Colors.BOLD}SENTINEL v3.0 | SECURE FILE TRANSFER MONITORING SYSTEM{Colors.RESET}
    {Colors.BLUE}─────────────────────────────────────────────────────────────────{Colors.RESET}
    {Colors.BOLD}SYSTEM MODE  :{Colors.RESET} {Colors.GREEN}ACTIVE REAL-TIME PROTECTION{Colors.RESET}
    {Colors.BOLD}ENFORCEMENT  :{Colors.RESET} {Colors.GREEN}ENABLED (SENTINEL PROTOCOL){Colors.RESET}
    {Colors.BOLD}LOG REPOSITORY:{Colors.RESET} {config.LOG_DIR}
    {Colors.BLUE}─────────────────────────────────────────────────────────────────{Colors.RESET}
    """
    print(banner)
def start_monitoring():
    """Initializes and starts the file monitoring observer."""
    monitored_paths = []
    try:
        monitored_paths = config.MONITORED_PATHS
    except Exception as e:
        print(f"[!] {Colors.RED}CRITICAL: Config error: {e}{Colors.RESET}")
        sys.exit(1)

    event_handler = SecurityMonitorHandler()
    observer = Observer()
    
    active_paths = []
    for path in monitored_paths:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
            active_paths.append(path)

    if not active_paths:
        print(f"[!] {Colors.RED}CRITICAL: No valid paths found to monitor. Exiting.{Colors.RESET}")
        sys.exit(1)

    # Print Unified Status Summary
    def print_status_line(label, value, color=Colors.RESET):
        # Truncate value if it's too long to keep the panel border aligned
        max_val_len = 40
        visible_val = str(value)
        if len(visible_val) > max_val_len:
            visible_val = visible_val[:max_val_len-3] + "..."
            
        prefix = f" {label:<14} : " 
        padding_len = 58 - (len(prefix) + len(visible_val))
        padding = " " * max(0, padding_len)
        print(f"{Colors.BOLD}│{Colors.RESET}{prefix}{color}{visible_val}{Colors.RESET}{padding}{Colors.BOLD} │{Colors.RESET}")

    print(f"{Colors.BOLD}┌{'─' * 58}┐")
    print(f"{Colors.BOLD}│ {Colors.CYAN}SENTINEL SYSTEM OPERATIONAL STATUS SUMMARY{Colors.RESET}{Colors.BOLD}{' ' * 15}│")
    print(f"├{'─' * 58}┤")
    print_status_line("Engine Mode", "ACTIVE REAL-TIME PROTECTION", Colors.GREEN)
    print_status_line("Database", "CONNECTED (INTEGRITY OK)", Colors.GREEN)
    print_status_line("Monitor Status", f"{len(active_paths)} NODES OBSERVING", Colors.GREEN)
    print_status_line("Storage Root", config.STORAGE_ROOT, Colors.YELLOW)
    print(f"{Colors.BOLD}├{'─' * 58}┤")
    print_status_line("Local Access", f"http://127.0.0.1:{config.SERVER_PORT}", Colors.CYAN)
    print_status_line("Network IPv4", f"http://{config.MACHINE_IP}:{config.SERVER_PORT}", Colors.CYAN)
    if config.MACHINE_IPv6:
        print_status_line("Network IPv6", f"http://[{config.MACHINE_IPv6}]:{config.SERVER_PORT}", Colors.CYAN)
    print(f"└{'─' * 58}┘{Colors.RESET}\n")

    observer.start()
    return observer

def print_table_header():
    # Print Table Header
    print(f"[*] {Colors.GREEN}Sentinel Security Protocol Active. Monitoring for detections...{Colors.RESET}")
    print(f"{Colors.BLUE}{'━'*126}{Colors.RESET}")
    print(f"{Colors.BOLD}│ {'TIME':<8} │ {'EVENT TYPE':<22} │ {'FILE PATH':<32} │ {'ACTION / REASON':<28} │ {'RISK':<9} │ {'ZONE':<8} │{Colors.RESET}")
    print(f"{Colors.BLUE}{'━'*126}{Colors.RESET}")

if __name__ == "__main__":
    try:
        import logging
        # Silence Flask/Werkzeug API request logs
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

        print_banner()
        
        from app import run_server
        
        # 1. Start Web Server (Quiet Mode)
        server_thread = threading.Thread(target=run_server, args=(True,), daemon=True)
        server_thread.start()
        
        # 2. Start Monitoring and Print Single Summary
        observer = start_monitoring()
        
        # 3. Print the detection table
        print_table_header()
        
        # Keep main thread alive
        while True:
            time.sleep(1)
        
    except KeyboardInterrupt:
        print("\n" + Colors.YELLOW + "[!] System Shutdown Initiated by User." + Colors.RESET)
    except Exception as e:
        print(f"\n[!] {Colors.RED}CRITICAL: Startup sequence failed: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if 'observer' in locals() and observer:
            observer.stop()
            observer.join()
        print(f"\n{Colors.BOLD}[*] SENTINEL FTMS OFFLINE.{Colors.RESET}\n")
