"""
SENTINEL FTMS - Production Startup Script
"""
import sys
import os
import threading
import time
import logging
import traceback
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

try:
    from colorama import init
    init(autoreset=True)
except ImportError:
    pass

# Fix for Windows Unicode printing
if os.name == 'nt' and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# ==========================================
# SYSTEM PATH CONFIGURATION
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, 'config'))
sys.path.insert(0, os.path.join(BASE_DIR, 'core'))
sys.path.insert(0, os.path.join(BASE_DIR, 'server'))

if __name__ == "__main__":
    from core.monitor import start_monitoring, print_table_header, print_banner, Colors
    from server.app import run_server
    
    try:
        # Silence Flask/Werkzeug API request logs
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

        print_banner()
        
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
        traceback.print_exc()
        sys.exit(1)
    finally:
        if 'observer' in locals() and observer:
            observer.stop()
            observer.join()
        print(f"\n{Colors.BOLD}[*] SENTINEL FTMS OFFLINE.{Colors.RESET}\n")
