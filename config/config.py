import os
import platform

# --- PATH CONFIGURATIONS ---
# Identify the project root (one level up from this config folder)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Detect OS and set paths dynamically
OS_TYPE = platform.system()

# Cross-platform External/USB detection roots
if OS_TYPE == "Windows":
    # On Windows, we detect the system drive or use a relative mnt/external
    USB_ROOT = os.path.join(BASE_DIR, 'mnt', 'external')
else:
    # Standard Linux/macOS mount points
    USB_ROOT = "/media/" if OS_TYPE == "Linux" else "/Volumes/"

# The File Manager operates on the 'storage' directory
STORAGE_ROOT = os.path.normpath(os.path.join(BASE_DIR, "storage"))
SENSITIVE_ROOT = os.path.normpath(os.path.join(STORAGE_ROOT, "admin", "sensitive"))

# List of directories to monitor recursively
MONITORED_PATHS = [
    STORAGE_ROOT,
]

QUARANTINE_DIR = os.path.normpath(os.path.join(STORAGE_ROOT, ".quarantine"))

# Ensure core directories exist regardless of environment
os.makedirs(STORAGE_ROOT, exist_ok=True)
os.makedirs(SENSITIVE_ROOT, exist_ok=True)
os.makedirs(USB_ROOT, exist_ok=True) # Ensure dummy USB root exists for testing
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# --- SENSITIVITY RULES ---
SENSITIVE_EXTENSIONS = ['.pem', '.key', '.crt', '.xlsx', '.docx', '.pdf']
SENSITIVE_KEYWORDS = ['salary', 'password', 'confidential', 'secret', 'key']

# --- THREAT INTELLIGENCE ---
# Indicators of Compromise (IoCs)
RANSOMWARE_EXTENSIONS = ['.locked', '.enc', '.cry', '.crypt', '.crypted']
SUSPICIOUS_EXECUTABLES = ['.exe', '.bat', '.ps1', '.vbs', '.scr']

# --- THRESHOLDS ---
BULK_THRESHOLD = 5
BULK_WINDOW = 10  # seconds (Malware typically acts fast)
WORKING_HOURS = (9, 18) # 9 AM to 6 PM (Start Hour, End Hour)

# Base directory for logs
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# --- RISK LEVELS ---
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"

# --- SECURITY ---
try:
    import API
    API_KEY = getattr(API, 'FTMS_API_KEY', os.environ.get('FTMS_API_KEY', 'SUPER_SECRET_ADMIN_KEY_123'))
    GEMINI_API_KEY = getattr(API, 'GEMINI_API_KEY', os.environ.get('GEMINI_API_KEY', ''))
except ImportError:
    API_KEY = os.environ.get('FTMS_API_KEY', 'SUPER_SECRET_ADMIN_KEY_123')
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')

# --- ENCRYPTION ---
ENCRYPTION_KEY = os.environ.get('FTMS_ENCRYPTION_KEY', 'U3RlZ29zYXVydXNfU2VjdXJlX0tleV9Gb3JfRlRNU18yMDI2PQ==')
# --- NETWORK ---
from utils.network_detector import get_local_ip_address

# Detect primary machine IP based on configuration
MACHINE_IP = get_local_ip_address()

# For legacy support and dual-stack display
def get_ipv6():
    # Use the same detector but force ipv6 mode temporarily if needed
    # or just rely on the detector's auto logic.
    # Here we just want to know if there's an IPv6 available for display.
    from utils.network_detector import psutil, socket
    interfaces = psutil.net_if_addrs()
    for name, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET6 and not addr.address.startswith('fe80') and addr.address != '::1':
                return addr.address
    return None

MACHINE_IPv6 = get_ipv6()

# Server binding configuration
SERVER_HOST = os.environ.get('FTMS_HOST', MACHINE_IP)
SERVER_PORT = int(os.environ.get('FTMS_PORT', 5000))
