import os
import socket
import platform
import psutil
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NetworkDetector")

def get_preferred_ip(family=socket.AF_INET):
    """
    Uses a UDP connection trick to find the IP address of the primary 
    network interface used to reach the public internet.
    """
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        # We don't actually connect, just use the connect() call to 
        # let the OS find the best interface/source IP.
        # 8.8.8.8 is Google DNS, 2001:4860:4860::8888 is Google IPv6
        target = "8.8.8.8" if family == socket.AF_INET else "2001:4860:4860::8888"
        s.connect((target, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def get_local_ip_address():
    """
    Detects the machine's active network IP address (IPv4 or IPv6) 
    based on configuration and interface status.
    """
    detection_mode = os.environ.get('IP_DETECTION_MODE', 'auto').lower()
    version_priority = os.environ.get('IP_VERSION_PRIORITY', 'ipv4').lower()
    debug_mode = os.environ.get('FLASK_ENV', 'development') == 'development'

    if debug_mode:
        logger.setLevel(logging.DEBUG)

    # 1. Try "Auto" detection using OS routing table preference (UDP trick)
    if detection_mode == 'auto':
        preferred_ipv4 = get_preferred_ip(socket.AF_INET)
        preferred_ipv6 = get_preferred_ip(socket.AF_INET6)
        
        if version_priority == 'ipv6' and preferred_ipv6:
            logger.debug(f"Auto-detected preferred IPv6: {preferred_ipv6}")
            return preferred_ipv6
        if preferred_ipv4:
            logger.debug(f"Auto-detected preferred IPv4: {preferred_ipv4}")
            return preferred_ipv4
        if preferred_ipv6: # Fallback to v6 if v4 not found
            logger.debug(f"Auto-detected preferred IPv6 (fallback): {preferred_ipv6}")
            return preferred_ipv6

    # 2. Manual/Fallback Scan of all interfaces
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    detected_ipv4 = []
    detected_ipv6 = []
    
    # Common virtual/internal adapter patterns to ignore
    skip_patterns = [
        'lo', 'docker', 'veth', 'br-', 'vmnet', 'vbox', 'virtual', 
        'hyper-v', 'teredo', 'isatap', 'npcap', 'host-only'
    ]

    for interface_name, addrs in interfaces.items():
        # Skip down interfaces
        if interface_name in stats and not stats[interface_name].isup:
            continue

        # Skip known virtual/internal naming patterns
        if any(pattern in interface_name.lower() for pattern in skip_patterns):
            continue

        for addr in addrs:
            # Skip loopback
            if addr.address == '127.0.0.1' or addr.address == '::1':
                continue

            if addr.family == socket.AF_INET: # IPv4
                # Skip common virtual ranges if we're still seeing them
                if addr.address.startswith('192.168.56.'): # VirtualBox default
                    continue
                detected_ipv4.append((interface_name, addr.address))
            elif addr.family == socket.AF_INET6: # IPv6
                # Filter for global/unique-local (ignore link-local fe80:)
                if not addr.address.startswith('fe80'):
                    detected_ipv6.append((interface_name, addr.address))

    # Priority selection from filtered list
    if detection_mode == 'ipv6-only' and detected_ipv6:
        return detected_ipv6[0][1]
    if detection_mode == 'ipv4-only' and detected_ipv4:
        return detected_ipv4[0][1]
        
    if version_priority == 'ipv6':
        if detected_ipv6: return detected_ipv6[0][1]
        if detected_ipv4: return detected_ipv4[0][1]
    else: # Default: IPv4 Priority
        if detected_ipv4: return detected_ipv4[0][1]
        if detected_ipv6: return detected_ipv6[0][1]

    return "localhost"

if __name__ == "__main__":
    ip = get_local_ip_address()
    print(f"\nFinal Selected IP: {ip}")
