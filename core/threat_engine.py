import time
import os
import config

class ThreatEngine:
    def __init__(self):
        pass
        
    def _is_sensitive_source(self, path):
        """Check if the file originates from a sensitive directory."""
        return path.startswith(config.SENSITIVE_ROOT)

    def _get_zone(self, path):
        """Determine the security zone of a path."""
        if path.startswith(config.STORAGE_ROOT):
            return "Storage"
        
        # Cross-platform USB/External detection
        if path.startswith(config.USB_ROOT):
            return "External/USB"
            
        return "Internal"

    def detect_path_threat(self, path):
        """Analyze a single path for extension masking and sensitive keywords."""
        filename = os.path.basename(path).lower()
        
        # 1. Extension Masking (e.g. secret.docx.txt)
        if filename.count('.') > 1:
            for ext in config.SENSITIVE_EXTENSIONS:
                clean_ext = ext.lstrip('.')
                # Check if a sensitive extension is masked by another extension
                if f".{clean_ext}." in filename or (filename.count(ext) > 0 and not filename.endswith(ext)):
                    return ("EXTENSION_MASKING", f"Double extension detected: {filename}", config.RISK_HIGH)
        
        # 2. Sensitive Keyword Detection
        for kw in config.SENSITIVE_KEYWORDS:
            if kw in filename:
                return ("SENSITIVE_KEYWORD", f"File contains sensitive keyword: {kw}", config.RISK_MEDIUM)
                    
        return None, None, None

    def detect_transfer_threat(self, src_path, dest_path):
        """Analyze move/copy actions across security zones (FTMS Specific)."""
        src_zone = self._get_zone(src_path)
        dest_zone = self._get_zone(dest_path)
        
        # Check if source is sensitive
        is_sensitive = self._is_sensitive_source(src_path)
        if not is_sensitive:
            for ext in config.SENSITIVE_EXTENSIONS:
                if src_path.lower().endswith(ext.lower()):
                    is_sensitive = True
                    break

        target_zones = ["External/USB", "External/Other"] 
        
        # Rule: Storage -> External (High/Critical risk)
        if src_zone == "Storage" and dest_zone in target_zones:
            if is_sensitive:
                return ("SENSITIVE_EXIT", "Sensitive data transferred to external storage", config.RISK_CRITICAL)
            else:
                return ("STORAGE_EXIT", "Files moving out of monitored ecosystem", config.RISK_HIGH)
                
        return None, None, None

    def detect_malware_behavior(self, event_type, path):
        """Analyzes file events for malware-like patterns (ransomware, suspicious executables)."""
        filename = os.path.basename(path).lower()
        _, ext = os.path.splitext(filename)
        
        # 1. Suspicious Executable Detection
        if ext in config.SUSPICIOUS_EXECUTABLES:
            return ("UNAUTHORIZED_EXECUTABLE", f"Suspicious executable {event_type} in monitored zone", config.RISK_HIGH)
            
        # 2. Ransomware/Encryption Detection
        if ext in config.RANSOMWARE_EXTENSIONS:
            return ("RANSOMWARE_INDICATOR", "Potential encryption detected (Ransomware extension)", config.RISK_CRITICAL)
            
        return None, None, None
