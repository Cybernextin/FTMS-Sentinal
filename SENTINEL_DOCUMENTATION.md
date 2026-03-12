# SENTINEL v3.0: Secure File Transfer Monitoring System (FTMS)
## Project Documentation & Technical Specification

### 1. Project Overview
**Sentinel** is an advanced, multi-layered cybersecurity solution designed to protect sensitive files from unauthorized transfer, tampering, and malicious activity. It functions as both a **Data Loss Prevention (DLP)** system and a **File Integrity Monitoring (FIM)** tool, providing 24/7 real-time visibility into the local filesystem.

The project is built to address the "Insider Threat" and "Unauthorized Exfiltration" problems common in corporate and sensitive data environments.

---

### 2. Key Objectives
*   **Real-time Visibility**: Continuous monitoring of all file creation, movement, deletion, and modification.
*   **Access Control & Zoning**: Classifying directories into security zones (Internal, Storage, External/USB).
*   **Integrity Assurance**: Using SHA256 hashing to ensure files are not corrupted or tampered with during transit.
*   **Automated Threat Response**: Instantly quarantining suspicious files (Ransomware, Integrity Violations).
*   **Forensic Auditing**: Generating secure, encrypted logs and automated PDF security reports.

---

### 3. System Architecture

#### **A. High-Level Workflow**
1.  **Monitor**: The `watchdog` observer tracks the `storage` directory recursively.
2.  **Intercept**: All filesystem events are captured and passed to the **Threat Engine**.
3.  **Classify**: Events are classified based on source/destination zones and file metadata.
4.  **Verify**: If a file is moved, its SHA256 hash is compared against the database.
5.  **Log & Alert**: Every event is stored in a SQLite database and an encrypted on-disk audit log.
6.  **Respond**: Critical violations trigger an automatic move to the `.quarantine` zone.

#### **B. Project Structure**
```text
Sentinal--main/
├── run.py                 # Production startup script (Entry point)
├── config/
│   └── config.py          # Centralized system configurations & security rules
├── core/
│   ├── monitor.py         # FileSystem event handlers (Watchdog)
│   ├── threat_engine.py   # Detection logic (Zones, Keywords, Ransomware)
│   ├── crypto_utils.py    # AES-GCM Encryption for logs and files
│   ├── logger.py          # Tamper-proof encrypted log rotation
│   └── generate_report.py # PDF Audit Report generation (FPDF)
├── server/
│   ├── app.py             # Flask Web Interface
│   └── database_manager.py# SQLite Schema (Logs, Users, Files, Hashes)
├── storage/               # Main monitored data repository
│   ├── admin/             # Sensitive administrative zone
│   └── .quarantine/       # Hidden containment area for threats
└── logs/                  # Month-based encrypted audit logs
```

---

### 4. Core Security Features

#### **4.1. Threat Detection Engine**
The `ThreatEngine` applies rule-based logic to detect sophisticated attacks:
*   **Zone Transition Detection**: Triggers HIGH risk alerts if sensitive files move from `Storage` to simulated External media (`mnt/external`).
*   **Extension Masking**: Detects "Double Extensions" (e.g., `invoice.pdf.exe`) used to trick users.
*   **Sensitive Keywords**: Flags files containing terms like *salary*, *password*, or *confidential* regardless of their location.
*   **Ransomware Prevention**: Monitors for bulk file modifications and suspicious encryption-related extensions (`.locked`, `.crypt`).

#### **4.2. File Integrity Monitoring (FIM)**
*   **SHA256 Hashing**: Every file in the monitored zone has its hash stored in the database.
*   **In-Transit Check**: During a `MOVE` event, the system calculates the hash at the destination and compares it with the source record.
*   **Integrity Violation**: If hashes mismatch, the file is immediately quarantined as "Tampered."

#### **4.3. Secure Logging (Tamper-Proof)**
Unlike standard text logs, Sentinel uses a **Security Log Rotation System**:
*   **Encryption**: Every log line is encrypted using **AES-GCM** before being written to disk. This prevents an attacker from manually editing logs to hide their tracks.
*   **Month-Based Rotation**: Logs are automatically organized into folders by month (e.g., `logs/mar/`), ensuring long-term scalability.

#### **4.4. Automated Quarantine**
Suspicious files are not just logged; they are neutralized. The system moves them to a hidden `.quarantine` directory and renames them with a Unix-timestamp prefix to preserve evidence while preventing accidental execution.

---

### 5. Technical Requirements
*   **Language**: Python 3.x
*   **Dependencies**: 
    *   `watchdog`: Filesystem event capturing.
    *   `psutil`: Process tracking (linking events to specific apps).
    *   `pycryptodome`: Industrial-grade AES encryption.
    *   `fpdf`: PDF report generation.
    *   `Flask`: Management dashboard interface.

---

### 6. User Guide

#### **Installation**
1.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
2.  Start the system:
    ```bash
    python run.py
    ```

#### **How to Check Integrity Verification**
1.  Create a file in `storage/`.
2.  Manually modify the `sha256_hash` entry for that file in the `monitoring.db`.
3.  Move the file.
4.  The system will flag the `INTEGRITY_VIOLATION` and move the file to `.quarantine`.

---

### 7. Evaluation & Suitability
This project meets the requirements for a **Final Year Cybersecurity Project** by demonstrating skill in:
*   **Defensive Security**: Real-time monitoring and DLP.
*   **Cryptography**: Implementing AES-GCM for log security.
*   **Data Science/Forensics**: Structured logging and automated reporting.
*   **System Programming**: Multi-threaded Python application with OS-level hooks.

---

