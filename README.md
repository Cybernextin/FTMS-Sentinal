# Sentinel – FTMS Security Monitoring System

Sentinel is an advanced, production-ready Secure File Transfer Monitoring System (FTMS) designed to oversee, track, and protect critical storage sectors in real-time. It leverages asynchronous threat detection, role-based access control, file manipulation forensics, and malware heuristics.

## Architecture & Structure

- **server/**: The core Flask backend, hosting all API routes, database logic (`database_manager.py`), HTML templates, and the interactive frontend Javascript components.
- **core/**: The security backbone of Sentinel. Contains the watchdog daemon (`monitor.py`), the `threat_engine.py` for live heuristic analysis, the `severity_engine.py` for risk profiling, and associated reporting loops (`generate_report.py`).
- **config/**: Security parameters, network bindings, database configurations, and environment variables. (Ensure `.env` rules are applied during deployment).
- **storage/**: The primary monitored filesystem root. All files placed here are tracked for modifications, executable masks, keywords, and unauthorized exfiltration.
- **logs/**: Generated JSON and text audit telemetry.
- **docs/**: Project architecture and dependency information.
- **tests/**: Automation scripts testing security boundaries and endpoint responses.

## Project Setup

### 1. Clone the repository
```bash
git clone https://github.com/USERNAME/REPOSITORY_NAME.git
```

### 2. Enter project folder
```bash
cd REPOSITORY_NAME
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Add environment variables
Create a `.env` file in the root directory and add the required configuration.
Example:
```env
IP_DETECTION_MODE=auto
IP_VERSION_PRIORITY=ipv4
AI_REPORT_API_KEY=your_api_key_here
```

### 5. Start the application
Run the unified startup script:
```bash
python run.py
```

## Security Features
- **Dynamic Threaded Monitoring:** Active monitoring of the `storage` volume tracking CREATE, MODIFY, RENAME, DIRECTORY, and OVERWRITE operations via `core/monitor.py`.
- **Ransomware Defense:** Heuristics checking for bulk file encryption behavior and sudden, massive volume modifications within milliseconds.
- **Web Interface:** Secure Admin Dashboard with graphical logging, environment switching, User Provisioning, tactical Data Purge (Nuclear Wipe via Sec-Ops mode),.
- **Access Control (RBAC):** Strict roles defined at DB level (`database_manager.py`).


##ADMINISTRATOR PASSWORD

--USER: admin
--PASSWORD: password123

Then u can chnage the admin password 

## Contributing
Follow standard branching rules and please maintain Python type hinting within core engine modules to preserve maintainability.

---
**Status: Production Ready | Defense Protocol: ACTIVE**

