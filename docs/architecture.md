# Sentinel FTMS Architecture

## Core Conceptual View
**Sentinel** tracks the `storage/` grid. Any filesystem changes initiated directly on the OS level, or through the web dashboard, trigger events natively through Python's `watchdog`.

### 1. The Web Layer (`server/app.py` & `server/templates`)
A robust Flask application operating strictly on REST and synchronous endpoints using Jinja templates for full client rendering without exposing internal state to APIs.
- Built-in session security with Flask-Login.
- RBAC integrated at endpoint initialization (`@role_required`).
- Static assets located inside `server/static`.

### 2. The Database Layer (`server/database_manager.py`)
Standardized SQLite implementation (`.sqlite`). Operates locally, removing dependency tracking.
The manager controls:
- Users (Identities, Login Attempts, Roles)
- Files (Metadata, Permissions, Hierarchies, Virtual "Public/Private" environments)
- Security Event Auditing

### 3. The Threat Engine (`core/threat_engine.py` & `core/severity_engine.py`)
An abstraction tier separating detection behaviors from the monitor loop. 
- Analyzes bulk alterations indicative of ransomware tasks.
- Verifies system calls for file extension spoofing (e.g. `document.txt.exe`).
- Classifies Risk Level: INFO, LOW, MEDIUM, HIGH, CRITICAL based on parameters, origin, user, and execution time using `severity_engine.py`.

### 4. The Telemetry Layer (`core/monitor.py` & `core/logger.py`)
Runs asynchronously adjacent to the Flask App. Subscribes straight into the OS API level to trace modification of tracking sectors. Sends live payloads and handles terminal outputs for SOC analysts (`run.py` command window output). 
Generates `.log` files locally outside the codebase inside the `logs/` directory.

### Structural Flow
1. **User Action (Upload / Alter / Delete)**
2. → `app.py` receives execution
3. → `database_manager.py` executes transaction & permissions
4. → OS alters file in `storage/`
5. → `monitor.py` (Watchdog) discovers alteration
6. → `threat_engine.py` verifies action semantics
7. → `severity_engine.py` scales action metrics (Low/High risk)
8. → Console Notification and JSON API synchronization
