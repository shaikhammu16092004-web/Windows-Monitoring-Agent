import psutil
import time
import hashlib
import json
import subprocess
import os
from datetime import datetime

# ==============================
# CONFIGURATION
# ==============================

SUSPICIOUS_PARENTS = ["powershell.exe", "cmd.exe"]
SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\local\\temp"]
USER_FOLDERS = ["\\desktop\\", "\\downloads\\"]

SAFE_SYSTEM_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64"
]

SAFE_SYSTEM_PROCESSES = [
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "wudfhost.exe"
]

LOG_FILE = "alerts.txt"
JSON_REPORT = "report.json"

SCAN_INTERVAL = 10
SERVICE_INTERVAL = 60

# ==============================
# LOAD LISTS
# ==============================

def load_list(filename):
    try:
        with open(filename, "r") as f:
            return [line.strip().lower() for line in f.readlines()]
    except:
        return []

WHITELIST = load_list("whitelist.txt")
BLACKLIST = load_list("blacklist.txt")

ALERT_HISTORY = set()
REPORT_DATA = []

SUMMARY = {
    "total_alerts": 0,
    "process_alerts": 0,
    "service_alerts": 0,
    "high_risk": 0,
    "medium_risk": 0
}

# ==============================
# UTILITY FUNCTIONS
# ==============================

def log_alert(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def save_json():
    output = {
        "summary": SUMMARY,
        "detections": REPORT_DATA
    }
    with open(JSON_REPORT, "w") as f:
        json.dump(output, f, indent=4)

def calculate_sha256(filepath):
    try:
        if not os.path.exists(filepath):
            return "Unavailable"
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except:
        return "Unavailable"

# ✅ Proper Digital Signature Verification
def verify_digital_signature(filepath):
    try:
        command = [
            "powershell",
            "-Command",
            f"Get-AuthenticodeSignature '{filepath}' | Select-Object -ExpandProperty Status"
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        status = result.stdout.strip()
        return status if status else "Unknown"
    except:
        return "Unknown"

# ✅ Improved Writable Check (Skip System32)
def check_file_writable(filepath):
    try:
        path_lower = filepath.lower()
        if any(path_lower.startswith(safe) for safe in SAFE_SYSTEM_PATHS):
            return False
        return os.access(filepath, os.W_OK)
    except:
        return False

def build_process_chain(pid):
    chain = []
    try:
        current = psutil.Process(pid)
        while current:
            chain.append(current.name())
            if current.ppid() == 0:
                break
            current = psutil.Process(current.ppid())
    except:
        pass
    return " -> ".join(chain)

# ==============================
# ALERT ENGINE
# ==============================

def generate_alert(entry):
    signature = f"{entry['type']}-{entry.get('name')}-{entry.get('reasons')}"
    if signature in ALERT_HISTORY:
        return

    ALERT_HISTORY.add(signature)
    REPORT_DATA.append(entry)

    SUMMARY["total_alerts"] += 1

    if entry["type"] == "PROCESS":
        SUMMARY["process_alerts"] += 1
    else:
        SUMMARY["service_alerts"] += 1

    if entry["risk_score"] >= 8:
        SUMMARY["high_risk"] += 1
    else:
        SUMMARY["medium_risk"] += 1

    print("=" * 80)
    print(f" {entry['type']} ALERT ")
    print("=" * 80)

    if entry["risk_score"] >= 8:
        print(f"🔴 HIGH RISK ({entry['risk_score']}) -> {entry['name']} | {entry['reasons']}")
    else:
        print(f"🟡 MEDIUM RISK ({entry['risk_score']}) -> {entry['name']} | {entry['reasons']}")

    log_alert(json.dumps(entry))
    save_json()

# ==============================
# PROCESS MONITORING
# ==============================

def scan_processes():
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            ppid = proc.info['ppid']
            name = proc.info['name']
            path = proc.info['exe'] or ""

            if not name:
                continue

            name_lower = name.lower()
            path_lower = path.lower()

            # ✅ Skip safe system processes
            if name_lower in SAFE_SYSTEM_PROCESSES:
                continue

            if name_lower in WHITELIST:
                continue

            risk_score = 0
            reasons = []

            if name_lower in BLACKLIST:
                risk_score += 10
                reasons.append("Blacklisted Process")

            # Parent check
            try:
                parent = psutil.Process(ppid)
                parent_name = parent.name().lower()
                if parent_name in SUSPICIOUS_PARENTS:
                    risk_score += 5
                    reasons.append("Spawned by Script Engine")
            except:
                parent_name = "Unknown"

            if any(p in path_lower for p in SUSPICIOUS_PATHS):
                risk_score += 5
                reasons.append("Running from Temp Folder")

            if any(p in path_lower for p in USER_FOLDERS):
                risk_score += 4
                reasons.append("Running from User Folder")

            if name_lower.endswith(".tmp"):
                risk_score += 5
                reasons.append("Temporary File Execution")

            if path:
                signature_status = verify_digital_signature(path)

                # ✅ Auto-trust Microsoft signed System32
                if any(path_lower.startswith(safe) for safe in SAFE_SYSTEM_PATHS) and signature_status == "Valid":
                    continue

                if signature_status != "Valid":
                    risk_score += 3
                    reasons.append(f"Invalid Signature ({signature_status})")

                if check_file_writable(path):
                    risk_score += 2
                    reasons.append("Executable Writable")

                sha256 = calculate_sha256(path)
            else:
                sha256 = "Unavailable"
                signature_status = "Unknown"

            if risk_score >= 4:
                entry = {
                    "timestamp": str(datetime.now()),
                    "type": "PROCESS",
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "path": path,
                    "parent": parent_name,
                    "process_chain": build_process_chain(pid),
                    "sha256": sha256,
                    "digital_signature": signature_status,
                    "risk_score": risk_score,
                    "reasons": reasons
                }

                generate_alert(entry)

        except:
            continue

# ==============================
# SERVICE AUDIT
# ==============================

def audit_services():
    for service in psutil.win_service_iter():
        try:
            s = service.as_dict()

            name = s['name']
            start_type = s['start_type']
            path = s['binpath'] or ""

            name_lower = name.lower()
            path_lower = path.lower()

            risk_score = 0
            reasons = []

            if name_lower in BLACKLIST:
                risk_score += 10
                reasons.append("Blacklisted Service")

            if "\\temp\\" in path_lower:
                risk_score += 5
                reasons.append("Service running from Temp")

            if "\\users\\" in path_lower:
                risk_score += 4
                reasons.append("Service running from User directory")

            if start_type.lower() == "auto" and risk_score > 0:
                risk_score += 3
                reasons.append("Auto-start suspicious")

            if risk_score >= 3:
                entry = {
                    "timestamp": str(datetime.now()),
                    "type": "SERVICE",
                    "name": name,
                    "start_type": start_type,
                    "path": path,
                    "risk_score": risk_score,
                    "reasons": reasons
                }

                generate_alert(entry)

        except:
            continue

# ==============================
# MAIN LOOP
# ==============================

if __name__ == "__main__":
    print("🚀 PRODUCTION Windows Monitoring Agent Started...\n")

    service_timer = 0

    while True:
        scan_processes()

        if service_timer >= SERVICE_INTERVAL // SCAN_INTERVAL:
            audit_services()
            service_timer = 0

        service_timer += 1
        time.sleep(SCAN_INTERVAL)
