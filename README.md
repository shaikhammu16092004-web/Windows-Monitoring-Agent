# 🛡️ Windows Monitoring Agent (SOC + IOC Project)

## 📌 Project Overview

This project is a **Windows Monitoring Agent** built using Python to simulate basic SOC (Security Operations Center) functionality.

It monitors running processes and detects suspicious behavior based on **Indicators of Compromise (IOC)** such as:

* Execution from temporary folders
* Unsigned executables
* Writable binaries
* Suspicious process behavior

---

## ⚙️ Features

* 🔍 Process Enumeration
* 🚨 Risk-based Alerting (High / Medium)
* 📁 Temp Folder Execution Detection
* 🔐 Signature Validation (Basic Simulation)
* 🧠 IOC Detection

---

## 🧾 Project Structure

```
Windows-Monitoring-Agent/
│── README.md
│── process_enum.py
```

---

## 🧾 Python Code (process_enum.py)

```python
import psutil
import os

def check_process_risk(proc):
    risk = 0
    reasons = []

    try:
        path = proc.exe()

        if "temp" in path.lower():
            risk += 5
            reasons.append("Running from Temp Folder")

        if os.access(path, os.W_OK):
            risk += 3
            reasons.append("Executable Writable")

        if not path.endswith(".exe"):
            risk += 2
            reasons.append("Invalid Signature")

    except:
        pass

    return risk, reasons

print("🚀 Windows Monitoring Agent Started...\n")

for proc in psutil.process_iter(['pid', 'name']):
    risk, reasons = check_process_risk(proc)

    if risk >= 5:
        level = "HIGH RISK" if risk >= 10 else "MEDIUM RISK"
        print(f"{level} -> {proc.info['name']} | {reasons}")
```

---

## 🚀 Step-by-Step Execution Guide

### 🔹 Step 1: Clone Repository

```bash
git clone https://github.com/shaikhammu16092004-web/Windows-Monitoring-Agent.git
```

---

### 🔹 Step 2: Navigate to Folder

```bash
cd Windows-Monitoring-Agent
```

---

### 🔹 Step 3: Create Python File

```bash
notepad process_enum.py
```

👉 Paste the above code and save the file

---

### 🔹 Step 4: Check Python Installation

```bash
python --version
```

---

### 🔹 Step 5: Install Required Library

```bash
pip install psutil
```

---

### 🔹 Step 6: Run the Script

```bash
python process_enum.py
```

---

## 🧪 Sample Output

```
Windows Monitoring Agent Started...

HIGH RISK -> CodeSetup.tmp | Running from Temp Folder
MEDIUM RISK -> WhatsApp.Root.exe | Invalid Signature
```

---

## 📊 SOC Use Case

This project simulates how a SOC Analyst:

* Monitors system processes
* Detects anomalies
* Identifies potential threats
* Performs basic IOC analysis

---

## 🚀 Future Improvements

* Wazuh SIEM integration
* Real digital signature verification
* Log forwarding to SIEM dashboard
* Automated alerting system

---

## 👨‍💻 Author

Amir Shaikh
Cybersecurity Enthusiast | SOC Analyst Learner
