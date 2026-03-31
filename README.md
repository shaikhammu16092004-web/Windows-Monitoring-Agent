# Windows-Monitoring-Agent
Advanced Windows Process &amp; Service Monitoring Agent (Mini-EDR)
# 🛡️ Windows Service & Process Monitoring Agent

## 📌 Project Overview
This project is a Windows-based monitoring agent designed to detect **malicious, unauthorized, and suspicious process behavior**. It focuses on identifying threats such as malware execution, persistence mechanisms, and privilege escalation techniques.

---

## 🎯 Objectives
- Monitor active Windows processes
- Analyze parent-child process relationships
- Audit startup services
- Detect unauthorized or suspicious processes
- Generate alerts and detailed reports

---

## 🚨 Key Features

### 🔹 Parent-Child Process Monitoring
- Tracks process hierarchy using PID & PPID
- Detects suspicious chains  
  *(e.g., winword.exe → powershell.exe)*

### 🔹 Startup Service Auditing
- Identifies newly added or modified services
- Detects unusual service paths
- Highlights misconfigurations

### 🔹 Unauthorized Process Detection
- Uses whitelist/blacklist approach
- Detects unknown or unsigned processes
- Flags processes running from temp directories

### 🔹 Alert & Reporting System
- Logs events with timestamp, PID, path
- Flags high severity alerts
- Generates final detection report

---

## 🛠️ Tools & Technologies

- **Programming Language:** Python  
- **Modules Used:**  
  - psutil  
  - wmi  
  - win32service / win32process  
- **Other Tools:**  
  - PowerShell (Get-Service, Get-Process)

---

## ⚙️ How It Works (Workflow)

1. Enumerate active processes & services  
2. Build parent-child process tree  
3. Audit startup services  
4. Detect unauthorized processes  
5. Generate alerts  
6. Create final report  

---

## 🔄 Project Flow

```
START
↓
Enumerate Processes & Services
↓
Analyze Parent-Child Relationship
↓
Audit Startup Services
↓
Detect Suspicious Activity
↓
Generate Alerts
↓
Export Report
↓
END
```

---

## 📊 Sample Detection Output

- Suspicious Process: `winword.exe → powershell.exe`  
- Unknown Startup Service: `UnknownServiceXYZ`  
- Unauthorized Process: Running from Temp Directory  

---

## 🧠 Learning Outcomes

- Windows process & service architecture  
- Malware behavior analysis  
- Blue Team detection techniques  
- Real-time monitoring concepts  
- Security alert engineering  

---

## 🛡️ Blue Team Relevance

This project simulates real-world SOC operations by:
- Detecting threats in real-time  
- Identifying persistence mechanisms  
- Supporting incident response  

---

## 📁 Project Deliverables

- Monitoring Agent Script  
- Project Documentation  
- Logs & Screenshots  
- Flowcharts & Architecture  
- PPT Presentation  

---

## 👨‍💻 Author

**Amir Shaikh**  
Cybersecurity Enthusiast | SOC Analyst (Aspiring)

---

## ⭐ Conclusion

This project demonstrates a practical approach to detecting Windows-based threats using behavior analysis and monitoring techniques, making it highly relevant for Blue Team and SOC roles.
