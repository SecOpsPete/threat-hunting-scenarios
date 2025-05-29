# 🧠 Threat Hunting Scenarios

A collection of hands-on threat hunting labs built around Microsoft Defender for Endpoint (MDE). Each lab demonstrates how to identify malicious or suspicious behavior, supported by KQL queries and mapped to MITRE ATT&CK techniques.

## 🔍 Included Labs

- 🛡️ [PwnCrypt Ransomware Detection](./pwncrypt-ransomware-detection/README.md)  
  Detects file encryption activity, delivery via PowerShell, and execution of the `pwncrypt.ps1` ransomware script using Microsoft Defender telemetry and MITRE ATT&CK mapping.

- 📦 [Insider Data Exfiltration](./insider-data-exfil/README.md)  
  Investigates PowerShell and 7-Zip usage to stage and exfiltrate sensitive employee data.

- 🔐 [Brute Force Detection](./brute-force-detection/README.md)  
  Detects suspicious authentication failures and patterns that indicate password guessing or brute force attacks.

- 🌐 [Port Scanning Detection](./port-scanning-detection/README.md)  
  Identifies network reconnaissance activity within internal IP ranges using PowerShell port scanning.
