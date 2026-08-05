# Microsoft Sentinel Home Lab
A hands-on home lab documenting real SIEM deployment,  log ingestion, KQL detection engineering, and incident  response using Microsoft Sentinel.

Building for the purpose of demonstrating practical SOC skills 

## The environment
 
| Component | What I used |
|---|---|
| SIEM | Microsoft Sentinel |
| Log source | Azure Activity Logs, via diagnostic settings |
| Query language | KQL |
| Detections | Custom scheduled analytics rules |
 
Azure Activity Logs were a deliberate choice. They're free, they exist in every
subscription, and they record the control-plane operations an attacker with
stolen credentials would actually perform — creating resources, changing
permissions, deleting things. No agents, no connectors to license.
 

# Use Cases 

## 1. We will first look into "Suspicious Deletion of resources". An insider or an attacker could potentially participate in this scenario. Azure should detect the deleted resource.
## 2. Next "Unusual Login Location", unexpected locations where authorized users are logging in from
## 3. Privilege Escalation attempt, Azure should detect when someone is trying to assign themselves a higher role
## 4. A sudden "Mass Resource creation" Azure should detect a spike in resource creation 


## 01. Detection: Suspicious Resource Deletion
Check detection rules folder.
Check screenshot in the screenshots folder for the result. 

## What this Lab covers
- Microsoft Sentinel deployment and configuration
- Azure Activity Log ingestion via diagnostic settings
- KQL detection queries for real attack techniques
- Custom Analytics Rule — Suspicious Resource Deletion
- Automated incident creation from live detection
- Incident investigation and response workflow
- [INPROGRESS] Incident response playbooks
