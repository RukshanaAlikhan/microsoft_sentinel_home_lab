# Microsoft Sentinel Home Lab
### A hands-on SIEM detection engineering lab built from scratch on Azure

![Azure](https://img.shields.io/badge/Microsoft_Azure-0078D4?style=flat&logo=microsoft-azure&logoColor=white)
![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Detection_Engineering-blue?style=flat)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=flat)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat)

---

## Overview

This project documents the end-to-end deployment of a Microsoft Sentinel SIEM environment, including log ingestion, custom KQL detection rule engineering, automated analytics rules, and real-time incident creation.

Every detection rule in this lab was tested against **live Azure Activity Log data** — not simulated or mocked. Each rule fired a real automated incident in Sentinel.

**Built by:** Rukshana Alikhan  
**LinkedIn:** [linkedin.com/in/rukshana-alikhan](https://linkedin.com/in/rukshana-alikhan)  
**Website:** [rukshana.dev](https://rukshana.dev)

---

## Lab Architecture

```
Azure Subscription (Free Tier)
│
├── Resource Group: sentinel-home-lab
│   │
│   ├── Log Analytics Workspace: sentinel-law-homelab
│   │   └── Ingests Azure Activity Logs via Diagnostic Settings
│   │
│   ├── Microsoft Sentinel
│   │   ├── Data Connectors → Azure Activity
│   │   ├── Analytics Rules → 4 Custom Detection Rules
│   │   ├── Incidents → Auto-generated from rule triggers
│   │   └── Automation → Logic App Playbook
│   │
│   └── Azure Activity Logs
│       └── Source of all security events monitored
```

---

## Lab Setup

### Step 1 — Resource Group
Created resource group `sentinel-home-lab` to contain all lab resources.

### Step 2 — Log Analytics Workspace
Deployed `sentinel-law-homelab` as the data store for all ingested logs.

### Step 3 — Microsoft Sentinel
Enabled Microsoft Sentinel on top of the Log Analytics Workspace via the Azure portal.

### Step 4 — Data Connector
Connected **Azure Activity Logs** as the primary data source via:
- Content Hub → Azure Activity solution installed
- Diagnostic Settings pipeline configured to stream subscription-level events
- Verified log ingestion using KQL query `AzureActivity | take 10`

### Step 5 — Detection Rules
Built 4 custom analytics rules (documented below).

### Step 6 — Incident Response Playbook
Created a Logic App automation that triggers on high-severity incidents.

---

## Detection Rules

All rules are mapped to **MITRE ATT&CK** and tested against live log data.

---

### Rule 1 — Suspicious Resource Deletion
**File:** `detection-rules/resource-deletion.kql`  
**Severity:** High  
**MITRE ATT&CK:** T1485 — Data Destruction  

**Description:**  
Detects when Azure resources are deleted by a non-Microsoft caller. Attackers commonly delete resources to cover their tracks after a breach or during a destructive attack.

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "DELETE"
| where ActivityStatusValue == "Success"
| where Caller !contains "microsoft"
| project TimeGenerated, Caller,
          ResourceGroup, OperationNameValue,
          CallerIpAddress
| order by TimeGenerated desc
```

**Trigger used for testing:** Deleted a resource tag in the lab environment.  
**Result:** ✅ Incident auto-generated in Sentinel

---

### Rule 2 — Defence Evasion via Alert Rule Modification
**File:** `detection-rules/defence-evasion-alert-rule-modification.kql`  
**Severity:** Critical  
**MITRE ATT&CK:** T1562.001 — Impair Defences: Disable or Modify Tools  

**Description:**  
Detects when Sentinel analytics rules are modified or created. Attackers who gain access to a SIEM environment may attempt to disable or modify detection rules to evade detection. This rule monitors for any changes to alert rules.

```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue == "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE"
| where ActivityStatusValue == "Success"
| where Caller !contains "microsoft"
| project TimeGenerated, Caller,
          OperationNameValue,
          ActivityStatusValue,
          CallerIpAddress
| order by TimeGenerated desc
```

**Note:** During development, Azure Activity Logs recorded rule modifications under `MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE` rather than the expected `roleAssignments` operation — discovered through raw log analysis, demonstrating real-world SOC investigation methodology.  
**Result:** ✅ Incident auto-generated in Sentinel

---

### Rule 3 — Mass Resource Creation
**File:** `detection-rules/mass-resource-creation.kql`  
**Severity:** Medium  
**MITRE ATT&CK:** T1578 — Modify Cloud Compute Infrastructure  

**Description:**  
Detects a sudden spike in resource creation operations. Attackers who compromise cloud environments often spin up compute resources for cryptomining, data exfiltration infrastructure, or command and control.

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "WRITE"
| where ActivityStatusValue == "Success"
| where Caller !contains "microsoft"
| summarize ResourcesCreated = count()
    by Caller, bin(TimeGenerated, 1h)
| where ResourcesCreated > 2
| order by ResourcesCreated desc
```

**Trigger used for testing:** Created multiple resource tags in rapid succession to exceed the threshold.  
**Result:** ✅ Incident auto-generated in Sentinel

---

### Rule 4 — After Hours Azure Activity
**File:** `detection-rules/after-hours-activity.kql`  
**Severity:** Medium  
**MITRE ATT&CK:** T1078 — Valid Accounts  

**Description:**  
Detects Azure portal activity outside of business hours. Legitimate users rarely access cloud infrastructure late at night or early in the morning — unusual access patterns can indicate compromised accounts or insider threat activity.

```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatusValue == "Success"
| where Caller !contains "microsoft"
| extend HourOfDay = hourofday(TimeGenerated)
| where HourOfDay < 7 or HourOfDay > 20
| project TimeGenerated, Caller,
          OperationNameValue,
          CallerIpAddress,
          HourOfDay
| order by TimeGenerated desc
```

**Note:** Rule was tuned based on actual log analysis — ran `summarize count() by hourofday(TimeGenerated)` to identify real activity hours in the environment before setting thresholds.  
**Result:** ✅ Incident auto-generated in Sentinel

---

## MITRE ATT&CK Coverage

| Rule | Tactic | Technique | ID |
|---|---|---|---|
| Suspicious Resource Deletion | Impact | Data Destruction | T1485 |
| Alert Rule Modification | Defence Evasion | Impair Defences | T1562.001 |
| Mass Resource Creation | Defence Evasion | Modify Cloud Compute | T1578 |
| After Hours Activity | Initial Access / Persistence | Valid Accounts | T1078 |

---

## Incident Response Playbook

Built a **Logic App automation** that triggers automatically when a high-severity incident is created in Sentinel:

```
Trigger: Microsoft Sentinel Incident Created
↓
Condition: Severity == High or Critical
↓
Action: Send automated email notification
  - To: SOC analyst email
  - Subject: [Incident Title] — dynamic content
  - Body: Severity, Description, Incident URL
```

This demonstrates automated response capability — reducing mean time to acknowledge (MTTA) for critical incidents.

---

## Key Learning Moments

**Raw log analysis over assumptions**  
When role assignment logs weren't appearing as expected, I ran `summarize count() by OperationNameValue` to see exactly what Azure was logging. This revealed the actual operation name (`MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE`) and led to a more interesting detection — defence evasion via alert rule modification — than the original plan. This is real SOC methodology: follow the data, not the assumption.

**Threshold tuning from real data**  
Rather than guessing thresholds for the Mass Resource Creation rule, I ran `summarize count() by Caller, bin(TimeGenerated, 1h)` to understand normal baseline activity before setting the alert threshold. This is how production detection rules are built.

**Timing and log ingestion**  
Learned that Azure Activity Logs can take 15-60 minutes to appear in Sentinel after initial connector setup — important to understand when building detection pipelines in production environments.

---

## Skills Demonstrated

| Skill | Evidence |
|---|---|
| SIEM Deployment | End-to-end Sentinel setup from scratch |
| Log Ingestion | Azure Activity Logs via diagnostic settings |
| KQL | 4 detection queries written and tested against live data |
| Detection Engineering | Rules mapped to MITRE ATT&CK, tuned from real log analysis |
| Incident Response | All 4 rules generated automated real-time incidents |
| Automation | Logic App playbook for automated email alerting |
| Cloud Security | Azure subscription-level security monitoring |
| Investigation Methodology | Raw log analysis to identify actual operation names |

---

## Screenshots

*See `/screenshots` folder for:*
- Sentinel Incidents page showing all 4 incidents
- Individual incident investigation view
- KQL queries returning live results
- Analytics rules configuration
- Logic App playbook design

---

## Tools Used

- **Microsoft Azure** — cloud infrastructure
- **Microsoft Sentinel** — SIEM platform
- **Log Analytics** — data storage and querying
- **KQL (Kusto Query Language)** — detection query language
- **Azure Logic Apps** — incident response automation
- **Azure Activity Logs** — primary log source

---

## What's Next

- [ ] Add Microsoft Defender for Cloud as additional data source
- [ ] Build threat hunting queries using MITRE ATT&CK navigator
- [ ] Create incident response playbooks for each detection rule
- [ ] Add workbook dashboard for security posture visualisation
- [ ] Integrate Threat Intelligence feeds
