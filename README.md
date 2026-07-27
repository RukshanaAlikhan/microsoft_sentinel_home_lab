# Microsoft Sentinel Home Lab
A hands-on home lab documenting real SIEM deployment,  log ingestion, KQL detection engineering, and incident  response using Microsoft Sentinel.

Building for the purpose of demonstrating practical SOC skills 

#Lab enviroment build
Components | Tool
1. SIEM platform | Microsoft Sentinel
2. Log source | Azure activity logs
3. Query Language | KQL
4. Detection rules | Custom Analytical rules

#Use Cases 

###1. We will first look into "Suspicious Deletion of resources". An insider or an attacker could potentially participate in this scenario. Azure should detect the deleted resource.
###2. Next "Unusual Login Location", unexpected locations where authorized users are logging in from
###3. Privilege Escalation attempt, Azure should detect when someone is trying to assign themselves a higher role
###4. A sudden "Mass Resource creation" Azure should detect a spike in resource creation 
