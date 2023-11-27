# Disable Windows AntiVirus

## Basic Information

- **Author:** y0uf0ol
- **Creation Date:** 11/27/23
- **Maturity:** Testing
- **Reference:** ttps://www.microsoft.com/en-us/security/blog/2022/10/25/dev-0832-vice-society-opportunistic-ransomware-campaigns-impacting-us-education-sector/
https://attack.mitre.org/techniques/T1562/001/

## Naming

- **Name:** Disabled Windows Defender 
- **Description:** Detects if Windows Defender gets disabled, either via powershell, gui or via other AV-Product

## Technical Details

- **Tags:** T1562.001
- **Data Source:** Kusto: DeviceRegistryEvents

## Rule Implementation

```yaml
DeviceRegistryEvents
| where RegistryKey contains "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender"
| where RegistryValueName == "DisableRealtimeMonitoring" or RegistryValueName == "PassiveMode"
| where RegistryValueData == 1
```

- **Response:** Check for legimitate use or testing, else run live response script to enable AV again
- **False Positive:** Admitesting or Troubleshooting Mode
- **Severity:** High
- **Confidence:** High
 

 ## Unit Test

```yaml
Set-MpPreference -DisableRealtimeMonitoring $True
```
