# New Local Use added to Local Administrator Group

## Basic Information

- **Author:** y0uf0ol
- **Creation Date:** 11/20/2023
- **Maturity:** Testing
- **Reference:** https://attack.mitre.org/techniques/T1136/001/

## Naming

- **Name:** New Local User added to Local Administrator Group
- **Description:** Detects when a newly created user gets added to the local admin group

## Technical Details

- **Tags:** T1136.001 / T1078 / T1098
- **Data Source:** Kusto: DeviceEvents

## Rule Implementation

```yaml
let added_to_admins=DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| where AdditionalFields contains "Administrators"
| project AccountSid;
DeviceEvents
| where ActionType == "UserAccountCreated"
| where AccountSid in (added_to_admins)
| project Timestamp, AccountName, DeviceName, InitiatingProcessAccountName
```

- **Response:** Check if ligitimate usage or not
- **False Positive:** Ligitimate addition through administartor or feature 
- **Severity:** medium
- **Confidence:** medium
 

 ## Unit Test
```yaml
net user /add "#{username}" "#{password}"
net localgroup administrators "#{username}" /add
```
