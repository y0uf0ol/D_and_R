# Anomaly Unusual High User Activity in Entra ID

## Basic Information

- **Author:** y0uf0ol
- **Creation Date:** 12/12/23
- **Maturity:** Development
- **Reference:** /

## Naming

- **Name:** Anomaly Unusual High User Activity in Entra ID
- **Description:** This Rule Alerts on unusual High Activitys from Users in Entra ID

## Technical Details

- **Tags:** TA0003 / TA0004
- **Data Source:** Kusto: Entra ID Audit Logs

## Rule Implementation

```yaml
let approved_accounts = dynamic([ ]);//set exclustions
let mint = toscalar(AuditLogs | where TimeGenerated > ago(14d)| summarize min(TimeGenerated));
let maxt = toscalar(AuditLogs | where TimeGenerated > ago(14d)| summarize max(TimeGenerated));
AuditLogs
| extend initator = tostring(InitiatedBy.user.userPrincipalName)
| where initator != "" //exclude spn
| where not( initator has_any (approved_accounts))
| make-series actions=count() on TimeGenerated from mint to maxt step 1d by initator
| extend Sum_actions = array_sum(actions)
| extend avarage = Sum_actions/14
| where avarage > 25 // fill with threshold
```

- **Response:** Look up the activities that the user created 
- **False Positive:** Check for planed changes
- **Severity:** low 
- **Confidence:** low
 

 ## Unit Test

Run this query and build up from there. Check for Service Accounts or other unusual stuff and build Exclustions
```yaml
let approved_accounts = dynamic([ ]);//set exclustions
let mint = toscalar(AuditLogs | where TimeGenerated > ago(14d)| summarize min(TimeGenerated));
let maxt = toscalar(AuditLogs | where TimeGenerated > ago(14d)| summarize max(TimeGenerated));
AuditLogs
| extend initator = tostring(InitiatedBy.user.userPrincipalName)
| where initator != "" //exclude spn
| where not( initator has_any (approved_accounts))
| make-series actions=count() on TimeGenerated from mint to maxt step 1d by initator
| render timechart 
```
