# High Risk Login with Changes to MFA

## Basic Information

- **Author:** y0uf0ol
- **Creation Date:** 01/04/24
- **Maturity:** Development
- **Reference:** /

## Naming

- **Name:** High Risk Login with Changes to MFA 
- **Description:** This analytic detects when a user logs in with a high or medium risk during signin and immediately changes MFA or adds MFA                                                                                                             

## Technical Details

- **Tags:** TA1098 / T1078
- **Data Source:** Kusto: Entra ID Audit Logs and SignIn Logs

## Rule Implementation

```yaml
let Operations = dynamic (["User changed default security info", "User registered all required security info", "User registered security info","Admin registered security Info"]);
let audit_time = AuditLogs
| extend UserId = tostring(TargetResources.[0].id)
| where OperationName in ( Operations)
| extend Audit_Time = TimeGenerated ;
SigninLogs
| where RiskLevelDuringSignIn contains "medium" or RiskLevelDuringSignIn contains "high"
| where ResultType == 0
| join audit_time on UserId
| where Audit_Time  between (TimeGenerated .. (TimeGenerated+15m) )
| project SigninTime=TimeGenerated ,Audit_Time, UserPrincipalName, RiskLevelDuringSignIn, AppDisplayName, ResultDescription1, OperationName1, Location, IPAddress
```

- **Response:** Look up the activities that the user created 
- **False Positive:** New User registering a MFA Method
- **Severity:** medium 
- **Confidence:** low
 

 ## Unit Test

Try Loging with a User from TOR Browser and Register MFA
```yaml
TBD..
```
