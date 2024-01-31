SigninLogs
| where TimeGenerated > ago(15m)
| where AppId == "YOUR APP ID"
| where AuthenticationDetails !contains "MFA requirement satisfied by claim in the token"
| extend ['Feedback']=iff(ResultType has_any (0,50140), ['Feedback'] = 'yes',['Feedback'] = 'no' )
| where UserPrincipalName == "USER ENTITY"
| project  ['Feedback']
