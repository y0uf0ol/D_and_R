# Java Script executed out of AppData

## Basic Information

- **Author:** y0uf0ol
- **Creation Date:** 11/22/2023
- **Maturity:** Development
- **Reference:** https://attack.mitre.org/techniques/T1059/

## Naming

- **Name:** Java Script File Executed out of AppData
- **Description:** This Rule detects any execution of javascript from AppData

## Technical Details

- **Tags:** T1059.007
- **Data Source:** Kusto: DeviceProcessEvents, DeviceFilesEvents

## Rule Implementation

```yaml
DeviceProcessEvents
| where ProcessCommandLine contains "AppData"
| where ProcessCommandLine has ".js"
| where FileName == "wscript.exe"
| extend ExecutedFileName1 = tostring(split(ProcessCommandLine, '\\')[-1])
| extend ExecutedFileName = substring(ExecutedFileName1, 0, strlen(ExecutedFileName1) - 2) // seems -2 is needed cause there is a space 
| join (DeviceFileEvents 
    | summarize by ExecutedFileName=FileName, ExecutedFileHash=SHA1)
    on ExecutedFileName
| project Timestamp, DeviceName, ExecutedFileName, ExecutedFileHash, ProcessCommandLine, InitiatingProcessCommandLine 
```

- **Response:** Analyse if this is a legitimate execution or mal. one / check source of the file with hash
- **False Positive:** Legitimate Programm execution / Admin testing
- **Severity:** medium
- **Confidence:** medium
 

 ## Unit Test

- **Source:** https://atomicredteam.io/execution/T1059.007/
The Script below is a fixed version of the [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) ToolKit

```yaml
var objWMIService, objList, objItem, strDomain, strName, strManu, strModel;

try {
  objWMIService = GetObject("winmgmts:\\\\.\\root\\cimv2");
  objList = objWMIService.ExecQuery("SELECT * FROM Win32_ComputerSystem");

  if (!objList.Count) {
    WScript.Echo("No items found");
    WScript.Quit();
  }

  objItem = new Enumerator(objList);
  for (; !objItem.atEnd(); objItem.moveNext()) {
    strDomain = objItem.item().Domain;
    strName = objItem.item().Name;
    strManu = objItem.item().Manufacturer;
    strModel = objItem.item().Model;

    WScript.Echo("Domain: " + strDomain);
    WScript.Echo("Computer Name: " + strName);
    WScript.Echo("Manufacturer: " + strManu);
    WScript.Echo("Model: " + strModel);
  }
} catch (e) {
  WScript.Echo("An error occurred: " + e.message);
}

```
