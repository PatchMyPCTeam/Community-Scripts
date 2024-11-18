# Get-IsInProvisioningMode

## Synopsis

Returns 'Applicable' if the device is in provisioning mode.  

Created on:   2024-06-17  
Created by:   Ben Whitmore @PatchMyPC  
Filename:     Get-IsInProvisioningMode.ps1  

## Description

This script can be used as an additional requirement rule for a Win32 app to ensure the Win32 app is only applicable if the device is in provisioning mode. There are several conditions that can be checked if a device is provisioning mode. If the device is found to be in provisioning mode, the script will return 'Applicable'.

References/credit:  
[Microsoft Documentation](https://learn.microsoft.com/en-us/windows/client-management/mdm/enrollmentstatustracking-csp)

## Usage

To use this script, add it as an additional requirement rule to the Win32 app. You can change the following variable to perform beta confidence testing if the device is being provisioned.

```powershell
$betaHighConfidenceTesting -eq $false
````

### Registry Tests

The following registry tests are performed to determine if the device is in provisioning mode.

```yml
  TestName: "Reg_ProvisioningAgentStatus"
  TestPath: "HKLM\\SOFTWARE\\Microsoft\\Provisioning\\Agent"
  TestValueName: "CurrentEvent"
  ProvisioningFinishedValue: "0x5"
```

```yml
  TestName: "Reg_AutopilotDeviceSetupPhase"
  TestPath: "HKLM\\SOFTWARE\\Microsoft\\Windows\\Autopilot\\EnrollmentStatusTracking\\Device\Setup"
  TestValueName: "HasProvisioningCompleted"
  ProvisioningFinishedValue: "0xffffffff"
```

```yml
 TestName: "Reg_AutopilotAccountSetupPhase"
  TestPath: "HKLM\\SOFTWARE\\Microsoft\\Windows\Autopilot\\EnrollmentStatusTracking\\{^S-1-12-1-(\\d+-)+\d+$}\\Setup"
  TestValueName: "HasProvisioningCompleted"
  ProvisioningFinishedValue: "0xffffffff"
```

```yml
  TestName: "Reg_DevicePreparationCategoryStatus"
  TestPath: "HKLM\\SOFTWARE\\Microsoft\\Provisioning\\AutopilotSettings"
  TestValueName: "DevicePreparationCategory.Status"
  TestJsonValue: "categoryState"
  ProvisioningFinishedValue: "succeeded"
```

```yml
  TestName: "Reg_DeviceSetupCategoryStatus"
  TestPath: "HKLM\\SOFTWARE\\Microsoft\\Provisioning\\AutopilotSettings"
  TestValueName: "DeviceSetupCategory.Status"
  TestJsonValue: "categoryState"
  ProvisioningFinishedValue: "succeeded"
```

```yml
  TestName: "Reg_AccountSetupCategoryStatus"
  TestPath: "HKLM\\SOFTWARE\\Microsoft\\Provisioning\\AutopilotSettings"
  TestValueName: "AccountSetupCategory.Status"
  TestJsonValue: "categoryState"
  ProvisioningFinishedValue:
    - "succeeded"
    - "notStarted"
```

### WMI Tests

The following WMI tests are performed to determine if the device is in provisioning mode.

```yaml
  TestName: "Wmi_HasProvisioningCompleted"
  TestClass: "root\\cimv2\\mdm\\dmmap"
  TestNamespace: "MDM_EnrollmentStatusTracking_Setup01"
  TestValueName: "HasProvisioningCompleted"
  ProvisioningFinishedValue: true
```

## Further Testing
You can uncomment lines 306 & 396 to see the results of the search using the $appNameList array. Dont forget to comment it out again before using the script in Intune.  

```powershell
306  #$fullResults
```

```powershell
396  #$groupResults
```
