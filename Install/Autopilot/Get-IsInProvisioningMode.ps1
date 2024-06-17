<#
.Synopsis
Returns 'Applicable' if the device is in provisioning mode.

Created on:   2024-06-17
Created by:   Ben Whitmore @PatchMyPC
Filename:     Get-IsInProvisioningMode.ps1

.Description
This script can be used as an additional requirement rule for a Win32 app to ensure the Win32 app is only applicable if the device is in provisioning mode.
There are several conditions that can be checked if a device is provisioning mode. If the device is found to be in provisioning mode, the script will return 'Applicable'.

References/credit:
https://learn.microsoft.com/en-us/windows/client-management/mdm/enrollmentstatustracking-csp

---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

#>

# Enable the script to test an undocumented registry value for high confidence testing
$betaHighConfidenceTesting -eq $false

# Create a PSCustomObject array to store the registry tests
$registryTests = @()

$registryTests += @{
  TestName                  = 'Reg_ProvisioningAgentStatus'
  TestPath                  = 'HKLM\SOFTWARE\Microsoft\Provisioning\Agent'
  TestValueName             = 'CurrentEvent'
  ProvisioningFinishedValue = @('0x5')
}

$registryTests += @{
  TestName                  = 'Reg_AutopilotDeviceSetupPhase'
  TestPath                  = 'HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\Device\Setup'
  TestValueName             = 'HasProvisioningCompleted'
  ProvisioningFinishedValue = @('0xffffffff')
}

$registryTests += @{
  TestName                  = 'Reg_AutopilotAccountSetupPhase'
  TestPath                  = 'HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\{0}\Setup' -f '{^S-1-12-1-(\d+-)+\d+$}'
  TestValueName             = 'HasProvisioningCompleted'
  ProvisioningFinishedValue = @('0xffffffff')
}

$registryTests += @{
  TestName                  = 'Reg_DevicePreparationCategoryStatus'
  TestPath                  = 'HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
  TestValueName             = 'DevicePreparationCategory.Status'
  TestJsonValue             = 'categoryState'  
  ProvisioningFinishedValue = @('succeeded')
}

$registryTests += @{
  TestName                  = 'Reg_DeviceSetupCategoryStatus'
  TestPath                  = 'HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
  TestValueName             = 'DeviceSetupCategory.Status'
  TestJsonValue             = 'categoryState'  
  ProvisioningFinishedValue = @('succeeded')
}

$registryTests += @{
  TestName                  = 'Reg_AccountSetupCategoryStatus'
  TestPath                  = 'HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
  TestValueName             = 'AccountSetupCategory.Status'
  TestJsonValue             = 'categoryState'  
  ProvisioningFinishedValue = @('succeeded', 'notStarted')
}

# Create a PSCustomObject array to store the WMI tests
$wmiTests = @()

$wmiTests += @{
  TestName                  = 'Wmi_HasProvisioningCompleted'
  TestClass                 = 'root\cimv2\mdm\dmmap'
  TestNamespace             = 'MDM_EnrollmentStatusTracking_Setup01'
  TestValueName             = 'HasProvisioningCompleted'
  ProvisioningFinishedValue = @($true)
}

# Set the error action preference to stop the script if an error occurs
$ErrorActionPreference = 'Stop'

function Get-TranslatedRegistryPath {
  param (
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  # Extract the regex pattern from the input string
  if ($Path -match '\{(.+)\}') {
    $regexPattern = $matches[1]
  }
  else {
    if (Test-Path "Registry::$Path") {
      return $Path
    }
    else {
      return $false
    }
  }

  # Capture any path segments following the regex pattern
  $extraPath = $Path.Substring($Path.IndexOf('}') + 1)

  # Determine the base registry path without the regex part and the extra path
  $baseRegistryPath = $Path -replace '\{.+?\}.*$', ''

  try {

    # Split the base registry path into parent path and potential child pattern
    $parentPath = $baseRegistryPath

    # Open the registry key
    $key = Get-Item -Path "Registry::$parentPath" -ErrorAction SilentlyContinue

    # List all subkeys and test each one against the regex pattern
    $subkeys = $key.GetSubKeyNames()

    foreach ($subkey in $subkeys) {
      
      if ($subkey -match $regexPattern) {
        $fullPath = Join-Path -Path $parentPath -ChildPath $subkey

        # Append extra path if it exists
        if ($extraPath) {
          $fullPath = Join-Path -Path $fullPath -ChildPath $extraPath.TrimStart('\')
        }
        else {
          $fullPath = $Path
        }
        
        # If the full path exists, return it
        if (Test-Path "Registry::$fullPath") {
          return $fullPath
        }
        else {
          return $false
        }
      }
    }
  }
  catch {
    return $false
  }
}

function Get-RegistryTestResults {
  param (
    [Parameter(Mandatory = $true)]
    [string]$TestName,
    [string]$TestPath,
    [string]$TestValueName,
    [object]$ProvisioningFinishedValue,
    [Parameter(Mandatory = $false)]
    [string]$TestJsonValue
  )

  # Test the registry path
  $Path = Get-TranslatedRegistryPath -Path $TestPath

  # Initialize the result object
  $result = [PSCustomObject]@{
    TestName   = $TestName
    TestValue  = $ProvisioningFinishedValue
    TestResult = $null
  }

  if ($Path -ne $false) {

    if (-not $PSBoundParameters.ContainsKey('TestJsonValue')) {

      try {
        # Get the registry key value
        $value = (Get-Item "Registry::$Path").GetValue($TestValueName)

        # Check values and account for hex values too
        $valueType = (Get-Item "Registry::$Path").GetValueKind($TestValueName)

        if ($valueType -in ('DWord', 'QWord')) {
          $value = ('0x{0:X}' -f $value).ToLower()
        }
        
        if ($value -in $ProvisioningFinishedValue) {
          $result.TestResult = $value
        }
      }
      catch {
        $result.TestResult = 'ValueCouldNotBeRead'
      }
    }
    else {
      try {

        # Get the JSON value from the registry key
        $value = (Get-Item "Registry::$Path").GetValue($TestValueName) | ConvertFrom-Json

        # Dynamically access the JSON property based on the path
        $dynamicValue = $value | Select-Object -ExpandProperty $TestJsonValue

        # Check values and account for hex values too
        $result.TestResult = $dynamicValue
      }
      catch {
        $result.TestResult = 'ValueCouldNotBeRead'
      }
    }
  }
  else {
    $result.TestResult = 'KeyNotFound'
  }

  return $result
}

function Get-WMITestResults {
  param (
    [Parameter(Mandatory = $true)]
    [string]$TestName,
    [string]$TestClass,
    [string]$TestNamespace,
    [string]$TestValueName,
    [object]$ProvisioningFinishedValue
  )

  # Add the required assembly
  Add-Type -AssemblyName System.Management

  # Initialize the result object
  $result = [PSCustomObject]@{
    TestName   = $TestName
    TestValue  = $ProvisioningFinishedValue
    TestResult = $false
  }

  try {
    $scope = New-Object System.Management.ManagementScope $TestClass
    $scope.Connect()

    $path = New-Object System.Management.ManagementPath $TestNamespace
    $options = New-Object System.Management.ObjectGetOptions

    # Attempt to create a ManagementClass object
    $class = New-Object System.Management.ManagementClass($scope, $path, $options)
    
    if ($class) {
      $query = New-Object System.Management.ObjectQuery "SELECT * FROM $($TestNamespace)"

      try {

        # Execute the query
        $searcher = New-Object System.Management.ManagementObjectSearcher($scope, $query)
        $queryResults = $searcher.Get()

        # Iterate over the results and print the 'HasProvisioningCompleted' property
        foreach ($obj in $queryResults) {
          $hasProvisioningCompleted = $obj[$TestValueName]
    
          if ($hasProvisioningCompleted -in $ProvisioningFinishedValue) {
            $result.TestResult = $true
          }
          else {
            $result.TestResult = $false
          }
        }
      }
      catch {
        $result.TestResult = 'QueryFailed'
      }
    }
  }
  catch {
    $result.TestResult = 'NamespaceOrClassNotFound'
  }

  return $result
}

# Begin the tests
$fullResults = @()

# Run the registry tests
foreach ($regTest in $registryTests) {
  $regtTestResult = Get-RegistryTestResults @regTest
  $regTest.TestGroup = $regTest.TestGroup
  $fullResults += $regtTestResult
}

# Run the WMI tests
foreach ($wmiTest in $wmiTests) {
  $wmiTestResult = Get-WMITestResults @wmiTest
  $wmiTest.TestGroup = $wmiTest.TestGroup
  $fullResults += $wmiTestResult
}
# For testing, uncommen the line below to see the results
#$fullResults

# Evaluate the results
# Initialize a hashtable with default values for each test group
$groupResults = @{}

# Set default values for each test group
$ProvisioningAgentStatus = $false
$DevicePreparationCategoryStatus = $false
$DeviceSetupCategoryStatus = $false
$AccountSetupCategoryStatus = $false
$AutopilotDeviceSetupPhase = $false
$AutopilotAccountSetupPhase = $false
$WmiHasProvisioningCompleted = $false

foreach ($result in $fullResults) {

  # Catch undocumented provisioning status results
  if ($result.TestName -eq 'Reg_ProvisioningAgentStatus' -and $result.TestResult -in $result.TestValue ) { $ProvisioningAgentStatus = $true }

  # Autopilot Tests
  if ($result.TestName -eq 'Reg_DevicePreparationCategoryStatus' -and ($result.TestResult -in $result.TestValue) ) { $DevicePreparationCategoryStatus = $true }
  if ($result.TestName -eq 'Reg_DeviceSetupCategoryStatus' -and ($result.TestResult -in $result.TestValue) ) { $DeviceSetupCategoryStatus = $true }
  if ($result.TestName -eq 'Reg_AutopilotDeviceSetupPhase' -and ($result.TestResult -in $result.TestValue) ) { $AutopilotDeviceSetupPhase = $true }
  if ($result.TestName -eq 'Reg_AutopilotAccountSetupPhase' -and ($result.TestResult -in $result.TestValue) ) { $AutopilotAccountSetupPhase = $true }
  if ($result.TestName -eq 'Reg_AccountSetupCategoryStatus' -and ($result.TestResult -eq 'succeeded') ) { $AccountSetupCategoryStatus = $true }
  if ($result.TestName -eq 'Reg_AccountSetupCategoryStatus' -and ($result.TestResult -eq 'notStarted') ) { $AccountSetupCategoryStatus = $false }
  if ($result.TestName -eq 'Wmi_HasProvisioningCompleted' -and ($result.TestResult -in $result.TestValue) ) { $WmiHasProvisioningCompleted = $true }
}

# Confidence high that ESP has finished the device preparation phase after checking the registry vaules
if ($DevicePreparationCategoryStatus -eq $true) {
  $groupResults['DevicePreparation'] = 'Complete'
}
else { 
  $groupResults['DevicePreparation'] = 'InComplete'
}

# Confidence high that ESP has finished the device setup phase after checking the registry values
if ($DevicePreparationCategoryStatus -eq $true -and $DeviceSetupCategoryStatus -eq $true -and $AutopilotDeviceSetupPhase -eq $true) {
  $groupResults['DeviceSetup'] = 'Complete'
}
else {
  $groupResults['DeviceSetup'] = 'InComplete'
}

# Confidence high that ESP has finished the account setup phase after checking the registry values
if ($DevicePreparationCategoryStatus -eq $true -and $DeviceSetupCategoryStatus -eq $true -and $AutopilotDeviceSetupPhase -eq $true -and $AccountSetupCategoryStatus -eq $true -and $AutopilotAccountSetupPhase -eq $true) {
  $groupResults['AccountSetup'] = 'Complete'
}
elseif ($DevicePreparationCategoryStatus -eq $true -and $DeviceSetupCategoryStatus -eq $true -and $AutopilotDeviceSetupPhase -eq $true -and $AccountSetupCategoryStatus -eq $false -and $AutopilotAccountSetupPhase -eq $true) {
  $groupResults['AccountSetup'] = 'NotStarted'
}
else {
  $groupResults['AccountSetup'] = 'InComplete'
}

# Further confidence that ESP has finished all phases after checking the WMI values
if ($WmiHasProvisioningCompleted -eq $true) {
  $groupResults['WmiHasProvisioningCompleted'] = 'True'
}
else {
  $groupResults['WmiHasProvisioningCompleted'] = 'False'
}

# Further confidence that ESP has finished all phases after checking undocumented provisioning registry values
if ($ProvisioningAgentStatus -eq $true) {
  $groupResults['ProvisioningAgentStatus'] = 'True'
}
else {
  $groupResults['ProvisioningAgentStatus'] = 'False'
}

# Confidence high that ESP has finished All ESP phases after checking the registry values
if ($DevicePreparationCategoryStatus -eq $true -and $DeviceSetupCategoryStatus -eq $true -and $AutopilotDeviceSetupPhase -eq $true -and $AccountSetupCategoryStatus -eq $true -and $AutopilotAccountSetupPhase -eq $true) {
  $groupResults['ESPAllPhases'] = 'Complete'
}
else {
  $groupResults['ESPAllPhases'] = 'InComplete'
}

# Confidence high that ESP has finished all phases, except AccountSetup phase after checking the registry values
if ($DevicePreparationCategoryStatus -eq $true -and $DeviceSetupCategoryStatus -eq $true -and $AutopilotDeviceSetupPhase -eq $true -and $AccountSetupCategoryStatus -eq $false -and $AutopilotAccountSetupPhase -eq $true) {
  $groupResults['ESPAllPhasesButAccountSetupPhaseSkipped'] = 'Complete'
}
else {
  $groupResults['ESPAllPhasesButAccountSetupPhaseSkipped'] = 'NotRequired'
}

# For testing, uncommen the line below to see the results
#$groupResults

if ($betaHighConfidenceTesting -eq $true) {

  # Conclusion with High confidence that ESP has finished phases using all tests and the undocumented ProvisioningAgentStatus test
  if ($groupResults['ESPAllPhasesButAccountSetupPhaseSkipped'] -eq 'Complete' -and $groupResults['WmiHasProvisioningCompleted'] -eq 'True' -and $groupResults['ProvisioningAgentStatus'] -eq 'True') {}

  # Conclusion with high confidence that ESP has finished phases using all tests and the undocumented ProvisioningAgentStatus test but AccountSetup phases was skipped
  elseif ($groupResults['ESPAllPhasesButAccountSetupPhaseSkipped'] -eq 'Complete' -and $groupResults['WmiHasProvisioningCompleted'] -eq 'True' -and $groupResults['ProvisioningAgentStatus'] -eq 'True') {
  }
  else {
    return 'Applicable'
  }
}
else {

  # Conclusion with normal confidence that ESP has finished phases using all tests except the undocumented ProvisioningAgentStatus test
  if ($groupResults['ESPAllPhases'] -eq 'Complete' -and $groupResults['WmiHasProvisioningCompleted'] -eq 'True') {
  }

  # Conclusion with high confidence that ESP has finished phases using all tests but AccountSetup phases was skipped and the undocumented ProvisioningAgentStatus test is ignored
  elseif ($groupResults['ESPAllPhasesButAccountSetupPhaseSkipped'] -eq 'Complete' -and $groupResults['WmiHasProvisioningCompleted'] -eq 'True') {
  }
  else {
    return 'Applicable'
  }
}