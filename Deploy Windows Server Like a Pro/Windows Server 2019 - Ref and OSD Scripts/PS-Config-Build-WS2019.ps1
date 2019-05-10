<#
.SYNOPSIS
    Baseconfig for WS2019
.DESCRIPTION
    Baseconfig for WS2019
.EXAMPLE
    Baseconfig for WS2019
.NOTES
        ScriptName: Baseconfig for WS2019.ps1
        Author:     Mikael Nystrom
        Twitter:    @mikael_nystrom
        Email:      mikael.nystrom@truesec.se
        Blog:       https://deploymentbunny.com

    Version History
    1.0.0 - Script created [01/16/2019 13:12:16]

Copyright (c) 2019 Mikael Nystrom

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

[cmdletbinding(SupportsShouldProcess=$True)]
Param(
)

# Set Vars
$VerbosePreference = "continue"
$writetoscreen = $true
$osv = ''
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptName = Split-Path -Leaf $MyInvocation.MyCommand.Path
$ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE

#Import TSxUtility
$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
$Logpath = $tsenv.Value("LogPath")
$LogFile = $Logpath + "\" + "$ScriptName.log"
$DeployRoot = $tsenv.Value("DeployRoot")
Import-Module $DeployRoot\Tools\Modules\TSxUtility\TSxUtility.psm1

#Start logging
Start-Log -FilePath $LogFile
Write-Log "$ScriptName - Logging to $LogFile"

# Generate Vars
$OSSKU = Get-OSSKU
$TSMake = $tsenv.Value("Make")
$TSModel = $tsenv.Value("Model")
Get-VIAOSVersion -osv ([ref]$osv)  

#Output more info
Write-Log "$ScriptName - ScriptDir: $ScriptDir"
Write-Log "$ScriptName - ScriptName: $ScriptName"
Write-Log "$ScriptName - Integration with TaskSequence(LTI/ZTI): $MDTIntegration"
Write-Log "$ScriptName - Log: $LogFile"
Write-Log "$ScriptName - OSSKU: $OSSKU"
Write-Log "$ScriptName - OSVersion: $osv"
Write-Log "$ScriptName - Make:: $TSMake"
Write-Log "$ScriptName - Model: $TSModel"

#Custom Code Starts--------------------------------------

#Action
$Action = "Create folder structure"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 10 -Id 1
Write-Log "$ScriptName - $Action"
try
{
    New-Item -Path C:\Temp -ItemType Directory -Force
    New-Item -Path C:\Tools -ItemType Directory -Force
}
catch{
    Write-Log "$ScriptName - $Action - Fail"
}

#Action
$Action = "Install SNMP and Telnet"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 10 -Id 1
Write-Log "$ScriptName - $Action"
try
{
    Add-WindowsFeature -Name SNMP-Service -IncludeAllSubfeature -IncludeManagementTools
    Add-WindowsFeature -Name SNMP-WMI-Provider -IncludeAllSubfeature -IncludeManagementTools
    Add-WindowsFeature -Name Telnet-Client -IncludeAllSubfeature -IncludeManagementTools
    Add-WindowsFeature -Name FS-FileServer -IncludeAllSubfeature -IncludeManagementTools
}
catch{
    Write-Log "$ScriptName - $Action - Fail"
}

#Action
$Action = "Configure DoNotOpenServerManagerAtLogon"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 10 -Id 1
Write-Log "$ScriptName - $Action"
try
{
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -Force
}
catch{
    Write-Log "$ScriptName - $Action - Fail"
}

#Action
$Action = "Configure NoWindowsAdminPopup"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 10 -Id 1
Write-Log "$ScriptName - $Action"
try
{
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ServerManager -Name DoNotPopWACConsoleAtSMLaunch -PropertyType DWORD -Value 1 -Force
}
catch{
    Write-Log "$ScriptName - $Action - Fail"
}


#Action
$Action = "Enable Remote Desktop"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 10 -Id 1
Write-Log "$ScriptName - $Action"
try
{
    cscript.exe /nologo C:\windows\system32\SCregEdit.wsf /AR 0
}
catch{
    Write-Log "$ScriptName - $Action - Fail"
}

#Action
$Action = "Set Remote Destop Security"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 20 -Id 1
Write-Log "$ScriptName - $Action"
try
{
    cscript.exe /nologo C:\windows\system32\SCregEdit.wsf /CS 1
}
catch{
    Write-Log "$ScriptName - $Action - Fail"
}


#Server Manager Performance Monitor
$Action = "Start-SMPerformanceCollector -CollectorName 'Server Manager Performance Monitor'"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 40 -Id 1
Write-Log "$ScriptName - $Action"
Start-SMPerformanceCollector -CollectorName 'Server Manager Performance Monitor'

#Disable Show Welcome Tile for all users
$Action = "Disable Show Welcome Tile for all users"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 50 -Id 1
Write-Log "$ScriptName - $Action"

$XMLBlock = @(
'<?xml version="1.0" encoding="utf-8"?>
  <configuration>
   <configSections>
    <sectionGroup name="userSettings" type="System.Configuration.UserSettingsGroup, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <section name="Microsoft.Windows.ServerManager.Common.Properties.Settings" type="System.Configuration.ClientSettingsSection, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" allowExeDefinition="MachineToLocalUser" requirePermission="false" />
    </sectionGroup>
   </configSections>
   <userSettings>
    <Microsoft.Windows.ServerManager.Common.Properties.Settings>
     <setting name="WelcomeTileVisibility" serializeAs="String">
      <value>Collapsed</value>
     </setting>
    </Microsoft.Windows.ServerManager.Common.Properties.Settings>
   </userSettings>
  </configuration>'
  )
$XMLBlock | Out-File -FilePath C:\Windows\System32\ServerManager.exe.config -Encoding ascii -Force

#Configure global settings for all servers in the fabric
$Action = "Enable SmartScreen"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 60 -Id 1
Write-Log "$ScriptName - $Action"
$OptionType = 2
$KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
New-ItemProperty -Path $KeyPath -Name EnableSmartScreen -Value $OptionType -PropertyType DWord -Force

#Set CrashControl
$Action = "Set CrashControl"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 70 -Id 1
Write-Log "$ScriptName - $Action"
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "AutoReboot" -value 00000001
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "CrashDumpEnabled" -value 00000002
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "LogEvent" -value 00000001
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "MinidumpsCount" -value 00000005
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "Overwrite" -value 00000001
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "AlwaysKeepMemoryDump" -value 00000000

#Firewall File/Printsharing
$Action = "Configure firewall rules"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 80 -Id 1
Write-Log "$ScriptName - $Action"
#Get-NetFirewallRule -DisplayName "*File and Printer Sharing*" | Enable-NetFirewallRule -Verbose
Get-NetFirewallRule -Group "@FirewallAPI.dll,-28752" | Enable-NetFirewallRule -Verbose

#Configure Eventlogs
$Action = "Configure Eventlogs"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 90 -Id 1
Write-Log "$ScriptName - $Action"
$EventLogs = "Application","Security","System"
$MaxSize = 2GB
foreach($EventLog in $EventLogs){
    try{
        Limit-EventLog -LogName $EventLog -MaximumSize $MaxSize
    }
    catch{
        Write-Warning "Could not set $EventLog to $MaxSize, sorry"
    }
}

Write-Log "$ScriptName - Done"
#Custom Code Ends--------------------------------------