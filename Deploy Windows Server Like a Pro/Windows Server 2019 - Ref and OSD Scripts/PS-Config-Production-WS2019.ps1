<#
.SYNOPSIS
    PS-Config-Production-WS2019.ps1
.DESCRIPTION
    PS-Config-Production-WS2019.ps1
.EXAMPLE
    PS-Config-Production-WS2019.ps1
.NOTES
        ScriptName: PS-Config-Production-WS2019.ps1
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
    $IsVM = "False"
    $IsVM = $tsenv.Value("IsVM")
    $DeplEnv = $tsenv.Value("DeplEnv")
    $IsServerCoreOS = $tsenv.Value("IsServerCoreOS")

<#
    $Win32_computersystem  = Get-WmiObject -Class Win32_computersystem 
    switch ($Win32_computersystem.Model)
    {
        'VMware Virtual Platform' {$IsVM = "True"}
        'VMware7,1' {$IsVM = "True"}
        'Virtual Machine' {$IsVM = "True"}
        'Virtual Box' {$IsVM = "True"}
        Default {$IsVM = "True"}
    }
#>


#Output more info
	Write-Log "$ScriptName - ScriptDir: $ScriptDir"
	Write-Log "$ScriptName - ScriptName: $ScriptName"
	Write-Log "$ScriptName - Integration with TaskSequence(LTI/ZTI): $MDTIntegration"
	Write-Log "$ScriptName - Log: $LogFile"
	Write-Log "$ScriptName - OSSKU: $OSSKU"
	Write-Log "$ScriptName - OSVersion: $osv"
	Write-Log "$ScriptName - Make:: $TSMake"
	Write-Log "$ScriptName - Model: $TSModel"
	Write-Log "$ScriptName - DeplEnv: $DeplEnv"
	Write-Log "$ScriptName - IsVM: $IsVM"

#Custom Code Starts--------------------------------------

#Determine what to do
$Action = "Determine what to do"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1

#Set PowerSchemaSettings to High Performance
$Action = "Set PowerSchemaSettings to High Performance"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
Invoke-VIAExe -Executable powercfg.exe -Arguments "/SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -Verbose

Write-Log "$ScriptName - Check if we are IsServerCoreOS"
if($IsServerCoreOS -eq "False")
{
    Write-Log "$ScriptName - IsServerCoreOS is now $IsServerCoreOS"
    #Set ConfirmDeleteQuestion to ask before deletion
    $Action = "Set ConfirmDeleteQuestion to ask before deletion"
    Write-Log "$ScriptName - $Action"
    Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    New-ItemProperty -Path $RegistryPath -Name "ConfirmFileDelete" -PropertyType DWORD -Value "0000001" -Force

}
else
{
    Write-Log "$ScriptName - IsServerCoreOS is now $IsServerCoreOS"
}

# Disable "Connected User Experiences and Telemetry " Service
$Action = "Disable Connected User Experiences and Telemetry Service"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
Get-Service -Name DiagTrack | Set-Service -StartupType Disabled

# Configure SNMP
$SNMPsysContact = $tsenv.Value("SNMPsysContact")
$SNMPsysLocation = $tsenv.Value("SNMPsysLocation")
$SNMPValidCommunities = $tsenv.Value("SNMPValidCommunities")
$SNMPPermittedManagers = $tsenv.Value("SNMPPermittedManagers")

$Action = "Configure SNMP"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1

$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"
New-ItemProperty -Path $RegistryPath -Name "EnableAuthenticationTraps" -PropertyType DWORD -Value "00000000" -Force -Verbose
                             
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\RFC1156Agent"
New-ItemProperty -Path $RegistryPath -Name "sysContact" -Value "$SNMPsysContact" -Force -Verbose
New-ItemProperty -Path $RegistryPath -Name "sysLocation" -Value "$SNMPsysLocation" -Force -Verbose
                        
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration"
New-Item -Path $RegistryPath -Name "$SNMPValidCommunities" -Force -Verbose
			
$RegistryPath = "HKLM:\SOFTWARE\Policies\SNMP\Parameters"
New-Item -Path $RegistryPath\PermittedManagers -Force
New-Item -Path $RegistryPath\ValidCommunities -Force
New-ItemProperty -Path $RegistryPath\ValidCommunities -Name "1" -Value "$SNMPValidCommunities" -Force -Verbose

$RegistryPath = "HKLM:\SOFTWARE\Policies\SNMP\Parameters\PermittedManagers"
New-ItemProperty -Path $RegistryPath -Name "1" -Value "$SNMPPermittedManagers" -Force -Verbose
				
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration\$SNMPValidCommunities"
New-ItemProperty -Path $RegistryPath -Name "1" -Value "$SNMPPermittedManagers" -Force -Verbose

#Configure w32 Time
$Action = "Configure w32 Time"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
$Arguments =  "triggerinfo w32time start/networkon stop/networkoff"
$Executable = "sc.exe"
Invoke-VIAExe -Executable $Executable -Arguments $Arguments -Verbose
        
# Open Firewall for Backup
$Action = "Open Firewall for Backup"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
$Arguments =  "advfirewall firewall add rule name=""Allow-NetBackup"" dir=in action=allow profile=any localport=1556,13724,13782-13783 protocol=TCP"
$Executable = "netsh.exe"
Invoke-VIAExe -Executable $Executable -Arguments $Arguments -Verbose
     
# Set KMS and Activate
$Action = "Set KMS and Activate"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
$KMSServer = $tsenv.Value("KMSServer")

#Set KMS Server
$Action = "Set KMS Server"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
$Arguments =  "C:\Windows\system32\slmgr.vbs -skms $KMSServer"
$Executable = "cscript.exe"
Invoke-VIAExe -Executable $Executable -Arguments $Arguments -Verbose

#Activate Windows
$Action = "Activate Windows"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
$Arguments =  "C:\system32\slmgr.vbs -ato"
$Executable = "cscript.exe"
Invoke-VIAExe -Executable $Executable -Arguments $Arguments -Verbose


if($IsServerCoreOS -eq "False")
{
    #Adding ShortCut for Notepad in the SendTo folder
    $Action = "Adding ShortCut for Notepad in the SendTo folder"
    Write-Log "$ScriptName - $Action"
    Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1

    $Folder = "C:\Users\Default\AppData\Roaming\Microsoft\Windows\SendTo\"
    $linkPath = "$Folder\Notepad.lnk"
    $wshShell = New-Object -comObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($linkPath)
    $shortcut.Description = "Notepad"
    $shortcut.HotKey = ""
    $shortcut.IconLocation = "C:\Windows\System32\Notepad.exe,0"
    $shortcut.TargetPath = "C:\Windows\System32\Notepad.exe"
    $shortcut.WindowStyle = 3
    $shortcut.WorkingDirectory = "C:\Windows\System32"
    $shortcut.Save()
}

$Action = "Configure Screen Saver for User/Current User"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1

$null = New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value 900 -PropertyType String -Force
Write-Log "$ScriptName - ScreenSaverIsSecure is now: $((Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "ScreenSaverIsSecure").ScreenSaverIsSecure)"
Write-Log "$ScriptName - ScreenSaveActive is now: $((Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "ScreenSaveActive").ScreenSaveActive)"
Write-Log "$ScriptName - ScreenSaveTimeOut is now: $((Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "ScreenSaveTimeOut").ScreenSaveTimeOut)"

REG LOAD HKEY_LOCAL_MACHINE\defuser  "C:\Users\Default\NTUSER.DAT"

$null = New-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name ScreenSaveActive -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value 900 -PropertyType String -Force
Write-Log "$ScriptName - ScreenSaverIsSecure is now: $((Get-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name "ScreenSaverIsSecure").ScreenSaverIsSecure)"
Write-Log "$ScriptName - ScreenSaveActive is now: $((Get-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name "ScreenSaveActive").ScreenSaveActive)"
Write-Log "$ScriptName - ScreenSaveTimeOut is now: $((Get-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name "ScreenSaveTimeOut").ScreenSaveTimeOut)"

[gc]::collect()
REG UNLOAD HKEY_LOCAL_MACHINE\defuser


if($IsServerCoreOS -eq "False")
{
    #'// Show small icons on taskbar
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name TaskbarSmallIcons -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.TaskbarSmallIcons)"	

    #'// Folderoptions Show file extensions	
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideFileExt is now: $($result.HideFileExt)"	
    
    #'// Folderoptions Show hidden files, show hidden systemfiles file
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name Hidden -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - Hidden is now: $($result.Hidden)"	
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowSuperHidden -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - SuperHidden is now: $($result.ShowSuperHidden)"	

    #'// Folderoptions Always shows Menus
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name AlwaysShowMenus -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - AlwaysShowMenus is now: $($result.AlwaysShowMenus)"	

    #'// Folderoptions Display the full path in the title bar
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name FullPath -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - FullPath is now: $($result.FullPath)"	

    #'// Folderoptions HideMerge Conflicts
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideMergeConflicts -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideMergeConflicts is now: $($result.HideMergeConflicts)"	

    #'// Folderoptions Hide empty drives in the computer folder	
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideDrivesWithNoMedia -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideDrivesWithNoMedia is now: $($result.HideDrivesWithNoMedia)"	

    #'// Folderoptions launch folder windows in separate process
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name SeparateProcess -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - SeparateProcess is now: $($result.SeparateProcess)"	

    #'// Folderoptions Always show icons never thumbnails
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name IconsOnly -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - IconsOnly is now: $($result.IconsOnly)"	

    #'// Dont show tooltip	
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowInfoTip -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - ShowInfoTip is now: $($result.ShowInfoTip)"	

    #'// Show computer on desktop
    $null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' -Force
    $null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.'{20D04FE0-3AEA-1069-A2D8-08002B30309D}')"	

    #'// Always show all taskbar icons and notifcations
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name EnableAutoTray -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - EnableAutoTray is now: $($result.EnableAutoTray)"	

    #'// Set control panel to small icons view 
    $null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Force
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name AllItemsIconView -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - AllItemsIconView is now: $($result.AllItemsIconView)"	
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name StartupPage -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - StartupPage is now: $($result.StartupPage)"	
	
    #'// Disable the Volume Icon in system icons
    $null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' -Force
    $null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name HideSCAVolume -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideSCAVolume is now: $($result.HideSCAVolume)"	

    #'// Disable Search in the address bar and the search box on the new tab page
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main' -Name Autosearch -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - Autosearch is now: $($result.Autosearch)"	

    #'// Set AutoDetectProxySettings Empty 
    $result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoDetect -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - AutoDetect is now: $($result.AutoDetect)"	


    & REG LOAD HKEY_LOCAL_MACHINE\defuser  "C:\Users\Default\NTUSER.DAT"


    #'// Show small icons on taskbar
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name TaskbarSmallIcons -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.TaskbarSmallIcons)"	

    #'// Folderoptions Show file extensions	
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideFileExt is now: $($result.HideFileExt)"	
    
    #'// Folderoptions Show hidden files, show hidden systemfiles file
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name Hidden -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - Hidden is now: $($result.Hidden)"	
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowSuperHidden -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - SuperHidden is now: $($result.ShowSuperHidden)"	

    #'// Folderoptions Always shows Menus
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name AlwaysShowMenus -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - AlwaysShowMenus is now: $($result.AlwaysShowMenus)"	

    #'// Folderoptions Display the full path in the title bar
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name FullPath -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - FullPath is now: $($result.FullPath)"	

    #'// Folderoptions HideMerge Conflicts
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideMergeConflicts -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideMergeConflicts is now: $($result.HideMergeConflicts)"	

    #'// Folderoptions Hide empty drives in the computer folder	
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideDrivesWithNoMedia -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideDrivesWithNoMedia is now: $($result.HideDrivesWithNoMedia)"	

    #'// Folderoptions launch folder windows in separate process
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name SeparateProcess -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - SeparateProcess is now: $($result.SeparateProcess)"	

    #'// Folderoptions Always show icons never thumbnails
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name IconsOnly -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - IconsOnly is now: $($result.IconsOnly)"	

    #'// Dont show tooltip	
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowInfoTip -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - ShowInfoTip is now: $($result.ShowInfoTip)"	

    #'// Show computer on desktop
    $null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' -Force
    $null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.'{20D04FE0-3AEA-1069-A2D8-08002B30309D}')"	

    #'// Always show all taskbar icons and notifcations
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name EnableAutoTray -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - EnableAutoTray is now: $($result.EnableAutoTray)"	

    #'// Set control panel to small icons view 
    $null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Force
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name AllItemsIconView -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - AllItemsIconView is now: $($result.AllItemsIconView)"	
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name StartupPage -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - StartupPage is now: $($result.StartupPage)"	
	
    #'// Disable the Volume Icon in system icons
    $null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' -Force
    $null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name HideSCAVolume -Value 1 -PropertyType DWORD -Force
    Write-Log "$ScriptName - HideSCAVolume is now: $($result.HideSCAVolume)"	

    #'// Disable Search in the address bar and the search box on the new tab page
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Internet Explorer\Main' -Name Autosearch -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - Autosearch is now: $($result.Autosearch)"	

    #'// Set AutoDetectProxySettings Empty 
    $result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoDetect -Value 0 -PropertyType DWORD -Force
    Write-Log "$ScriptName - AutoDetect is now: $($result.AutoDetect)"	

    [gc]::collect()

    Start-Sleep -Seconds 5

    & REG UNLOAD HKEY_LOCAL_MACHINE\defuser
}

Write-Log "$ScriptName - Done!"
