<#
.SYNOPSIS
  This is a script to hunt and delete WMI components created by WannaMine malware, as they are discovered.  
.DESCRIPTION
  This script will identify and delete the following WMI components used by WannaMine:
	__EventFilters named "DSM Event Log Filter" or "SCM Events Log Filter" 
	__EventConsumers named "DSM Event Log Consumer" or "SCM Events Log Consumer" 
	__FilterToConsumerBindings using filters named "DSM Event Log Filter" or "SCM Events Log Filter"
	Classes named "Win32_Services" or "systemcore_Updater" under the "root\default" namespace
  After removing the WMI components above, it will kill all Powershell processes besides the one that the script is running under (the user is given 5 seconds to cancel this action). 
  It also logs identification, removal, and failures to the Windows Powershell Event Log to allow for centralized tracking of remediation efforts. 
  As the object names associated with WannaMine change, this script will change to adapt to them. 
  
  Changelog:
  1.0: Initial creation
  1.1: Added removal of bad Win32_Services class created under the "root\default" namespace. Thanks to some good people for help here.
  1.2: Added removal of bad systemcore_Updater class created under the "root\default" namespace. 
.OUTPUTS
  Windows Powershell Event Log (these descriptions are generalized; actual logs provide more specific information)
	EventID 4444 - WMI component found on local system 
	EventID 5555 - Successfully removed WMI component from local system
	EventID 9999 - Failed to remove WMI component from local system
.NOTES
  Version:        1.2
  Author:         @nixg_
  Updated:  April 2018
  
.EXAMPLE
  powershell.exe -noexit .\Remove-WannaMineWMI
#>

# Grab WMI components created by WannaMine 
$EventFilter = Get-WmiObject -Namespace "root\subscription" -Class '__EventFilter' | Where-Object {"DSM Event Log Filter","SCM Events Log Filter" -contains $_.Name}
$EventConsumer = Get-WmiObject -Namespace "root\subscription" -Class '__EventConsumer' | Where-Object {"DSM Event Log Consumer","SCM Events Log Consumer" -contains $_.Name}
$FilterToConsumerBinding = Get-WmiObject -Namespace "root\subscription" -Class '__FilterToConsumerBinding' | Where-Object {'__EventFilter.Name="DSM Event Log Filter"','__EventFilter.Name="SCM Events Log Filter"' -contains $_.Filter}
$EvilClass = Get-WmiObject -Namespace "root\default" -List | Where-Object {"Win32_Services","systemcore_Updater" -contains$_.Name}

$computer = $env:computername

$removed = 0

# Function only gets called if the WMI components were found
function remove_component ($WMIComponent) {
	$class = $WMIComponent.__CLASS # for less clutter throughout code
	Write-Host "[+] Found bad WMI component..." -foreground Green
	Write-Host "[i] Component Class: $class" -foreground Yellow
	
	if ($class -eq "__FilterToConsumerBinding") { # conditional because FilterToConsumerBinding has different properties than the EventFilter and EventConsumer
		Write-Host "[i] Filter: " -foreground Yellow -NoNewline; $WMIComponent.Filter
		Write-Host "[i] Consumer: " -foreground Yellow -NoNewline; $WMIComponent.Consumer
		# Write event to Windows Powershell Event Log to allow for centralized tracking of infected/remediated machines
		Write-EventLog -LogName "Windows PowerShell" -Source "Powershell" -EventID 4444 -Message "$class with filter name $WMIComponent.Filter was found on $computer." 
		} else {
		Write-Host "[i] Name: " -foreground Yellow -NoNewline; $WMIComponent.Name
		Write-EventLog -LogName "Windows PowerShell" -Source "Powershell" -EventID 4444 -Message "$class with name $WMIComponent.Name was found on $computer."
		}
		
	Write-Host "[i] Removing bad $class..." -foreground Yellow
	$WMIComponent | Remove-WmiObject 
	Write-Host "[i] Confirming successful removal..." -foreground Yellow
	$StillExists = Get-WmiObject -Namespace "root\subscription" -Class $class | Where-Object {"*DSM Event Log*","*SCM Events Log*" -like $_} # should return nothing now
	if ($StillExists) {
		Write-Host "[-] WARNING: Did not remove $class." -foreground Red
		Write-EventLog -LogName "Windows PowerShell" -Source "Powershell" -EventID 9999 -Message "Failed to remove bad $class from $computer."
		} else {
		Write-Host "[+] Bad $class removed!" -foreground Green
		Write-EventLog -LogName "Windows PowerShell" -Source "Powershell" -EventID 5555 -Message "Bad $class was removed from $computer." 
		$script:removed++
		}
	}
	
if ($EventFilter) {
	remove_component($EventFilter)
	} else {
	Write-Host "[-] Bad EventFilter not found." -foreground Red
	}

if ($EventConsumer) {
	remove_component($EventConsumer)
	} else {
	Write-Host "[-] Bad EventConsumer not found." -foreground Red
	}
	
if ($FilterToConsumerBinding) {
	remove_component($FilterToConsumerBinding)
	} else {
	Write-Host "[-] Bad FilterToConsumerBinding not found." -foreground Red
	}
	
if ($EvilClass) {
	$EvilClass | Remove-WmiObject
	$script:removed++
	Write-EventLog -LogName "Windows PowerShell" -Source "Powershell" -EventID 5555 -Message "Bad WMI class was removed from $computer." 
	} else {
	Write-Host "[-] Bad WMI class not found in namespace 'root\default'." -foreground Red
	}
	
if ($removed -eq 4) {
    Write-Host "[+] Successfully removed all objects." -foreground Green
    Write-Host "[i] Killing all PowerShell processes (except this one) in 5 seconds..." -foreground Yellow
    Write-Host "[i] Press CTRL+C to cancel..." -foreground Yellow
    Start-Sleep 5
    Get-Process Powershell  | Where-Object { $_.ID -ne $pid } | Stop-Process
    }
