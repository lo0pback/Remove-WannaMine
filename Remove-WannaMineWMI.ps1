<#
.SYNOPSIS
  This is a script to hunt and delete WMI components created by the WannaMine malware during the February 2018 campaign. 
.DESCRIPTION
  This script will identify and delete the following WMI components used by WannaMinie in February 2018:
	__EventFilters named "DSM Event Log Filter" 
	__EventConsumers named "DSM Event Log Consumer"
	__FilterToConsumerBindings using filters named "DSM Event Log Filter"
  After removing the WMI components above, it will kill all Powershell processes besides the one that the script is running under (the user is given 5 seconds to cancel this action). 
  It also logs identification, removal, and failures to the Windows Powershell Event Log to allow for centralized tracking of remediation efforts. 
  As the TTPs associated with WannaMine change, this script will change to adapt to them. 
.OUTPUTS
  Windows Powershell Event Log (these descriptions are generalized; actual logs provide more specific information)
	EventID 4444 - WMI component found on local system 
	EventID 5555 - Successfully removed WMI component from local system
	EventID 9999 - Failed to remove WMI component from local system
.NOTES
  Version:        1.0
  Author:         @nixg_
  Creation Date:  February 2018
  Purpose/Change: Initial script development
  
.EXAMPLE
  powershell.exe -noexit .\Remove-WannaMineWMI
#>

# Grab WMI components created by WannaMine 
$EventFilter = Get-WmiObject -Namespace "root\subscription" -Class '__EventFilter' | Where-Object {$_.Name -eq "DSM Event Log Filter"}
$EventConsumer = Get-WmiObject -Namespace "root\subscription" -Class '__EventConsumer' | Where-Object {$_.Name -eq "DSM Event Log Consumer"}
$FilterToConsumerBinding = Get-WmiObject -Namespace "root\subscription" -Class '__FilterToConsumerBinding' | Where-Object {$_.Filter -eq '__EventFilter.Name="DSM Event Log Filter"'}

$computer = $env:computername

$removed = 0

# Function only gets called if the WMI components were found
function remove_and_log ($WMIComponent) {
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
	$StillExists = Get-WmiObject -Namespace "root\subscription" -Class $class | Where-Object {$_ -like "*DSM Event Log*"} # should return nothing now
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
	remove_and_log($EventFilter)
	} else {
	Write-Host "[-] Bad EventFilter not found." -foreground Red
	}

if ($EventConsumer) {
	remove_and_log($EventConsumer)
	} else {
	Write-Host "[-] Bad EventConsumer not found." -foreground Red
	}
	
if ($FilterToConsumerBinding) {
	remove_and_log($FilterToConsumerBinding)
	} else {
	Write-Host "[-] Bad FilterToConsumerBinding not found." -foreground Red
	}
	
if ($removed -eq 3) {
    Write-Host "[+] Successfully removed all objects." -foreground Green
    Write-Host "[i] Killing all PowerShell processes (except this one) in 5 seconds..." -foreground Yellow
    Write-Host "[i] Press CTRL+C to cancel..." -foreground Yellow
    Start-Sleep 5
    Get-Process Powershell  | Where-Object { $_.ID -ne $pid } | Stop-Process
    }