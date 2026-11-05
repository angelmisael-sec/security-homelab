#Requires -RunAsAdministrator
# Week 11: first-response triage for a lab VM, the "Containment + evidence" step of the incident response plan.
# Order of volatility: network connections and processes vanish first, so they are captured BEFORE isolating.
# Isolation = unplug the VM's NICs in Hyper-V (the lab's version of an EDR "isolate host"). PowerShell Direct
# goes through the hypervisor, not the network, so evidence collection keeps working while the VM is cut off.
# Evidence goes to E:\Lab\evidence\<VM>-<UTC time>\ (outside the repo) with SHA-256 hashes for chain of custody.
# Usage:  .\19-ir-triage.ps1 -VM WS01 [-Isolate]      .\19-ir-triage.ps1 -VM WS01 -Reconnect
param([Parameter(Mandatory)][ValidateSet('DC01', 'WS01')][string]$VM, [switch]$Isolate, [switch]$Reconnect)

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))

if ($Reconnect) { Connect-VMNetworkAdapter -VMName $VM -SwitchName LabSwitch; "$VM reconnected to LabSwitch"; return }

$ts  = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
$dir = New-Item -ItemType Directory -Force "E:\Lab\evidence\$VM-$ts"
"Evidence folder: $dir"

'1) Volatile first: connections and processes'
Invoke-Command -VMName $VM -Credential $dom {
    Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
        @{n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } }
} | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | Export-Csv "$dir\01-connections.csv" -NoTypeInformation
Invoke-Command -VMName $VM -Credential $dom {
    Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
} | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | Export-Csv "$dir\02-processes.csv" -NoTypeInformation

if ($Isolate) {
    '2) Isolate: unplug every NIC (PowerShell Direct keeps working)'
    Disconnect-VMNetworkAdapter -VMName $VM
    Get-VMNetworkAdapter -VMName $VM | ForEach-Object { "   NIC $($_.MacAddress): switch = '$($_.SwitchName)'" }
}

'3) Who is on it, what persists, what the logs saw (last 24 h)'
Invoke-Command -VMName $VM -Credential $dom {
    $since = (Get-Date).AddHours(-24)
    @{
        '03-sessions'        = (quser 2>&1) -join "`n"
        '04-local-admins'    = (Get-LocalGroupMember Administrators | Select-Object Name, ObjectClass, PrincipalSource | Out-String)
        '05-scheduled-tasks' = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskPath, TaskName, State, @{n = 'Action'; e = { $_.Actions.Execute }} | Out-String -Width 300)
        '06-sysmon-processes' = (Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $since } -ErrorAction SilentlyContinue |
                                 ForEach-Object { '{0:u}  {1}' -f $_.TimeCreated, (($_.Message -split [Environment]::NewLine) -match '^CommandLine:' -join '') } | Out-String -Width 400)
        '07-logons'          = (Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625; StartTime = $since } -ErrorAction SilentlyContinue |
                                 ForEach-Object { '{0:u}  {1}  user={2}  type={3}  from={4}' -f $_.TimeCreated, $_.Id, $_.Properties[5].Value, $_.Properties[8].Value, $_.Properties[18].Value } | Out-String -Width 300)
    }
} | ForEach-Object { $_.GetEnumerator() | Where-Object Key -like '0*' | ForEach-Object { $_.Value | Set-Content "$dir\$($_.Key).txt" -Encoding utf8 } }

'4) Chain of custody: who collected what, when, and the hash of every file'
"Collected by: $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME`nTarget: $VM`nUTC: $ts`nIsolated: $([bool]$Isolate)" | Set-Content "$dir\00-custody.txt" -Encoding utf8
Get-ChildItem $dir -File | Where-Object Name -ne 'hashes.txt' | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { '{0}  {1}' -f $_.Hash, (Split-Path $_.Path -Leaf) } | Set-Content "$dir\hashes.txt" -Encoding ascii
# Self-check: re-hash and compare, so a silent write failure can't pass as evidence
$bad = Get-Content "$dir\hashes.txt" | Where-Object { $h, $f = $_ -split '  '; (Get-FileHash "$dir\$f" -Algorithm SHA256).Hash -ne $h }
if ($bad) { throw "Hash mismatch: $bad" }
Get-ChildItem $dir -File | Format-Table Name, Length -AutoSize
