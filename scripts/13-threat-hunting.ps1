#Requires -RunAsAdministrator
# Week 8: threat hunting over the centralized logs. Defensive goal: prove the telemetry from week 7 is enough to
# spot four classic suspicious patterns, and keep the queries as reusable detections.
# Method: WS01 produces harmless "look-alike" activity (every command only runs whoami / writes a text line / resolves a name),
# then DC01 is searched. If a hunt returns nothing, the logging has a gap - that is the finding.
# Queries filter by event ID and time first: an unfiltered scan of ForwardedEvents crashed the EventLog service on a 4 GB DC01.
param([switch]$HuntOnly, [int]$Minutes = 120)   # -HuntOnly: skip generating activity, just search what is already logged

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))

if (-not $HuntOnly) {
    '=== 1) WS01: generate harmless look-alike activity ==='
    Invoke-Command -VMName WS01 -Credential $dom -ScriptBlock {
        $ErrorActionPreference = 'Continue'
        # a) PowerShell started with an encoded command (hides the text from a casual glance; the payload here is just "whoami")
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
        powershell.exe -NoProfile -EncodedCommand $enc | Out-Null
        # b) a script file written to a user-writable temp folder
        Set-Content "$env:TEMP\hunt-test.ps1" 'whoami'
        # c) a lookup of a name that does not exist (stand-in for beaconing to an unknown domain)
        Resolve-DnsName 'updates.hunt-test.invalid' -ErrorAction SilentlyContinue | Out-Null
        # d) six failed sign-ins for an account that does not exist (no lockout risk; looks like password guessing)
        1..6 | ForEach-Object { net use \\dc01.lab.local\IPC$ /user:LAB\hunt.noexiste 'NotThePassword1!' 2>&1 | Out-Null }
        'activity generated'
    }
    'waiting 40 s for forwarding...'; Start-Sleep 40
}

'';"=== 2) DC01: the hunts (last $Minutes minutes) ==="
Invoke-Command -VMName DC01 -Credential $dom -ArgumentList $Minutes -ScriptBlock {
    param($Minutes)
    $ErrorActionPreference = 'Continue'
    $since = (Get-Date).AddMinutes(-$Minutes)
    # Turn an event into a flat object (EventData name -> value) so queries read like SQL
    function ConvertTo-Flat($e) {
        $x = [xml]$e.ToXml(); $d = [ordered]@{ Time = $e.TimeCreated.ToString('HH:mm:ss'); Id = $e.Id; Host = ($e.MachineName -split '\.')[0] }
        foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
        [pscustomobject]$d
    }
    # Do NOT filter ForwardedEvents by Id/time in the query: that hung and then crashed the EventLog service here (RPC unavailable).
    # Reading newest-first without a filter is fast, so filtering happens client-side. The local Security log filters fine.
    function Get-Flat($log, $ids) {
        if ($log -eq 'ForwardedEvents') { Get-WinEvent -LogName $log -MaxEvents 2500 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in $ids -and $_.TimeCreated -ge $since } | ForEach-Object { ConvertTo-Flat $_ } }
        else { Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = $since } -MaxEvents 400 -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-Flat $_ } }
    }

    '';'--- H1 Encoded PowerShell (T1059.001 / T1027): process start whose command line has -EncodedCommand ---'
    Get-Flat ForwardedEvents 1, 4688 | Where-Object { $_.CommandLine -match '(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{8,}' } |
        Select-Object Time, Id, Host, @{ n = 'Parent'; e = { Split-Path $_.ParentImage -Leaf } }, CommandLine | Format-List | Out-String

    '--- H2 Scripts/executables dropped in user-writable folders (Sysmon 11), noise from PowerShell itself removed ---'
    Get-Flat ForwardedEvents 11 | Where-Object { $_.TargetFilename -match '(?i)\\(Temp|Downloads|Public)\\.*\.(ps1|exe|dll|bat|js|vbs)$' -and $_.TargetFilename -notmatch '__PSScriptPolicyTest' } |
        Select-Object Time, Host, @{ n = 'Image'; e = { Split-Path $_.Image -Leaf } }, TargetFilename | Format-Table -AutoSize -Wrap | Out-String

    '--- H3 Password-guessing shape: 3+ failed sign-ins (4625) for one account, network type 3 (DC01 Security log) ---'
    # Threshold lesson: the test sent 6 attempts but only 3 were logged ~45 s apart (client retry delay); a threshold of 5 missed it
    Get-Flat Security 4625 | Where-Object LogonType -eq '3' | Group-Object TargetUserName |
        Where-Object Count -ge 3 | Select-Object Count, Name, @{ n = 'From'; e = { ($_.Group.IpAddress | Sort-Object -Unique) -join ',' } }, @{ n = 'First'; e = { $_.Group[-1].Time } }, @{ n = 'Last'; e = { $_.Group[0].Time } } |
        Format-Table -AutoSize | Out-String

    '--- H4 DNS lookups outside the lab domain, with the process that asked (Sysmon 22) ---'
    Get-Flat ForwardedEvents 22 | Where-Object { $_.QueryName -notmatch '(?i)(\.lab\.local|microsoft|windows|msftncsi)' } |
        Select-Object Time, Host, @{ n = 'Image'; e = { Split-Path $_.Image -Leaf } }, QueryName, QueryStatus | Format-Table -AutoSize | Out-String
}
