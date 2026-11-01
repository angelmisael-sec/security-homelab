#Requires -RunAsAdministrator
# Week 8 (follow-up): close the audit gap found while hunting.
# Finding: the week 4 "Advanced audit baseline" GPO was listed as applied by gpresult, but its audit.csv was never processed.
# Root cause: the script wrote audit.csv straight into SYSVOL and never registered the Audit Policy Configuration client-side
# extension ({F3CCC681-...}) in the GPO's gPCMachineExtensionNames, so no machine read the file. 4688 and Kerberos/credential
# failures were silently not logged. (Setting the GPO through the audit UI or auditpol import registers it automatically.)
# Fix: register the extension, bump the GPO version so clients re-read it, put the baseline on the DC OU ahead of the
# Default Domain Controllers Policy, and force subcategory settings to override legacy category settings.
# Proof: a failed Kerberos sign-in for a user that does not exist must now leave event 4768 with status 0x6, and
# `auditpol` on both machines must show Success and Failure.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))

'=== 1) DC01: register the audit extension, bump the GPO version, link on the DC OU ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    $ErrorActionPreference = 'Continue'
    Import-Module GroupPolicy, ActiveDirectory
    $name = 'LAB - Advanced audit baseline'; $ou = 'OU=Domain Controllers,DC=lab,DC=local'
    $g = Get-GPO -Name $name
    $dn = "CN={$($g.Id)},CN=Policies,CN=System,DC=lab,DC=local"
    $cse = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
    $o = Get-ADObject $dn -Properties gPCMachineExtensionNames, versionNumber
    if ($o.gPCMachineExtensionNames -notmatch 'F3CCC681-B74C-4060-9F26-CD84525DCA2A') {
        $ver = $o.versionNumber + 1   # machine version = low 16 bits; this GPO has no user settings
        Set-ADObject $dn -Replace @{ gPCMachineExtensionNames = $o.gPCMachineExtensionNames + $cse; versionNumber = $ver }
        $ini = "C:\Windows\SYSVOL\sysvol\lab.local\Policies\{$($g.Id)}\GPT.INI"
        (Get-Content $ini) -replace '^Version=\d+', "Version=$ver" | Set-Content $ini -Encoding ascii
        "Registered audit extension; GPO version -> $ver"
    } else { 'Audit extension already registered' }
    if (-not (Get-GPInheritance -Target $ou).GpoLinks.Where({ $_.DisplayName -eq $name })) { New-GPLink -Name $name -Target $ou -LinkEnabled Yes -Order 1 | Out-Null }
    else { Set-GPLink -Name $name -Target $ou -Order 1 | Out-Null }
    # "Audit: Force audit policy subcategory settings to override audit policy category settings" = Enabled
    Set-GPRegistryValue -Name $name -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName SCENoApplyLegacyAuditPolicy -Type DWord -Value 1 | Out-Null
    $o = Get-ADObject $dn -Properties gPCMachineExtensionNames
    'Extensions now: ' + $o.gPCMachineExtensionNames
}

'';'=== 2) Apply on both machines and show the effective audit policy ==='
foreach ($vm in 'DC01', 'WS01') {
    "--- $vm ---"
    Invoke-Command -VMName $vm -Credential $dom -ScriptBlock {
        $ErrorActionPreference = 'Continue'
        gpupdate /target:computer /force 2>&1 | Out-Null
        Start-Sleep 5
        auditpol /get '/subcategory:"Logon","Kerberos Authentication Service","Credential Validation","Process Creation"' | Out-String
    }
}

'';'=== 3) WS01: sign in with a user that does not exist (harmless; no lockout possible) ==='
Invoke-Command -VMName WS01 -Credential $dom -ScriptBlock {
    $ErrorActionPreference = 'Continue'
    net use \\dc01.lab.local\IPC$ /user:LAB\hunt.noexiste2 'NotThePassword1!' 2>&1 | Out-Null
}
Start-Sleep 5

'';'=== 4) DC01: the failed Kerberos request must now be logged (4768, status 0x6 = client not found) ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768, 4776; StartTime = (Get-Date).AddMinutes(-3) } -ErrorAction SilentlyContinue | ForEach-Object {
        $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        [pscustomobject]@{ Time = $_.TimeCreated.ToString('HH:mm:ss'); Id = $_.Id; Result = $_.KeywordsDisplayNames[0]; User = $d.TargetUserName; Status = if ($d.Status) { $d.Status } else { $d.ResultCode } }
    } | Where-Object User -like 'hunt*' | Format-Table -AutoSize | Out-String
}
