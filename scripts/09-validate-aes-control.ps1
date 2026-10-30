#Requires -RunAsAdministrator
# Week 5: validates the AES-only Kerberos control from week 4, using only built-in Windows tools.
# From WS01 (already on LabSwitch, domain-joined) a domain user requests a service ticket for the
# test account's SPN; we read which encryption type the KDC issued, and pull the matching 4769 on DC01.
# This is a defensive check: confirm RC4 is gone and the audit trail records the ticket. Nothing is cracked.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$SPN      = 'MSSQLSvc/sql01.lab.local:1433'   # the SPN on the test account svc_sql
$ErrorActionPreference = 'Stop'

function Get-LabCred($name, $user) {
    $line = Get-Content $CredFile | Where-Object { $_ -like "$name *" } | Select-Object -Last 1
    $pass = ($line -split 'password: ')[1].Split(' ')[0]
    [pscredential]::new($user, (ConvertTo-SecureString $pass -AsPlainText -Force))
}
$dom = Get-LabCred 'DC01' 'LAB\Administrator'

'=== Test account current encryption support (DC01) ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    Import-Module ActiveDirectory
    $u = Get-ADUser svc_sql -Properties msDS-SupportedEncryptionTypes, ServicePrincipalName
    $e = $u.'msDS-SupportedEncryptionTypes'
    "svc_sql  SPN: $($u.ServicePrincipalName -join ', ')"
    "svc_sql  msDS-SupportedEncryptionTypes: $(if ($null -eq $e) {'(not set -> KDC default)'} else {'0x{0:x} ({0})' -f $e})"
}

'';'=== Request the service ticket from WS01 and read its encryption type ==='
Invoke-Command -VMName WS01 -Credential $dom -ArgumentList $SPN -ScriptBlock {
    param($spn)
    klist purge | Out-Null
    Add-Type -AssemblyName System.IdentityModel
    $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken($spn)
    # klist prints 'KerbTicket Encryption Type' per cached ticket; show the one for our SPN
    (klist) -join "`n"
}

'';'=== Matching 4769 on DC01 (TicketEncryptionType: 0x12=AES256, 0x17=RC4) ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    Start-Sleep 2
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769; StartTime = (Get-Date).AddMinutes(-5) } -ErrorAction SilentlyContinue |
        ForEach-Object {
            $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            [pscustomobject]@{
                Time = $_.TimeCreated.ToString('HH:mm:ss'); Service = $d.ServiceName
                User = $d.TargetUserName; Enc = $d.TicketEncryptionType; Ip = $d.IpAddress; Status = $d.Status
            }
        } | Where-Object { $_.Service -eq 'svc_sql' } | Select-Object -First 5 |
        Format-Table -AutoSize | Out-String -Width 200
}

'';'=== Harden the service account: pin it to AES only (0x18), so RC4 can never be negotiated ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    Import-Module ActiveDirectory
    Set-ADUser svc_sql -Replace @{ 'msDS-SupportedEncryptionTypes' = 0x18 }
    $e = (Get-ADUser svc_sql -Properties msDS-SupportedEncryptionTypes).'msDS-SupportedEncryptionTypes'
    'svc_sql msDS-SupportedEncryptionTypes now: 0x{0:x} ({0})  [24 = AES only, RC4 excluded]' -f $e
}
