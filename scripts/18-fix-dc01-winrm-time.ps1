#Requires -RunAsAdministrator
# Week 10 (follow-up): close two more week 9 findings on DC01.
# #4 WinRM (5985) on DC01 answered every lab host. It can't just close: WS01 forwards its events to DC01 over WinRM
#    (week 7). So scope it to the domain-member range 10.10.0.11-10.10.0.39; the analysis VM (.40) and anything new are out.
# #6 DC01's clock ran ~43 s behind with no real time source. The PDC emulator is the root of time for the whole domain
#    (Kerberos fails beyond 5 minutes), so point it at LNX01, which runs chrony and syncs from Internet NTP over its NAT NIC.
#    Hyper-V's time integration is turned off inside DC01 so the host doesn't fight NTP (Microsoft's guidance for DCs).
# LDAPS without a certificate (#3) waits for the certificates week.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))
$Members = '10.10.0.11-10.10.0.39'
$Ntp     = '10.10.0.40'

Invoke-Command -VMName DC01 -Credential $dom -ArgumentList $Members, $Ntp -ScriptBlock {
    param($Members, $Ntp)
    '=== #4 WinRM inbound only from domain members ==='
    $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Where-Object { ($_ | Get-NetFirewallPortFilter).LocalPort -contains '5985' }
    $rules | Set-NetFirewallRule -RemoteAddress $Members
    $rules | ForEach-Object { '{0,-45} from {1}' -f $_.DisplayName, (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',') }

    '';'=== #6 PDC emulator takes time from LNX01 ==='
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider' -Name Enabled -Value 0
    w32tm /config /manualpeerlist:"$Ntp,0x8" /syncfromflags:manual /reliable:yes /update | Out-Null
    Restart-Service w32time
    Start-Sleep 5
    w32tm /resync /force | Out-Null
    Start-Sleep 5
    w32tm /query /status | Select-String 'Leap|Stratum|Last Successful|Source'
    '';'Offset against LNX01:'
    w32tm /stripchart /computer:$Ntp /samples:3 /dataonly | Select-Object -Last 3
}
