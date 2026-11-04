#Requires -RunAsAdministrator
# Week 10: fix the top findings of the Greenbone scan (run 1) and the week 9 Nmap review, then prove each one.
# 1) WS01 answers RPC (135) and WinRM (5985) to every lab host -> scope those inbound rules to DC01, the admin host.
#    Also stop CDPSvc (5040/tcp), a consumer listener with no use on a corporate workstation.
# 2) TCP timestamps on DC01 + WS01 leak uptime (= when the box was last patched/rebooted) -> disable them.
# 3) NetBIOS over TCP/IP still answers on DC01 (137/udp, 139/tcp); week 4 only killed LLMNR -> disable it on both.
# DC01's own 135 stays open on purpose: domain members need the RPC endpoint mapper. Accepted risk, documented.
# Afterwards run 16-greenbone-scan.sh again on LNX01 (run 2) and compare.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))
$AdminHost = '10.10.0.10'

# Fixes 2 and 3 are the same on both machines
$common = {
    netsh int tcp set global timestamps=disabled | Out-Null
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' |
        Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null   # 2 = disabled
    "$env:COMPUTERNAME  timestamps: " + ((netsh int tcp show global) -match 'Timestamps' -replace '\s+', ' ').Trim()
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' |
        ForEach-Object { "$env:COMPUTERNAME  NetBIOS on $($_.IPAddress[0]): " + @('DHCP default', 'enabled', 'DISABLED')[$_.TcpipNetbiosOptions] }
}

'=== 1) WS01: RPC + WinRM inbound only from the admin host, CDPSvc off ==='
Invoke-Command -VMName WS01 -Credential $dom -ArgumentList $AdminHost -ScriptBlock {
    param($AdminHost)
    $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Where-Object { ($_ | Get-NetFirewallPortFilter).LocalPort | Where-Object { $_ -in '135', 'RPCEPMap', '5985' } }
    $rules | Set-NetFirewallRule -RemoteAddress $AdminHost
    $rules | ForEach-Object { '{0,-45} port {1,-9} from {2}' -f $_.DisplayName, (($_ | Get-NetFirewallPortFilter).LocalPort -join ','), (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',') }
    Stop-Service CDPSvc -Force; Set-Service CDPSvc -StartupType Disabled
    'CDPSvc: ' + (Get-Service CDPSvc).Status + ' / ' + (Get-Service CDPSvc).StartType
}

'';'=== 2+3) DC01 and WS01: TCP timestamps off, NetBIOS over TCP/IP off ==='
Invoke-Command -VMName DC01, WS01 -Credential $dom -ScriptBlock $common | Sort-Object
