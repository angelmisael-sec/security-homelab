#Requires -RunAsAdministrator
# Gives DC01 a static IP and promotes it to the first domain controller of lab.local.
# Runs from the host through PowerShell Direct (no network needed). Passwords live in E:\Lab\credenciales-lab.txt, never in the repo.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'

function Get-LabPassword($name) {
    $line = Get-Content $CredFile | Where-Object { $_ -like "$name *" } | Select-Object -Last 1
    if ($line) { ($line -split 'password: ')[1].Split(' ')[0] }
}
$adminPass = Get-LabPassword 'DC01'
$cred = [pscredential]::new('Administrator', (ConvertTo-SecureString $adminPass -AsPlainText -Force))

# Directory Services Restore Mode password: random, created once
$dsrm = Get-LabPassword 'DSRM'
if (-not $dsrm) {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%*-_'.ToCharArray()
    $dsrm = -join (1..18 | ForEach-Object { $chars | Get-Random })
    Add-Content -Encoding utf8 $CredFile "DSRM  user: (restore mode)  password: $dsrm  (created $(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
}

Invoke-Command -VMName DC01 -Credential $cred -ArgumentList $dsrm -ScriptBlock {
    param($dsrm)
    $ErrorActionPreference = 'Stop'
    # Servers subnet 10.10.0.0/26; .1 is reserved for the future lab router
    $nic = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
    if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress 10.10.0.10 -ErrorAction SilentlyContinue)) {
        Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress 10.10.0.10 -PrefixLength 26 -DefaultGateway 10.10.0.1 | Out-Null
        'Static IP 10.10.0.10/26 set'
    }
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses 127.0.0.1

    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { 'Already a domain controller'; return }
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
    'AD DS role installed, promoting (the VM reboots by itself)...'
    Install-ADDSForest -DomainName 'lab.local' -DomainNetbiosName 'LAB' -InstallDns `
        -SafeModeAdministratorPassword (ConvertTo-SecureString $dsrm -AsPlainText -Force) -Force -WarningAction SilentlyContinue | Out-Null
}
