#Requires -RunAsAdministrator
# Usage: .\05-capture-ws01-dc01.ps1 -Tag w03   (w02 = before the domain join, w03 = after)
param([string]$Tag = 'w02')
# Week 2: captures WS01 <-> DC01 traffic with pktmon (built into Windows, nothing to install in the VM),
# generates DNS / Kerberos / LDAP / SMB on purpose, and copies the .pcapng to the host for Wireshark.
# The capture is NOT committed: it contains Kerberos material that can be cracked offline.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$OutDir   = 'E:\Lab\captures'
$Out      = "$OutDir\$Tag-ws01-dc01.pcapng"
$ErrorActionPreference = 'Stop'

function Get-LabCred($name, $user) {
    $line = Get-Content $CredFile | Where-Object { $_ -like "$name *" } | Select-Object -Last 1
    $pass = ($line -split 'password: ')[1].Split(' ')[0]
    [pscredential]::new($user, (ConvertTo-SecureString $pass -AsPlainText -Force))
}
$ws  = Get-LabCred 'WS01' 'WS01\labadmin'
$dom = Get-LabCred 'DC01' 'LAB\Administrator'

New-Item -ItemType Directory -Force $OutDir | Out-Null
$s = New-PSSession -VMName WS01 -Credential $ws
try {
    Invoke-Command -Session $s -ArgumentList $dom -ScriptBlock {
        param($dom)
        New-Item -ItemType Directory -Force C:\cap | Out-Null
        Remove-Item C:\cap\* -Force -ErrorAction SilentlyContinue
        pktmon filter remove | Out-Null
        pktmon start --capture --comp nics --pkt-size 0 --file-name C:\cap\w02.etl | Out-Null

        try {
            Clear-DnsClientCache
            Resolve-DnsName dc01.lab.local | Out-Null                              # DNS
            Resolve-DnsName _ldap._tcp.dc._msdcs.lab.local -Type SRV | Out-Null    # how clients find a DC
            # LDAP bind as a domain user -> Kerberos AS-REQ/TGS-REQ + LDAP search
            $u = $dom.UserName; $p = $dom.GetNetworkCredential().Password
            $root = New-Object DirectoryServices.DirectoryEntry('LDAP://dc01.lab.local/DC=lab,DC=local', $u, $p)
            "LDAP users found: $((New-Object DirectoryServices.DirectorySearcher($root, '(objectClass=user)')).FindAll().Count)"
            # SMB to SYSVOL; optional, a failure is logged and the capture goes on
            try {
                New-PSDrive -Name S -PSProvider FileSystem -Root \\dc01.lab.local\SYSVOL -Credential $dom -ErrorAction Stop | Out-Null
                Get-ChildItem S:\ -Recurse -Depth 2 | Out-Null; Remove-PSDrive S; 'SMB to SYSVOL: ok'
            } catch { "SMB to SYSVOL failed: $($_.Exception.Message)" }
            ping -n 4 10.10.0.10 | Out-Null                                         # ICMP
        } finally {
            pktmon stop | Out-Null
            pktmon etl2pcap C:\cap\w02.etl --out C:\cap\w02.pcapng | Out-Null
        }
    }
    Copy-Item -FromSession $s C:\cap\w02.pcapng -Destination $Out -Force
    "Capture saved: $Out ($([math]::Round((Get-Item $Out).Length/1KB)) KB)"
} finally { Remove-PSSession $s }

# Protocol summary, so we know the capture has what the lesson needs
$tshark = 'C:\Program Files\Wireshark\tshark.exe'
if (Test-Path $tshark) {
    foreach ($p in 'dns', 'kerberos', 'ldap', 'smb2', 'icmp') {
        $n = (& $tshark -r $Out -Y $p 2>$null | Measure-Object).Count
        "{0,-9} {1} packets" -f $p, $n
    }
}
