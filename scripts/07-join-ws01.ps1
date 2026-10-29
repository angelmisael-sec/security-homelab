#Requires -RunAsAdministrator
# Week 3: joins WS01 to lab.local (it lands in OU=Workstations thanks to redircmp in script 06),
# waits for the reboot and checks the secure channel with the DC.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'

function Get-LabCred($name, $user) {
    $line = Get-Content $CredFile | Where-Object { $_ -like "$name *" } | Select-Object -Last 1
    $pass = ($line -split 'password: ')[1].Split(' ')[0]
    [pscredential]::new($user, (ConvertTo-SecureString $pass -AsPlainText -Force))
}
$ws  = Get-LabCred 'WS01' 'WS01\labadmin'
$dom = Get-LabCred 'DC01' 'LAB\Administrator'

$joined = Invoke-Command -VMName WS01 -Credential $ws -ScriptBlock { (Get-CimInstance Win32_ComputerSystem).PartOfDomain }
if ($joined) { 'WS01 is already domain-joined' }
else {
    Invoke-Command -VMName WS01 -Credential $ws -ArgumentList $dom -ScriptBlock {
        param($dom)
        Add-Computer -DomainName lab.local -Credential $dom -Force
    }
    'Joined, rebooting WS01...'
    Restart-VM WS01 -Force -Wait -For Heartbeat
}

# PS Direct answers before the logon service is ready, so retry for up to 5 minutes
$deadline = (Get-Date).AddMinutes(5)
while ($true) {
    try {
        Invoke-Command -VMName WS01 -Credential $dom -ErrorAction Stop -ScriptBlock {
            $cs = Get-CimInstance Win32_ComputerSystem
            "Domain: $($cs.Domain)  PartOfDomain: $($cs.PartOfDomain)"
            "Secure channel with DC: $(Test-ComputerSecureChannel)"
            nltest /dsgetdc:lab.local | Select-String 'DC:|Address:|Flags:'
        }
        break
    } catch {
        if ((Get-Date) -gt $deadline) { throw }
        Start-Sleep 10
    }
}

Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    Get-ADComputer WS01 | Select-Object Name, DistinguishedName, Enabled | Format-List | Out-String
}
