#Requires -RunAsAdministrator
# Week 14: install the Wazuh agent on DC01 and WS01 and enroll them with the manager on LNX01 (10.10.0.40, Docker).
# The lab switch has no Internet, so the MSI is downloaded on the host, its Authenticode signature checked,
# and copied in over PowerShell Direct (same pattern as Sysmon in week 7).
# Sysmon collection is not set here: the manager pushes it to every Windows agent through the "default" group (agent.conf).

$Version  = '4.14.10-1'
$Manager  = '10.10.0.40'
$Tools    = 'E:\Lab\tools'
$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
$msi = "$Tools\wazuh-agent-$Version.msi"
if (-not (Test-Path $msi)) { Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version.msi" -OutFile $msi }
$sig = Get-AuthenticodeSignature $msi
"MSI signature: $($sig.Status) ($($sig.SignerCertificate.Subject -replace ',.*'))"
if ($sig.Status -ne 'Valid') { throw 'Wazuh MSI signature is not valid; not installing it' }

$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))

foreach ($vm in 'DC01', 'WS01') {
    "=== $vm ==="
    $s = New-PSSession -VMName $vm -Credential $dom
    Invoke-Command -Session $s { New-Item -ItemType Directory -Force C:\Wazuh | Out-Null }
    Copy-Item $msi -Destination C:\Wazuh\ -ToSession $s -Force
    Invoke-Command -Session $s -ArgumentList $Version, $Manager, $vm {
        param($Version, $Manager, $Name)
        if (-not (Get-Service WazuhSvc -ErrorAction SilentlyContinue)) {
            $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i C:\Wazuh\wazuh-agent-$Version.msi /q WAZUH_MANAGER=$Manager WAZUH_AGENT_NAME=$Name"
            if ($p.ExitCode -ne 0) { throw "msiexec exit code $($p.ExitCode)" }
        }
        Start-Service WazuhSvc
        Start-Sleep 15
        'Service: ' + (Get-Service WazuhSvc).Status
        'Manager connection: ' + ((Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 200) -match 'Connected to the server|Requesting a key|Valid key received' | Select-Object -Last 1)
    }
    Remove-PSSession $s
}
