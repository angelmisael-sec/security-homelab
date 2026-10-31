#Requires -RunAsAdministrator
# Week 7 (part 1): install Sysmon on DC01 and WS01 with a small, readable config.
# The lab switch is private (no Internet), so Sysmon is downloaded on the host and pushed in over PowerShell Direct.
# Result: a new log, Microsoft-Windows-Sysmon/Operational, with process creation (1), network connections (3),
# DNS queries (22), file creation (11) and process access to lsass (10).

$Tools    = 'E:\Lab\tools'
$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Tools | Out-Null

if (-not (Test-Path "$Tools\Sysmon64.exe")) {
    Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile "$Tools\Sysmon.zip"
    Expand-Archive "$Tools\Sysmon.zip" $Tools -Force
}
'Sysmon version: ' + (Get-Item "$Tools\Sysmon64.exe").VersionInfo.FileVersion
(Get-AuthenticodeSignature "$Tools\Sysmon64.exe").Status   # must be Valid (signed by Microsoft)

@'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>sha256</HashAlgorithms>
  <EventFiltering>
    <!-- 1: every process start, with full command line and parent -->
    <RuleGroup groupRelation="or"><ProcessCreate onmatch="exclude">
      <Image condition="is">C:\Windows\System32\conhost.exe</Image>
      <Image condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</Image>
    </ProcessCreate></RuleGroup>
    <!-- 3: outbound connections from non-system binaries (skip loopback) -->
    <RuleGroup groupRelation="or"><NetworkConnect onmatch="exclude">
      <DestinationIp condition="is">127.0.0.1</DestinationIp>
      <DestinationIp condition="is">::1</DestinationIp>
    </NetworkConnect></RuleGroup>
    <!-- 10: anything opening lsass (where credentials live in memory) -->
    <RuleGroup groupRelation="or"><ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
    </ProcessAccess></RuleGroup>
    <!-- 11: executables and scripts dropped in user-writable places -->
    <RuleGroup groupRelation="or"><FileCreate onmatch="include">
      <TargetFilename condition="contains any">\Temp\;\Downloads\;\AppData\;\Users\Public\</TargetFilename>
    </FileCreate></RuleGroup>
    <!-- 22: DNS lookups, with the process that asked -->
    <RuleGroup groupRelation="or"><DnsQuery onmatch="exclude">
      <QueryName condition="end with">.lab.local</QueryName>
    </DnsQuery></RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Set-Content "$Tools\sysmon-lab.xml" -Encoding ascii

$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))

foreach ($vm in 'DC01', 'WS01') {
    "=== $vm ==="
    $s = New-PSSession -VMName $vm -Credential $dom
    Invoke-Command -Session $s { New-Item -ItemType Directory -Force C:\Sysmon | Out-Null }
    Copy-Item "$Tools\Sysmon64.exe", "$Tools\sysmon-lab.xml" -Destination C:\Sysmon -ToSession $s -Force
    Invoke-Command -Session $s {
        $ErrorActionPreference = 'Continue'   # Sysmon prints progress on stderr; don't treat that as failure
        if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { $null = C:\Sysmon\Sysmon64.exe -c C:\Sysmon\sysmon-lab.xml 2>&1 }   # already installed: just reload config
        else { $null = C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmon-lab.xml 2>&1 }
        'Service: ' + (Get-Service Sysmon64).Status
    }
    Remove-PSSession $s
}

'';'=== Prove it logs: run a harmless command on WS01 and find it in the Sysmon log (event 1) ==='
Invoke-Command -VMName WS01 -Credential $dom -ScriptBlock {
    whoami /groups | Out-Null
    Start-Sleep 2
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 } -MaxEvents 30 |
        ForEach-Object { $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            [pscustomobject]@{ Time = $_.TimeCreated.ToString('HH:mm:ss'); Image = Split-Path $d.Image -Leaf; Parent = Split-Path $d.ParentImage -Leaf; CommandLine = $d.CommandLine } } |
        Where-Object Image -eq 'whoami.exe' | Select-Object -First 2 | Format-List | Out-String
}
