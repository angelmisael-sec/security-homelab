#Requires -RunAsAdministrator
# Week 7 (part 2): Windows Event Forwarding. DC01 is the collector; workstations push their events to it
# (source-initiated, so no per-machine setup on DC01). One place to search: the ForwardedEvents log.
# Forwarded: all Sysmon events + Security 4624/4625 (logons), 4688 (process start), 4768/4769 (Kerberos), 4720/4732 (account/group changes).

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'
$line = Get-Content $CredFile | Where-Object { $_ -like 'DC01 *' } | Select-Object -Last 1
$dom  = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (($line -split 'password: ')[1].Split(' ')[0]) -AsPlainText -Force))

'=== 1) DC01: turn on the collector service and create the subscription ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    $ErrorActionPreference = 'Continue'
    winrm quickconfig -q 2>&1 | Out-Null
    wecutil qc /q 2>&1 | Out-Null
    $ErrorActionPreference = 'Stop'
    $xml = @'
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>LabForward</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Sysmon + key Security events from lab workstations</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>MinLatency</ConfigurationMode>
  <Delivery Mode="Push"><Batching><MaxItems>1</MaxItems><MaxLatencyTime>1000</MaxLatencyTime></Batching><PushSettings><Heartbeat Interval="60000"/></PushSettings></Delivery>
  <Query><![CDATA[<QueryList><Query Id="0">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
    <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4768 or EventID=4769 or EventID=4720 or EventID=4732)]]</Select>
  </Query></QueryList>]]></Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)S:</AllowedSourceDomainComputers>
</Subscription>
'@
    $f = 'C:\Sysmon\lab-subscription.xml'
    $xml | Set-Content $f -Encoding utf8
    $ErrorActionPreference = 'Continue'
    wecutil ds LabForward 2>&1 | Out-Null     # recreate cleanly so reruns are idempotent (error 0x2 = didn't exist yet)
    wecutil cs $f 2>&1 | Out-Null             # prints a harmless warning on stderr (MinLatency ignores delivery settings)
    $ErrorActionPreference = 'Stop'
    'Subscriptions: ' + ((wecutil es) -join ', ')

    # GPO: tell workstations where the collector is (Refresh = how often, in seconds, they re-check)
    Import-Module GroupPolicy
    $name = 'LAB - Event forwarding'; $ou = 'OU=Workstations,OU=LAB,DC=lab,DC=local'
    if (-not (Get-GPO -Name $name -ErrorAction SilentlyContinue)) { New-GPO -Name $name | Out-Null }
    if (-not (Get-GPInheritance -Target $ou).GpoLinks.Where({ $_.DisplayName -eq $name })) { New-GPLink -Name $name -Target $ou -LinkEnabled Yes | Out-Null }
    Set-GPRegistryValue -Name $name -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' `
        -ValueName 1 -Type String -Value 'Server=http://dc01.lab.local:5985/wsman/SubscriptionManager/WEC,Refresh=60' | Out-Null
    'GPO "LAB - Event forwarding" linked on Workstations'
}

'';'=== 2) WS01: apply policy, start WinRM, let the forwarder read the Security log ==='
Invoke-Command -VMName WS01 -Credential $dom -ScriptBlock {
    $ErrorActionPreference = 'Continue'
    gpupdate /target:computer /force 2>&1 | Out-Null
    winrm quickconfig -q 2>&1 | Out-Null
    Set-Service WinRM -StartupType Automatic; Start-Service WinRM
    Add-LocalGroupMember -Group 'Event Log Readers' -Member 'NT AUTHORITY\NETWORK SERVICE' -ErrorAction SilentlyContinue   # forwarder runs as Network Service
    # The Sysmon channel has its own ACL that excludes Network Service; append read access (A;;0x1;;;NS) to its SDDL
    $sddl = ((wevtutil gl Microsoft-Windows-Sysmon/Operational) | Select-String 'channelAccess:').ToString().Split(':', 2)[1].Trim()
    if ($sddl -notmatch ';NS\)') { wevtutil sl Microsoft-Windows-Sysmon/Operational "/ca:$sddl(A;;0x1;;;NS)" }
    Restart-Service WinRM
    'WinRM: ' + (Get-Service WinRM).Status
    'Manager: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager').1
}

Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock { $ErrorActionPreference = 'Continue'; wecutil rs LabForward 2>&1 | Out-Null }   # retry: the first attempt gave up before WS01 had access

'';'=== 3) Generate events on WS01 and wait for them to appear on DC01 (up to 4 min) ==='
Invoke-Command -VMName WS01 -Credential $dom -ScriptBlock { hostname | Out-Null; ipconfig /all | Out-Null; nltest /dsgetdc:lab.local | Out-Null }
$found = $null
for ($i = 0; $i -lt 16 -and -not $found; $i++) {
    Start-Sleep 15
    $found = Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
        Get-WinEvent -LogName ForwardedEvents -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object { $_.MachineName -like 'WS01*' } |
            Group-Object Id | Sort-Object Count -Descending | Select-Object -First 6 Name, Count | Format-Table -AutoSize | Out-String
    }
}
if ($found) { 'ForwardedEvents on DC01, coming from WS01 (event ID, count):'; $found } else { 'Nothing arrived yet - check WinRM/GPO' }
