#Requires -RunAsAdministrator
# Week 4: baseline hardening of lab.local through Group Policy. Idempotent: creates each GPO if missing,
# then (re)writes its settings and links it. All changes are undone by deleting the GPO.
# Runs from the host via PowerShell Direct, as LAB\Administrator.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'

function Get-LabPassword($name) {
    $line = Get-Content $CredFile | Where-Object { $_ -like "$name *" } | Select-Object -Last 1
    if ($line) { ($line -split 'password: ')[1].Split(' ')[0] }
}
$cred = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (Get-LabPassword 'DC01') -AsPlainText -Force))

Invoke-Command -VMName DC01 -Credential $cred -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    Import-Module GroupPolicy, ActiveDirectory
    $root = 'DC=lab,DC=local'

    function Ensure-GPO($name, $link) {
        $g = Get-GPO -Name $name -ErrorAction SilentlyContinue
        if (-not $g) { $g = New-GPO -Name $name; "GPO created: $name" }
        if (-not (Get-GPInheritance -Target $link).GpoLinks.Where({ $_.DisplayName -eq $name })) {
            New-GPLink -Name $name -Target $link -LinkEnabled Yes | Out-Null
        }
        $g
    }
    function Reg($gpo, $key, $value, $type, $data) {
        Set-GPRegistryValue -Name $gpo -Key $key -ValueName $value -Type $type -Value $data | Out-Null
    }

    # 1) Password + lockout policy (default domain policy; NIST-style: length over forced rotation)
    Set-ADDefaultDomainPasswordPolicy -Identity lab.local `
        -MinPasswordLength 14 -PasswordHistoryCount 24 -ComplexityEnabled $true `
        -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 15) -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
        -MinPasswordAge (New-TimeSpan -Days 1) -MaxPasswordAge (New-TimeSpan -Days 365)
    'Password/lockout policy set (14 chars, 5 tries, 15 min lockout)'

    # 2) Kerberos: AES only, kill RC4 (the Kerberoasting weak spot). 0x18 = AES128 + AES256.
    $h = Ensure-GPO 'LAB - Kerberos AES only' $root
    Reg $h.DisplayName 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
        'SupportedEncryptionTypes' DWord 0x18
    'RC4 disabled, AES enforced for Kerberos'

    # 3) Kill LLMNR + NetBIOS name resolution (classic spoofing/relay vector)
    $h = Ensure-GPO 'LAB - Disable legacy name resolution' $root
    Reg $h.DisplayName 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' DWord 0   # LLMNR off
    'LLMNR disabled via GPO'

    # 4) SMB: require signing on client and server (blocks NTLM-over-SMB relay)
    $h = Ensure-GPO 'LAB - SMB signing required' $root
    Reg $h.DisplayName 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'RequireSecuritySignature' DWord 1
    Reg $h.DisplayName 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' DWord 1
    'SMB signing required (client + server)'

    # 5) Advanced audit policy: the events a SIEM actually needs (logons, Kerberos, process creation)
    $h = Ensure-GPO 'LAB - Advanced audit baseline' $root
    $audit = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,,1
,System,Kerberos Authentication Service,{0cce9242-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Kerberos Service Ticket Operations,{0cce9240-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1
,System,Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success and Failure,,3
'@
    $sysvol = "C:\Windows\SYSVOL\sysvol\lab.local\Policies\{$($h.Id)}\Machine\Microsoft\Windows NT\Audit"
    New-Item -ItemType Directory -Force $sysvol | Out-Null
    $audit | Out-File -Encoding ascii "$sysvol\audit.csv"
    # also turn on command-line logging in 4688 (huge for threat hunting)
    Reg $h.DisplayName 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' DWord 1
    'Advanced audit baseline + command-line logging in 4688'

    gpupdate /force | Out-Null
    ''
    'Linked GPOs on the domain root:'
    (Get-GPInheritance -Target $root).GpoLinks | Select-Object DisplayName, Enabled | Format-Table -AutoSize | Out-String
    'Effective encryption types (should be 0x18 = 24):'
    (Get-GPRegistryValue -Name 'LAB - Kerberos AES only' -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -ValueName SupportedEncryptionTypes).Value
}
