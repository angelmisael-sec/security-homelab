#Requires -RunAsAdministrator
# Week 6: Windows LAPS (built into Server 2025 / Win11 24H2, nothing to install).
# Each workstation gets its own local-admin password, rotated automatically and stored encrypted in AD.
# Steps: extend the AD schema, let computers write their own password, push the policy by GPO,
# force WS01 to apply it, then read the password back from AD as LAB\Administrator.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'

function Get-LabPassword($name) {
    $line = Get-Content $CredFile | Where-Object { $_ -like "$name *" } | Select-Object -Last 1
    if ($line) { ($line -split 'password: ')[1].Split(' ')[0] }
}
$dom = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (Get-LabPassword 'DC01') -AsPlainText -Force))

'=== 1) Extend the AD schema for LAPS + let workstations store their own password ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    Import-Module LAPS
    Update-LapsADSchema -Confirm:$false | Out-Null          # idempotent; adds the LAPS attributes to AD
    $ou = 'OU=Workstations,OU=LAB,DC=lab,DC=local'
    Set-LapsADComputerSelfPermission -Identity $ou | Out-Null   # computers can write (not read) their own password
    "Schema updated; self-write permission granted on $ou"
}

'';'=== 2) GPO that tells workstations to back up the local-admin password to AD ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    Import-Module GroupPolicy
    $name = 'LAB - Windows LAPS'
    $ou   = 'OU=Workstations,OU=LAB,DC=lab,DC=local'
    if (-not (Get-GPO -Name $name -ErrorAction SilentlyContinue)) { New-GPO -Name $name | Out-Null }
    if (-not (Get-GPInheritance -Target $ou).GpoLinks.Where({ $_.DisplayName -eq $name })) {
        New-GPLink -Name $name -Target $ou -LinkEnabled Yes | Out-Null
    }
    $key = 'HKLM\Software\Microsoft\Policies\LAPS'
    Set-GPRegistryValue -Name $name -Key $key -ValueName BackupDirectory         -Type DWord  -Value 2  | Out-Null  # 2 = Active Directory
    Set-GPRegistryValue -Name $name -Key $key -ValueName AdministratorAccountName -Type String -Value 'labadmin' | Out-Null  # the local account LAPS manages
    Set-GPRegistryValue -Name $name -Key $key -ValueName PasswordLength           -Type DWord  -Value 20 | Out-Null
    Set-GPRegistryValue -Name $name -Key $key -ValueName PasswordComplexity       -Type DWord  -Value 4  | Out-Null  # 4 = upper+lower+digits+symbols
    Set-GPRegistryValue -Name $name -Key $key -ValueName PasswordAgeDays          -Type DWord  -Value 30 | Out-Null
    'GPO "LAB - Windows LAPS" linked on Workstations OU (AD backup, account labadmin, 20 chars, 30-day rotation)'
}

'';'=== 3) Force WS01 to apply the policy now and rotate its password ==='
Invoke-Command -VMName WS01 -Credential $dom -ScriptBlock {
    gpupdate /target:computer /force | Out-Null
    Import-Module LAPS
    Invoke-LapsPolicyProcessing          # makes LAPS act immediately instead of waiting for the cycle
    'WS01 processed the LAPS policy'
}

'';'=== 4) Read the stored password back from AD (as LAB\Administrator) ==='
Invoke-Command -VMName DC01 -Credential $dom -ScriptBlock {
    Import-Module LAPS
    $p = Get-LapsADPassword -Identity WS01 -AsPlainText
    # The point of LAPS is that an authorized admin CAN retrieve it. We don't print the value here;
    # confirm it exists and show metadata. Retrieve it on demand with:  Get-LapsADPassword -Identity WS01 -AsPlainText
    [pscustomobject]@{
        Computer        = 'WS01'
        ManagedAccount  = $p.Account
        PasswordLength  = $p.Password.Length
        LastRotated     = $p.PasswordUpdateTime
        ExpiresNext     = $p.ExpirationTimestamp
    } | Format-List | Out-String
}
