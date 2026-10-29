#Requires -RunAsAdministrator
# Week 3: builds a small company inside lab.local (OUs, groups, users, one service account).
# Idempotent: re-running skips what already exists. Passwords go to E:\Lab\credenciales-lab.txt, never to the repo.

$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'

function Get-LabPassword($name) {
    $line = Get-Content $CredFile | Where-Object { $_ -like "$name *" } | Select-Object -Last 1
    if ($line) { ($line -split 'password: ')[1].Split(' ')[0] }
}
$cred = [pscredential]::new('LAB\Administrator', (ConvertTo-SecureString (Get-LabPassword 'DC01') -AsPlainText -Force))

# sam, given name, surname, department OU-group, extra group
$people = @(
    @('ana.rivera',    'Ana',    'Rivera', 'Finance',  $null),
    @('carlos.ortiz',  'Carlos', 'Ortiz',  'Helpdesk', $null),
    @('maria.santos',  'Maria',  'Santos', 'HR',       $null),
    @('jose.cruz',     'Jose',   'Cruz',   'Sales',    $null),
    # Separate admin account: daily work as a normal user, admin rights only on adm.* (tiering)
    @('adm.angel',     'Angel',  'Admin',  'Admins',   'Domain Admins')
)
$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%*-_'.ToCharArray()
foreach ($p in $people) {
    if (-not (Get-LabPassword $p[0])) {
        $pw = -join (1..18 | ForEach-Object { $chars | Get-Random })
        Add-Content -Encoding utf8 $CredFile "$($p[0])  user: LAB\$($p[0])  password: $pw  (created $(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
    }
}
# Deliberately weak, from a common wordlist: target for the Kerberoasting exercise in Phase 2
if (-not (Get-LabPassword 'svc_sql')) {
    Add-Content -Encoding utf8 $CredFile "svc_sql  user: LAB\svc_sql  password: Summer2026!  (WEAK ON PURPOSE, created $(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
}
$pwds = @{}; foreach ($n in ($people | ForEach-Object { $_[0] }) + 'svc_sql') { $pwds[$n] = Get-LabPassword $n }

Invoke-Command -VMName DC01 -Credential $cred -ArgumentList $people, $pwds -ScriptBlock {
    param($people, $pwds)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory
    $root = 'DC=lab,DC=local'
    $base = "OU=LAB,$root"

    function Ensure-OU($name, $path) {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$name'" -SearchBase $path -SearchScope OneLevel)) {
            New-ADOrganizationalUnit -Name $name -Path $path   # protected from accidental deletion by default
            "OU created: $name"
        }
    }
    Ensure-OU 'LAB' $root
    foreach ($ou in 'Admins', 'Staff', 'Groups', 'ServiceAccounts', 'Workstations', 'Servers') { Ensure-OU $ou $base }

    foreach ($g in 'Finance', 'Helpdesk', 'HR', 'Sales') {
        if (-not (Get-ADGroup -Filter "Name -eq 'GG-$g'")) {
            New-ADGroup -Name "GG-$g" -GroupScope Global -GroupCategory Security -Path "OU=Groups,$base"
            "Group created: GG-$g"
        }
    }

    foreach ($p in $people) {
        $sam, $given, $sur, $dept, $extra = $p
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'")) {
            $ou = if ($dept -eq 'Admins') { "OU=Admins,$base" } else { "OU=Staff,$base" }
            New-ADUser -SamAccountName $sam -UserPrincipalName "$sam@lab.local" -Name "$given $sur" `
                -GivenName $given -Surname $sur -Department $dept -Path $ou -Enabled $true `
                -AccountPassword (ConvertTo-SecureString $pwds[$sam] -AsPlainText -Force)
            "User created: $sam"
        }
        if ($dept -ne 'Admins') { Add-ADGroupMember "GG-$dept" -Members $sam }
        if ($extra) { Add-ADGroupMember $extra -Members $sam }
    }

    if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'")) {
        New-ADUser -SamAccountName svc_sql -UserPrincipalName 'svc_sql@lab.local' -Name 'SQL Service' `
            -Path "OU=ServiceAccounts,$base" -Enabled $true -PasswordNeverExpires $true `
            -ServicePrincipalNames 'MSSQLSvc/sql01.lab.local:1433' `
            -AccountPassword (ConvertTo-SecureString $pwds['svc_sql'] -AsPlainText -Force)
        'Service account created: svc_sql (SPN MSSQLSvc/sql01.lab.local:1433)'
    }

    # New computers land in OU=Workstations instead of the default CN=Computers (GPOs cannot link to containers)
    redircmp "OU=Workstations,$base" | Out-Null

    Get-ADUser -Filter * -SearchBase $base -Properties Department, MemberOf, ServicePrincipalName |
        Select-Object SamAccountName, Department,
            @{n = 'Groups'; e = { ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', ' } },
            @{n = 'SPN'; e = { $_.ServicePrincipalName -join ', ' } } |
        Format-Table -AutoSize | Out-String -Width 200
}
