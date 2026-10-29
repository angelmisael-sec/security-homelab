#Requires -RunAsAdministrator
# Builds WS01 (Windows 11 Pro workstation) end to end: VM with vTPM, DISM image apply + unattend,
# first boot, then static IP and DNS pointing at DC01 through PowerShell Direct.
# Same technique as 01/02 for DC01. Password goes to E:\Lab\credenciales-lab.txt, never the repo.

$VMName   = 'WS01'
$VMPath   = 'E:\Lab\VMs'
$VHD      = "$VMPath\$VMName\$VMName.vhdx"
$ISO      = 'F:\14 ISOs y Sistemas\Win11_24H2_EnglishInternational_x64.iso'
$CredFile = 'E:\Lab\credenciales-lab.txt'
$IP       = '10.10.0.30'   # servers /26 for now; moves to clients /26 once the lab router exists
$ErrorActionPreference = 'Stop'

# 1. VM: Gen 2, Secure Boot, vTPM, on the private lab switch
if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue)) {
    New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 4GB -Path $VMPath `
           -NewVHDPath $VHD -NewVHDSizeBytes 64GB -SwitchName 'LabSwitch' | Out-Null
    Set-VM -Name $VMName -ProcessorCount 2 -StaticMemory -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $VMName -SecureBootTemplate MicrosoftWindows
    try { Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector; Enable-VMTPM -VMName $VMName; 'vTPM enabled' }
    catch { "vTPM not enabled: $($_.Exception.Message)" }
    "VM $VMName created"
}

# 2. Apply Windows 11 Pro into the empty disk (guard: never overwrite an installed OS)
if ((Get-Item $VHD).Length -lt 100MB) {
    $free = [char[]]('PQRSTUVWXYZ') | Where-Object { -not (Test-Path "${_}:\") }
    $S, $W = $free[0], $free[1]
    @"
select vdisk file="$VHD"
attach vdisk
convert gpt
create partition efi size=260
format quick fs=fat32 label=System
assign letter=$S
create partition msr size=16
create partition primary
format quick fs=ntfs label=Windows
assign letter=$W
"@ | Set-Content -Encoding ascii "$env:TEMP\ws01-part.txt"
    diskpart /s "$env:TEMP\ws01-part.txt" | Out-Null
    if (-not (Test-Path "${W}:\")) { throw 'Partitioning failed' }
    try {
        $isoVol = Mount-DiskImage -ImagePath $ISO -PassThru | Get-Volume
        $wim = Get-ChildItem "$($isoVol.DriveLetter):\sources\install.*" | Where-Object Extension -in '.wim', '.esd' | Select-Object -First 1
        $img = Get-WindowsImage -ImagePath $wim.FullName | Where-Object ImageName -eq 'Windows 11 Pro'
        "Applying: $($img.ImageName) (index $($img.ImageIndex))"
        Expand-WindowsImage -ImagePath $wim.FullName -Index $img.ImageIndex -ApplyPath "${W}:\" | Out-Null
        bcdboot "${W}:\Windows" /s "${S}:" /f UEFI | Out-Null

        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%*-_'.ToCharArray()
        $pass = -join (1..18 | ForEach-Object { $chars | Get-Random })
        $sh = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"'
        $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" $sh>
      <ComputerName>$VMName</ComputerName>
      <TimeZone>SA Western Standard Time</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" $sh>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" $sh>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>labadmin</Name><Group>Administrators</Group>
            <Password><Value>$pass</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
    </component>
  </settings>
</unattend>
"@
        New-Item -ItemType Directory -Force "${W}:\Windows\Panther" | Out-Null
        Set-Content -Encoding utf8 "${W}:\Windows\Panther\unattend.xml" $xml
        Add-Content -Encoding utf8 $CredFile "WS01  user: labadmin  password: $pass  (created $(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
        "Password saved to $CredFile"
    }
    finally {
        Dismount-DiskImage -ImagePath $ISO | Out-Null
        "select vdisk file=`"$VHD`"`ndetach vdisk" | Set-Content -Encoding ascii "$env:TEMP\ws01-detach.txt"
        diskpart /s "$env:TEMP\ws01-detach.txt" | Out-Null
    }
    Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName)
}

# 3. First boot, wait for login through PowerShell Direct
if ((Get-VM $VMName).State -ne 'Running') { Start-VM -Name $VMName }
$line = Get-Content $CredFile | Where-Object { $_ -like "$VMName *" } | Select-Object -Last 1
$pass = ($line -split 'password: ')[1].Split(' ')[0]
$cred = [pscredential]::new("$VMName\labadmin", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddMinutes(12)
while ($true) {
    try { Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop -ScriptBlock { 1 } | Out-Null; break }
    catch { if ((Get-Date) -gt $deadline) { throw "WS01 did not accept login in time: $($_.Exception.Message)" }; Start-Sleep 20 }
}

# 4. Network: static IP, DNS = DC01, then prove it can reach the domain
Invoke-Command -VMName $VMName -Credential $cred -ArgumentList $IP -ScriptBlock {
    param($IP)
    $nic = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
    if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IP -ErrorAction SilentlyContinue)) {
        Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IP -PrefixLength 26 -DefaultGateway 10.10.0.1 | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses 10.10.0.10
    Start-Sleep 5
    "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)  IP: $IP/26"
    "TPM present: $((Get-Tpm).TpmPresent)"
    "dc01.lab.local -> $((Resolve-DnsName dc01.lab.local -Type A -ErrorAction SilentlyContinue).IPAddress)"
    "LDAP 389 to DC01 open: $((Test-NetConnection 10.10.0.10 -Port 389 -WarningAction SilentlyContinue).TcpTestSucceeded)"
}
