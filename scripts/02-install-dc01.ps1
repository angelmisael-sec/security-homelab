#Requires -RunAsAdministrator
# Installs Windows Server 2025 (Desktop Experience) into DC01's empty disk without the setup wizard:
# applies the image with DISM, makes it bootable and drops an unattend.xml so first boot skips OOBE.
# The Administrator password is random and saved OUTSIDE the repo, in E:\Lab\credenciales-lab.txt.

$VMName  = 'DC01'
$VHD     = 'E:\Lab\VMs\DC01\DC01.vhdx'
$ISO     = 'F:\14 ISOs y Sistemas\26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso'
$CredFile = 'E:\Lab\credenciales-lab.txt'
$ErrorActionPreference = 'Stop'

if ((Get-VM $VMName).State -ne 'Off') { throw "$VMName must be off" }
# Guard: only touch a disk that is still empty, never one with an installed OS.
if ((Get-Item $VHD).Length -gt 100MB) { throw "$VHD is not empty, refusing to overwrite it" }

$free = [char[]]('PQRSTUVWXYZ') | Where-Object { -not (Test-Path "${_}:\") }
$S, $W = $free[0], $free[1]

# 1. Partition the VHD for UEFI: EFI + MSR + Windows
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
"@ | Set-Content -Encoding ascii "$env:TEMP\dc01-part.txt"
diskpart /s "$env:TEMP\dc01-part.txt" | Out-Null
if (-not (Test-Path "${W}:\")) { throw 'Partitioning failed' }

try {
    # 2. Apply the Standard (Desktop Experience) image
    $isoVol = Mount-DiskImage -ImagePath $ISO -PassThru | Get-Volume
    $wim = "$($isoVol.DriveLetter):\sources\install.wim"
    $img = Get-WindowsImage -ImagePath $wim | Where-Object { $_.ImageName -like '*Standard*Desktop*' } | Select-Object -First 1
    Write-Output "Applying: $($img.ImageName) (index $($img.ImageIndex))"
    Expand-WindowsImage -ImagePath $wim -Index $img.ImageIndex -ApplyPath "${W}:\" | Out-Null

    # 3. Make it bootable
    bcdboot "${W}:\Windows" /s "${S}:" /f UEFI | Out-Null

    # 4. Answer file: name, time zone (Puerto Rico = SA Western), Administrator password, no OOBE questions
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%*-_'.ToCharArray()
    $pass = -join (1..18 | ForEach-Object { $chars | Get-Random })
    $sh = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
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
      <UserAccounts><AdministratorPassword><Value>$pass</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <OOBE><HideEULAPage>true</HideEULAPage><ProtectYourPC>3</ProtectYourPC></OOBE>
    </component>
  </settings>
</unattend>
"@
    New-Item -ItemType Directory -Force "${W}:\Windows\Panther" | Out-Null
    Set-Content -Encoding utf8 "${W}:\Windows\Panther\unattend.xml" $xml
    Add-Content -Encoding utf8 $CredFile "DC01  user: Administrator  password: $pass  (created $(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
    Write-Output "Password saved to $CredFile"
}
finally {
    Dismount-DiskImage -ImagePath $ISO | Out-Null
    "select vdisk file=`"$VHD`"`ndetach vdisk" | Set-Content -Encoding ascii "$env:TEMP\dc01-detach.txt"
    diskpart /s "$env:TEMP\dc01-detach.txt" | Out-Null
}

# 5. Boot from the disk, drop the DVD and start
Get-VMDvdDrive -VMName $VMName | Remove-VMDvdDrive
Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName)
Start-VM -Name $VMName
Get-VM $VMName | Select-Object Name, State | Format-Table -AutoSize | Out-String
