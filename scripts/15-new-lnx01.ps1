#Requires -RunAsAdministrator
# Builds LNX01, the Ubuntu Server 24.04 analysis VM (nmap now, Greenbone in week 10, Wazuh in week 14).
# Two NICs: LabSwitch (10.10.0.40/26, the lab) and Default Switch (NAT, only to pull packages and SSH from the host).
# Unattended: Subiquity autoinstall read from a small CIDATA disk. The only manual step it needs, answering
# "Continue with autoinstall?", is typed through the Hyper-V virtual keyboard.
# Password hash and SSH key come from outside the repo (E:\Lab\VMs\lnx01-hash.txt, ~\.ssh\lab_ed25519.pub).
# Make the hash with:  wsl -- openssl passwd -6 '<password>'   (argument, NOT a pipe: PowerShell 5.1 pipes add a BOM and \r)

$VMName  = 'LNX01'
$VMPath  = 'E:\Lab\VMs'
$VHD     = "$VMPath\$VMName\$VMName.vhdx"
$Seed    = "$VMPath\$VMName\cidata.vhdx"
$ISO     = 'E:\Lab\ISOs\ubuntu-24.04.5-live-server-amd64.iso'
$Hash    = (Get-Content "$VMPath\lnx01-hash.txt" -Raw).Trim()
$PubKey  = (Get-Content "$env:USERPROFILE\.ssh\lab_ed25519.pub" -Raw).Trim()
$MacLab  = '00155D100040'   # fixed MACs so netplan can tell the two NICs apart
$MacWan  = '00155D100041'
$ErrorActionPreference = 'Stop'

function Format-Mac($m) { ($m -split '(..)' | Where-Object { $_ }) -join ':' }

# 1. VM: Gen 2 with the Microsoft UEFI CA template (Linux shim), lab NIC + NAT NIC, installer ISO first in boot order
if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue)) {
    New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 4GB -Path $VMPath `
           -NewVHDPath $VHD -NewVHDSizeBytes 60GB -SwitchName 'LabSwitch' | Out-Null
    Set-VM -Name $VMName -ProcessorCount 2 -StaticMemory -AutomaticCheckpointsEnabled $false
    Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -StaticMacAddress $MacLab
    Add-VMNetworkAdapter -VMName $VMName -SwitchName 'Default Switch' -StaticMacAddress $MacWan
    Set-VMFirmware -VMName $VMName -SecureBootTemplate MicrosoftUEFICertificateAuthority
    $dvd = Add-VMDvdDrive -VMName $VMName -Path $ISO -Passthru
    Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd
    "VM $VMName created"
}

# 2. CIDATA seed disk with the autoinstall config (NoCloud datasource finds it by volume label)
if (-not (Test-Path $Seed)) {
    # NICs are matched by MAC without set-name: renaming eth0<->eth1 collides in the live installer and leaves both unconfigured
    $userData = @"
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard: {layout: us}
  timezone: America/Puerto_Rico
  identity: {hostname: lnx01, username: angel, password: "$Hash"}
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys: ["$PubKey"]
  network:
    version: 2
    ethernets:
      wan:
        match: {macaddress: "$(Format-Mac $MacWan)"}
        dhcp4: true
      lab:
        match: {macaddress: "$(Format-Mac $MacLab)"}
        addresses: [10.10.0.40/26]
        nameservers: {addresses: [10.10.0.10], search: [lab.local]}
  storage: {layout: {name: direct}}
  packages: [nmap, docker.io, linux-cloud-tools-virtual]
  late-commands:
    - curtin in-target -- usermod -aG docker angel
  shutdown: poweroff
"@
    New-VHD -Path $Seed -SizeBytes 64MB -Dynamic | Out-Null
    $disk = Mount-VHD -Path $Seed -Passthru | Initialize-Disk -PartitionStyle MBR -PassThru
    $vol = $disk | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem FAT32 -NewFileSystemLabel CIDATA
    Set-Content -Encoding ascii "$($vol.DriveLetter):\user-data" ($userData -replace "`r`n", "`n") -NoNewline
    Set-Content -Encoding ascii "$($vol.DriveLetter):\meta-data" "instance-id: lnx01`n" -NoNewline
    Dismount-VHD -Path $Seed
    Add-VMHardDiskDrive -VMName $VMName -Path $Seed
    'Seed disk ready'
}

# 3. Install: boot the ISO, wait out GRUB (typing early would hit its 'e' edit key), then confirm autoinstall
if ((Get-Item $VHD).Length -lt 1GB) {
    Start-VM -Name $VMName
    Start-Sleep 60   # past GRUB's 30 s menu
    $kb = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_Keyboard |
          Where-Object SystemName -eq (Get-VM $VMName).Id.Guid.ToUpper()
    # The prompt's timing varies run to run, so answer every 30 s until the disk starts filling
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Item $VHD).Length -lt 200MB) {
        if ((Get-Date) -gt $deadline) { throw 'Install never started; open the LNX01 console' }
        Invoke-CimMethod -InputObject $kb -MethodName TypeText -Arguments @{ asciiText = 'yes' } | Out-Null
        Invoke-CimMethod -InputObject $kb -MethodName TypeKey -Arguments @{ keyCode = [uint32]13 } | Out-Null   # Enter
        Start-Sleep 30
    }
    'Autoinstall confirmed; installing (VM powers off when done)...'
    $deadline = (Get-Date).AddMinutes(40)
    while ((Get-VM $VMName).State -ne 'Off') {
        if ((Get-Date) -gt $deadline) { throw 'Install did not finish in 40 min; check the VM console' }
        Start-Sleep 30
    }
    'Install finished'
}

# Boot from disk from now on (first, Hyper-V won't detach the current boot device), then drop installer media and seed
if ((Get-VMDvdDrive -VMName $VMName).Path) {
    Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName | Where-Object Path -eq $VHD)
    Get-VMHardDiskDrive -VMName $VMName | Where-Object Path -eq $Seed | Remove-VMHardDiskDrive
    Set-VMDvdDrive -VMName $VMName -Path $null
}

# 4. First boot from disk; the KVP daemon reports the NAT address so the host can SSH in
if ((Get-VM $VMName).State -ne 'Running') { Start-VM -Name $VMName }
$deadline = (Get-Date).AddMinutes(5)
do {
    Start-Sleep 10
    $ip = (Get-VMNetworkAdapter -VMName $VMName | Where-Object SwitchName -eq 'Default Switch').IPAddresses |
          Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
} until ($ip -or (Get-Date) -gt $deadline)
"LNX01 NAT address: $ip   ->   ssh -i ~/.ssh/lab_ed25519 angel@$ip"
