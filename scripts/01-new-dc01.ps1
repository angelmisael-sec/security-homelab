#Requires -RunAsAdministrator
# Creates the isolated lab switch and the DC01 VM (Windows Server 2025, Gen 2).
# Re-running is safe: existing switch/VM are left as they are.

$SwitchName = 'LabSwitch'
$VMName     = 'DC01'
$VMPath     = 'E:\Lab\VMs'
$ISO        = 'F:\14 ISOs y Sistemas\26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso'

if (-not (Test-Path $ISO)) { throw "ISO not found: $ISO" }

# Private switch: VMs only see each other, no path to the host or the home network.
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Private | Out-Null
    Write-Output "Switch $SwitchName created (Private)"
} else { Write-Output "Switch $SwitchName already exists" }

if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue)) {
    $vhd = Join-Path $VMPath "$VMName\$VMName.vhdx"
    New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 4GB -Path $VMPath `
           -NewVHDPath $vhd -NewVHDSizeBytes 60GB -SwitchName $SwitchName | Out-Null
    Set-VM -Name $VMName -ProcessorCount 2 -StaticMemory -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $VMName -SecureBootTemplate MicrosoftWindows
    $dvd = Add-VMDvdDrive -VMName $VMName -Path $ISO -Passthru
    Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd
    Write-Output "VM $VMName created: 2 vCPU, 4 GB RAM, 60 GB disk at $vhd"
} else { Write-Output "VM $VMName already exists" }

Get-VM -Name $VMName | Select-Object Name, State, ProcessorCount, @{n='RAM_GB';e={$_.MemoryStartup/1GB}} | Format-Table -AutoSize | Out-String
