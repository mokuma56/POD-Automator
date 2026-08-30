# Enable WinRM on Jumphost1 so POD Automator can publish the student Duo
# passcode page and read the iDAC URL.
#
# WHY THIS CANNOT BE AUTOMATED
# WinRM is the only channel the automation has to the jump host, so it cannot
# be used to turn itself on. Bake this into the dCloud base image, or push the
# equivalent by GPO from AD1 (which we can reach), and it survives rebuilds.
#
# WHAT THE AUTOMATION ACTUALLY DOES HERE
#   * writes C:\Users\Public\Duo-Login.html and a .lnk on the Public Desktop
#   * stages a Duo .ico alongside them
#   * runs idac_sdk to mint a fresh iDAC URL
# Nothing else. It connects as the local Administrator over HTTP/5985 using
# NTLM, which encrypts the payload — Basic auth and AllowUnencrypted are NOT
# needed and are deliberately not enabled here.
#
# Run as Administrator. Safe to re-run.

$ErrorActionPreference = 'Stop'

Write-Host '== Enabling PowerShell remoting ==' -ForegroundColor Cyan
# -SkipNetworkProfileCheck matters: a dCloud NIC often lands on the Public
# profile, and plain Enable-PSRemoting refuses to create the firewall rule
# there, leaving WinRM running but unreachable.
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null

Write-Host '== Ensuring the HTTP listener on 5985 ==' -ForegroundColor Cyan
$listener = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
if (-not $listener) {
    New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force | Out-Null
    Write-Host '   created HTTP listener'
} else {
    Write-Host '   HTTP listener already present'
}

Write-Host '== Firewall: allow inbound 5985 on every profile ==' -ForegroundColor Cyan
if (-not (Get-NetFirewallRule -DisplayName 'WinRM-HTTP-In-5985' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'WinRM-HTTP-In-5985' -Direction Inbound `
        -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any | Out-Null
    Write-Host '   rule created'
} else {
    Write-Host '   rule already present'
}

Write-Host '== Allowing the local Administrator to authenticate over the network ==' -ForegroundColor Cyan
# Without this, UAC remote token filtering hands a NON-elevated token to a
# local (non-domain) admin connecting over the network. WinRM then connects
# but every privileged operation fails with Access Denied — which looks like a
# credentials problem and is not.
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host '== Shell limits ==' -ForegroundColor Cyan
# The passcode page is pushed as a base64 blob in a single command; the stock
# 150MB/shell is ample, but the default 5 concurrent shells is not when
# several PODs publish at once.
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024 -Force
Set-Item WSMan:\localhost\Shell\MaxShellsPerUser 30 -Force

Write-Host '== Service startup ==' -ForegroundColor Cyan
Set-Service -Name WinRM -StartupType Automatic
Restart-Service WinRM

Write-Host ''
Write-Host '== Verification ==' -ForegroundColor Cyan
Test-WSMan -ComputerName localhost | Out-Null
Write-Host '   Test-WSMan: OK'
Get-Service WinRM | Format-Table Name, Status, StartType -AutoSize
Get-ChildItem WSMan:\localhost\Listener | ForEach-Object {
    Write-Host ('   listener: ' + ($_.Keys -join ' '))
}
Write-Host ''
Write-Host 'WinRM is ready. Verify from the POD Automator host with:' -ForegroundColor Green
Write-Host '  docker run --rm --network container:vpn-POD-17 --entrypoint python3 pod-automator:latest \'
Write-Host '    -c "import winrm; s=winrm.Session(''http://198.18.133.36:5985/wsman'', auth=(''administrator'',''<password>''), transport=''ntlm''); print(s.run_ps(''hostname'').std_out)"'
