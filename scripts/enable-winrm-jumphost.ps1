# Enable WinRM on Jumphost1 so POD Automator can reach it.
#
# Run as Administrator, from RDP or the console — NOT over WinRM (see below).
# Safe to re-run: every step is idempotent, and the firewall rule is recreated
# rather than skipped so a stale or wrongly-scoped rule gets repaired.
#
# EVERY SETTING HERE SURVIVES A REBOOT. Service startup type, the WSMan listener,
# the firewall rule, the registry policy and the shell limits are all persistent
# stores. Restart-Service is the only runtime action, and StartupType=Automatic
# covers boot.
#
# GOLDEN IMAGE: if you sysprep /generalize, Windows REMOVES the WinRM listener.
# The service, registry policy and firewall rule survive, so the image boots
# looking correct with nothing listening on 5985. Either snapshot without
# generalizing, or re-create the listener on first boot from
# C:\Windows\Setup\Scripts\SetupComplete.cmd.

# --- Do not kill our own session -------------------------------------------
# Restarting WinRM while connected THROUGH WinRM drops the session mid-script,
# so the verification below never runs and a good configuration looks failed.
$OverWinRM = [bool]$PSSenderInfo
if ($OverWinRM) {
  Write-Host 'NOTE: running over WinRM — the service restart will be SKIPPED.' -ForegroundColor Yellow
  Write-Host '      Reboot, or re-run locally, to apply the service restart.' -ForegroundColor Yellow
  Write-Host ''
}

# --- PowerShell remoting ----------------------------------------------------
# -SkipNetworkProfileCheck matters: a dCloud NIC often lands on the Public
# profile, where plain Enable-PSRemoting refuses to create the firewall rule and
# leaves WinRM running but unreachable.
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null

# --- HTTP listener on 5985 --------------------------------------------------
if (-not (Get-ChildItem WSMan:\localhost\Listener -EA SilentlyContinue | Where-Object { $_.Keys -contains 'Transport=HTTP' })) { New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force | Out-Null }

# --- Firewall ---------------------------------------------------------------
# Remove first, then create. A guard that skips when a rule of this name already
# exists cannot repair one that is disabled or scoped to the wrong profile —
# which is exactly why re-pasting an earlier version of this script did nothing.
Get-NetFirewallRule -DisplayName 'WinRM-HTTP-In-5985*' -EA SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'WinRM-HTTP-In-5985-Any' -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -Enabled True | Out-Null
Enable-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -EA SilentlyContinue
Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -Profile Any -EA SilentlyContinue

# --- Let the local Administrator authenticate over the network --------------
# Without this, UAC remote token filtering hands a NON-elevated token to a local
# (non-domain) admin connecting over the network. WinRM connects, then every
# privileged operation fails with Access Denied — which reads as a bad password
# and is not.
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -PropertyType DWord -Force | Out-Null

# --- Shell limits -----------------------------------------------------------
# The default 5 concurrent shells is not enough when several PODs publish at once.
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024 -Force
Set-Item WSMan:\localhost\Shell\MaxShellsPerUser 30 -Force

# --- Service ----------------------------------------------------------------
Set-Service -Name WinRM -StartupType Automatic
if (-not $OverWinRM) { Restart-Service WinRM }

# --- Verification -----------------------------------------------------------
Write-Host ''
Write-Host '================ VERIFICATION ================' -ForegroundColor Cyan

$svc = Get-Service WinRM
$okSvc = ($svc.Status -eq 'Running') -and ($svc.StartType -like 'Automatic*')
$listeners = @(Get-ChildItem WSMan:\localhost\Listener -EA SilentlyContinue | Where-Object { $_.Keys -contains 'Transport=HTTP' })
$okListener = $listeners.Count -gt 0
# Rule enumeration is INFORMATIONAL only — see the verdict below.
#
# Two earlier versions of this check reported [FAIL] on a host whose port 5985
# was open and serving: first because it matched -DisplayName '*WinRM*' (the
# built-ins are called "Windows Remote Management (HTTP-In)"), then because
# Get-NetFirewallRule returns Enabled as an ENUM so -eq 'True' was false on
# enabled rules. Enumerating rules is a fragile way to prove something the port
# test proves directly, so it no longer gates the result.
$fw = @(Get-NetFirewallRule -EA SilentlyContinue | Where-Object {
  $_.Direction -eq 'Inbound' -and [string]$_.Enabled -eq 'True' -and
  ($_.DisplayName -like '*WinRM*' -or $_.DisplayName -like '*Windows Remote Management*' -or $_.Name -like 'WINRM-HTTP-In-TCP*')
})
$latfp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA SilentlyContinue).LocalAccountTokenFilterPolicy
$okReg = ($latfp -eq 1)
$okPort = (Test-NetConnection -ComputerName localhost -Port 5985 -WarningAction SilentlyContinue).TcpTestSucceeded

function Show($label, $ok, $detail) {
  $mark = if ($ok) { '[ OK ]' } else { '[FAIL]' }
  $col  = if ($ok) { 'Green' } else { 'Red' }
  Write-Host ("{0} {1,-34} {2}" -f $mark, $label, $detail) -ForegroundColor $col
}

Show 'WinRM service'            $okSvc      ("{0} / {1}" -f $svc.Status, $svc.StartType)
Show 'HTTP listener on 5985'    $okListener (($listeners | ForEach-Object { $_.Keys -join ' ' }) -join ' | ')
Write-Host ('[INFO] {0,-34} {1}' -f 'Inbound WinRM rules', $(if ($fw.Count) { ($fw | ForEach-Object { $_.DisplayName + ' [' + $_.Profile + ']' }) -join ' | ' } else { 'none enumerated (port test above is authoritative)' })) -ForegroundColor DarkGray
Show 'LocalAccountTokenFilterPolicy' $okReg ("value = {0}" -f $(if ($null -eq $latfp) { '<missing>' } else { $latfp }))
Show 'TCP 5985 reachable'       $okPort     ("Test-NetConnection = {0}" -f $okPort)

Write-Host ''
Write-Host ('Network profile(s): ' + ((Get-NetConnectionProfile | ForEach-Object { $_.Name + '=' + $_.NetworkCategory }) -join ', '))
Write-Host ''

if ($okSvc -and $okListener -and $okReg -and $okPort) {
  Write-Host 'WinRM IS READY — safe to save the golden image.' -ForegroundColor Green
} else {
  Write-Host 'WinRM IS NOT READY — see the [FAIL] lines above.' -ForegroundColor Red
  if (-not $okListener) { Write-Host '  No HTTP listener. If this image was sysprepped, sysprep removed it — re-create it on first boot.' -ForegroundColor Yellow }
  if (-not $okReg)      { Write-Host '  Registry policy missing: remote logons get a non-elevated token and fail with Access Denied.' -ForegroundColor Yellow }
  if ($OverWinRM)       { Write-Host '  Service restart was skipped because this ran over WinRM — reboot or re-run locally.' -ForegroundColor Yellow }
}
