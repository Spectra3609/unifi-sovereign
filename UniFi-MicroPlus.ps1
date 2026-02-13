<#
.SYNOPSIS
  UniFi MicroPlus -- SSH-based device inform toolkit.

.DESCRIPTION
  Scans a subnet or IP list for UniFi devices via SSH, then performs one of:
    SANITY  - read-only credential + info check
    MIGRATE - re-point devices to a new controller (no reset)
    ADOPT   - full adoption with optional factory reset

  Cross-platform: Windows PowerShell 5.1+ and PowerShell 7+ (macOS/Linux).
  Auto-installs dependencies (Posh-SSH).

.PARAMETER Mode
  Operation mode: Sanity, Migrate, or Adopt. If omitted, prompts interactively.

.PARAMETER Cidr
  Target subnet in CIDR notation (e.g. 192.168.1.0/24). Mutually exclusive with -IPs.

.PARAMETER IPs
  Comma-separated list of target IPs. Mutually exclusive with -Cidr.

.PARAMETER Controller
  Target controller IP or hostname. Required for Migrate and Adopt modes.

.PARAMETER Username
  SSH username to try first (before factory defaults).

.PARAMETER Password
  SSH password (plaintext -- will be converted to SecureString internally).

.PARAMETER ResetFirst
  (Adopt mode only) Factory reset devices before sending set-inform.

.PARAMETER SshTimeout
  SSH connection timeout in seconds. Default: 7.

.PARAMETER ScanTimeout
  TCP port scan timeout per host in seconds. Default: 3.

.PARAMETER Parallel
  Max parallel scan threads. Default: 128.

.PARAMETER OutCsv
  Path for CSV output. Defaults to Desktop or current directory.

.EXAMPLE
  # Interactive mode -- prompts for everything
  .\UniFi-MicroPlus.ps1

.EXAMPLE
  # One-liner migrate: re-point a /24 to a new controller
  .\UniFi-MicroPlus.ps1 -Mode Migrate -Cidr 192.168.1.0/24 -Controller 10.0.0.5 -Username admin -Password ubnt

.EXAMPLE
  # Remote execute (paste into any terminal with PowerShell)
  irm https://raw.githubusercontent.com/YOUR_USER/unifi-tools/main/UniFi-MicroPlus.ps1 | iex

.NOTES
  If execution policy blocks you: Set-ExecutionPolicy -Scope Process Bypass
#>

[CmdletBinding()]
param(
    [ValidateSet("Sanity","Migrate","Adopt")]
    [string]$Mode,

    [string]$Cidr,

    [string]$IPs,

    [string]$Controller,

    [string]$Username,

    [string]$Password,

    [switch]$ResetFirst,

    [int]$SshTimeout = 7,

    [int]$ScanTimeout = 3,

    [int]$Parallel = 128,

    [string]$OutCsv
)

$ErrorActionPreference = "Continue"
$script:ScriptVersion = "2.0.0"

# ===================================================================
# PLATFORM DETECTION
# ===================================================================

$script:IsWindows51 = ($PSVersionTable.PSVersion.Major -le 5)
$script:IsNonWindows = $false
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $script:IsNonWindows = (-not $IsWindows)
}

# ===================================================================
# UI HELPERS
# ===================================================================

function Write-Banner {
    $lines = @(
        "",
        "  ============================================================",
        "   _   _       _ _____ _   __  __ _            ____  _       ",
        "  | | | |_ __ (_)  ___(_) |  \/  (_) ___ _ __ |  _ \| |_   _ ___ ",
        "  | | | | '_ \| | |_  | | | |\/| | |/ __| '__ \| |_) | | | | / __|",
        "  | |_| | | | | |  _| | | | |  | | | (__| |  | |  __/| | |_| \__ \",
        "   \___/|_| |_|_|_|   |_| |_|  |_|_|\___|_|  |_|_|   |_|\__,_|___/",
        "",
        "   SSH Inform Toolkit                              v$($script:ScriptVersion)",
        "  ============================================================",
        ""
    )
    foreach ($line in $lines) {
        Write-Host $line -ForegroundColor DarkCyan
    }
}

function Write-Step {
    param([string]$Text, [string]$Status = "INFO", [string]$Detail = "")
    $colors = @{
        "INFO" = "DarkGray"; "OK" = "Green"; "FAIL" = "Red";
        "WARN" = "Yellow";   "RUN" = "Cyan";  "SKIP" = "DarkGray"
    }
    $color = "White"
    if ($colors.ContainsKey($Status)) { $color = $colors[$Status] }
    $tag = "[$Status]".PadRight(7)
    Write-Host "  $tag " -ForegroundColor $color -NoNewline
    Write-Host $Text -NoNewline
    if ($Detail) { Write-Host " $Detail" -ForegroundColor DarkGray } else { Write-Host "" }
}

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "  -- $Text --" -ForegroundColor Cyan
    Write-Host ""
}

function Read-YesNo {
    param([string]$Prompt, [ValidateSet('Y','N')]$Default = 'N')
    while ($true) {
        $r = Read-Host "  $Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
        $r = $r.Trim().ToUpper()
        if ($r -in @('Y','YES')) { return 'Y' }
        elseif ($r -in @('N','NO')) { return 'N' }
        Write-Host "    Please answer Y or N." -ForegroundColor Yellow
    }
}

function Read-NonEmpty {
    param([string]$Prompt)
    while ($true) {
        $v = Read-Host "  $Prompt"
        if ($v -and $v.Trim()) { return $v.Trim() }
        Write-Host "    Cannot be blank." -ForegroundColor Yellow
    }
}

function Read-MenuChoice {
    param([string]$Title, [string[]]$Options, [int]$Default = 1)
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ""
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $num = $i + 1
        if ($num -eq $Default) {
            Write-Host "    [$num] $($Options[$i])" -ForegroundColor Cyan
        } else {
            Write-Host "    [$num] $($Options[$i])"
        }
    }
    Write-Host ""
    while ($true) {
        $raw = Read-Host "    Choice [default=$Default]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
        $val = 0
        if ([int]::TryParse($raw.Trim(), [ref]$val) -and $val -ge 1 -and $val -le $Options.Count) {
            return $val
        }
        Write-Host "    Enter 1-$($Options.Count)." -ForegroundColor Yellow
    }
}

function Write-ResultsTable {
    param([array]$Results)
    if ($Results.Count -eq 0) { return }

    Write-Host ""
    Write-Host ("  {0,-16} {1,-18} {2,-22} {3,-8} {4}" -f "IP","MAC","Model","Status","Note") -ForegroundColor White
    Write-Host ("  {0,-16} {1,-18} {2,-22} {3,-8} {4}" -f ("=" * 15),("=" * 17),("=" * 21),("=" * 7),("=" * 20)) -ForegroundColor DarkGray

    foreach ($r in ($Results | Sort-Object IP)) {
        $color = "White"
        switch ($r.Status) {
            "OK"    { $color = "Green"  }
            "CHECK" { $color = "Yellow" }
            "FAIL"  { $color = "Red"    }
        }
        $mac   = if ($r.MAC)   { $r.MAC }   else { "-" }
        $model = if ($r.Model) { $r.Model } else { "-" }
        $note  = if ($r.Note)  { $r.Note }  else { "" }
        # Truncate long fields for display
        if ($model.Length -gt 21) { $model = $model.Substring(0,18) + "..." }
        if ($note.Length  -gt 35) { $note  = $note.Substring(0,32) + "..."  }

        Write-Host ("  {0,-16} {1,-18} {2,-22} " -f $r.IP, $mac, $model) -NoNewline
        Write-Host ("{0,-8}" -f $r.Status) -ForegroundColor $color -NoNewline
        Write-Host " $note"
    }
    Write-Host ""
}

# ===================================================================
# PLATFORM-SAFE HELPERS
# ===================================================================

function ConvertTo-SafeSecureString {
    param([string]$Plain)
    return (ConvertTo-SecureString $Plain -AsPlainText -Force)
}

function Get-DefaultCsvPath {
    param([string]$ModeStr)
    $filename = "unifi-" + $ModeStr.ToLower() + "-log.csv"

    # Try Desktop first (works on Windows + most Linux DEs)
    $desktop = [Environment]::GetFolderPath("Desktop")
    if ($desktop -and (Test-Path $desktop)) {
        return Join-Path $desktop $filename
    }

    # Try home directory
    $home = [Environment]::GetFolderPath("UserProfile")
    if (-not $home) { $home = $env:HOME }
    if ($home -and (Test-Path $home)) {
        return Join-Path $home $filename
    }

    # Fallback to current directory
    return Join-Path $PWD.Path $filename
}

# CIDR -> array of IPs (excludes network + broadcast)
function Get-IPsFromCidr {
    param([Parameter(Mandatory=$true)][string]$CidrStr)
    $parts = $CidrStr -split '/'
    if ($parts.Count -ne 2) { throw "Invalid CIDR: $CidrStr" }
    $baseIp = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
    [Array]::Reverse($baseIp)
    $net = [BitConverter]::ToUInt32($baseIp, 0)
    $maskBits = [int]$parts[1]
    if ($maskBits -lt 0 -or $maskBits -gt 32) { throw "Bad mask: $CidrStr" }
    $mask  = ([uint32]::MaxValue) -shl (32 - $maskBits)
    $first = ($net -band $mask) + 1
    $last  = ($first + (([uint32]::MaxValue - $mask) - 1))
    $lst   = New-Object System.Collections.Generic.List[string]
    for ($i = $first; $i -le $last; $i++) {
        $b = [BitConverter]::GetBytes([uint32]$i); [Array]::Reverse($b)
        $lst.Add(([System.Net.IPAddress]::new($b)).ToString()) | Out-Null
    }
    return $lst.ToArray()
}

function Build-CredList([array]$spec) {
    $l = @()
    foreach ($c in $spec) { $l += [pscredential]::new($c.u, $c.p) }
    return $l
}

# ===================================================================
# DEVICE INTERACTION
# ===================================================================

function Get-DeviceMac {
    param([int]$SessId, [int]$Timeout)
    try {
        $o = Invoke-SSHCommand -SessionId $SessId -Command "info" -TimeOut $Timeout
        $txt = ($o.Output -join "`n")
        if ($txt -match "MAC Address:\s*([0-9A-Fa-f:]{17})") { return $Matches[1].ToLower() }
        if ($txt -match "MAC:\s*([0-9A-Fa-f:]{17})")         { return $Matches[1].ToLower() }
    } catch {}

    foreach ($cmd in @(
        "cat /sys/class/net/eth0/address 2>/dev/null",
        "cat /sys/class/net/br0/address 2>/dev/null",
        "/sbin/ifconfig eth0 2>/dev/null | grep -i 'ether' | awk '{print `$2}'",
        "ip link show eth0 2>/dev/null | awk '/link\/ether/ {print `$2}'"
    )) {
        try {
            $r = Invoke-SSHCommand -SessionId $SessId -Command $cmd -TimeOut $Timeout
            $val = (($r.Output -join ' ').Trim())
            if ($val -match "([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})") { return $Matches[1].ToLower() }
        } catch {}
    }
    return ""
}

function Get-DeviceInfo {
    param([int]$SessId, [int]$Timeout)
    $info = @{ Model=""; Firmware=""; Hostname=""; AdoptStatus=""; MAC=""; InformURL="" }
    try {
        $r = Invoke-SSHCommand -SessionId $SessId -Command "info" -TimeOut $Timeout
        $text = ($r.Output -join "`n")
        if ($text) {
            if ($text -match "Model:\s*(.+)")            { $info.Model       = $Matches[1].Trim() }
            if ($text -match "Version:\s*(.+)")           { $info.Firmware    = $Matches[1].Trim() }
            if ($text -match "Hostname:\s*(.+)")          { $info.Hostname    = $Matches[1].Trim() }
            if ($text -match "Status:\s*(.+)")            { $info.AdoptStatus = $Matches[1].Trim() }
            if ($text -match "Inform URL:\s*(.+)")        { $info.InformURL   = $Matches[1].Trim() }
            if ($text -match "MAC Address:\s*([0-9A-Fa-f:]{17})") { $info.MAC = $Matches[1].ToLower() }
            elseif ($text -match "MAC:\s*([0-9A-Fa-f:]{17})")     { $info.MAC = $Matches[1].ToLower() }
        }
    } catch {}
    if (-not $info.MAC) {
        $info.MAC = Get-DeviceMac -SessId $SessId -Timeout $Timeout
    }
    return $info
}

# Factory reset cascade (ADOPT mode only)
# A successful reset kills the SSH session -- we treat that as success.
function Invoke-HardReset {
    param([int]$SessId, [int]$Timeout, [string]$Ip)

    function Try-ResetCmd {
        param([int]$Sid, [string]$Cmd, [int]$T)
        try {
            $r = Invoke-SSHCommand -SessionId $Sid -Command $Cmd -TimeOut $T -ErrorAction Stop
            if ($r.ExitStatus -eq 42) { return "skip" }
            return "ok"
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'Unable to connect|not available|reset|broken pipe|closed|failed to establish|timed out|timeout') {
                return "session_died"
            }
            return "error"
        }
    }

    $cmd1 = @'
sh -c '
  if [ -f /tmp/default.cfg ]; then
    cp -f /tmp/default.cfg /tmp/system.cfg && \
    { which cfgmtd >/dev/null 2>&1 && cfgmtd -f /tmp/system.cfg -w || /sbin/cfgmtd -f /tmp/system.cfg -w ; } && \
    sync && sleep 1 && reboot;
  elif [ -f /etc/default.cfg ]; then
    cp -f /etc/default.cfg /tmp/system.cfg && \
    { which cfgmtd >/dev/null 2>&1 && cfgmtd -f /tmp/system.cfg -w || /sbin/cfgmtd -f /tmp/system.cfg -w ; } && \
    sync && sleep 1 && reboot;
  else
    exit 42
  fi
'
'@
    $r1 = Try-ResetCmd -Sid $SessId -Cmd $cmd1 -T $Timeout
    if ($r1 -in @("ok","session_died")) { return @{ ok=$true; note="reset: cp/cfgmtd/reboot" } }

    $r2 = Try-ResetCmd -Sid $SessId -Cmd "syswrapper.sh restore-default" -T $Timeout
    if ($r2 -in @("ok","session_died")) { return @{ ok=$true; note="reset: syswrapper.sh" } }

    $r3 = Try-ResetCmd -Sid $SessId -Cmd "set-default" -T $Timeout
    if ($r3 -in @("ok","session_died")) { return @{ ok=$true; note="reset: set-default" } }

    return @{ ok=$false; note="reset failed (all methods exhausted)" }
}

function Test-ControllerEndpoint {
    param([string]$Ctrl)
    $url = "http://${Ctrl}:8080/inform"
    try {
        Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec 5 | Out-Null
        Write-Step "Controller reachable" "OK" $url
        return $true
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 400) {
            Write-Step "Controller reachable (HTTP 400 = normal)" "OK" $url
            return $true
        }
        Write-Step "Controller unreachable" "WARN" $url
        Write-Step "Devices may fail to adopt if they cannot reach this endpoint." "WARN"
        return $false
    }
}

# ===================================================================
# DEPENDENCY BOOTSTRAP
# ===================================================================

function Install-Dependencies {
    Write-Header "Dependencies"

    # NuGet provider (Windows PS 5.1 only)
    if ($script:IsWindows51) {
        $nuget = Get-PackageProvider -ListAvailable -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -eq 'NuGet' }
        if (-not $nuget -or ($nuget.Version -lt [version]"2.8.5.201")) {
            Write-Step "Installing NuGet provider..." "RUN"
            try {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
                Write-Step "NuGet provider ready" "OK"
            } catch {
                Write-Step "NuGet install failed -- module install may prompt" "WARN"
            }
        } else {
            Write-Step "NuGet provider" "OK"
        }
    }

    # Trust PSGallery
    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }

    # Posh-SSH
    if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
        Write-Step "Installing Posh-SSH..." "RUN"
        try {
            Install-Module Posh-SSH -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Step "Posh-SSH installed" "OK"
        } catch {
            Write-Step "Posh-SSH install failed" "FAIL"
            Write-Host ""
            Write-Host "    Try manually: Install-Module Posh-SSH -Scope CurrentUser -Force" -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Step "Posh-SSH" "OK"
    }

    Import-Module Posh-SSH -ErrorAction Stop
}

# ===================================================================
# PORT SCAN (parallel runspaces + Write-Progress)
# ===================================================================

function Invoke-PortScan {
    param([string[]]$Targets, [int]$TimeoutSec, [int]$MaxParallel)

    Write-Header "Port Scan (TCP/22)"
    Write-Step "Scanning $($Targets.Count) hosts..." "RUN"

    $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool  = [RunspaceFactory]::CreateRunspacePool(1, [Math]::Min([Math]::Max(1,$MaxParallel), 512), $state, $Host)
    $pool.Open()

    $jobs = @()
    foreach ($ip in $Targets) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($ip, $t)
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $iar = $tcp.BeginConnect($ip, 22, $null, $null)
                $ok  = $iar.AsyncWaitHandle.WaitOne($t * 1000)
                if ($ok) { $tcp.EndConnect($iar) }
                $tcp.Close()
                if ($ok) { return $ip }
            } catch {}
            return $null
        }).AddArgument($ip).AddArgument($TimeoutSec)
        $jobs += [pscustomobject]@{ Handle=$ps; Task=$ps.BeginInvoke() }
    }

    $open = New-Object System.Collections.Generic.List[string]
    $done = 0
    $total = $jobs.Count
    foreach ($j in $jobs) {
        $done++
        $pct = [Math]::Floor(($done / $total) * 100)
        Write-Progress -Activity "Scanning TCP/22" -Status "$done / $total hosts ($pct%)" -PercentComplete $pct
        try { $hit = $j.Handle.EndInvoke($j.Task) } catch { $hit = $null }
        $j.Handle.Dispose()
        if ($hit) { $open.Add($hit) | Out-Null }
    }
    Write-Progress -Activity "Scanning TCP/22" -Completed
    $pool.Close(); $pool.Dispose()

    if ($open.Count -eq 0) {
        Write-Step "No hosts with SSH open" "FAIL"
        Write-Step "Check VLAN/firewall, subnet, or device power." "WARN"
        exit 1
    }

    Write-Step "$($open.Count) hosts with SSH open" "OK"
    return $open.ToArray()
}

# ===================================================================
# MAIN LOGIC
# ===================================================================

Write-Banner
Install-Dependencies

# ----- Resolve Mode -----
$modeStr = $Mode
if (-not $modeStr) {
    $mc = Read-MenuChoice -Title "Operation mode:" -Options @(
        "SANITY   - verify SSH access + collect device info (read-only)",
        "MIGRATE  - re-point devices to a new controller (no reset, no wipe)",
        "ADOPT    - full adoption with optional factory reset"
    ) -Default 1
    switch ($mc) {
        1 { $modeStr = "Sanity"  }
        2 { $modeStr = "Migrate" }
        3 { $modeStr = "Adopt"   }
    }
}
$modeStr = $modeStr.Substring(0,1).ToUpper() + $modeStr.Substring(1).ToLower()
Write-Step "Mode: $($modeStr.ToUpper())" "INFO"

# ----- Resolve Targets -----
Write-Header "Targets"
$targetList = @()
$targetType = ""

if ($Cidr) {
    $targetType = "CIDR"
    try { $targetList = Get-IPsFromCidr $Cidr }
    catch { Write-Step $_.Exception.Message "FAIL"; exit 1 }
} elseif ($IPs) {
    $targetType = "List"
    $targetList = ($IPs -split '[,\s]+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -Unique
} else {
    $tc = Read-MenuChoice -Title "Target input:" -Options @(
        "CIDR subnet  (e.g. 192.168.1.0/24)",
        "IP list      (comma-separated)"
    ) -Default 1
    if ($tc -eq 2) {
        $targetType = "List"
        $raw = Read-NonEmpty "IPs (comma-separated)"
        $targetList = ($raw -split '[,\s]+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -Unique
    } else {
        $targetType = "CIDR"
        $raw = Read-NonEmpty "CIDR (e.g. 192.168.1.0/24)"
        try { $targetList = Get-IPsFromCidr $raw }
        catch { Write-Step $_.Exception.Message "FAIL"; exit 1 }
    }
}

if ($targetList.Count -eq 0) { Write-Step "No valid targets." "FAIL"; exit 1 }
Write-Step "$($targetList.Count) IPs ($targetType)" "OK"

# ----- Controller (Migrate + Adopt) -----
$informUrl = ""
$doReset   = $false

if ($modeStr -in @("Migrate","Adopt")) {
    Write-Header "Controller"
    if (-not $Controller) {
        $Controller = Read-NonEmpty "Target controller IP or hostname"
    }
    $informUrl = "http://${Controller}:8080/inform"
    Write-Step "Inform URL: $informUrl" "INFO"
    Test-ControllerEndpoint -Ctrl $Controller | Out-Null

    if ($modeStr -eq "Adopt") {
        if ($ResetFirst) {
            $doReset = $true
        } elseif (-not $PSBoundParameters.ContainsKey('ResetFirst')) {
            $doReset = (Read-YesNo "Factory reset before adoption?" 'N') -eq 'Y'
        }
    }
    if ($modeStr -eq "Migrate") {
        Write-Host ""
        Write-Step "MIGRATE: no reset, no wipe -- inform URL only" "INFO"
    }
}

# ----- Credentials -----
Write-Header "SSH Credentials"
$credSpec = @()

if ($Username) {
    $pw = if ($Password) { ConvertTo-SafeSecureString $Password } else { Read-Host "Password for '$Username'" -AsSecureString }
    $credSpec += @{u=$Username; p=$pw}
    Write-Step "Custom credential: $Username" "OK"
} elseif (-not $PSBoundParameters.ContainsKey('Username')) {
    if ((Read-YesNo "Provide a known SSH credential?" 'N') -eq 'Y') {
        $u = Read-NonEmpty "SSH Username"
        $p = Read-Host "  SSH Password (hidden)" -AsSecureString
        $credSpec += @{u=$u; p=$p}
    }
    while ((Read-YesNo "Add another credential?" 'N') -eq 'Y') {
        $u2 = Read-NonEmpty "SSH Username"
        $p2 = Read-Host "  SSH Password (hidden)" -AsSecureString
        $credSpec += @{u=$u2; p=$p2}
    }
}

# Always append factory defaults
$credSpec += @{u='ubnt'; p=(ConvertTo-SafeSecureString 'ubnt')}
$credSpec += @{u='root'; p=(ConvertTo-SafeSecureString 'ubnt')}

$credLabel = ($credSpec | ForEach-Object { $_.u }) -join " -> "
Write-Step "Credential chain: $credLabel" "INFO"

# ----- CSV Path -----
if (-not $OutCsv) {
    $defaultPath = Get-DefaultCsvPath $modeStr
    $OutCsv = Read-Host "  CSV output path [$defaultPath]"
    if ([string]::IsNullOrWhiteSpace($OutCsv)) { $OutCsv = $defaultPath }
}

# ----- Plan Summary -----
Write-Header "Plan Summary"
Write-Step "Mode        : $($modeStr.ToUpper())" "INFO"
Write-Step "Targets     : $($targetList.Count) IPs ($targetType)" "INFO"
if ($modeStr -in @("Migrate","Adopt")) {
    Write-Step "Controller  : $Controller" "INFO"
    Write-Step "Inform URL  : $informUrl" "INFO"
    if ($modeStr -eq "Adopt") {
        $rl = "No"
        if ($doReset) { $rl = "YES" }
        Write-Step "Reset First : $rl" "INFO"
    }
}
Write-Step "SSH Timeout : ${SshTimeout}s" "INFO"
Write-Step "Scan        : ${ScanTimeout}s timeout / $Parallel parallel" "INFO"
Write-Step "CSV         : $OutCsv" "INFO"

Write-Host ""
if ((Read-YesNo "Execute?" 'Y') -ne 'Y') { Write-Host "  Aborted."; exit }

# ===================================================================
# SCAN
# ===================================================================

$openHosts = Invoke-PortScan -Targets $targetList -TimeoutSec $ScanTimeout -MaxParallel $Parallel

# ===================================================================
# DEVICE PROCESSING
# ===================================================================

Write-Header "Processing Devices ($($modeStr.ToUpper()))"

$credList = Build-CredList $credSpec
$results  = @()
$total    = $openHosts.Count

for ($idx = 0; $idx -lt $total; $idx++) {
    $ip = $openHosts[$idx]
    $num = $idx + 1
    $pct = [Math]::Floor(($num / $total) * 100)
    Write-Progress -Activity "Processing devices" -Status "[$num/$total] $ip" -PercentComplete $pct
    Write-Host ""
    Write-Host "  [$num/$total] $ip" -ForegroundColor Yellow

    $resetLabel = "N/A"
    switch ($modeStr) {
        "Sanity"  { $resetLabel = "N/A" }
        "Migrate" { $resetLabel = "N/A" }
        "Adopt"   { if ($doReset) { $resetLabel = "Requested" } else { $resetLabel = "No" } }
    }

    $row = [ordered]@{
        Timestamp     = (Get-Date).ToString("s")
        IP            = $ip
        MAC           = ""
        Connected     = $false
        Username      = ""
        Model         = ""
        DevHostname   = ""
        Firmware      = ""
        AdoptStatus   = ""
        CurrentInform = ""
        Reset         = $resetLabel
        Inform1       = "N/A"
        Inform2       = "N/A"
        Status        = "FAIL"
        Note          = ""
    }

    try {
        # -- SSH connect --
        $sess = $null; $ok = $false; $used = $null
        foreach ($c in $credList) {
            try {
                $sess = New-SSHSession -ComputerName $ip -Credential $c -AcceptKey -ConnectionTimeout $SshTimeout -ErrorAction Stop
                $used = $c.UserName; $ok = $true; break
            } catch {}
        }
        if (-not $ok) {
            $row.Note = "SSH auth failed"
            Write-Step "SSH auth failed" "FAIL" "(all credentials exhausted)"
            $results += [pscustomobject]$row; continue
        }
        $row.Connected = $true; $row.Username = $used
        Write-Step "Connected" "OK" "user=$used"

        # -- Device info --
        $devInfo = Get-DeviceInfo -SessId $sess.SessionId -Timeout ($SshTimeout * 2)
        $row.MAC           = $devInfo.MAC
        $row.Model         = $devInfo.Model
        $row.Firmware      = $devInfo.Firmware
        $row.DevHostname   = $devInfo.Hostname
        $row.AdoptStatus   = $devInfo.AdoptStatus
        $row.CurrentInform = $devInfo.InformURL

        if ($devInfo.Model -or $devInfo.MAC) {
            $infoLine = @()
            if ($devInfo.Model)     { $infoLine += $devInfo.Model }
            if ($devInfo.MAC)       { $infoLine += $devInfo.MAC }
            if ($devInfo.Hostname)  { $infoLine += $devInfo.Hostname }
            Write-Step "Device" "INFO" ($infoLine -join " | ")
        }
        if ($devInfo.InformURL) {
            Write-Step "Current inform" "INFO" $devInfo.InformURL
        }

        # -- SANITY: done --
        if ($modeStr -eq "Sanity") {
            $row.Status = "OK"
            Write-Step "Sanity passed" "OK"
            Remove-SSHSession -SessionId $sess.SessionId | Out-Null
            $results += [pscustomobject]$row; continue
        }

        # -- ADOPT: optional reset --
        if ($modeStr -eq "Adopt" -and $doReset) {
            Write-Step "Sending factory reset..." "RUN"
            $reset = Invoke-HardReset -SessId $sess.SessionId -Timeout $SshTimeout -Ip $ip
            if ($reset.ok) {
                $row.Reset = "OK ($($reset.note))"
                Write-Step "Reset sent -- waiting 90s" "OK" $reset.note
                try { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } catch {}
                Start-Sleep -Seconds 90

                $sess = $null; $ok = $false; $used = $null
                foreach ($c in $credList) {
                    try {
                        $sess = New-SSHSession -ComputerName $ip -Credential $c -AcceptKey -ConnectionTimeout ($SshTimeout * 3) -ErrorAction Stop
                        $used = $c.UserName; $ok = $true; break
                    } catch {}
                }
                if (-not $ok) {
                    $row.Note = "Re-login failed post-reset"
                    Write-Step "Reconnect failed after reset" "FAIL"
                    $results += [pscustomobject]$row; continue
                }
                $row.Username = $used
                Write-Step "Reconnected" "OK" "user=$used"
            } else {
                $row.Reset = "Failed"
                $row.Note  = $reset.note
                Write-Step "Reset failed" "FAIL" $reset.note
            }
        }

        # -- MIGRATE + ADOPT: set-inform (x2) --
        $cmd = "set-inform $informUrl"
        Write-Step "set-inform #1" "RUN"

        $r1 = Invoke-SSHCommand -SessionId $sess.SessionId -Command $cmd -TimeOut ($SshTimeout * 2)
        $row.Inform1 = ($r1.Output -join ' ').Trim()

        Start-Sleep -Seconds 5

        Write-Step "set-inform #2" "RUN"
        $r2 = Invoke-SSHCommand -SessionId $sess.SessionId -Command $cmd -TimeOut ($SshTimeout * 2)
        $row.Inform2 = ($r2.Output -join ' ').Trim()

        if ($row.Inform1 -match 'Adoption request sent|set-inform' -or
            $row.Inform2 -match 'Adoption request sent|Inform URL updated|set-inform') {
            $row.Status = "OK"
            Write-Step "set-inform accepted" "OK"
        } else {
            $row.Status = "CHECK"
            $row.Note   = ($row.Note + "; unexpected output").Trim('; ')
            Write-Step "Unexpected response -- verify manually" "WARN"
        }

        Remove-SSHSession -SessionId $sess.SessionId | Out-Null
        $results += [pscustomobject]$row

    } catch {
        $row.Status = "FAIL"
        $row.Note   = $_.Exception.Message
        Write-Step "Error: $($_.Exception.Message)" "FAIL"
        try { if ($sess) { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } } catch {}
        $results += [pscustomobject]$row
    }
}

Write-Progress -Activity "Processing devices" -Completed

# ===================================================================
# RESULTS
# ===================================================================

Write-Header "Results"

# Export CSV with fallback
$results | Sort-Object IP | Export-Csv -NoTypeInformation -Path $OutCsv -ErrorAction SilentlyContinue -ErrorVariable csvErr
if ($csvErr) {
    $fallback = Get-DefaultCsvPath $modeStr
    Write-Step "Cannot write to '$OutCsv' -- trying '$fallback'" "WARN"
    $results | Sort-Object IP | Export-Csv -NoTypeInformation -Path $fallback -ErrorAction SilentlyContinue -ErrorVariable csvErr2
    if ($csvErr2) {
        $fallback = Join-Path $env:TEMP ("unifi-" + $modeStr.ToLower() + "-log.csv")
        $results | Sort-Object IP | Export-Csv -NoTypeInformation -Path $fallback -ErrorAction Stop
    }
    $OutCsv = $fallback
}
Write-Step "CSV: $OutCsv" "OK"

# Results table
Write-ResultsTable $results

# Summary
$okCount    = @($results | Where-Object { $_.Status -eq "OK" }).Count
$checkCount = @($results | Where-Object { $_.Status -eq "CHECK" }).Count
$failCount  = @($results | Where-Object { $_.Status -eq "FAIL" }).Count

Write-Host "  -------------------------------------------" -ForegroundColor DarkGray
Write-Host ("  OK: {0}   " -f $okCount) -ForegroundColor Green -NoNewline
if ($checkCount -gt 0) { Write-Host ("CHECK: {0}   " -f $checkCount) -ForegroundColor Yellow -NoNewline }
if ($failCount  -gt 0) { Write-Host ("FAIL: {0}   " -f $failCount) -ForegroundColor Red -NoNewline }
Write-Host ("Total: {0}" -f $results.Count) -ForegroundColor DarkGray
Write-Host "  -------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

switch ($modeStr) {
    "Sanity"  { Write-Step "Sanity check complete." "OK" }
    "Migrate" {
        Write-Step "Migration complete." "OK"
        Write-Step "Devices should check in with $Controller shortly." "INFO"
    }
    "Adopt" {
        Write-Step "Adoption run complete." "OK"
        Write-Step "Watch for pending devices in the controller." "INFO"
    }
}
Write-Host ""
