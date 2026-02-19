<#
.SYNOPSIS
  UniFi Sovereign v3.2.0 — SSH-based device migration & adoption toolkit (Windows)

.DESCRIPTION
  Scans a subnet or IP list for UniFi devices via SSH, then performs:
    SANITY  — read-only credential + info check
    MIGRATE — re-point devices to a new controller (no reset)
    ADOPT   — full adoption with optional factory reset

  Auto-installs Posh-SSH. Uses SSH Shell Streams for UniFi builtins.

.PARAMETER Mode
  Operation mode: Sanity, Migrate, or Adopt.

.PARAMETER Cidr
  Target subnet (e.g. 192.168.1.0/24).

.PARAMETER IPs
  Comma-separated IP list.

.PARAMETER Controller
  Target controller IP/hostname.

.PARAMETER Username
  SSH username (default: ubnt).

.PARAMETER Password
  SSH password (plaintext).

.PARAMETER ResetFirst
  Factory reset before adoption (Adopt only).

.PARAMETER SshTimeout
  SSH timeout in seconds (default: 7).

.PARAMETER ScanTimeout
  Port scan timeout per host (default: 3).

.PARAMETER Parallel
  Max parallel scan threads (default: 128).

.PARAMETER OutCsv
  CSV output path.

.PARAMETER DryRun
  Show plan without executing.

.PARAMETER NoColor
  Disable colored output.

.PARAMETER ShowVersion
  Print version and exit.

.EXAMPLE
  .\unifi-sovereign.ps1

.EXAMPLE
  .\unifi-sovereign.ps1 -Mode Migrate -Cidr 192.168.1.0/24 -Controller 10.0.0.5

.EXAMPLE
  .\unifi-sovereign.ps1 -Mode Sanity -Cidr 10.0.1.0/24 -DryRun

.NOTES
  v3.2.0 — TUI overhaul, feature parity with bash/zsh version.
  If execution policy blocks: Set-ExecutionPolicy -Scope Process Bypass
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
    [string]$OutCsv,
    [switch]$DryRun,
    [switch]$Verbose_,
    [switch]$Quiet_,
    [switch]$NoColor,
    [switch]$ShowVersion
)

$ErrorActionPreference = "Continue"
$script:ScriptVersion = "3.2.0"
$script:UseColor = -not $NoColor

# ===================================================================
# VERSION
# ===================================================================

if ($ShowVersion) {
    Write-Host "UniFi Sovereign v$($script:ScriptVersion)"
    exit 0
}

# ===================================================================
# PLATFORM
# ===================================================================

$script:IsWindows51 = ($PSVersionTable.PSVersion.Major -le 5)
$script:IsNonWindows = $false
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $script:IsNonWindows = (-not $IsWindows)
}

# ===================================================================
# PALETTE
#
# Deep navy base, surgical red accent, muted gold secondary.
# True-color (24-bit) ANSI with automatic 16-color fallback.
# ===================================================================

$script:ESC = [char]27

function Test-TrueColorSupport {
    if ($env:COLORTERM -in @('truecolor','24bit')) { return $true }
    if ($env:TERM -match '256color|direct') { return $true }
    if ($env:WT_SESSION) { return $true }
    if ($PSVersionTable.PSVersion.Major -ge 7) { return $true }
    return $false
}

$script:TrueColor = $false
if ($script:UseColor) { $script:TrueColor = Test-TrueColorSupport }

function Write-C {
    param(
        [string]$Text,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    if ($script:UseColor) {
        Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
    } else {
        Write-Host $Text -NoNewline:$NoNewline
    }
}

# Write raw ANSI text to console
function Write-A {
    param([string]$Text, [switch]$NoNewline)
    if ($NoNewline) { [Console]::Write($Text) } else { [Console]::WriteLine($Text) }
}

# Get ANSI color escape code
function Get-Ansi([string]$Name) {
    if (-not $script:UseColor) { return "" }
    $e = $script:ESC
    if ($script:TrueColor) {
        switch ($Name) {
            'RED' { "$e[38;2;146;20;12m" }
            'GRN' { "$e[38;2;47;157;110m" }
            'GLD' { "$e[38;2;222;203;183m" }
            'CYN' { "$e[38;2;71;183;216m" }
            'MUT' { "$e[38;2;122;134;154m" }
            'WRN' { "$e[38;2;215;177;87m" }
            'TXT' { "$e[38;2;247;240;245m" }
            'DIM' { "$e[38;2;143;161;179m" }
            'BLD' { "$e[1m" }
            'RST' { "$e[0m" }
            default { "$e[0m" }
        }
    } else {
        switch ($Name) {
            'RED' { "$e[31m" }
            'GRN' { "$e[32m" }
            'GLD' { "$e[33m" }
            'CYN' { "$e[36m" }
            'MUT' { "$e[37m" }
            'WRN' { "$e[1;33m" }
            'TXT' { "$e[37m" }
            'DIM' { "$e[2m" }
            'BLD' { "$e[1m" }
            'RST' { "$e[0m" }
            default { "$e[0m" }
        }
    }
}

# ===================================================================
# OUTPUT PRIMITIVES
# ===================================================================

function Write-Rule {
    param([string]$Label = "")
    $width = 52
    Write-Host ""
    if ($Label) {
        $pad = $width - $Label.Length - 5
        if ($pad -lt 2) { $pad = 2 }
        Write-C "  ── " "DarkYellow" -NoNewline
        Write-C $Label "White" -NoNewline
        Write-C " " "DarkYellow" -NoNewline
        Write-C ("─" * $pad) "DarkYellow"
    } else {
        Write-C ("  " + ("─" * $width)) "DarkYellow"
    }
    Write-Host ""
}

function Write-Banner {
    if ($script:TrueColor) {
        $c = Get-Ansi 'CYN'; $g = Get-Ansi 'GLD'; $r = Get-Ansi 'RED'
        $t = Get-Ansi 'TXT'; $d = Get-Ansi 'DIM'; $b = Get-Ansi 'BLD'
        $x = Get-Ansi 'RST'
        Write-A ""
        Write-A "  ${c}      ▄████████████████████████▄${x}"
        Write-A "  ${c}       ▀██████████████████████▀${x}        ${t}${b}UNIFI SOVEREIGN${x}"
        Write-A "  ${c}          ▀▀██████████████▀▀${x}           ${g}━━━━━━━━━━━━━━━${x}"
        Write-A "  ${g}        ▄██████████████████████▄${x}       ${d}v$($script:ScriptVersion)${x}"
        Write-A "  ${g}         ▀██████████████████▀${x}"
        Write-A "  ${g}            ▀▀██████████▀▀${x}             ${d}SSH Device Migration${x}"
        Write-A "  ${r}          ▄████████████████████▄${x}       ${d}& Adoption${x}"
        Write-A "  ${r}           ▀████████████████▀${x}"
        Write-A "  ${r}              ▀▀████████▀▀${x}"
        Write-A ""
    } else {
        Write-Host ""
        Write-C "        ▄████████████████████████▄" "Cyan"
        Write-C "         ▀██████████████████████▀" "Cyan" -NoNewline
        Write-C "        UNIFI SOVEREIGN" "White"
        Write-C "            ▀▀██████████████▀▀" "Cyan" -NoNewline
        Write-C "           " "DarkYellow" -NoNewline
        Write-C "━━━━━━━━━━━━━━━" "DarkYellow"
        Write-C "          ▄██████████████████████▄" "DarkYellow" -NoNewline
        Write-C "       v$($script:ScriptVersion)" "DarkGray"
        Write-C "           ▀██████████████████▀" "DarkYellow"
        Write-C "              ▀▀██████████▀▀" "DarkYellow" -NoNewline
        Write-C "             SSH Device Migration" "DarkGray"
        Write-C "            ▄████████████████████▄" "Red" -NoNewline
        Write-C "       & Adoption" "DarkGray"
        Write-C "             ▀████████████████▀" "Red"
        Write-C "                ▀▀████████▀▀" "Red"
        Write-Host ""
    }
}

function Write-Info  { param([string]$Text) if (-not $Quiet_) { Write-C "  ● " "Cyan" -NoNewline; Write-Host $Text } }
function Write-Ok    { param([string]$Text) Write-C "  ● " "Green" -NoNewline; Write-Host $Text }
function Write-Warn  { param([string]$Text) Write-C "  ● " "Yellow" -NoNewline; Write-Host $Text }
function Write-Fail  { param([string]$Text) Write-C "  ● " "Red" -NoNewline; Write-Host $Text }
function Write-Opt   { param([string]$Text) if (-not $Quiet_) { Write-C "  ○ " "DarkGray" -NoNewline; Write-Host $Text } }
function Write-Item  { param([string]$Text) if (-not $Quiet_) { Write-C "  ▸ " "DarkYellow" -NoNewline; Write-Host $Text } }
function Write-Dbg   { param([string]$Text) if ($Verbose_) { Write-C "    ⌁ " "DarkGray" -NoNewline; Write-C $Text "DarkGray" } }

# Custom progress bar — gold fill, muted empty (matches bash)
function Write-ScanProgress {
    param([int]$Current, [int]$Total, [string]$Label = "")
    $width = 24
    $pct = if ($Total -gt 0) { [Math]::Floor(($Current / $Total) * 100) } else { 0 }
    $filled = [Math]::Floor($pct * $width / 100)
    $empty  = $width - $filled
    $barFill  = ([string][char]0x2501) * $filled   # ━
    $barEmpty = ([string][char]0x254C) * $empty     # ╌
    if ($script:TrueColor) {
        $g = Get-Ansi 'GLD'; $m = Get-Ansi 'MUT'; $d = Get-Ansi 'DIM'; $x = Get-Ansi 'RST'
        [Console]::Write("`r  ${d}${Label}${x}${g}${barFill}${x}${m}${barEmpty}${x}  ${d}$($pct.ToString().PadLeft(3))%  ${Current}/${Total}${x}  ")
    } else {
        Write-Host "`r  ${Label}${barFill}${barEmpty}  $($pct.ToString().PadLeft(3))%  ${Current}/${Total}  " -NoNewline
    }
}

function Write-DepLine {
    param([string]$Name, [string]$Status, [string]$StatusColor, [string]$NameColor = "Cyan")
    $dotCount = 24 - $Name.Length
    if ($dotCount -lt 2) { $dotCount = 2 }
    $dots = "·" * $dotCount
    Write-C "  " "" -NoNewline
    if ($Status -eq "installed") {
        Write-C "● " "Green" -NoNewline
    } elseif ($Status -eq "missing") {
        Write-C "● " "Red" -NoNewline
    } else {
        Write-C "○ " "DarkGray" -NoNewline
    }
    Write-C $Name $NameColor -NoNewline
    Write-C " $dots " "DarkGray" -NoNewline
    Write-C $Status $StatusColor
}

function Write-DeviceLine {
    param([string]$IP, [string]$Model, [string]$Status, [string]$Detail)
    $colIp = $IP.PadRight(16)
    $colModel = if ($Model) { $Model.PadRight(14) } else { "—".PadRight(14) }
    $statusColor = switch ($Status) {
        "OK"    { "Green" }
        "CHECK" { "Yellow" }
        "FAIL"  { "Red" }
        default { "DarkGray" }
    }
    $statusText = switch ($Status) {
        "OK"    { "  OK  " }
        "CHECK" { "CHECK " }
        "FAIL"  { " FAIL " }
        default { " ---  " }
    }
    Write-C "  ▸ " "DarkYellow" -NoNewline
    Write-C $colIp "White" -NoNewline
    Write-C $colModel "DarkGray" -NoNewline
    Write-C $statusText $statusColor -NoNewline
    Write-C $Detail "DarkGray"
}

# ===================================================================
# INTERACTIVE PROMPTS
# ===================================================================

function Read-MenuChoice {
    param([string]$Title, [string[]]$Options, [int]$Default = 1)
    Write-Host ""
    Write-C "  $Title" "White"
    Write-Host ""
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $num = $i + 1
        Write-C "    " "" -NoNewline
        Write-C "[$num]" "DarkYellow" -NoNewline
        Write-Host " $($Options[$i])"
    }
    Write-Host ""
    while ($true) {
        $raw = Read-Host "    Choice [$Default]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
        $val = 0
        if ([int]::TryParse($raw.Trim(), [ref]$val) -and $val -ge 1 -and $val -le $Options.Count) {
            return $val
        }
        Write-Warn "Enter 1-$($Options.Count)"
    }
}

function Read-YesNo {
    param([string]$Prompt, [ValidateSet('Y','N')]$Default = 'N')
    while ($true) {
        $r = Read-Host "    $Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
        $r = $r.Trim().ToUpper()
        if ($r -in @('Y','YES')) { return 'Y' }
        elseif ($r -in @('N','NO')) { return 'N' }
        Write-Warn "Y or N"
    }
}

function Read-NonEmpty {
    param([string]$Prompt)
    while ($true) {
        $v = Read-Host "    $Prompt"
        if ($v -and $v.Trim()) { return $v.Trim() }
        Write-Warn "Cannot be blank"
    }
}

function Read-WithDefault {
    param([string]$Prompt, [string]$Default)
    $v = Read-Host "    $Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

# ===================================================================
# UTILITY
# ===================================================================

function ConvertTo-SafeSecureString {
    param([string]$Plain)
    return (ConvertTo-SecureString $Plain -AsPlainText -Force)
}

function Get-DefaultCsvPath {
    param([string]$ModeStr)
    $ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $filename = "unifi-$($ModeStr.ToLower())-$ts.csv"
    $desktop = [Environment]::GetFolderPath("Desktop")
    if ($desktop -and (Test-Path $desktop)) { return Join-Path $desktop $filename }
    $homePath = [Environment]::GetFolderPath("UserProfile")
    if (-not $homePath) { $homePath = $env:HOME }
    if ($homePath -and (Test-Path $homePath)) { return Join-Path $homePath $filename }
    return Join-Path $PWD.Path $filename
}

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
# SSH SHELL STREAM
# ===================================================================

function Send-ShellCommand {
    param(
        [object]$Stream,
        [string]$Command,
        [int]$WaitMs = 3000,
        [int]$ReadRetries = 5
    )
    Start-Sleep -Milliseconds 300
    if ($Stream.DataAvailable) { $Stream.Read() | Out-Null }
    $Stream.WriteLine($Command)
    Start-Sleep -Milliseconds $WaitMs

    $output = ""
    for ($i = 0; $i -lt $ReadRetries; $i++) {
        if ($Stream.DataAvailable) {
            $output += $Stream.Read()
            Start-Sleep -Milliseconds 500
        } else {
            if ($output) { break }
            Start-Sleep -Milliseconds 1000
        }
    }

    $lines = $output -split "`n" | ForEach-Object { $_.TrimEnd("`r") }
    if ($lines.Count -gt 0 -and $lines[0].Trim() -match [regex]::Escape($Command.Trim())) {
        $lines = $lines[1..($lines.Count-1)]
    }
    if ($lines.Count -gt 0) {
        $lastLine = $lines[-1].Trim()
        if ($lastLine -match '^[A-Za-z0-9._@-]+[#\$>]\s*$' -or $lastLine -eq '' -or $lastLine -match '^\s*#\s*$') {
            if ($lines.Count -gt 1) { $lines = $lines[0..($lines.Count-2)] }
            else { $lines = @() }
        }
    }
    return ($lines -join "`n").Trim()
}

function New-ShellStream {
    param([int]$SessionId)
    $stream = New-SSHShellStream -SessionId $SessionId
    Start-Sleep -Milliseconds 2000
    if ($stream.DataAvailable) { $stream.Read() | Out-Null }
    return $stream
}

# ===================================================================
# DEVICE INTERACTION
# ===================================================================

function Get-DeviceInfo {
    param([object]$Stream, [int]$SessionId, [int]$Timeout)

    $info = @{
        Model = ""; Firmware = ""; Hostname = ""; AdoptStatus = ""
        MAC = ""; InformURL = ""; RawInfo = ""
    }

    $text = ""
    try { $text = Send-ShellCommand -Stream $Stream -Command "info" -WaitMs 3000; $info.RawInfo = $text } catch {}

    if ($text) {
        if ($text -match "Model:\s*(.+)")                        { $info.Model       = $Matches[1].Trim() }
        if ($text -match "Version:\s*(.+)")                      { $info.Firmware     = $Matches[1].Trim() }
        if ($text -match "Hostname:\s*(.+)")                     { $info.Hostname     = $Matches[1].Trim() }
        if ($text -match "Status:\s*(.+)")                       { $info.AdoptStatus  = $Matches[1].Trim() }
        if ($text -match "Inform\s*URL:\s*(.+)")                 { $info.InformURL    = $Matches[1].Trim() }
        if ($text -match "MAC\s*Address:\s*([0-9A-Fa-f:]{17})")  { $info.MAC = $Matches[1].ToLower() }
        elseif ($text -match "MAC:\s*([0-9A-Fa-f:]{17})")        { $info.MAC = $Matches[1].ToLower() }
    }

    if (-not $info.MAC) {
        foreach ($cmd in @("cat /sys/class/net/eth0/address 2>/dev/null","cat /sys/class/net/br0/address 2>/dev/null")) {
            try {
                $r = Invoke-SSHCommand -SessionId $SessionId -Command $cmd -TimeOut $Timeout -ErrorAction Stop
                $val = (($r.Output -join ' ').Trim())
                if ($val -match "([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})") {
                    $info.MAC = $Matches[1].ToLower(); break
                }
            } catch {}
        }
    }
    return $info
}

function Send-SetInform {
    param([object]$Stream, [string]$InformUrl, [int]$Attempt = 1)

    $result = @{ Output = ""; Success = $false; Method = "" }

    $out1 = ""
    try {
        $out1 = Send-ShellCommand -Stream $Stream -Command "set-inform $InformUrl" -WaitMs 4000
        $result.Output = $out1; $result.Method = "set-inform"
    } catch { $result.Output = "ERROR: $($_.Exception.Message)" }

    if ($out1 -match 'Adoption request sent|Inform URL|inform|adopted|Resolve|set-inform') {
        $result.Success = $true; return $result
    }

    $out2 = ""
    try {
        $out2 = Send-ShellCommand -Stream $Stream -Command "mca-cli-op set-inform $InformUrl" -WaitMs 4000
        $result.Output = $out2; $result.Method = "mca-cli-op"
    } catch { $result.Output += " | mca-cli-op ERROR: $($_.Exception.Message)" }

    if ($out2 -match 'Adoption request sent|Inform URL|inform|adopted|Resolve|set-inform') {
        $result.Success = $true; return $result
    }

    if (($out1 -or $out2) -and $out1 -notmatch 'not found|unknown|error|denied|invalid' -and $out2 -notmatch 'not found|unknown|error|denied|invalid') {
        $result.Success = $true
        $result.Output = "set-inform: [$out1] | mca-cli-op: [$out2]"
        $result.Method = "accepted (non-standard)"
        return $result
    }
    return $result
}

function Invoke-HardReset {
    param([object]$Stream, [int]$SessionId, [int]$Timeout, [string]$Ip)

    function Try-ExecReset {
        param([int]$Sid, [string]$Cmd, [int]$T)
        try {
            $r = Invoke-SSHCommand -SessionId $Sid -Command $Cmd -TimeOut $T -ErrorAction Stop
            if ($r.ExitStatus -eq 42) { return "skip" }
            return "ok"
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'Unable to connect|not available|reset|broken pipe|closed|failed|timed out|timeout') {
                return "session_died"
            }
            return "error"
        }
    }

    $cmd1 = @'
sh -c 'if [ -f /tmp/default.cfg ]; then cp -f /tmp/default.cfg /tmp/system.cfg && { which cfgmtd >/dev/null 2>&1 && cfgmtd -f /tmp/system.cfg -w || /sbin/cfgmtd -f /tmp/system.cfg -w ; } && sync && sleep 1 && reboot; elif [ -f /etc/default.cfg ]; then cp -f /etc/default.cfg /tmp/system.cfg && { which cfgmtd >/dev/null 2>&1 && cfgmtd -f /tmp/system.cfg -w || /sbin/cfgmtd -f /tmp/system.cfg -w ; } && sync && sleep 1 && reboot; else exit 42; fi'
'@
    $r1 = Try-ExecReset -Sid $SessionId -Cmd $cmd1 -T $Timeout
    if ($r1 -in @("ok","session_died")) { return @{ ok=$true; note="cfgmtd" } }

    try { Send-ShellCommand -Stream $Stream -Command "syswrapper.sh restore-default" -WaitMs 5000 | Out-Null; return @{ ok=$true; note="syswrapper" } } catch {}

    $r2 = Try-ExecReset -Sid $SessionId -Cmd "syswrapper.sh restore-default" -T $Timeout
    if ($r2 -in @("ok","session_died")) { return @{ ok=$true; note="syswrapper" } }

    try { Send-ShellCommand -Stream $Stream -Command "set-default" -WaitMs 5000 | Out-Null; return @{ ok=$true; note="set-default" } } catch {}

    $r3 = Try-ExecReset -Sid $SessionId -Cmd "set-default" -T $Timeout
    if ($r3 -in @("ok","session_died")) { return @{ ok=$true; note="set-default" } }

    return @{ ok=$false; note="all methods exhausted" }
}

function Test-ControllerEndpoint {
    param([string]$Ctrl)
    $url = "http://${Ctrl}:8080/inform"
    try {
        Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec 5 | Out-Null
        Write-Ok "Controller reachable ($url)"
        return $true
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 400) {
            Write-Ok "Controller reachable ($url)"
            return $true
        }
        Write-Warn "Controller unreachable ($url)"
        return $false
    }
}

# ===================================================================
# PREREQUISITES
# ===================================================================

function Install-Prerequisites {
    Write-Rule "Prerequisites"

    $platform = if ($script:IsNonWindows) { "PowerShell $($PSVersionTable.PSVersion) (cross-platform)" } else { "Windows PowerShell $($PSVersionTable.PSVersion)" }
    Write-Info "Platform: $platform"
    Write-Host ""

    # NuGet (Windows PS 5.1 only)
    if ($script:IsWindows51) {
        $nuget = Get-PackageProvider -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'NuGet' }
        if (-not $nuget -or ($nuget.Version -lt [version]"2.8.5.201")) {
            Write-DepLine "NuGet" "missing" "Red" "Cyan"
            Write-Info "Installing NuGet provider..."
            try {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
                Write-DepLine "NuGet" "installed" "Green" "Cyan"
            } catch {
                Write-DepLine "NuGet" "failed" "Red" "Cyan"
            }
        } else {
            Write-DepLine "NuGet" "installed" "Green" "Cyan"
        }
    }

    # PSGallery trust
    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }

    # Posh-SSH
    if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
        Write-DepLine "Posh-SSH" "missing" "Red" "Cyan"
        Write-Host ""
        $answer = Read-YesNo "Install Posh-SSH from PowerShell Gallery?" "Y"
        if ($answer -eq 'Y') {
            Write-Info "Installing Posh-SSH..."
            try {
                Install-Module Posh-SSH -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-DepLine "Posh-SSH" "installed" "Green" "Cyan"
            } catch {
                Write-Fail "Posh-SSH install failed"
                Write-Host "    Try: Install-Module Posh-SSH -Scope CurrentUser -Force" -ForegroundColor DarkGray
                exit 1
            }
        } else {
            Write-Fail "Posh-SSH is required"
            exit 1
        }
    } else {
        Write-DepLine "Posh-SSH" "installed" "Green" "Cyan"
    }

    Import-Module Posh-SSH -ErrorAction Stop

    # PowerShell version check
    Write-DepLine "PowerShell" "v$($PSVersionTable.PSVersion)" "Green" "Cyan"

    Write-Host ""
    Write-Ok "Ready"
}

# ===================================================================
# PORT SCAN (parallel runspaces)
# ===================================================================

function Invoke-PortScan {
    param([string[]]$Targets, [int]$TimeoutSec, [int]$MaxParallel)

    Write-Rule "Scan"
    Write-Info "Sweeping $($Targets.Count) hosts for SSH (TCP/22)"
    Write-Host ""

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
    $done = 0; $jobTotal = $jobs.Count

    foreach ($j in $jobs) {
        $done++
        Write-ScanProgress -Current $done -Total $jobTotal
        try { $hit = $j.Handle.EndInvoke($j.Task) } catch { $hit = $null }
        $j.Handle.Dispose()
        if ($hit) { $open.Add($hit) | Out-Null }
    }

    Write-Host ("`r" + (" " * 80) + "`r") -NoNewline  # clear progress line
    $pool.Close(); $pool.Dispose()

    Write-Host ""
    if ($open.Count -eq 0) {
        Write-Fail "No hosts with SSH open"
        exit 1
    }

    Write-Ok "$($open.Count) hosts responding"
    return $open.ToArray()
}

# ===================================================================
# MAIN
# ===================================================================

Write-Banner

if ($DryRun) {
    Write-Warn "DRY RUN — no changes will be made"
    Write-Host ""
}

Install-Prerequisites

# ── Mode ──
$modeStr = $Mode
if (-not $modeStr) {
    $mc = Read-MenuChoice -Title "Operation mode:" -Options @(
        "SANITY   — verify SSH access, collect device info (read-only)",
        "MIGRATE  — re-point devices to a new controller (no reset)",
        "ADOPT    — full adoption with optional factory reset",
        "EXIT     — quit"
    ) -Default 1
    switch ($mc) {
        1 { $modeStr = "Sanity" }
        2 { $modeStr = "Migrate" }
        3 { $modeStr = "Adopt" }
        4 { Write-Host ""; Write-Info "Exited."; Write-Host ""; exit 0 }
    }
}
$modeStr = $modeStr.Substring(0,1).ToUpper() + $modeStr.Substring(1).ToLower()

Write-Rule "Configuration"
Write-Info "Mode: $($modeStr.ToUpper())"

# ── Targets ──
$targetList = @()
if ($Cidr) {
    try { $targetList = Get-IPsFromCidr $Cidr } catch { Write-Fail $_.Exception.Message; exit 1 }
} elseif ($IPs) {
    $targetList = ($IPs -split '[,\s]+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -Unique
} else {
    $tc = Read-MenuChoice -Title "Target input:" -Options @(
        "CIDR subnet  (e.g. 192.168.1.0/24)",
        "IP list      (comma-separated)",
        "EXIT"
    ) -Default 1
    if ($tc -eq 3) { Write-Host ""; Write-Info "Exited."; Write-Host ""; exit 0 }
    if ($tc -eq 2) {
        $raw = Read-NonEmpty "IPs (comma-separated)"
        $targetList = ($raw -split '[,\s]+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -Unique
    } else {
        $raw = Read-NonEmpty "CIDR (e.g. 192.168.1.0/24)"
        try { $targetList = Get-IPsFromCidr $raw } catch { Write-Fail $_.Exception.Message; exit 1 }
    }
}

if ($targetList.Count -eq 0) { Write-Fail "No valid target IPs"; exit 1 }
Write-Info "Targets: $($targetList.Count) IPs"

# ── Controller ──
$informUrl = ""; $doReset = $false
if ($modeStr -in @("Migrate","Adopt")) {
    if (-not $Controller) { $Controller = Read-NonEmpty "Target controller IP or hostname" }
    $informUrl = "http://${Controller}:8080/inform"
    Write-Info "Inform URL: $informUrl"
    Test-ControllerEndpoint -Ctrl $Controller | Out-Null

    if ($modeStr -eq "Adopt") {
        if ($ResetFirst) { $doReset = $true }
        elseif (-not $PSBoundParameters.ContainsKey('ResetFirst')) {
            $doReset = (Read-YesNo "Factory reset before adoption?" 'N') -eq 'Y'
        }
        if ($doReset) { Write-Warn "Factory reset: ENABLED" }
    }
}

# ── Credentials ──
Write-Rule "Credentials"
$credSpec = @()
if ($Username) {
    $pw = if ($Password) { ConvertTo-SafeSecureString $Password } else { Read-Host "Password for '$Username'" -AsSecureString }
    $credSpec += @{u=$Username; p=$pw}
} elseif (-not $PSBoundParameters.ContainsKey('Username')) {
    if ((Read-YesNo "Provide a known SSH credential?" 'N') -eq 'Y') {
        $u = Read-NonEmpty "SSH username"
        $p = Read-Host "    SSH password" -AsSecureString
        $credSpec += @{u=$u; p=$p}
    }
}
$credSpec += @{u='ubnt'; p=(ConvertTo-SafeSecureString 'ubnt')}
$credSpec += @{u='root'; p=(ConvertTo-SafeSecureString 'ubnt')}
$credSpec += @{u='admin'; p=(ConvertTo-SafeSecureString 'ubnt')}

$credChain = ($credSpec | ForEach-Object { $_.u }) -join ' → '
Write-Info "Credential chain: $credChain"

# ── CSV ──
if (-not $OutCsv) {
    $defaultPath = Get-DefaultCsvPath $modeStr
    $OutCsv = Read-WithDefault "CSV output path" $defaultPath
}

# ── Plan ──
Write-Rule "Plan"
Write-Item "Mode         $($modeStr.ToUpper())"
Write-Item "Targets      $($targetList.Count) IPs"
if ($informUrl) {
    Write-Item "Controller   $Controller"
    Write-Item "Inform URL   $informUrl"
}
if ($doReset) { Write-C "  ▸ " "DarkYellow" -NoNewline; Write-C "Reset        " "" -NoNewline; Write-C "YES" "Red" }
Write-Item "SSH Timeout  ${SshTimeout}s"
Write-Item "Parallel     $Parallel threads"
Write-Item "Output       $OutCsv"

if ($DryRun) {
    Write-Host ""
    Write-Warn "DRY RUN — stopping before execution"
    exit 0
}

Write-Host ""
if ((Read-YesNo "Execute?" 'Y') -ne 'Y') { Write-Host ""; Write-Info "Aborted."; exit 0 }

# ── Scan ──
$openHosts = Invoke-PortScan -Targets $targetList -TimeoutSec $ScanTimeout -MaxParallel $Parallel

# ── Process ──
Write-Rule "Processing"

$credList = Build-CredList $credSpec
$results  = @()
$total    = $openHosts.Count
$countOk = 0; $countCheck = 0; $countFail = 0

for ($idx = 0; $idx -lt $total; $idx++) {
    $ip  = $openHosts[$idx]
    $num = $idx + 1

    $row = [ordered]@{
        Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        IP = $ip; MAC = ""; Connected = $false; Username = ""
        Model = ""; DevHostname = ""; Firmware = ""; AdoptStatus = ""
        CurrentInform = ""; Reset = "N/A"; Inform1 = "N/A"; Inform2 = "N/A"
        InformMethod = ""; Status = "FAIL"; Note = ""; DebugInfo = ""
    }

    try {
        # SSH connect with retry
        $sess = $null; $ok = $false; $used = $null
        foreach ($c in $credList) {
            try {
                $sess = New-SSHSession -ComputerName $ip -Credential $c -AcceptKey -ConnectionTimeout $SshTimeout -ErrorAction Stop
                $used = $c.UserName; $ok = $true; break
            } catch {}
            # Retry once
            Start-Sleep -Milliseconds 1000
            try {
                $sess = New-SSHSession -ComputerName $ip -Credential $c -AcceptKey -ConnectionTimeout $SshTimeout -ErrorAction Stop
                $used = $c.UserName; $ok = $true; break
            } catch {}
        }

        if (-not $ok) {
            $row.Note = "SSH auth failed"
            Write-DeviceLine $ip "" "FAIL" "SSH auth failed"
            $countFail++
            $results += [pscustomobject]$row; continue
        }

        $row.Connected = $true; $row.Username = $used

        # Shell stream
        $stream = $null
        try { $stream = New-ShellStream -SessionId $sess.SessionId } catch {}

        # Device info
        if ($stream) {
            $devInfo = Get-DeviceInfo -Stream $stream -SessionId $sess.SessionId -Timeout ($SshTimeout * 2)
        } else {
            $devInfo = @{ Model=""; Firmware=""; Hostname=""; AdoptStatus=""; MAC=""; InformURL=""; RawInfo="" }
            foreach ($cmd in @("cat /sys/class/net/eth0/address 2>/dev/null","cat /sys/class/net/br0/address 2>/dev/null")) {
                try {
                    $r = Invoke-SSHCommand -SessionId $sess.SessionId -Command $cmd -TimeOut ($SshTimeout * 2) -ErrorAction Stop
                    $val = (($r.Output -join ' ').Trim())
                    if ($val -match "([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})") { $devInfo.MAC = $Matches[1].ToLower(); break }
                } catch {}
            }
        }

        $row.MAC           = $devInfo.MAC
        $row.Model         = $devInfo.Model
        $row.Firmware      = $devInfo.Firmware
        $row.DevHostname   = $devInfo.Hostname
        $row.AdoptStatus   = $devInfo.AdoptStatus
        $row.CurrentInform = $devInfo.InformURL
        $row.DebugInfo     = ($devInfo.RawInfo -replace "`n"," | " -replace "`r","").Trim()

        # SANITY
        if ($modeStr -eq "Sanity") {
            $row.Status = "OK"; $countOk++
            $adoptDisplay = if ($devInfo.AdoptStatus) { $devInfo.AdoptStatus } else { "unknown" }
            Write-DeviceLine $ip $devInfo.Model "OK" $adoptDisplay
            if ($stream) { $stream.Dispose() }
            Remove-SSHSession -SessionId $sess.SessionId | Out-Null
            $results += [pscustomobject]$row; continue
        }

        # ADOPT reset
        if ($modeStr -eq "Adopt" -and $doReset) {
            Write-Info "${ip}: sending factory reset..."
            $reset = Invoke-HardReset -Stream $stream -SessionId $sess.SessionId -Timeout $SshTimeout -Ip $ip
            if ($reset.ok) {
                $row.Reset = "OK ($($reset.note))"
                Write-Info "${ip}: reset sent, waiting 90s..."
                try { if ($stream) { $stream.Dispose() } } catch {}
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
                    Write-DeviceLine $ip $devInfo.Model "FAIL" "not back after reset"
                    $countFail++; $results += [pscustomobject]$row; continue
                }
                $row.Username = $used
                try { $stream = New-ShellStream -SessionId $sess.SessionId } catch { $stream = $null }
            } else {
                $row.Reset = "Failed"; $row.Note = $reset.note
                Write-Warn "${ip}: reset failed ($($reset.note))"
            }
        }

        # MIGRATE / ADOPT: set-inform
        if (-not $stream) {
            $row.Note = "Shell stream unavailable"; $row.Status = "FAIL"; $countFail++
            Write-DeviceLine $ip $devInfo.Model "FAIL" "no shell stream"
            try { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } catch {}
            $results += [pscustomobject]$row; continue
        }

        $si1 = Send-SetInform -Stream $stream -InformUrl $informUrl -Attempt 1
        $row.Inform1 = $si1.Output
        if ($si1.Method) { $row.InformMethod = $si1.Method }

        Start-Sleep -Seconds 5

        $si2 = Send-SetInform -Stream $stream -InformUrl $informUrl -Attempt 2
        $row.Inform2 = $si2.Output
        if ($si2.Method -and -not $row.InformMethod) { $row.InformMethod = $si2.Method }

        if ($si1.Success -or $si2.Success) {
            $row.Status = "OK"; $countOk++
            $methodNote = if ($row.InformMethod) { "($($row.InformMethod))" } else { "" }
            Write-DeviceLine $ip $devInfo.Model "OK" "set-inform accepted $methodNote"
        } else {
            $row.Status = "CHECK"; $countCheck++
            $row.Note = ($row.Note + "; verify in controller").Trim('; ')
            Write-DeviceLine $ip $devInfo.Model "CHECK" "verify in controller"
        }

        if ($stream) { $stream.Dispose() }
        Remove-SSHSession -SessionId $sess.SessionId | Out-Null
        $results += [pscustomobject]$row

    } catch {
        $row.Status = "FAIL"; $row.Note = $_.Exception.Message; $countFail++
        Write-DeviceLine $ip "" "FAIL" $_.Exception.Message
        try { if ($stream) { $stream.Dispose() } } catch {}
        try { if ($sess) { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } } catch {}
        $results += [pscustomobject]$row
    }
}

# ── Results ──
Write-Rule "Results"

$totalProcessed = $countOk + $countCheck + $countFail
$cardWidth = 36

Write-C "  ┌$("─" * $cardWidth)┐" "DarkYellow"
Write-C "  │" "DarkYellow" -NoNewline; Write-C "  Scanned          " "DarkGray" -NoNewline; Write-C "$($total)".PadRight($cardWidth - 20) "Cyan" -NoNewline; Write-C "│" "DarkYellow"
Write-C "  │" "DarkYellow" -NoNewline; Write-C "  SSH accessible   " "DarkGray" -NoNewline; Write-C "$($totalProcessed)".PadRight($cardWidth - 20) "White" -NoNewline; Write-C "│" "DarkYellow"
Write-C "  │" "DarkYellow" -NoNewline; Write-C "  Successful       " "DarkGray" -NoNewline; Write-C "$($countOk)".PadRight($cardWidth - 20) "Green" -NoNewline; Write-C "│" "DarkYellow"
if ($countCheck -gt 0) {
    Write-C "  │" "DarkYellow" -NoNewline; Write-C "  Needs attention  " "DarkGray" -NoNewline; Write-C "$($countCheck)".PadRight($cardWidth - 20) "Yellow" -NoNewline; Write-C "│" "DarkYellow"
}
if ($countFail -gt 0) {
    Write-C "  │" "DarkYellow" -NoNewline; Write-C "  Failed           " "DarkGray" -NoNewline; Write-C "$($countFail)".PadRight($cardWidth - 20) "Red" -NoNewline; Write-C "│" "DarkYellow"
}
Write-C "  ├$("─" * $cardWidth)┤" "DarkYellow"
Write-C "  │" "DarkYellow" -NoNewline; Write-C "  Output  " "DarkGray" -NoNewline
$csvDisplay = $OutCsv
if ($csvDisplay.Length -gt ($cardWidth - 11)) { $csvDisplay = "..." + $csvDisplay.Substring($csvDisplay.Length - ($cardWidth - 14)) }
Write-C $csvDisplay.PadRight($cardWidth - 10) "DarkYellow" -NoNewline; Write-C "│" "DarkYellow"
Write-C "  └$("─" * $cardWidth)┘" "DarkYellow"

# Export CSV with metadata header
try {
    $metaLine = "# UniFi Sovereign v$($script:ScriptVersion) | Mode: $($modeStr.ToUpper()) | Targets: $total | Date: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
    Set-Content -Path $OutCsv -Value $metaLine -ErrorAction Stop
    $results | Sort-Object IP | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 0 | Add-Content -Path $OutCsv
} catch {
    $fallback = Get-DefaultCsvPath $modeStr
    Write-Warn "Cannot write to '$OutCsv' — trying '$fallback'"
    try {
        Set-Content -Path $fallback -Value $metaLine
        $results | Sort-Object IP | ConvertTo-Csv -NoTypeInformation | Add-Content -Path $fallback
        $OutCsv = $fallback
    } catch { Write-Fail "CSV write failed: $($_.Exception.Message)" }
}

Write-Host ""
switch ($modeStr) {
    "Sanity"  { Write-Ok "Sanity check complete." }
    "Migrate" { Write-Ok "Migration complete. Devices should appear on $Controller shortly." }
    "Adopt"   { Write-Ok "Adoption run complete. Check controller for pending devices." }
}
Write-Host ""
