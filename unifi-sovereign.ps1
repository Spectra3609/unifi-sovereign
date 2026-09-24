<#
.SYNOPSIS
  UniFi Sovereign v3.8.0 -- SSH-based device migration & adoption toolkit (Windows)

.DESCRIPTION
  Scans a subnet or IP list for UniFi devices via SSH, then performs:
    SANITY  -- read-only credential + info check
    MIGRATE -- re-point devices to a new controller (no reset)
    ADOPT   -- full adoption with optional factory reset

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

.PARAMETER SkipAdopted
  Skip devices already connected to any controller. Only touches unadopted/pending devices.

.PARAMETER RestoreNames
  After adoption, restore each device's original name via the controller API.

.PARAMETER ApiKey
  UniFi OS API key for controller auth (preferred - generate in UI under Settings > API Keys).

.PARAMETER ApiUser
  Controller admin username (fallback auth if -ApiKey not provided).

.PARAMETER ApiPass
  Controller admin password (fallback auth if -ApiKey not provided).

.PARAMETER ApiPort
  Controller API port (default: 443).

.PARAMETER SshTimeout
  SSH timeout in seconds (default: 7).

.PARAMETER ScanTimeout
  Port scan timeout per host (default: 3).

.PARAMETER Parallel
  Max parallel scan threads (default: 128).

.PARAMETER OutCsv
  CSV output path.

.PARAMETER InCsv
  CSV input path.
    Rename mode: reads MAC+hostname pairs from a prior scan CSV.
    Sanity/Migrate/Adopt: reads IP column as the target list. If the CSV
      also has a MAC column, the MAC is validated after SSH contact and
      mismatches are flagged in the Note field (device-on-wrong-IP check).

.PARAMETER Class
  Device class filter for Migrate/Adopt. One of: All, AP, Switch, Gateway, Other.
  Model prefix classifier: UAP*/U7*/U6*/UA* = AP; USW*/US-* = Switch;
  UDM*/USG*/UXG* = Gateway; anything else = Other.
  Omit the flag to get an interactive post-discovery selection menu (recommended).

.PARAMETER StrictMacMatch
  When -InCsv is used with MAC data, refuse to act on devices whose MAC
  does not match the CSV entry. Default: warn and proceed.

.PARAMETER AdoptPending
  Rename / -RestoreNames: devices the controller lists as pending adoption
  (e.g. after a factory reset) are adopted via the controller API first,
  since a name only sticks on an adopted device. Without this flag you are
  asked interactively; with -Quiet_ they are reported and skipped.

.PARAMETER AdoptWait
  Seconds to wait for API-adopted devices to finish adopting (default: 180).

.PARAMETER Site
  Controller site name or description to search. Default: every site the
  account can see.

.PARAMETER ScanRetries
  Extra TCP/22 sweep passes over hosts that did not answer (default: 1).
  Catches devices that dropped the first SYN (ARP storms, busy/mesh APs).

.PARAMETER ResetWait
  Max seconds to wait for a device to come back after factory reset
  (default: 240). Polls from 60s onward instead of a single fixed wait.

.PARAMETER StrictHostKeys
  Enforce Posh-SSH's stored host keys. Off by default because a factory
  reset regenerates the device host key (and DHCP can move devices between
  IPs), which otherwise fails the connection as "Key exchange negotiation
  failed".

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
  v3.7.0 -- CSV target ingest + class filter for Migrate/Adopt.
    -InCsv  : works in Sanity/Migrate/Adopt now (reads IP column for targets,
              validates MAC on SSH contact if MAC column present).
    -Class  : AP/Switch/Gateway/Other/All. Omit for interactive post-scan menu.
  If execution policy blocks: Set-ExecutionPolicy -Scope Process Bypass
#>

[CmdletBinding()]
param(
    [ValidateSet("Sanity","Migrate","Adopt","Rename")]
    [string]$Mode,
    [string]$Cidr,
    [string]$IPs,
    [string]$Controller,
    [string]$Username,
    [string]$Password,
    [switch]$ResetFirst,
    [switch]$SkipAdopted,
    [switch]$RestoreNames,
    [string]$ApiKey,
    [string]$ApiUser,
    [string]$ApiPass,
    [int]$ApiPort = 443,
    [int]$SshTimeout = 7,
    [int]$ScanTimeout = 3,
    [int]$Parallel = 128,
    [string]$OutCsv,
    [string]$InCsv,
    [ValidateSet("All","AP","Switch","Gateway","Other")]
    [string]$Class,
    [switch]$StrictMacMatch,
    [switch]$AdoptPending,
    [int]$AdoptWait = 180,
    [string]$Site,
    [int]$ScanRetries = 1,
    [int]$ResetWait = 240,
    [switch]$StrictHostKeys,
    [switch]$DryRun,
    [switch]$Verbose_,
    [switch]$Quiet_,
    [switch]$NoColor,
    [switch]$ShowVersion
)

# Force UTF-8 output if possible (PS 5.1 compat)
if ($PSVersionTable.PSVersion.Major -le 5) {
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
}

$ErrorActionPreference = "Continue"
$script:ScriptVersion = "3.8.0"
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
    if ($script:UseColor -and $Color) {
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
        Write-C "  -- " "DarkYellow" -NoNewline
        Write-C $Label "White" -NoNewline
        Write-C " " "DarkYellow" -NoNewline
        Write-C ("-" * $pad) "DarkYellow"
    } else {
        Write-C ("  " + ("-" * $width)) "DarkYellow"
    }
    Write-Host ""
}

function Write-Banner {
    if ($script:TrueColor) {
        $c = Get-Ansi 'CYN'; $g = Get-Ansi 'GLD'; $r = Get-Ansi 'RED'
        $t = Get-Ansi 'TXT'; $d = Get-Ansi 'DIM'; $b = Get-Ansi 'BLD'
        $x = Get-Ansi 'RST'
        Write-A ""
        Write-A "  ${c}         /\                   ${x}"
        Write-A "  ${c}        /  \                  ${x}        ${t}${b}UNIFI SOVEREIGN${x}"
        Write-A "  ${c}       /____\                 ${x}           ${g}===============${x}"
        Write-A "  ${g}          /\                  ${x}       ${d}v$($script:ScriptVersion)${x}"
        Write-A "  ${g}         /  \                 ${x}"
        Write-A "  ${g}        /____\                ${x}             ${d}SSH Device Migration${x}"
        Write-A "  ${r}           /\                 ${x}       ${d}& Adoption${x}"
        Write-A "  ${r}          /  \                ${x}"
        Write-A "  ${r}         /____\               ${x}"
        Write-A ""
    } else {
        Write-Host ""
        Write-C "           /\                   " "Cyan"
        Write-C "          /  \                  " "Cyan" -NoNewline
        Write-C "        UNIFI SOVEREIGN" "White"
        Write-C "         /____\                 " "Cyan" -NoNewline
        Write-C "           " "DarkYellow" -NoNewline
        Write-C "===============" "DarkYellow"
        Write-C "            /\                  " "DarkYellow" -NoNewline
        Write-C "       v$($script:ScriptVersion)" "DarkGray"
        Write-C "           /  \                 " "DarkYellow"
        Write-C "          /____\                " "DarkYellow" -NoNewline
        Write-C "             SSH Device Migration" "DarkGray"
        Write-C "             /\                 " "Red" -NoNewline
        Write-C "       & Adoption" "DarkGray"
        Write-C "            /  \                " "Red"
        Write-C "           /____\               " "Red"
        Write-Host ""
    }
}

function Write-Info  { param([string]$Text) if (-not $Quiet_) { Write-C "  * " "Cyan" -NoNewline; Write-Host $Text } }
function Write-Ok    { param([string]$Text) Write-C "  * " "Green" -NoNewline; Write-Host $Text }
function Write-Warn  { param([string]$Text) Write-C "  * " "Yellow" -NoNewline; Write-Host $Text }
function Write-Fail  { param([string]$Text) Write-C "  * " "Red" -NoNewline; Write-Host $Text }
function Write-Opt   { param([string]$Text) if (-not $Quiet_) { Write-C "  o " "DarkGray" -NoNewline; Write-Host $Text } }
function Write-Item  { param([string]$Text) if (-not $Quiet_) { Write-C "  > " "DarkYellow" -NoNewline; Write-Host $Text } }
function Write-Dbg   { param([string]$Text) if ($Verbose_) { Write-C "    ~ " "DarkGray" -NoNewline; Write-C $Text "DarkGray" } }

# Custom progress bar -- gold fill, muted empty (matches bash)
function Write-ScanProgress {
    param([int]$Current, [int]$Total, [string]$Label = "")
    $width = 24
    $pct = if ($Total -gt 0) { [Math]::Floor(($Current / $Total) * 100) } else { 0 }
    $filled = [Math]::Floor($pct * $width / 100)
    $empty  = $width - $filled
    $barFill  = "=" * $filled
    $barEmpty = "-" * $empty
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
    $dots = "." * $dotCount
    Write-C "  " "" -NoNewline
    if ($Status -eq "installed") {
        Write-C "* " "Green" -NoNewline
    } elseif ($Status -eq "missing") {
        Write-C "* " "Red" -NoNewline
    } else {
        Write-C "o " "DarkGray" -NoNewline
    }
    Write-C $Name $NameColor -NoNewline
    Write-C " $dots " "DarkGray" -NoNewline
    Write-C $Status $StatusColor
}

function Write-DeviceLine {
    param([string]$IP, [string]$Model, [string]$Status, [string]$Detail)
    $colIp = $IP.PadRight(16)
    $colModel = if ($Model) { $Model.PadRight(14) } else { "--".PadRight(14) }
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
    Write-C "  > " "DarkYellow" -NoNewline
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

function Get-DeviceClass {
    # Map a UniFi device Model string to a coarse class for filtering.
    # Prefix-based: handles known U-series naming conventions.
    # Returns one of: AP, Switch, Gateway, Other.
    param([string]$Model)
    if (-not $Model) { return "Other" }
    $m = $Model.ToUpper().Trim()

    # Access Points -- covers UAP legacy and U-gen (U6/U7/UA/UACC-AP) including
    # variants: UAP-AC-Pro, UAP-AC-Pro-Gen2, UAP-AC-LR, UAP-LR, UAP-nanoHD,
    # UAP-IW, UAP-IW-HD, UAP-FlexHD, UAP-HD, UAP-Outdoor+, UAP-AC-M, UAP-AC-M-PRO,
    # U6-Lite, U6-LR, U6-Pro, U6-Mesh, U6-Enterprise, U6-IW, U7-Pro, U7-Outdoor,
    # UACC-AP (access control), UA-G2 (UniFi Access G2 reader -- still AP class).
    # Also the board short codes some firmware reports instead of the marketing
    # name (U7PG2, U7LT, U7NHD, UAL6, UALR6, UAP6MP, U6ENT, U6+, UCMSH, BZ2...),
    # E7 (Enterprise 7), UK-Ultra, UWB-XG, UDB (Device Bridge), legacy U2/U5.
    # Anchored match so we don't catch UDM by accident.
    if ($m -match '^(UAP|U6|U7|E7|UAL|UAE|UAM|UAIW|UACC-AP|UA[-_]|UK[-_]|UWB|UDB|U2|U5|BZ2|UCMSH|UFLHD|UHDIW)') { return "AP" }

    # Gateways / consoles -- UDM (UDM-Pro, UDM-SE, UDM-Base), UDR, UDW, USG
    # (USG-Pro, USG-3P), UXG (UXG-Pro, UXG-Lite), UCG (Cloud Gateway Ultra/Max),
    # UX-*, UCK (Cloud Key Gen1/Gen2). Checked before switches so USG* is not
    # swallowed by the US* switch prefix.
    if ($m -match '^(UDM|UDR|UDW|USG|UXG|UCG|UX[-_]|UX$|UCK)') { return "Gateway" }

    # Switches -- USW-*, US-*, USW-Flex, USW-Enterprise, USW-Pro, USW-Aggregation,
    # US-8, US-16, US-24, US-48, USW-Lite, USW-Mission-Critical, plus short codes
    # (US8P60, US24P250, USL16LP, USMINI, USF5P, USC8, ...), EdgeSwitch ES-*.
    if ($m -match '^(US|ES[-_])') { return "Switch" }

    return "Other"
}

function Test-HasRadio {
    # True if the device exposes any 802.11 PHY. Fallback classifier for
    # devices whose model string is empty or unrecognised.
    param([int]$SessionId, [int]$Timeout)
    try {
        $r = Invoke-SSHCommand -SessionId $SessionId -Command "ls /sys/class/ieee80211 2>/dev/null" -TimeOut $Timeout -ErrorAction Stop
        return [bool](($r.Output -join '').Trim())
    } catch { return $false }
}

function Resolve-DeviceClass {
    # Model-prefix class, falling back to a radio probe when the model is
    # unknown so an AP with a slow/empty `info` isn't filtered out as Other.
    param([string]$Model, [int]$SessionId, [int]$Timeout)
    $cls = Get-DeviceClass $Model
    if ($cls -eq "Other" -and (Test-HasRadio -SessionId $SessionId -Timeout $Timeout)) { return "AP" }
    return $cls
}

function Test-DeviceAdopted {
    # Is the device managed by some controller? The factory default inform
    # target (http://unifi:8080/inform) and "Not Adopted" status mean no --
    # treating those as adopted made -SkipAdopted silently drop freshly reset
    # devices.
    param([string]$AdoptStatus, [string]$InformUrl)
    $s = "$AdoptStatus"
    if ($s -match '(?i)not\s*adopted|unadopted|default') { return $false }
    if ($s -match '(?i)^\s*connected') { return $true }
    $informHost = ""
    if ($InformUrl -match '://([^:/]+)') { $informHost = $Matches[1].ToLower() }
    if ($informHost -eq 'unifi') { return $false }
    return [bool]$informHost
}

function ConvertTo-NormalMac {
    # Accepts aa:bb:.., AA-BB-.., aabb.ccdd.eeff or bare hex; returns aa:bb:cc:dd:ee:ff or "".
    param([string]$Mac)
    if (-not $Mac) { return "" }
    $hex = ($Mac -replace '[^0-9A-Fa-f]', '').ToLower()
    if ($hex.Length -ne 12) { return "" }
    return (($hex -split '(..)' | Where-Object { $_ }) -join ':')
}

function Connect-DeviceSsh {
    # Every device SSH session goes through here. Unless -StrictHostKeys is
    # set, the stored host-key check is skipped: a factory reset regenerates
    # the key, and SSH.NET then aborts with "Key exchange negotiation failed"
    # -- which broke post-reset re-login and every later run against reset APs.
    param([string]$Ip, [pscredential]$Credential, [int]$Timeout)
    $p = @{ ComputerName = $Ip; Credential = $Credential; ConnectionTimeout = $Timeout; ErrorAction = 'Stop' }
    if ($StrictHostKeys) { $p.AcceptKey = $true } else { $p.Force = $true }
    return New-SSHSession @p
}

function Wait-InformVerified {
    # Poll the device's info output with backoff until its reported inform URL
    # matches the target host, or the timeout budget runs out.
    #
    # Returns: @{ Verified=$true|$false; PostInform=""; PostHost=""; Attempts=n }
    #
    # Rationale: a single 3s post-check catches fast devices but misses slower
    # firmware (seen on UAP-AC-Pro-Gen2) that can take 10-20s to update its
    # local `info` output after set-inform. Polling with backoff gives those
    # devices room without slowing down the fast ones.
    param(
        [object]$Stream,
        [int]$SessionId,
        [int]$Timeout,
        [string]$TargetHost,
        [string]$ControllerName,
        [string]$Ip
    )
    # Poll schedule: 3, 5, 8, 10 seconds (cumulative 3, 8, 16, 26s max wait)
    $intervals = @(3, 5, 8, 10)
    $attempt = 0
    $postInform = ""
    $postHost   = ""

    foreach ($wait in $intervals) {
        $attempt++
        Start-Sleep -Seconds $wait

        try {
            $postInfo   = Get-DeviceInfo -Stream $Stream -SessionId $SessionId -Timeout $Timeout
            $postInform = $postInfo.InformURL
            $postHost   = ""
            if ($postInform -match '://([^:/]+)') { $postHost = $Matches[1].ToLower() }
        } catch {
            $postInform = ""; $postHost = ""
        }

        Write-Dbg "${Ip}: [post-check T+$([int]($intervals[0..($attempt-1)] | Measure-Object -Sum).Sum)s] inform='$postInform' host='$postHost'"

        if ($postHost -and $postHost -eq $TargetHost) { break }
        if ($postHost -and $ControllerName -and $postHost -eq $ControllerName.ToLower()) { break }
    }

    $verified = $false
    if ($postHost -and $postHost -eq $TargetHost) { $verified = $true }
    if (-not $verified -and $postHost -and $ControllerName -and $postHost -eq $ControllerName.ToLower()) { $verified = $true }

    return @{
        Verified   = $verified
        PostInform = $postInform
        PostHost   = $postHost
        Attempts   = $attempt
    }
}

function Read-IpsFromCsv {
    # Parse a prior scan CSV. Returns a hashtable:
    #   { IPs = @(ordered, unique list of valid IPs)
    #     MacMap = @{ ip -> expected_mac (lowercased) } }
    # Skips '#' comment lines and the 'Timestamp' header row.
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "CSV not found: $Path"
    }
    $lines = Get-Content $Path | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^Timestamp' -and $_.Trim() }
    $ips = @()
    $map = @{}
    foreach ($line in $lines) {
        $fields = $line -split ',' | ForEach-Object { $_.Trim('"').Trim() }
        # scan CSV schema: Timestamp(0) IP(1) MAC(2) Connected(3) Username(4) Model(5) DevHostname(6) ...
        if ($fields.Count -lt 2) { continue }
        $ip = $fields[1]
        if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
        if ($ips -contains $ip) { continue }
        $ips += $ip
        if ($fields.Count -ge 3) {
            $mac = $fields[2].ToLower()
            if ($mac -match '^([0-9a-f]{2}:){5}[0-9a-f]{2}$') {
                $map[$ip] = $mac
            }
        }
    }
    return @{ IPs = $ips; MacMap = $map }
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

    $parse = {
        param([string]$text)
        if (-not $text) { return }
        if ($text -match "Model:\s*(.+)")                        { $info.Model       = $Matches[1].Trim() }
        if ($text -match "Version:\s*(.+)")                      { $info.Firmware     = $Matches[1].Trim() }
        if ($text -match "Hostname:\s*(.+)")                     { $info.Hostname     = $Matches[1].Trim() }
        if ($text -match "Status:\s*(.+)")                       { $info.AdoptStatus  = $Matches[1].Trim() }
        if ($text -match "Inform\s*URL:\s*(.+)")                 { $info.InformURL    = $Matches[1].Trim() }
        # Fallback: 6.x firmware embeds the inform URL inside the Status line's parens
        #   (e.g. "Status: Connected (http://192.168.0.3:8080/inform)") and does not emit
        # a separate "Inform URL:" line. Without this, post-verify reads empty and flags
        # correctly-adopted devices as CHECK.
        if (-not $info.InformURL -and $info.AdoptStatus -match '\((https?://[^)]+)\)') {
            $info.InformURL = $Matches[1].Trim()
        }
        if ($text -match "MAC\s*Address:\s*([0-9A-Fa-f:]{17})")  { $info.MAC = $Matches[1].ToLower() }
        elseif ($text -match "MAC:\s*([0-9A-Fa-f:]{17})")        { $info.MAC = $Matches[1].ToLower() }
    }

    $text = ""
    try { $text = Send-ShellCommand -Stream $Stream -Command "info" -WaitMs 3000; $info.RawInfo = $text } catch {}
    . $parse $text

    # Busy APs (and mesh APs on a weak uplink) can miss the 3s read window and
    # return nothing. An empty Model made the class filter treat the AP as
    # "Other" and skip it silently, so retry once with a longer window.
    if (-not $info.Model) {
        try {
            $text = Send-ShellCommand -Stream $Stream -Command "info" -WaitMs 6000 -ReadRetries 8
            if ($text) { $info.RawInfo = $text }
        } catch {}
        . $parse $text
    }

    # Last resort for model/MAC: /etc/board.info via the exec channel (no shell builtins).
    #   board.name=UAP-AC-Pro-Gen2 / board.shortname=U7PG2 / board.hwaddr=788A20XXXXXX
    if (-not $info.Model -or -not $info.MAC) {
        try {
            $r  = Invoke-SSHCommand -SessionId $SessionId -Command "cat /etc/board.info 2>/dev/null" -TimeOut $Timeout -ErrorAction Stop
            $bi = ($r.Output -join "`n")
            if (-not $info.Model -and $bi -match 'board\.name=([^\r\n]+)')      { $info.Model = $Matches[1].Trim() }
            if (-not $info.Model -and $bi -match 'board\.shortname=([^\r\n]+)') { $info.Model = $Matches[1].Trim() }
            if (-not $info.MAC   -and $bi -match 'board\.hwaddr=([0-9A-Fa-f:]+)') { $info.MAC = ConvertTo-NormalMac $Matches[1] }
        } catch {}
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
# CONTROLLER API - NAMES / ADOPTION
#
# Context hashtable returned by New-ControllerContext:
#   Host, Port, Client (HttpClient), Csrf, Prefix ("/proxy/network" on
#   UniFi OS, "" on a classic controller, $null until detected), Sites
#   (@{Name; Desc} for every site searched).
# ===================================================================

$script:ControllerError = ""

function Get-InnermostMessage {
    param([System.Exception]$Ex)
    while ($Ex.InnerException) { $Ex = $Ex.InnerException }
    return $Ex.Message
}

function Initialize-HttpSupport {
    # Windows PowerShell 5.1 does not load System.Net.Http by default and may
    # not offer TLS 1.2, which UniFi OS requires.
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {}
    if ($script:IsWindows51) {
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        } catch {}
    }
}

function Set-HandlerTrustAll {
    # Controllers use self-signed certs. A scriptblock validation callback
    # runs on a TLS worker thread with no runspace and throws there, so use a
    # compiled delegate instead.
    param([System.Net.Http.HttpClientHandler]$Handler)
    $prop = [System.Net.Http.HttpClientHandler].GetProperty('DangerousAcceptAnyServerCertificateValidator')
    if ($prop) {
        $Handler.ServerCertificateCustomValidationCallback = $prop.GetValue($null)
        return
    }
    # .NET Framework (PS 5.1): HttpClientHandler honours ServicePointManager.
    if (-not ('SovereignTrustAll' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class SovereignTrustAll {
    public static bool Accept(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }
    public static void Install() { ServicePointManager.ServerCertificateValidationCallback = Accept; }
}
"@
    }
    [SovereignTrustAll]::Install()
}

function Invoke-UnifiApi {
    # Call a Network application endpoint. $Path is relative to the Network
    # app root, e.g. "/api/s/default/stat/device". Returns
    #   @{ Ok; Status; Data (the response's .data); Error }
    param([hashtable]$Ctx, [string]$Method = "GET", [string]$Path, [object]$Body)
    $prefixes = if ($null -ne $Ctx.Prefix) { @($Ctx.Prefix) } else { @("/proxy/network", "") }
    $last = @{ Ok = $false; Status = 0; Data = $null; Error = "no response" }
    foreach ($pre in $prefixes) {
        $url = "https://$($Ctx.Host):$($Ctx.Port)$pre$Path"
        try {
            $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::new($Method), $url)
            if ($null -ne $Body) {
                $req.Content = New-Object System.Net.Http.StringContent(($Body | ConvertTo-Json -Compress), [System.Text.Encoding]::UTF8, "application/json")
            }
            # Username/password sessions reject writes without the CSRF token.
            if ($Ctx.Csrf -and $Method -ne "GET") { [void]$req.Headers.TryAddWithoutValidation("X-CSRF-Token", $Ctx.Csrf) }
            $resp   = $Ctx.Client.SendAsync($req).GetAwaiter().GetResult()
            $status = [int]$resp.StatusCode
            $text   = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $vals = $null
            if ($resp.Headers.TryGetValues("X-Updated-CSRF-Token", [ref]$vals)) { $Ctx.Csrf = @($vals)[0] }

            if ($status -eq 404 -and $null -eq $Ctx.Prefix) {
                $last = @{ Ok = $false; Status = 404; Data = $null; Error = "HTTP 404 ($url)" }
                continue
            }
            $json = $null
            try { $json = $text | ConvertFrom-Json } catch {}
            if ($status -ge 200 -and $status -lt 300) {
                $Ctx.Prefix = $pre
                if ($json -and $json.meta -and $json.meta.rc -eq 'error') {
                    return @{ Ok = $false; Status = $status; Data = $null; Error = "controller error: $($json.meta.msg)" }
                }
                $data = if ($json) { $json.data } else { $null }
                return @{ Ok = $true; Status = $status; Data = $data; Error = "" }
            }
            $msg = "HTTP $status"
            if ($json -and $json.meta -and $json.meta.msg) { $msg += " ($($json.meta.msg))" }
            if ($status -in @(401, 403)) { $msg += " - check API key / admin permissions" }
            return @{ Ok = $false; Status = $status; Data = $null; Error = $msg }
        } catch {
            $last = @{ Ok = $false; Status = 0; Data = $null; Error = (Get-InnermostMessage $_.Exception) }
        }
    }
    return $last
}

function New-ControllerContext {
    # Log in (API key, or username/password on UniFi OS or a classic
    # controller), then resolve the sites to search. Tries each port in
    # $Ports (443 = UniFi OS, 8443 = classic). $null on failure, with the
    # reason in $script:ControllerError.
    param([string]$Host_, [int[]]$Ports, [string]$Key, [string]$User, [string]$Pass, [string]$Site)
    Initialize-HttpSupport
    $script:ControllerError = ""
    foreach ($port in $Ports) {
        $jar     = New-Object System.Net.CookieContainer
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.CookieContainer = $jar
        Set-HandlerTrustAll $handler
        $client  = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(20)
        $ctx = @{ Host = $Host_; Port = $port; Client = $client; Csrf = ""; Prefix = $null; Sites = @() }

        if ($Key) {
            [void]$client.DefaultRequestHeaders.TryAddWithoutValidation("X-API-KEY", $Key)
        } else {
            $loggedIn = $false
            foreach ($lp in @("/api/auth/login", "/api/login")) {
                try {
                    $body    = @{ username = $User; password = $Pass } | ConvertTo-Json -Compress
                    $content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
                    $resp    = $client.PostAsync("https://${Host_}:${port}${lp}", $content).GetAwaiter().GetResult()
                    $code    = [int]$resp.StatusCode
                    if ($code -in @(200, 204)) {
                        $vals = $null
                        if ($resp.Headers.TryGetValues("X-CSRF-Token", [ref]$vals)) { $ctx.Csrf = @($vals)[0] }
                        if (-not $ctx.Csrf) {
                            foreach ($ck in $jar.GetCookies([Uri]"https://${Host_}:${port}/")) {
                                if ($ck.Name -eq 'csrf_token') { $ctx.Csrf = $ck.Value }
                            }
                        }
                        $ctx.Prefix = if ($lp -eq "/api/auth/login") { "/proxy/network" } else { "" }
                        $loggedIn = $true; break
                    }
                    # Keep a real rejection (401) over the other login path's 404.
                    if ($code -ne 404 -or -not $script:ControllerError) {
                        $script:ControllerError = "login HTTP $code on port $port" + $(if ($code -in @(400, 401, 403)) { " (wrong username/password, or a cloud/SSO account -- use a local admin or an API key)" } else { "" })
                    }
                } catch { $script:ControllerError = "port ${port}: $(Get-InnermostMessage $_.Exception)" }
            }
            if (-not $loggedIn) { continue }
        }

        # Listing sites both finds every site to search and proves the auth works.
        $s = Invoke-UnifiApi -Ctx $ctx -Path "/api/self/sites"
        if (-not $s.Ok) { $script:ControllerError = "port ${port}: $($s.Error)"; continue }
        $all = @($s.Data | Where-Object { $_.name } | ForEach-Object {
            @{ Name = "$($_.name)"; Desc = $(if ($_.desc) { "$($_.desc)" } else { "$($_.name)" }) }
        })
        if ($Site) {
            $match = @($all | Where-Object { $_.Name -eq $Site -or $_.Desc -eq $Site })
            if ($match.Count -eq 0) {
                $script:ControllerError = "site '$Site' not found (available: $(($all | ForEach-Object { $_.Desc }) -join ', '))"
                return $null
            }
            $all = $match
        }
        if ($all.Count -eq 0) { $all = @(@{ Name = "default"; Desc = "Default" }) }
        $ctx.Sites = $all
        return $ctx
    }
    return $null
}

function Get-ControllerDevices {
    # MAC -> @{ Id; Site; SiteDesc; Name; Model; Adopted } across all context sites.
    param([hashtable]$Ctx)
    $map = @{}
    foreach ($s in $Ctx.Sites) {
        $r = Invoke-UnifiApi -Ctx $Ctx -Path "/api/s/$($s.Name)/stat/device"
        if (-not $r.Ok) { Write-Dbg "site $($s.Desc): $($r.Error)"; continue }
        foreach ($d in @($r.Data)) {
            if (-not $d) { continue }
            $mac = ConvertTo-NormalMac "$($d.mac)"
            if (-not $mac) { continue }
            # A pending device can be listed in several sites; prefer the adopted entry.
            if ($map.ContainsKey($mac) -and $map[$mac].Adopted) { continue }
            $map[$mac] = @{
                Id = "$($d._id)"; Site = $s.Name; SiteDesc = $s.Desc
                Name = "$($d.name)"; Model = "$($d.model)"; Adopted = [bool]$d.adopted
            }
        }
    }
    return $map
}

function Test-DefaultDeviceName {
    # Names that are what a factory-reset device reports, not what anyone set.
    # Renaming to these would wipe the real name, so they're refused.
    param([string]$Name, [string[]]$Models)
    if (-not $Name) { return $true }
    $n = $Name.Trim().ToLower()
    if ($n -in @('ubnt', 'unifi', 'localhost', '(none)')) { return $true }
    foreach ($m in $Models) { if ($m -and $n -eq $m.Trim().ToLower()) { return $true } }
    return $false
}

function Invoke-BatchRename {
    # Apply names to many devices in one pass:
    #   1. one device listing (all sites), re-polled up to FindWaitSec for late informers
    #   2. pending devices adopted via cmd/devmgr (a name only sticks once adopted)
    #   3. PUT rest/device name
    # Entries: @{ Mac; Name; Model; Ip; Explicit } (Explicit = name came from a Name column).
    # Returns one @{ Mac; Ip; Name; Site; Result; Detail } per entry.
    # Result: OK | ALREADY | NOTFOUND | PENDING | DEFAULTNAME | FAIL
    param(
        [hashtable]$Ctx,
        [array]$Entries,
        [int]$FindWaitSec = 0,
        [switch]$AdoptPending,
        [switch]$Interactive,
        [int]$AdoptWaitSec = 180
    )
    $out = [ordered]@{}
    $todo = @()
    foreach ($e in $Entries) {
        if ($out.Contains($e.Mac)) { continue }
        $out[$e.Mac] = @{ Mac = $e.Mac; Ip = $e.Ip; Name = $e.Name; Site = ""; Result = ""; Detail = "" }
        $todo += $e
    }

    Write-Info "Searching $($Ctx.Sites.Count) site(s) on $($Ctx.Host):$($Ctx.Port) for $($todo.Count) device(s)..."
    $devices  = Get-ControllerDevices $Ctx
    $deadline = (Get-Date).AddSeconds($FindWaitSec)
    while ((Get-Date) -lt $deadline) {
        $missing = @($todo | Where-Object { -not $devices.ContainsKey($_.Mac) })
        if ($missing.Count -eq 0) { break }
        Write-Dbg "waiting for $($missing.Count) device(s) to appear on the controller"
        Start-Sleep -Seconds 10
        $devices = Get-ControllerDevices $Ctx
    }

    # Refuse factory-default names before adopting anything for them.
    foreach ($e in $todo) {
        $d = $devices[$e.Mac]
        $models = @($e.Model); if ($d) { $models += $d.Model }
        if (-not $e.Explicit -and (Test-DefaultDeviceName -Name $e.Name -Models $models)) {
            $out[$e.Mac].Result = "DEFAULTNAME"
            $out[$e.Mac].Detail = "'$($e.Name)' is a factory-default name (use a scan CSV from before the reset, or add a Name column)"
        }
    }

    $pending = @($todo | Where-Object { -not $out[$_.Mac].Result -and $devices.ContainsKey($_.Mac) -and -not $devices[$_.Mac].Adopted })
    if ($pending.Count -gt 0 -and -not $AdoptPending -and $Interactive) {
        Write-Host ""
        Write-Warn "$($pending.Count) device(s) are pending adoption -- a name only sticks once a device is adopted."
        $AdoptPending = ((Read-YesNo "Adopt them now via the controller API?" 'Y') -eq 'Y')
    }
    if ($pending.Count -gt 0 -and $AdoptPending) {
        foreach ($e in $pending) {
            $d = $devices[$e.Mac]
            $r = Invoke-UnifiApi -Ctx $Ctx -Method POST -Path "/api/s/$($d.Site)/cmd/devmgr" -Body @{ cmd = "adopt"; mac = $e.Mac }
            if ($r.Ok) { Write-Info "$($e.Mac): adopt sent (site $($d.SiteDesc))" }
            else       { Write-Warn "$($e.Mac): adopt failed: $($r.Error)" }
        }
        Write-Info "Waiting up to ${AdoptWaitSec}s for adoption to complete..."
        $deadline = (Get-Date).AddSeconds($AdoptWaitSec)
        do {
            Start-Sleep -Seconds 10
            $devices = Get-ControllerDevices $Ctx
            $still = @($pending | Where-Object { -not ($devices.ContainsKey($_.Mac) -and $devices[$_.Mac].Adopted) })
            Write-Dbg "$($still.Count) device(s) still adopting"
        } while ($still.Count -gt 0 -and (Get-Date) -lt $deadline)
    }

    foreach ($e in $todo) {
        $r = $out[$e.Mac]
        if ($r.Result) { continue }
        $d = $devices[$e.Mac]
        if (-not $d) {
            $r.Result = "NOTFOUND"
            $r.Detail = "not on controller (searched: $(($Ctx.Sites | ForEach-Object { $_.Desc }) -join ', '))"
            continue
        }
        $r.Site = $d.SiteDesc
        if (-not $d.Adopted) {
            $r.Result = "PENDING"
            $r.Detail = if ($AdoptPending) { "still not adopted after ${AdoptWaitSec}s -- rerun Rename once it finishes" } else { "pending adoption -- adopt it (or rerun with -AdoptPending), then rename" }
            continue
        }
        if ($d.Name -ceq $e.Name) { $r.Result = "ALREADY"; continue }
        $put = Invoke-UnifiApi -Ctx $Ctx -Method PUT -Path "/api/s/$($d.Site)/rest/device/$($d.Id)" -Body @{ name = $e.Name }
        if ($put.Ok) { $r.Result = "OK" } else { $r.Result = "FAIL"; $r.Detail = $put.Error }
    }
    return @($out.Values)
}

function Write-RenameResult {
    param([hashtable]$R)
    $who = if ($R.Ip) { "$($R.Mac) ($($R.Ip))" } else { $R.Mac }
    switch ($R.Result) {
        "OK"          { Write-Ok   "$who -> '$($R.Name)'  [$($R.Site)]" }
        "ALREADY"     { Write-Opt  "$who already named '$($R.Name)'" }
        "NOTFOUND"    { Write-Warn "${who}: $($R.Detail)" }
        "PENDING"     { Write-Warn "${who}: $($R.Detail)" }
        "DEFAULTNAME" { Write-Warn "${who}: skipped, $($R.Detail)" }
        default       { Write-Fail "${who}: rename failed: $($R.Detail)" }
    }
}

function Read-RenameCsv {
    # Entries for Invoke-BatchRename from a CSV. With a header row, columns are
    # found by name: MAC (required), IP, Model, and the name from the first of
    # Name / NewName / DevHostname / Hostname that is set. A Name or NewName
    # column is taken as explicit intent and bypasses the default-name guard.
    # Headerless files use the scan layout (MAC = col 3, DevHostname = col 7).
    param([string]$Path)
    $lines = @(Get-Content $Path | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })
    if ($lines.Count -eq 0) { return @() }
    $header = @($lines[0] -split ',' | ForEach-Object { $_.Trim().Trim('"').ToLower() })
    $entries = @()
    if ($header -contains 'mac') {
        foreach ($row in ($lines | ConvertFrom-Csv)) {
            $cols = @($row.PSObject.Properties.Name)
            $name = ""; $explicit = $false
            foreach ($col in @('Name', 'NewName', 'DevHostname', 'Hostname')) {
                if ($cols -contains $col -and "$($row.$col)".Trim()) {
                    $name = "$($row.$col)".Trim(); $explicit = ($col -in @('Name', 'NewName')); break
                }
            }
            $mac = ConvertTo-NormalMac "$($row.MAC)"
            if (-not $mac -or -not $name) { continue }
            $entries += @{ Mac = $mac; Name = $name; Explicit = $explicit
                           Ip = $(if ($cols -contains 'IP') { "$($row.IP)" } else { "" })
                           Model = $(if ($cols -contains 'Model') { "$($row.Model)" } else { "" }) }
        }
    } else {
        foreach ($line in $lines) {
            $f = @($line -split ',' | ForEach-Object { $_.Trim('"').Trim() })
            if ($f.Count -lt 7) { continue }
            $mac = ConvertTo-NormalMac $f[2]
            if (-not $mac -or -not $f[6]) { continue }
            $entries += @{ Mac = $mac; Name = $f[6]; Explicit = $false; Ip = $f[1]; Model = $f[5] }
        }
    }
    return $entries
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
    param([string[]]$Targets, [int]$TimeoutSec, [int]$MaxParallel, [int]$Retries = 1)

    Write-Rule "Scan"
    Write-Info "Sweeping $($Targets.Count) hosts for SSH (TCP/22)"
    Write-Host ""

    $found = @{}
    foreach ($hit in (Invoke-TcpSweep -Targets $Targets -TimeoutSec $TimeoutSec -MaxParallel $MaxParallel)) { $found[$hit] = $true }
    Write-Info "Pass 1: $($found.Count) hosts responding"

    # A single SYN per host misses devices: hundreds of simultaneous connects
    # flood ARP resolution (Windows drops the overflow), and busy or mesh APs
    # can be slow to answer. Re-sweep the silent hosts with a longer timeout
    # and less parallelism.
    for ($pass = 1; $pass -le $Retries; $pass++) {
        $missing = @($Targets | Where-Object { -not $found.ContainsKey($_) })
        if ($missing.Count -eq 0) { break }
        $retryTimeout  = $TimeoutSec * 2
        $retryParallel = [Math]::Max(1, [Math]::Min($MaxParallel, 64))
        $before = $found.Count
        foreach ($hit in (Invoke-TcpSweep -Targets $missing -TimeoutSec $retryTimeout -MaxParallel $retryParallel)) { $found[$hit] = $true }
        Write-Info "Retry pass ${pass}: +$($found.Count - $before) hosts (re-checked $($missing.Count) silent IPs, ${retryTimeout}s timeout)"
    }

    Write-Host ""
    if ($found.Count -eq 0) {
        Write-Fail "No hosts with SSH open"
        exit 1
    }

    Write-Ok "$($found.Count) hosts responding"
    # Preserve target order
    return @($Targets | Where-Object { $found.ContainsKey($_) })
}

function Invoke-TcpSweep {
    param([string[]]$Targets, [int]$TimeoutSec, [int]$MaxParallel)

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

    return $open.ToArray()
}

# ===================================================================
# MAIN
# ===================================================================

Write-Banner

if ($DryRun) {
    Write-Warn "DRY RUN -- no changes will be made"
    Write-Host ""
}

Install-Prerequisites

# -- Mode --
$modeStr = $Mode
if (-not $modeStr) {
    $mc = Read-MenuChoice -Title "Operation mode:" -Options @(
        "SANITY   -- verify SSH access, collect device info (read-only)",
        "MIGRATE  -- re-point devices to a new controller (no reset)",
        "ADOPT    -- full adoption with optional factory reset",
        "RENAME   -- apply device names from a CSV via controller API",
        "EXIT     -- quit"
    ) -Default 1
    switch ($mc) {
        1 { $modeStr = "Sanity" }
        2 { $modeStr = "Migrate" }
        3 { $modeStr = "Adopt" }
        4 { $modeStr = "Rename" }
        5 { Write-Host ""; Write-Info "Exited."; Write-Host ""; exit 0 }
    }
}
$modeStr = $modeStr.Substring(0,1).ToUpper() + $modeStr.Substring(1).ToLower()

# Controller API ports: an explicit -ApiPort wins, otherwise try UniFi OS (443) then classic (8443).
$apiPorts = if ($PSBoundParameters.ContainsKey('ApiPort')) { @($ApiPort) } else { @(443, 8443) }

# RENAME mode - self-contained, no SSH needed
if ($modeStr -eq "Rename") {
    Write-Rule "Apply Names from CSV"

    if (-not $InCsv) { $InCsv = Read-NonEmpty "CSV file path" }
    if (-not (Test-Path $InCsv)) { Write-Fail "File not found: $InCsv"; exit 1 }
    if (-not $Controller) { $Controller = Read-NonEmpty "Controller IP or hostname" }

    if (-not $ApiKey -and -not $ApiUser) {
        $ac = Read-MenuChoice -Title "Controller auth method:" -Options @(
            "API key  (Settings > Control Plane > API Keys)",
            "Username / password"
        ) -Default 1
        if ($ac -eq 1) {
            $ApiKey = Read-NonEmpty "API key"
        } else {
            $ApiUser = Read-NonEmpty "Username"
            $ApiPass = Read-Host "    Password" -AsSecureString | ForEach-Object { [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }
        }
    }
    Write-Info $(if ($ApiKey) { "Auth: API key" } else { "Auth: $ApiUser" })

    $entries = @(Read-RenameCsv $InCsv)
    Write-Info "Source: $InCsv ($($entries.Count) device(s) with a MAC and a name)"
    if ($entries.Count -eq 0) { Write-Fail "No usable rows (need a MAC and a name per row)"; exit 1 }

    $ctx = New-ControllerContext -Host_ $Controller -Ports $apiPorts -Key $ApiKey -User $ApiUser -Pass $ApiPass -Site $Site
    if (-not $ctx) { Write-Fail "Controller API login failed: $script:ControllerError"; exit 1 }
    Write-Ok "Connected to $($Controller):$($ctx.Port) -- site(s): $(($ctx.Sites | ForEach-Object { $_.Desc }) -join ', ')"

    if ($DryRun) {
        $devices = Get-ControllerDevices $ctx
        Write-Host ""
        foreach ($e in $entries) {
            $d = $devices[$e.Mac]
            $state = if (-not $d) { "NOT FOUND" } elseif (-not $d.Adopted) { "PENDING ADOPTION" } else { "current '$($d.Name)'" }
            Write-Item "$($e.Mac) -> '$($e.Name)'  ($state)"
        }
        Write-Host ""; Write-Warn "DRY RUN -- no changes made"; exit 0
    }
    Write-Host ""

    $rr = Invoke-BatchRename -Ctx $ctx -Entries $entries -FindWaitSec 15 -AdoptPending:$AdoptPending -Interactive:(-not $Quiet_) -AdoptWaitSec $AdoptWait
    Write-Host ""
    foreach ($r in $rr) { Write-RenameResult $r }

    $tally = @{}
    foreach ($r in $rr) { $tally[$r.Result] = 1 + [int]$tally[$r.Result] }

    Write-Rule "Results"
    $cardWidth = 36
    Write-C "  +$("-" * $cardWidth)+" "DarkYellow"
    foreach ($line in @(
        @("OK",          "  Renamed           ", "Green"),
        @("ALREADY",     "  Already named     ", "DarkGray"),
        @("PENDING",     "  Pending adoption  ", "Yellow"),
        @("NOTFOUND",    "  Not found         ", "Yellow"),
        @("DEFAULTNAME", "  Default name skip ", "Yellow"),
        @("FAIL",        "  Failed            ", "Red"))) {
        if ($line[0] -eq "OK" -or $tally[$line[0]]) {
            Write-C "  |" "DarkYellow" -NoNewline; Write-C $line[1] "DarkGray" -NoNewline; Write-C "$([int]$tally[$line[0]])".PadRight($cardWidth - 20) $line[2] -NoNewline; Write-C "|" "DarkYellow"
        }
    }
    Write-C "  +$("-" * $cardWidth)+" "DarkYellow"

    # Per-device outcome CSV, so the leftovers can be fixed and re-fed.
    if (-not $OutCsv) { $OutCsv = Get-DefaultCsvPath "Rename" }
    try {
        $rr | ForEach-Object {
            [pscustomobject][ordered]@{
                Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"); MAC = $_.Mac; IP = $_.Ip
                DevHostname = $_.Name; Site = $_.Site; Result = $_.Result; Detail = $_.Detail
            }
        } | ConvertTo-Csv -NoTypeInformation | Set-Content -Path $OutCsv -ErrorAction Stop
        Write-Info "Results: $OutCsv"
    } catch { Write-Warn "Could not write $OutCsv -- $($_.Exception.Message)" }

    Write-Host ""; Write-Ok "Done."; Write-Host ""
    exit 0
}

Write-Rule "Configuration"
Write-Info "Mode: $($modeStr.ToUpper())"

# -- Targets --
# Conflict guard: InCsv is exclusive with Cidr/IPs
$targetFlagsSet = @()
if ($Cidr)  { $targetFlagsSet += "-Cidr" }
if ($IPs)   { $targetFlagsSet += "-IPs" }
if ($InCsv) { $targetFlagsSet += "-InCsv" }
if ($targetFlagsSet.Count -gt 1) {
    Write-Fail "Target sources are exclusive. Pick one: $($targetFlagsSet -join ', ')"
    exit 1
}

$targetList = @()
$csvMacMap  = @{}  # IP -> expected MAC from CSV (empty if no CSV or CSV lacks MACs)

if ($InCsv) {
    try {
        $csvParsed  = Read-IpsFromCsv $InCsv
        $targetList = $csvParsed.IPs
        $csvMacMap  = $csvParsed.MacMap
        Write-Info "Target source: CSV ($InCsv)"
        if ($csvMacMap.Count -gt 0) {
            Write-Info "MAC validation enabled for $($csvMacMap.Count) entries"
        }
    } catch { Write-Fail $_.Exception.Message; exit 1 }
} elseif ($Cidr) {
    try { $targetList = Get-IPsFromCidr $Cidr } catch { Write-Fail $_.Exception.Message; exit 1 }
} elseif ($IPs) {
    $targetList = ($IPs -split '[,\s]+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -Unique
} else {
    $tc = Read-MenuChoice -Title "Target input:" -Options @(
        "CIDR subnet  (e.g. 192.168.1.0/24)",
        "IP list      (comma-separated)",
        "CSV file     (from prior scan)",
        "EXIT"
    ) -Default 1
    if ($tc -eq 4) { Write-Host ""; Write-Info "Exited."; Write-Host ""; exit 0 }
    if ($tc -eq 3) {
        $raw = Read-NonEmpty "CSV path"
        try {
            $csvParsed  = Read-IpsFromCsv $raw
            $targetList = $csvParsed.IPs
            $csvMacMap  = $csvParsed.MacMap
            $InCsv      = $raw
            Write-Info "Loaded $($targetList.Count) IPs from $raw"
            if ($csvMacMap.Count -gt 0) {
                Write-Info "MAC validation enabled for $($csvMacMap.Count) entries"
            }
        } catch { Write-Fail $_.Exception.Message; exit 1 }
    } elseif ($tc -eq 2) {
        $raw = Read-NonEmpty "IPs (comma-separated)"
        $targetList = ($raw -split '[,\s]+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -Unique
    } else {
        $raw = Read-NonEmpty "CIDR (e.g. 192.168.1.0/24)"
        try { $targetList = Get-IPsFromCidr $raw } catch { Write-Fail $_.Exception.Message; exit 1 }
    }
}

if ($targetList.Count -eq 0) { Write-Fail "No valid target IPs"; exit 1 }
Write-Info "Targets: $($targetList.Count) IPs"

# -- Controller --
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

# -- Credentials --
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

$credChain = ($credSpec | ForEach-Object { $_.u }) -join ' -> '
Write-Info "Credential chain: $credChain"

# -- CSV --
if (-not $OutCsv) {
    $defaultPath = Get-DefaultCsvPath $modeStr
    $OutCsv = Read-WithDefault "CSV output path" $defaultPath
}

# -- Plan --
Write-Rule "Plan"
Write-Item "Mode         $($modeStr.ToUpper())"
Write-Item "Targets      $($targetList.Count) IPs"
if ($InCsv) {
    Write-C "  > " "DarkYellow" -NoNewline; Write-C "Target source  " "" -NoNewline; Write-C "CSV" "Cyan" -NoNewline; Write-C " ($InCsv)" "DarkGray"
    if ($csvMacMap.Count -gt 0) {
        $macPolicy = if ($StrictMacMatch) { "STRICT (skip on mismatch)" } else { "warn on mismatch" }
        Write-C "  > " "DarkYellow" -NoNewline; Write-C "MAC validation " "" -NoNewline; Write-C "$($csvMacMap.Count) entries" "Green" -NoNewline; Write-C " ($macPolicy)" "DarkGray"
    }
}
if ($Class) {
    Write-C "  > " "DarkYellow" -NoNewline; Write-C "Class filter   " "" -NoNewline; Write-C "$Class" "Cyan" -NoNewline; Write-C " (flag-set, non-matching devices skipped)" "DarkGray"
}
if ($informUrl) {
    Write-Item "Controller   $Controller"
    Write-Item "Inform URL   $informUrl"
}
if ($doReset) { Write-C "  > " "DarkYellow" -NoNewline; Write-C "Reset        " "" -NoNewline; Write-C "YES" "Red" }
if ($SkipAdopted) {
    Write-C "  > " "DarkYellow" -NoNewline; Write-C "Skip adopted   " "" -NoNewline; Write-C "YES" "Yellow" -NoNewline; Write-C " (already-connected devices will be ignored)" "DarkGray"
}
if ($RestoreNames) {
    $authDisplay = if ($ApiKey) { "API key" } elseif ($ApiUser) { "user: $ApiUser" } else { "<no auth set>" }
    Write-C "  > " "DarkYellow" -NoNewline; Write-C "Restore names  " "" -NoNewline; Write-C "YES" "Green" -NoNewline; Write-C " (via controller API - $authDisplay)" "DarkGray"
}
Write-Item "SSH Timeout  ${SshTimeout}s"
Write-Item "Parallel     $Parallel threads"
Write-Item "Output       $OutCsv"

if ($DryRun) {
    Write-Host ""
    Write-Warn "DRY RUN -- stopping before execution"
    exit 0
}

Write-Host ""
if ((Read-YesNo "Execute?" 'Y') -ne 'Y') { Write-Host ""; Write-Info "Aborted."; exit 0 }

# -- Scan --
$openHosts = @(Invoke-PortScan -Targets $targetList -TimeoutSec $ScanTimeout -MaxParallel $Parallel -Retries $ScanRetries)

# -- Credentials --
$credList = Build-CredList $credSpec

# -- Class filter: resolve + optional pre-scan for interactive menu --
# For Migrate/Adopt, when no -Class flag is provided and not in -Quiet_ mode,
# do a lightweight discovery pre-scan to show device counts by class and let
# the operator pick which class to act on. This is the "APs first, switches
# later" staged-rollout workflow.
$classFilter = $Class
if (-not $classFilter) { $classFilter = "All" }

$preScanModels = @{}   # IP -> Model from pre-scan (reused later to avoid double-SSH cost)
$preScanMacs   = @{}   # IP -> MAC from pre-scan
$preScanClass  = @{}   # IP -> class from pre-scan

if ($modeStr -in @("Migrate","Adopt") -and (-not $Class) -and (-not $Quiet_) -and $openHosts.Count -gt 0) {
    Write-Rule "Pre-scan"
    Write-Info "Discovering device classes across $($openHosts.Count) hosts..."
    Write-Host ""

    $psIdx = 0
    foreach ($ip in $openHosts) {
        $psIdx++
        Write-ScanProgress $psIdx $openHosts.Count $ip
        $psSess = $null
        foreach ($c in $credList) {
            try {
                $psSess = Connect-DeviceSsh -Ip $ip -Credential $c -Timeout $SshTimeout
                break
            } catch {}
        }
        if (-not $psSess) { continue }
        $psStream = $null
        try { $psStream = New-ShellStream -SessionId $psSess.SessionId } catch {}
        $psModel = ""
        if ($psStream) {
            try {
                $psInfo = Get-DeviceInfo -Stream $psStream -SessionId $psSess.SessionId -Timeout ($SshTimeout * 2)
                $psModel = $psInfo.Model
                if ($psInfo.Model) { $preScanModels[$ip] = $psInfo.Model }
                if ($psInfo.MAC)   { $preScanMacs[$ip]   = $psInfo.MAC.ToLower() }
            } catch {}
            try { $psStream.Dispose() } catch {}
        }
        # Classify every device we got a session on -- even with no model --
        # so the counts match what the processing pass will act on.
        $preScanClass[$ip] = Resolve-DeviceClass -Model $psModel -SessionId $psSess.SessionId -Timeout ($SshTimeout * 2)
        try { Remove-SSHSession -SessionId $psSess.SessionId | Out-Null } catch {}
    }
    Write-Host ""

    # Tally by class
    $classCounts = @{ All = 0; AP = 0; Switch = 0; Gateway = 0; Other = 0 }
    foreach ($ip in $preScanClass.Keys) {
        $cls = $preScanClass[$ip]
        $classCounts[$cls]++
        $classCounts.All++
    }
    $unreachable = $openHosts.Count - $classCounts.All

    Write-Rule "Discovered"
    Write-Item "APs              $($classCounts.AP)"
    Write-Item "Switches         $($classCounts.Switch)"
    Write-Item "Gateways         $($classCounts.Gateway)"
    Write-Item "Other            $($classCounts.Other)"
    if ($unreachable -gt 0) {
        Write-Item "Unreachable      $unreachable (no SSH / no info)"
    }
    Write-Host ""

    # Prompt unless only one class was found
    if ($classCounts.All -eq 0) {
        Write-Fail "No devices responded to SSH info probes. Nothing to act on."
        exit 1
    }

    # Build menu dynamically - only show classes that have > 0 devices
    $menuOptions = @()
    $menuClasses = @()
    $menuOptions += "All devices ($($classCounts.All))"
    $menuClasses += "All"
    foreach ($cls in @("AP","Switch","Gateway","Other")) {
        if ($classCounts[$cls] -gt 0) {
            $menuOptions += "$cls" + "s only ($($classCounts[$cls]))"
            $menuClasses += $cls
        }
    }
    $menuOptions += "EXIT"

    $cc = Read-MenuChoice -Title "Target class:" -Options $menuOptions -Default 1
    if ($cc -eq $menuOptions.Count) { Write-Host ""; Write-Info "Exited."; Write-Host ""; exit 0 }
    $classFilter = $menuClasses[$cc - 1]
    Write-Info "Class filter: $classFilter"
    Write-Host ""
}

# -- Process --
Write-Rule "Processing"

$results   = @()
$total     = $openHosts.Count
$countOk   = 0; $countCheck = 0; $countFail = 0
$countSkipClass = 0; $countSkipAdopted = 0; $countSkipMac = 0
$renameQueue = @()   # -RestoreNames: @{Mac;Name;Model;Ip}, applied in one batch after processing

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
        # SSH connect with retry -- capture actual exception per cred attempt so we
        # can distinguish auth-failed from KEX-negotiation-failed from timeout.
        # Posh-SSH (SSH.NET) disables older KEX algorithms that 6.x UniFi firmware
        # still uses, which surfaces as a generic failure unless we inspect the
        # exception message.
        $sess = $null; $ok = $false; $used = $null
        $lastSshErr = ""
        foreach ($c in $credList) {
            try {
                $sess = Connect-DeviceSsh -Ip $ip -Credential $c -Timeout $SshTimeout
                $used = $c.UserName; $ok = $true; break
            } catch { $lastSshErr = $_.Exception.Message }
            # Retry once
            Start-Sleep -Milliseconds 1000
            try {
                $sess = Connect-DeviceSsh -Ip $ip -Credential $c -Timeout $SshTimeout
                $used = $c.UserName; $ok = $true; break
            } catch { $lastSshErr = $_.Exception.Message }
        }

        if (-not $ok) {
            # Classify the failure so the user can see at a glance whether to
            # provide different creds, widen algorithm support, or chase a
            # network-reachability issue.
            $failCategory = "SSH failed"
            $failHint     = ""
            if ($lastSshErr -match "(?i)authentication|permission denied|no more authentication methods") {
                $failCategory = "SSH auth failed"
                $failHint     = "creds didn't match (pass -Username/-Password for hardened devices)"
            } elseif ($lastSshErr -match "(?i)key exchange|kex|no common|cipher|mac algorithm|host key algorithm|compression") {
                $failCategory = "SSH KEX failed"
                $failHint     = if ($StrictHostKeys) {
                    "host key changed (factory reset / IP moved) or legacy SSH algorithms -- retry without -StrictHostKeys"
                } else {
                    "device uses older SSH algorithms than Posh-SSH allows (native ssh.exe probably works)"
                }
            } elseif ($lastSshErr -match "(?i)timed out|timeout|unreachable|refused|actively refused|no route") {
                $failCategory = "SSH unreachable"
                $failHint     = "network / SSH port not reachable despite earlier port-scan hit"
            } elseif ($lastSshErr) {
                $failHint     = "raw: $lastSshErr"
            }
            $row.Note = if ($failHint) { "${failCategory}: $failHint" } else { $failCategory }
            $row.DebugInfo = $lastSshErr
            Write-DeviceLine $ip "" "FAIL" $failCategory
            if ($Verbose_ -and $lastSshErr) { Write-Dbg "${ip}: $lastSshErr" }
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

        # Fill gaps from the pre-scan, which may have caught a faster `info` reply.
        if (-not $devInfo.Model -and $preScanModels.ContainsKey($ip)) { $devInfo.Model = $preScanModels[$ip] }
        if (-not $devInfo.MAC   -and $preScanMacs.ContainsKey($ip))   { $devInfo.MAC   = $preScanMacs[$ip] }

        $row.MAC           = $devInfo.MAC
        $row.Model         = $devInfo.Model
        $row.Firmware      = $devInfo.Firmware
        $row.DevHostname   = $devInfo.Hostname
        $row.AdoptStatus   = $devInfo.AdoptStatus
        $row.CurrentInform = $devInfo.InformURL
        $row.DebugInfo     = ($devInfo.RawInfo -replace "`n"," | " -replace "`r","").Trim()

        # CLASS FILTER: if the operator picked a specific class, skip others.
        # Sanity mode always acts on everything (discovery report).
        if ($modeStr -ne "Sanity" -and $classFilter -and $classFilter -ne "All") {
            $deviceClass = Resolve-DeviceClass -Model $devInfo.Model -SessionId $sess.SessionId -Timeout ($SshTimeout * 2)
            if ($deviceClass -ne $classFilter) {
                $countSkipClass++
                Write-Dbg "${ip}: class $deviceClass, filter $classFilter -- skipped"
                if (-not $devInfo.Model) {
                    # Never drop an unidentified device silently -- this is how APs went missing.
                    Write-DeviceLine $ip "" "SKIP" "model unknown, no radio seen (filter: $classFilter) -- check by hand or use -Class All"
                    $row.Note = "model unknown, not classified (filter: $classFilter)"
                } else {
                    if ($Verbose_) { Write-DeviceLine $ip $devInfo.Model "SKIP" "class $deviceClass (filter: $classFilter)" }
                    $row.Note = "class $deviceClass (filter: $classFilter)"
                }
                if ($stream) { $stream.Dispose() }
                try { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } catch {}
                $row.Status = "SKIP"
                $results += [pscustomobject]$row; continue
            }
        }

        # MAC VALIDATION: if a CSV target with MAC was supplied, verify identity.
        # Default: warn-and-proceed; with -StrictMacMatch, skip mismatched devices.
        if ($csvMacMap.Count -gt 0 -and $csvMacMap.ContainsKey($ip) -and $devInfo.MAC) {
            $expectedMac = $csvMacMap[$ip]
            $actualMac   = $devInfo.MAC.ToLower()
            if ($expectedMac -ne $actualMac) {
                $msg = "MAC mismatch at ${ip}: CSV=$expectedMac actual=$actualMac"
                if ($StrictMacMatch) {
                    Write-Warn "$msg -- skipping (-StrictMacMatch)"
                    $countSkipMac++
                    $row.Status = "SKIP"
                    $row.Note   = "MAC mismatch (strict): CSV=$expectedMac actual=$actualMac"
                    if ($stream) { $stream.Dispose() }
                    try { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } catch {}
                    $results += [pscustomobject]$row; continue
                } else {
                    Write-Warn "$msg -- proceeding (use -StrictMacMatch to block)"
                    $row.Note = ($row.Note + "; MAC mismatch: CSV=$expectedMac actual=$actualMac").Trim('; ')
                }
            } else {
                Write-Dbg "${ip}: MAC validated ($actualMac)"
            }
        }

        # SKIP-ADOPTED: ignore devices already connected to any controller
        if ($SkipAdopted -and $modeStr -ne "Sanity") {
            if (Test-DeviceAdopted -AdoptStatus $devInfo.AdoptStatus -InformUrl $devInfo.InformURL) {
                $countSkipAdopted++
                $statusStr = if ($devInfo.AdoptStatus) { $devInfo.AdoptStatus } else { $devInfo.InformURL }
                Write-Dbg "${ip}: already adopted ($statusStr) -- skipped"
                if ($Verbose_) { Write-DeviceLine $ip $devInfo.Model "SKIP" "already adopted ($statusStr)" }
                if ($stream) { $stream.Dispose() }
                try { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } catch {}
                # Keep the row so the CSV accounts for every host that was scanned.
                $row.Status = "SKIP"; $row.Note = "already adopted ($statusStr)"
                $results += [pscustomobject]$row; continue
            }
        }

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
                Write-Info "${ip}: reset sent, waiting for it to come back (up to ${ResetWait}s)..."
                try { if ($stream) { $stream.Dispose() } } catch {}
                try { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } catch {}

                # Poll instead of one fixed 90s wait: some models take 2-3 min to
                # boot after a reset, and a single attempt marked them FAIL (so
                # set-inform never ran and they never reached the controller).
                $resetStart = Get-Date
                Start-Sleep -Seconds ([Math]::Min(60, $ResetWait))
                $sess = $null; $ok = $false; $used = $null; $lastSshErr = ""
                while (-not $ok) {
                    foreach ($c in $credList) {
                        try {
                            $sess = Connect-DeviceSsh -Ip $ip -Credential $c -Timeout ($SshTimeout * 2)
                            $used = $c.UserName; $ok = $true; break
                        } catch { $lastSshErr = $_.Exception.Message }
                    }
                    if ($ok -or ((Get-Date) - $resetStart).TotalSeconds -ge $ResetWait) { break }
                    Start-Sleep -Seconds 10
                }
                if (-not $ok) {
                    $row.Note = "Re-login failed post-reset (waited ${ResetWait}s): $lastSshErr"
                    Write-DeviceLine $ip $devInfo.Model "FAIL" "not back after reset (${ResetWait}s) -- raise -ResetWait or check DHCP"
                    $countFail++; $results += [pscustomobject]$row; continue
                }
                Write-Dbg "${ip}: back after $([int]((Get-Date) - $resetStart).TotalSeconds)s"
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

        # -- Pre-check: what controller is this device currently talking to? --
        $preInfo = Get-DeviceInfo -Stream $stream -SessionId $sess.SessionId -Timeout ($SshTimeout * 2)
        $currentInform = $preInfo.InformURL

        # After a reset the IP can be re-leased to another device; don't set-inform a stranger.
        if ($row.Reset -like "OK*" -and $row.MAC -and $preInfo.MAC -and ($preInfo.MAC.ToLower() -ne $row.MAC.ToLower())) {
            $row.Status = "FAIL"; $countFail++
            $row.Note = "different device at $ip after reset (was $($row.MAC), now $($preInfo.MAC)) -- re-scan to find it"
            Write-DeviceLine $ip $devInfo.Model "FAIL" "different device answered after reset"
            if ($stream) { $stream.Dispose() }
            try { Remove-SSHSession -SessionId $sess.SessionId | Out-Null } catch {}
            $results += [pscustomobject]$row; continue
        }
        $row.CurrentInform = $currentInform

        # Extract hostname/IP from both URLs for comparison
        $targetHost = ""
        if ($informUrl -match '://([^:/]+)') { $targetHost = $Matches[1].ToLower() }
        $currentHost = ""
        if ($currentInform -match '://([^:/]+)') { $currentHost = $Matches[1].ToLower() }

        # Check if device is already pointing to the correct controller
        $alreadyCorrect = $false
        if ($currentHost -and $targetHost -and ($currentHost -eq $targetHost)) {
            $alreadyCorrect = $true
        }
        # Also check if current inform matches the Controller param directly
        if (-not $alreadyCorrect -and $Controller -and $currentHost -eq $Controller.ToLower()) {
            $alreadyCorrect = $true
        }

        if ($alreadyCorrect) {
            $row.Status = "OK"; $countOk++
            $row.Note = ($row.Note + "; already on correct controller").Trim('; ')
            if ($modeStr -eq "Adopt" -and $RestoreNames -and $row.DevHostname -and $row.MAC) {
                $renameQueue += @{ Mac = $row.MAC; Name = $row.DevHostname; Model = $row.Model; Ip = $ip; Explicit = $false }
            }
            Write-DeviceLine $ip $devInfo.Model "OK" "already on $currentHost -- skipped"
        } else {
            # Device is NOT on the right controller -- set-inform twice
            if ($currentInform) {
                Write-Item "${ip}: currently on $currentHost -- needs migration to $targetHost"
            } else {
                Write-Item "${ip}: no inform URL detected -- setting to $targetHost"
            }

            $si1 = Send-SetInform -Stream $stream -InformUrl $informUrl -Attempt 1
            $row.Inform1 = $si1.Output
            if ($si1.Method) { $row.InformMethod = $si1.Method }

            Start-Sleep -Seconds 3

            $si2 = Send-SetInform -Stream $stream -InformUrl $informUrl -Attempt 2
            $row.Inform2 = $si2.Output
            if ($si2.Method -and -not $row.InformMethod) { $row.InformMethod = $si2.Method }

            # -- Post-verify: poll the device's info output with backoff.
            # Replaces the old single 3s check. Some firmware (seen on
            # UAP-AC-Pro-Gen2 at v6.6.77) needs 10-20s before `info` output
            # reflects the new inform URL locally. Polling catches those
            # without slowing down the fast ones -- breaks as soon as the
            # URL flips.
            $pv = Wait-InformVerified -Stream $stream -SessionId $sess.SessionId `
                                       -Timeout ($SshTimeout * 2) `
                                       -TargetHost $targetHost -ControllerName $Controller -Ip $ip
            $postInform = $pv.PostInform
            $postHost   = $pv.PostHost
            $verified   = $pv.Verified

            if ($verified) {
                $row.Status = "OK"; $countOk++
                $methodNote = if ($row.InformMethod) { "($($row.InformMethod))" } else { "" }
                $attemptNote = if ($pv.Attempts -gt 1) { " [verified on poll $($pv.Attempts)]" } else { "" }
                Write-DeviceLine $ip $devInfo.Model "OK" "verified on $postHost $methodNote$attemptNote"

                # Name restore is batched after the loop (see "Restore Names"):
                # a just-informed device needs time to appear on the controller,
                # and after a reset it is pending adoption until adopted.
                if ($modeStr -eq "Adopt" -and $RestoreNames -and $row.DevHostname -and $row.MAC) {
                    $renameQueue += @{ Mac = $row.MAC; Name = $row.DevHostname; Model = $row.Model; Ip = $ip; Explicit = $false }
                }
            } elseif ($si1.Success -or $si2.Success) {
                $row.Status = "CHECK"; $countCheck++
                $row.Note = ($row.Note + "; set-inform accepted but verify shows $postHost instead of $targetHost").Trim('; ')
                Write-DeviceLine $ip $devInfo.Model "CHECK" "set-inform accepted but still on $postHost"
            } else {
                $row.Status = "FAIL"; $countFail++
                $row.Note = ($row.Note + "; set-inform failed, still on $postHost").Trim('; ')
                Write-DeviceLine $ip $devInfo.Model "FAIL" "set-inform rejected, still on $postHost"
            }
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

# -- Restore names (batched) --
if ($renameQueue.Count -gt 0) {
    Write-Rule "Restore Names"
    if (-not ($ApiKey -or $ApiUser)) {
        Write-Warn "-RestoreNames needs -ApiKey or -ApiUser/-ApiPass -- skipped. Rerun later with -Mode Rename -InCsv <this run's CSV>."
    } else {
        $ctx = New-ControllerContext -Host_ $Controller -Ports $apiPorts -Key $ApiKey -User $ApiUser -Pass $ApiPass -Site $Site
        if (-not $ctx) {
            Write-Warn "Controller API login failed ($script:ControllerError) -- skipping name restore"
        } else {
            $rr = Invoke-BatchRename -Ctx $ctx -Entries $renameQueue -FindWaitSec 120 -AdoptPending:$AdoptPending -Interactive:(-not $Quiet_) -AdoptWaitSec $AdoptWait
            foreach ($r in $rr) {
                Write-RenameResult $r
                $resRow = $results | Where-Object { $_.MAC -and $_.MAC.ToLower() -eq $r.Mac } | Select-Object -First 1
                if ($resRow) { $resRow.Note = ($resRow.Note + "; name: $($r.Result) $($r.Detail)").Trim('; ') }
            }
        }
    }
}

# -- Results --
Write-Rule "Results"

$totalProcessed = $countOk + $countCheck + $countFail
$cardWidth = 36

Write-C "  +$("-" * $cardWidth)+" "DarkYellow"
Write-C "  |" "DarkYellow" -NoNewline; Write-C "  Scanned          " "DarkGray" -NoNewline; Write-C "$($total)".PadRight($cardWidth - 20) "Cyan" -NoNewline; Write-C "|" "DarkYellow"
Write-C "  |" "DarkYellow" -NoNewline; Write-C "  SSH accessible   " "DarkGray" -NoNewline; Write-C "$($totalProcessed)".PadRight($cardWidth - 20) "White" -NoNewline; Write-C "|" "DarkYellow"
Write-C "  |" "DarkYellow" -NoNewline; Write-C "  Successful       " "DarkGray" -NoNewline; Write-C "$($countOk)".PadRight($cardWidth - 20) "Green" -NoNewline; Write-C "|" "DarkYellow"
if ($countCheck -gt 0) {
    Write-C "  |" "DarkYellow" -NoNewline; Write-C "  Needs attention  " "DarkGray" -NoNewline; Write-C "$($countCheck)".PadRight($cardWidth - 20) "Yellow" -NoNewline; Write-C "|" "DarkYellow"
}
if ($countFail -gt 0) {
    Write-C "  |" "DarkYellow" -NoNewline; Write-C "  Failed           " "DarkGray" -NoNewline; Write-C "$($countFail)".PadRight($cardWidth - 20) "Red" -NoNewline; Write-C "|" "DarkYellow"
}
foreach ($sk in @(@("  Skipped (class)  ", $countSkipClass), @("  Skipped (adopted)", $countSkipAdopted), @("  Skipped (MAC)    ", $countSkipMac))) {
    if ($sk[1] -gt 0) {
        Write-C "  |" "DarkYellow" -NoNewline; Write-C $sk[0] "DarkGray" -NoNewline; Write-C "$($sk[1])".PadRight($cardWidth - 20) "DarkGray" -NoNewline; Write-C "|" "DarkYellow"
    }
}
$notConnected = $total - ($results | Where-Object { $_.Connected }).Count
if ($notConnected -gt 0) {
    Write-C "  |" "DarkYellow" -NoNewline; Write-C "  No SSH session   " "DarkGray" -NoNewline; Write-C "$notConnected".PadRight($cardWidth - 20) "Yellow" -NoNewline; Write-C "|" "DarkYellow"
}
Write-C "  +$("-" * $cardWidth)+" "DarkYellow"
Write-C "  |" "DarkYellow" -NoNewline; Write-C "  Output  " "DarkGray" -NoNewline
$csvDisplay = $OutCsv
if ($csvDisplay.Length -gt ($cardWidth - 11)) { $csvDisplay = "..." + $csvDisplay.Substring($csvDisplay.Length - ($cardWidth - 14)) }
Write-C $csvDisplay.PadRight($cardWidth - 10) "DarkYellow" -NoNewline; Write-C "|" "DarkYellow"
Write-C "  +$("-" * $cardWidth)+" "DarkYellow"

# Export CSV with metadata header
try {
    $metaLine = "# UniFi Sovereign v$($script:ScriptVersion) | Mode: $($modeStr.ToUpper()) | Targets: $total | Date: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
    Set-Content -Path $OutCsv -Value $metaLine -ErrorAction Stop
    $results | Sort-Object { [version]$_.IP } | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 0 | Add-Content -Path $OutCsv
} catch {
    $fallback = Get-DefaultCsvPath $modeStr
    Write-Warn "Cannot write to '$OutCsv' -- trying '$fallback'"
    try {
        Set-Content -Path $fallback -Value $metaLine
        $results | Sort-Object { [version]$_.IP } | ConvertTo-Csv -NoTypeInformation | Add-Content -Path $fallback
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
