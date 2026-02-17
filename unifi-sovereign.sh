#!/usr/bin/env bash

#
# UniFi Sovereign v3.1.0
# SSH-based device migration & adoption toolkit
# macOS / Linux (Bash 3.2+)
#
# Usage: ./unifi-sovereign.sh [OPTIONS]
#        ./unifi-sovereign.sh --help
#

set -uo pipefail

SCRIPT_VERSION="3.2.0"

# Bash 3.2 compat: BASH_SOURCE may be empty when piped via bash <(curl ...)
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR="$(pwd)"
fi

# ===================================================================
# GLOBAL STATE
# ===================================================================

MODE=""
CIDR=""
IPS_ARG=""
CONTROLLER=""
USERNAME="ubnt"
PASSWORD=""
RESET_FIRST=0
SSH_TIMEOUT=7
SCAN_TIMEOUT=3
OUT_CSV=""
DRY_RUN=0
VERBOSE=0
QUIET=0
NO_COLOR=0
DEPS_CHECKED=0

# ===================================================================
# PALETTE
#
# Deep navy base, surgical red accent, muted gold secondary.
# True-color (24-bit) ANSI with automatic 16-color fallback.
# ===================================================================

_supports_truecolor() {
  case "${COLORTERM:-}" in
    truecolor|24bit) return 0 ;;
  esac
  case "${TERM:-}" in
    *-256color|*-direct) return 0 ;;
  esac
  return 1
}

_setup_colors() {
  if [ "$NO_COLOR" -eq 1 ] || [ ! -t 1 ]; then
    C_RED="" C_GRN="" C_GLD="" C_CYN="" C_DIM="" C_MUT=""
    C_WRN="" C_INF="" C_TXT="" C_BRD=""
    C_BLD="" C_UND="" C_BG1="" C_BG2="" RST=""
    return
  fi

  RST='\033[0m'
  C_BLD='\033[1m'
  C_UND='\033[4m'
  C_DIM='\033[2m'

  if _supports_truecolor; then
    # True-color palette from design tokens
    C_RED='\033[38;2;146;20;12m'       # --c-accent    #92140c  surgical red
    C_GRN='\033[38;2;47;157;110m'      # --c-success   #2f9d6e
    C_GLD='\033[38;2;222;203;183m'     # --c-accent-2  #decbb7  muted gold
    C_CYN='\033[38;2;71;183;216m'      # --c-accent-3  #47b7d8  cool accent
    C_MUT='\033[38;2;122;134;154m'     # --c-text-mute #7a869a
    C_WRN='\033[38;2;215;177;87m'      # --c-warning   #d7b157
    C_INF='\033[38;2;47;111;161m'      # --c-info      #2f6fa1
    C_TXT='\033[38;2;247;240;245m'     # --c-text      #f7f0f5
    C_DIM='\033[38;2;143;161;179m'     # --c-text-dim  #8fa1b3
    C_BRD='\033[38;2;222;203;183m'     # --c-border    gold at 30% (rendered full for lines)
    C_BG1='\033[48;2;10;38;75m'        # --c-bg-1      #0a264b
    C_BG2='\033[48;2;15;52;95m'        # --c-bg-2      #0f345f
  else
    # 16-color fallback
    C_RED='\033[0;31m'
    C_GRN='\033[0;32m'
    C_GLD='\033[0;33m'
    C_CYN='\033[0;36m'
    C_MUT='\033[0;37m'
    C_WRN='\033[1;33m'
    C_INF='\033[0;34m'
    C_TXT='\033[0;37m'
    C_BRD='\033[0;33m'
    C_BG1=""
    C_BG2=""
  fi
}

# ===================================================================
# OUTPUT PRIMITIVES
# ===================================================================

# Horizontal rule with optional label — threshold style
_rule() {
  local label="${1:-}"
  local width=52
  echo ""
  if [ -n "$label" ]; then
    local pad=$(( width - ${#label} - 5 ))
    [ "$pad" -lt 2 ] && pad=2
    printf "  ${C_GLD}──${RST} ${C_TXT}${C_BLD}%s${RST} ${C_GLD}" "$label"
    local i=0; while [ "$i" -lt "$pad" ]; do printf '─'; i=$((i+1)); done
    printf "${RST}\n"
  else
    printf "  ${C_GLD}"
    local i=0; while [ "$i" -lt "$width" ]; do printf '─'; i=$((i+1)); done
    printf "${RST}\n"
  fi
  echo ""
}

# Banner — three descending triangles, each in an accent color
_banner() {
  echo ""
  echo -e "  ${C_CYN}      ▄████████████████████████▄${RST}"
  echo -e "  ${C_CYN}       ▀██████████████████████▀${RST}        ${C_TXT}${C_BLD}UNIFI SOVEREIGN${RST}"
  echo -e "  ${C_CYN}          ▀▀██████████████▀▀${RST}           ${C_GLD}━━━━━━━━━━━━━━━${RST}"
  echo -e "  ${C_GLD}        ▄██████████████████████▄${RST}       ${C_DIM}v${SCRIPT_VERSION}${RST}"
  echo -e "  ${C_GLD}         ▀██████████████████▀${RST}"
  echo -e "  ${C_GLD}            ▀▀██████████▀▀${RST}             ${C_DIM}SSH Device Migration${RST}"
  echo -e "  ${C_RED}          ▄████████████████████▄${RST}       ${C_DIM}& Adoption${RST}"
  echo -e "  ${C_RED}           ▀████████████████▀${RST}"
  echo -e "  ${C_RED}              ▀▀████████▀▀${RST}"
  echo ""
}

# Status indicators — semantic colors
_info()  { echo -e "  ${C_CYN}●${RST} $*"; }
_ok()    { echo -e "  ${C_GRN}●${RST} $*"; }
_warn()  { echo -e "  ${C_WRN}●${RST} $*"; }
_fail()  { echo -e "  ${C_RED}●${RST} $*"; }
_opt()   { echo -e "  ${C_MUT}○${RST} $*"; }
_item()  { echo -e "  ${C_GLD}▸${RST} $*"; }
_debug() { [ "$VERBOSE" -eq 1 ] && echo -e "  ${C_DIM}  ⌁ $*${RST}"; }

# Progress bar — gold fill, muted empty
_progress_bar() {
  local current="$1"
  local total="$2"
  local label="${3:-}"
  local width=24

  local pct=0
  [ "$total" -gt 0 ] && pct=$(( current * 100 / total ))
  local filled=$(( pct * width / 100 ))
  local empty=$(( width - filled ))

  local bar=""
  local i=0
  while [ "$i" -lt "$filled" ]; do bar="${bar}━"; i=$((i+1)); done
  i=0
  while [ "$i" -lt "$empty" ]; do bar="${bar}╌"; i=$((i+1)); done

  printf "\r  ${C_DIM}%s${RST}${C_GLD}%s${RST}${C_MUT}%s${RST}  ${C_DIM}%3d%%${RST}  ${C_MUT}%d/%d${RST}  " \
    "$label" \
    "$(echo "$bar" | head -c $((filled * 3)))" \
    "$(echo "$bar" | tail -c +$((filled * 3 + 1)))" \
    "$pct" "$current" "$total"
}

# Actually, the above head/tail trick won't work on multibyte chars. Rewrite:
_progress_bar() {
  local current="$1"
  local total="$2"
  local label="${3:-}"
  local width=24

  local pct=0
  [ "$total" -gt 0 ] && pct=$(( current * 100 / total ))
  local filled=$(( pct * width / 100 ))
  local empty=$(( width - filled ))

  printf "\r  ${C_DIM}%s${RST}${C_GLD}" "$label"
  local i=0; while [ "$i" -lt "$filled" ]; do printf '━'; i=$((i+1)); done
  printf "${RST}${C_MUT}"
  i=0; while [ "$i" -lt "$empty" ]; do printf '╌'; i=$((i+1)); done
  printf "${RST}  ${C_DIM}%3d%%  %d/%d${RST}  " "$pct" "$current" "$total"
}

# Summary box — quiet card style
_summary_box() {
  local width=44
  echo -e "  ${C_GLD}┌$(printf '%0.s─' $(seq 1 $width))┐${RST}"
  while [ $# -gt 0 ]; do
    local line="$1"; shift
    local stripped
    stripped=$(echo -e "$line" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#stripped}
    local pad=$(( width - len - 1 ))
    [ "$pad" -lt 0 ] && pad=0
    printf "  ${C_GLD}│${RST} %b" "$line"
    printf '%*s' "$pad" ""
    printf "${C_GLD}│${RST}\n"
  done
  echo -e "  ${C_GLD}└$(printf '%0.s─' $(seq 1 $width))┘${RST}"
}

# ===================================================================
# PLATFORM DETECTION
# ===================================================================

_detect_os() {
  local uname_s
  uname_s="$(uname -s)"
  case "$uname_s" in
    Darwin) echo "macos" ;;
    Linux)  echo "linux" ;;
    *)      echo "unknown" ;;
  esac
}

_detect_pkg_manager() {
  if command -v apt-get &>/dev/null; then echo "apt"
  elif command -v dnf &>/dev/null; then echo "dnf"
  elif command -v pacman &>/dev/null; then echo "pacman"
  elif command -v apk &>/dev/null; then echo "apk"
  else echo "unknown"
  fi
}

_has() { command -v "$1" &>/dev/null; }

# ===================================================================
# PREREQUISITE ENGINE
# ===================================================================

_install_homebrew() {
  echo ""
  _info "Homebrew is the standard package manager for macOS."
  _info "Required to install dependencies (sshpass, fzf, etc.)."
  echo ""
  local answer
  answer=$(_yes_no "Install Homebrew?" "y")
  if [ "$answer" = "Y" ]; then
    _info "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if _has brew; then
      _ok "Homebrew installed"
    else
      if [ -f /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
      elif [ -f /usr/local/bin/brew ]; then
        eval "$(/usr/local/bin/brew shellenv)"
      fi
      if _has brew; then
        _ok "Homebrew installed"
      else
        _fail "Homebrew installation may have failed. Check manually."
        return 1
      fi
    fi
  else
    _warn "Skipping Homebrew. Some dependencies may require manual installation."
    return 1
  fi
}

_install_pkg() {
  local pkg="$1" os="$2" mgr="$3"
  case "$os" in
    macos)
      if _has brew; then
        _info "Installing ${C_BLD}${pkg}${RST} via Homebrew..."
        brew install "$pkg" 2>/dev/null
      else
        _warn "Cannot install ${pkg}: Homebrew not available"
        return 1
      fi
      ;;
    linux)
      case "$mgr" in
        apt)    _info "Installing ${C_BLD}${pkg}${RST}..."; sudo apt-get install -y "$pkg" 2>/dev/null ;;
        dnf)    _info "Installing ${C_BLD}${pkg}${RST}..."; sudo dnf install -y "$pkg" 2>/dev/null ;;
        pacman) _info "Installing ${C_BLD}${pkg}${RST}..."; sudo pacman -S --noconfirm "$pkg" 2>/dev/null ;;
        apk)    _info "Installing ${C_BLD}${pkg}${RST}..."; sudo apk add "$pkg" 2>/dev/null ;;
        *)      _warn "Unknown package manager. Install ${pkg} manually."; return 1 ;;
      esac
      ;;
  esac
}

_pkg_name() {
  local tool="$1" os="$2" mgr="$3"
  case "$tool" in
    ssh)
      case "$mgr" in
        apt)    echo "openssh-client" ;;
        dnf)    echo "openssh-clients" ;;
        pacman) echo "openssh" ;;
        apk)    echo "openssh-client" ;;
        *)      echo "openssh" ;;
      esac
      ;;
    sshpass) echo "sshpass" ;;
    python3)
      case "$mgr" in
        pacman) echo "python" ;;
        *)      echo "python3" ;;
      esac
      ;;
    fzf)    echo "fzf" ;;
    expect) echo "expect" ;;
    *)      echo "$tool" ;;
  esac
}

check_prerequisites() {
  [ "$DEPS_CHECKED" -eq 1 ] && return 0
  DEPS_CHECKED=1

  local os mgr
  os="$(_detect_os)"
  mgr=""
  [ "$os" = "linux" ] && mgr="$(_detect_pkg_manager)"
  [ "$os" = "macos" ] && mgr="brew"

  _rule "Prerequisites"
  _info "Platform: ${C_BLD}${os}${RST}$([ -n "$mgr" ] && echo " ${C_DIM}($mgr)${RST}")"
  echo ""

  if [ "$os" = "macos" ] && ! _has brew; then
    _warn "Homebrew not found"
    _install_homebrew || true
    echo ""
  fi

  local required_tools="ssh sshpass grep awk sed python3"
  local optional_tools="fzf expect"
  local missing_required=""
  local missing_optional=""

  for tool in $required_tools; do
    local dots=""
    local name_len=${#tool}
    local dot_count=$((22 - name_len))
    local d=0; while [ "$d" -lt "$dot_count" ]; do dots="${dots}·"; d=$((d+1)); done
    if _has "$tool"; then
      echo -e "  ${C_GRN}●${RST} ${C_CYN}${tool}${RST} ${C_MUT}${dots}${RST} ${C_GRN}installed${RST}"
    else
      echo -e "  ${C_RED}●${RST} ${C_CYN}${tool}${RST} ${C_MUT}${dots}${RST} ${C_RED}missing${RST}"
      missing_required="${missing_required} ${tool}"
    fi
  done

  echo ""

  for tool in $optional_tools; do
    local dots=""
    local name_len=${#tool}
    local dot_count=$((22 - name_len))
    local d=0; while [ "$d" -lt "$dot_count" ]; do dots="${dots}·"; d=$((d+1)); done
    if _has "$tool"; then
      echo -e "  ${C_GRN}●${RST} ${C_GLD}${tool}${RST} ${C_MUT}${dots}${RST} ${C_GRN}installed${RST}"
    else
      echo -e "  ${C_MUT}○${RST} ${C_GLD}${tool}${RST} ${C_MUT}${dots} not found ${C_DIM}(optional)${RST}"
      missing_optional="${missing_optional} ${tool}"
    fi
  done

  if [ -n "$missing_required" ]; then
    echo ""
    _warn "Missing required:${C_RED}${missing_required}${RST}"
    local answer
    answer=$(_yes_no "Install missing dependencies?" "y")
    if [ "$answer" = "Y" ]; then
      for tool in $missing_required; do
        local pkg
        pkg="$(_pkg_name "$tool" "$os" "$mgr")"
        _install_pkg "$pkg" "$os" "$mgr"
      done
      for tool in $missing_required; do
        if ! _has "$tool"; then
          _fail "${tool} still not available after install attempt."
          _fail "Install it manually and re-run."
          exit 1
        fi
      done
      _ok "All required dependencies installed"
    else
      _fail "Cannot continue without required dependencies."
      exit 1
    fi
  fi

  if [ -n "$missing_optional" ]; then
    echo ""
    local answer
    answer=$(_yes_no "Install optional dependencies?${missing_optional}" "n")
    if [ "$answer" = "Y" ]; then
      for tool in $missing_optional; do
        local pkg
        pkg="$(_pkg_name "$tool" "$os" "$mgr")"
        _install_pkg "$pkg" "$os" "$mgr" || true
      done
    fi
  fi

  echo ""
  _ok "Ready"
}

# ===================================================================
# INTERACTIVE PROMPTS
# ===================================================================

_menu() {
  local prompt="$1"
  shift
  local options=("$@")

  if _has fzf; then
    local selected
    selected=$(printf '%s\n' "${options[@]}" | fzf \
      --height=40% \
      --border=rounded \
      --prompt="  ${prompt} " \
      --no-preview \
      --color='bg+:#0f345f,fg:#8fa1b3,fg+:#f7f0f5,hl:#92140c,hl+:#decbb7,pointer:#92140c,marker:#2f9d6e,spinner:#47b7d8,header:#47b7d8,border:#decbb7,prompt:#decbb7,info:#7a869a')
    echo "$selected"
    return 0
  fi

  echo ""
  echo -e "  ${C_TXT}${C_BLD}${prompt}${RST}"
  echo ""
  local i=0
  for opt in "${options[@]}"; do
    i=$((i + 1))
    echo -e "    ${C_GLD}[${i}]${RST} ${opt}"
  done
  echo ""

  local choice
  read -r -p "    Choice [1]: " choice
  choice="${choice:-1}"

  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
    echo "${options[$((choice - 1))]}"
  else
    _fail "Invalid choice"
    _menu "$prompt" "${options[@]}"
  fi
}

_input() {
  local prompt="$1"
  local default="${2:-}"
  local input

  if [ -n "$default" ]; then
    read -r -p "    ${prompt} [${default}]: " input
    echo "${input:-$default}"
  else
    while true; do
      read -r -p "    ${prompt}: " input
      if [ -n "$input" ]; then
        echo "$input"
        return
      fi
      _warn "Cannot be blank"
    done
  fi
}

_password() {
  local prompt="$1"
  local pass
  read -r -s -p "    ${prompt}: " pass
  echo ""
  echo "$pass"
}

_yes_no() {
  local prompt="$1"
  local default="${2:-n}"
  local input
  read -r -p "    ${prompt} [${default}]: " input
  input="${input:-$default}"
  case "$input" in
    [Yy]*) echo "Y" ;;
    *)     echo "N" ;;
  esac
}

# ===================================================================
# CIDR EXPANSION
# ===================================================================

cidr_to_ips() {
  local cidr="$1"
  python3 -c "
import ipaddress, sys
try:
    net = ipaddress.ip_network('${cidr}', strict=False)
    for ip in net.hosts():
        print(str(ip))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

# ===================================================================
# SSH FUNCTIONS
# ===================================================================

_ssh_exec() {
  local ip="$1" user="$2" pass="$3" cmd="$4" tout="${5:-7}"
  if [ -n "$pass" ]; then
    timeout "$tout" sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      -o BatchMode=no \
      "$user@$ip" "$cmd" 2>/dev/null || true
  else
    timeout "$tout" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      "$user@$ip" "$cmd" 2>/dev/null || true
  fi
}

_ssh_shell() {
  local ip="$1" user="$2" pass="$3" cmd="$4" tout="${5:-14}"
  if _has expect; then
    expect -c "
      log_user 0
      set timeout $tout
      spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $user@$ip
      expect {
        \"*assword*\" { send \"$pass\r\"; exp_continue }
        \"*#*\" { }
        timeout { exit 1 }
      }
      send \"$cmd\r\"
      expect \"*#*\"
      set output \$expect_out(buffer)
      send \"exit\r\"
      expect eof
      puts \$output
    " 2>/dev/null || true
  else
    echo "$cmd" | timeout "$tout" sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      -tt "$user@$ip" 2>/dev/null || true
  fi
}

_test_ssh() {
  local ip="$1" user="$2" pass="$3" tout="${4:-7}"
  local result
  result=$(_ssh_exec "$ip" "$user" "$pass" "echo __ALIVE__" "$tout")
  case "$result" in
    *__ALIVE__*) return 0 ;;
    *)           return 1 ;;
  esac
}

_get_device_info() {
  local ip="$1" user="$2" pass="$3" tout="${4:-14}"
  local output

  output=$(_ssh_shell "$ip" "$user" "$pass" "info" "$tout")
  if [ -z "$output" ]; then
    output=$(_ssh_exec "$ip" "$user" "$pass" "info" "$tout")
  fi

  local model firmware hostname mac status inform_url
  model=$(echo "$output" | grep -i '^Model:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//' | cut -c1-30)
  firmware=$(echo "$output" | grep -i '^Version:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')
  hostname=$(echo "$output" | grep -i '^Hostname:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')
  mac=$(echo "$output" | grep -ioE '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}' | head -1)
  status=$(echo "$output" | grep -i '^Status:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')
  inform_url=$(echo "$output" | grep -i 'Inform.*URL' | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*$//')

  if [ -z "$mac" ]; then
    mac=$(_ssh_exec "$ip" "$user" "$pass" "cat /sys/class/net/eth0/address 2>/dev/null || cat /sys/class/net/br0/address 2>/dev/null" "$tout" | grep -ioE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
  fi

  local tmpfile="${TMPDIR:-/tmp}/usov_info_$$"
  cat > "$tmpfile" <<DEVEOF
MODEL=${model:-}
FIRMWARE=${firmware:-}
HOSTNAME=${hostname:-}
MAC=${mac:-}
STATUS=${status:-}
INFORM_URL=${inform_url:-}
DEVEOF
  echo "RAW_OUTPUT<<RAWEOF" >> "$tmpfile"
  echo "$output" | tr -cd '[:print:]\n' | head -50 >> "$tmpfile"
  echo "RAWEOF" >> "$tmpfile"
  echo "$tmpfile"
}

_read_info_field() {
  local file="$1" field="$2"
  grep "^${field}=" "$file" 2>/dev/null | head -1 | sed "s/^${field}=//"
}

_read_info_raw() {
  local file="$1"
  sed -n '/^RAW_OUTPUT<<RAWEOF$/,/^RAWEOF$/p' "$file" 2>/dev/null | sed '1d;$d'
}

_send_set_inform() {
  local ip="$1" user="$2" pass="$3" url="$4" tout="${5:-14}"
  local output1 output2

  output1=$(_ssh_shell "$ip" "$user" "$pass" "set-inform $url" "$tout")
  _debug "set-inform → $output1"

  if echo "$output1" | grep -iqE 'adoption|inform|request|accepted'; then
    echo "METHOD=set-inform"; echo "SUCCESS=1"; echo "OUTPUT=$output1"
    return 0
  fi

  output2=$(_ssh_shell "$ip" "$user" "$pass" "mca-cli-op set-inform $url" "$tout")
  _debug "mca-cli-op → $output2"

  if echo "$output2" | grep -iqE 'adoption|inform|request|accepted'; then
    echo "METHOD=mca-cli-op"; echo "SUCCESS=1"; echo "OUTPUT=$output2"
    return 0
  fi

  local combined="${output1} ${output2}"
  if ! echo "$combined" | grep -iqE 'not found|unknown command|error|denied|invalid'; then
    echo "METHOD=set-inform+mca-cli-op"; echo "SUCCESS=1"; echo "OUTPUT=$combined"
    return 0
  fi

  echo "METHOD=none"; echo "SUCCESS=0"; echo "OUTPUT=$combined"
  return 1
}

_send_factory_reset() {
  local ip="$1" user="$2" pass="$3" tout="${4:-14}"
  _debug "Factory reset on $ip"

  _ssh_shell "$ip" "$user" "$pass" "cp /etc/default.cfg /tmp/system.cfg && cfgmtd -w -p /etc/ && reboot" "$tout" >/dev/null 2>&1
  if [ $? -eq 0 ]; then echo "METHOD=cfgmtd"; return 0; fi

  _ssh_shell "$ip" "$user" "$pass" "syswrapper.sh restore-default" "$tout" >/dev/null 2>&1
  if [ $? -eq 0 ]; then echo "METHOD=syswrapper"; return 0; fi

  _ssh_shell "$ip" "$user" "$pass" "set-default" "$tout" >/dev/null 2>&1
  if [ $? -eq 0 ]; then echo "METHOD=set-default"; return 0; fi

  echo "METHOD=none"
  return 1
}

# ===================================================================
# PORT SCANNING
# ===================================================================

_port_scan() {
  local ips=("$@")
  local total=${#ips[@]}
  local current=0
  local found=()

  _rule "Scan"
  _info "Sweeping ${C_BLD}${total}${RST} hosts for SSH (TCP/22)"
  echo ""

  for ip in "${ips[@]}"; do
    current=$((current + 1))
    _progress_bar "$current" "$total" ""

    if timeout "$SCAN_TIMEOUT" bash -c "cat < /dev/null > /dev/tcp/$ip/22" 2>/dev/null; then
      found+=("$ip")
    fi
  done

  printf "\r%80s\r" ""  # clear progress line
  echo ""

  if [ ${#found[@]} -eq 0 ]; then
    _fail "No hosts with SSH open"
    exit 1
  fi

  _ok "${C_BLD}${#found[@]}${RST} hosts responding"

  printf '%s\n' "${found[@]}"
}

# ===================================================================
# CSV OUTPUT
# ===================================================================

_csv_init() {
  local outfile="$1" mode="$2" target_count="$3"
  cat > "$outfile" <<CSVHDR
# UniFi Sovereign v${SCRIPT_VERSION} | Mode: ${mode} | Targets: ${target_count} | Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Timestamp,IP,MAC,Connected,Username,Model,DevHostname,Firmware,AdoptStatus,CurrentInform,Reset,Inform1,Inform2,InformMethod,Status,Note,DebugInfo
CSVHDR
}

_csv_escape() {
  local val="$1"
  val="${val//\"/\"\"}"
  echo "\"$val\""
}

_csv_row() {
  local outfile="$1"
  local timestamp="$2" ip="$3" mac="$4" connected="$5" username="$6"
  local model="$7" devhostname="$8" firmware="$9"
  shift 9
  local adopt_status="$1" current_inform="$2" reset="$3"
  local inform1="$4" inform2="$5" inform_method="$6"
  local status="$7" note="$8" debug_info="$9"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(_csv_escape "$timestamp")" \
    "$(_csv_escape "$ip")" \
    "$(_csv_escape "$mac")" \
    "$connected" \
    "$(_csv_escape "$username")" \
    "$(_csv_escape "$model")" \
    "$(_csv_escape "$devhostname")" \
    "$(_csv_escape "$firmware")" \
    "$(_csv_escape "$adopt_status")" \
    "$(_csv_escape "$current_inform")" \
    "$(_csv_escape "$reset")" \
    "$(_csv_escape "$inform1")" \
    "$(_csv_escape "$inform2")" \
    "$(_csv_escape "$inform_method")" \
    "$status" \
    "$(_csv_escape "$note")" \
    "$(_csv_escape "$debug_info")" \
    >> "$outfile"
}

# ===================================================================
# DEVICE RESULT LINE
# ===================================================================

_device_line() {
  local ip="$1" model="$2" status="$3" detail="$4"
  local col_ip col_model col_status

  # Pad IP to 16 chars
  col_ip=$(printf '%-16s' "$ip")

  # Model or placeholder
  if [ -n "$model" ]; then
    col_model=$(printf '%-14s' "$model")
  else
    col_model=$(printf '%-14s' "—")
  fi

  case "$status" in
    OK)    col_status="${C_GRN}  OK  ${RST}" ;;
    CHECK) col_status="${C_WRN}CHECK ${RST}" ;;
    FAIL)  col_status="${C_RED} FAIL ${RST}" ;;
    *)     col_status="${C_MUT} ---  ${RST}" ;;
  esac

  echo -e "  ${C_GLD}▸${RST} ${C_TXT}${col_ip}${RST}${C_DIM}${col_model}${RST}${col_status}${C_DIM}${detail}${RST}"
}

# ===================================================================
# MAIN
# ===================================================================

main() {
  _setup_colors
  _banner

  if [ "$DRY_RUN" -eq 1 ]; then
    _warn "DRY RUN — no changes will be made"
    echo ""
  fi

  check_prerequisites

  # ── Mode ──
  if [ -z "$MODE" ]; then
    MODE=$(_menu "Operation mode:" \
      "SANITY   — verify SSH access, collect device info (read-only)" \
      "MIGRATE  — re-point devices to a new controller (no reset)" \
      "ADOPT    — full adoption with optional factory reset")
    MODE=$(echo "$MODE" | awk '{print $1}')
  fi
  MODE=$(echo "$MODE" | tr '[:lower:]' '[:upper:]')

  _rule "Configuration"
  _info "Mode: ${C_BLD}${MODE}${RST}"

  # ── Targets ──
  local target_ips=()

  if [ -n "$CIDR" ]; then
    while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(cidr_to_ips "$CIDR")
  elif [ -n "$IPS_ARG" ]; then
    while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(echo "$IPS_ARG" | tr ',' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
  else
    local input_type
    input_type=$(_menu "Target input:" \
      "CIDR subnet  (e.g. 192.168.1.0/24)" \
      "IP list      (comma-separated)")
    if echo "$input_type" | grep -qi "list"; then
      local ips_str
      ips_str=$(_input "IPs (comma-separated)")
      while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(echo "$ips_str" | tr ',' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    else
      CIDR=$(_input "CIDR (e.g. 192.168.1.0/24)")
      while IFS= read -r _ip; do target_ips+=("$_ip"); done < <(cidr_to_ips "$CIDR")
    fi
  fi

  if [ ${#target_ips[@]} -eq 0 ]; then
    _fail "No valid target IPs"
    exit 1
  fi
  _info "Targets: ${C_BLD}${#target_ips[@]}${RST} IPs"

  # ── Controller ──
  local controller_url=""
  if [ "$MODE" = "MIGRATE" ] || [ "$MODE" = "ADOPT" ]; then
    if [ -z "$CONTROLLER" ]; then
      CONTROLLER=$(_input "Target controller IP or hostname")
    fi
    controller_url="http://${CONTROLLER}:8080/inform"
    _info "Inform URL: ${C_DIM}${controller_url}${RST}"

    if [ "$MODE" = "ADOPT" ] && [ "$RESET_FIRST" -eq 0 ]; then
      local do_reset
      do_reset=$(_yes_no "Factory reset before adoption?" "n")
      [ "$do_reset" = "Y" ] && RESET_FIRST=1
    fi
    [ "$RESET_FIRST" -eq 1 ] && _warn "Factory reset: ${C_RED}ENABLED${RST}"
  fi

  # ── Credentials ──
  _rule "Credentials"

  local cred_users=()
  local cred_passes=()

  if [ -n "$PASSWORD" ]; then
    cred_users+=("$USERNAME")
    cred_passes+=("$PASSWORD")
  else
    local add_cred
    add_cred=$(_yes_no "Provide a known SSH credential?" "n")
    if [ "$add_cred" = "Y" ]; then
      local u p
      u=$(_input "SSH username")
      p=$(_password "SSH password")
      cred_users+=("$u")
      cred_passes+=("$p")
    fi
  fi

  cred_users+=("ubnt" "root" "admin")
  cred_passes+=("ubnt" "ubnt" "ubnt")

  _info "Credential chain: ${C_DIM}$(echo "${cred_users[@]}" | tr ' ' ' → ')${RST}"

  # ── CSV ──
  if [ -z "$OUT_CSV" ]; then
    local default_csv="unifi-$(echo "$MODE" | tr '[:upper:]' '[:lower:]')-$(date +%Y%m%d-%H%M%S).csv"
    OUT_CSV=$(_input "CSV output path" "$default_csv")
  fi

  # ── Plan ──
  _rule "Plan"
  echo -e "  ${C_GLD}▸${RST} ${C_DIM}Mode${RST}         ${C_CYN}${C_BLD}${MODE}${RST}"
  echo -e "  ${C_GLD}▸${RST} ${C_DIM}Targets${RST}      ${C_TXT}${#target_ips[@]} IPs${RST}"
  if [ -n "$controller_url" ]; then
    echo -e "  ${C_GLD}▸${RST} ${C_DIM}Controller${RST}   ${C_CYN}${CONTROLLER}${RST}"
  fi
  [ "$RESET_FIRST" -eq 1 ] && echo -e "  ${C_GLD}▸${RST} ${C_DIM}Reset${RST}        ${C_RED}${C_BLD}YES${RST}"
  echo -e "  ${C_GLD}▸${RST} ${C_DIM}SSH Timeout${RST}  ${C_TXT}${SSH_TIMEOUT}s${RST}"
  echo -e "  ${C_GLD}▸${RST} ${C_DIM}Output${RST}       ${C_GLD}${OUT_CSV}${RST}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo ""
    _warn "DRY RUN — stopping before execution"
    exit 0
  fi

  echo ""
  local confirm
  confirm=$(_yes_no "Execute?" "y")
  if [ "$confirm" != "Y" ]; then
    echo ""
    _info "Aborted."
    exit 0
  fi

  # ── Scan ──
  local open_hosts=()
  while IFS= read -r _ip; do open_hosts+=("$_ip"); done < <(_port_scan "${target_ips[@]}")

  # ── Process ──
  _rule "Processing"

  _csv_init "$OUT_CSV" "$MODE" "${#open_hosts[@]}"

  local total=${#open_hosts[@]}
  local current=0
  local count_ok=0 count_check=0 count_fail=0

  for ip in "${open_hosts[@]}"; do
    current=$((current + 1))

    local connected="false"
    local used_user="" used_pass=""

    local ci=0
    for ci_user in "${cred_users[@]}"; do
      local ci_pass="${cred_passes[$ci]}"
      if _test_ssh "$ip" "$ci_user" "$ci_pass" "$SSH_TIMEOUT"; then
        connected="true"; used_user="$ci_user"; used_pass="$ci_pass"; break
      fi
      sleep 1
      if _test_ssh "$ip" "$ci_user" "$ci_pass" "$SSH_TIMEOUT"; then
        connected="true"; used_user="$ci_user"; used_pass="$ci_pass"; break
      fi
      ci=$((ci + 1))
    done

    local r_ts r_mac r_model r_host r_fw r_adopt r_inform
    local r_reset="N/A" r_inf1="N/A" r_inf2="N/A" r_method="" r_status="FAIL" r_note="" r_debug=""
    r_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    if [ "$connected" = "false" ]; then
      r_note="SSH auth failed"
      _device_line "$ip" "" "FAIL" "SSH auth failed"
      count_fail=$((count_fail + 1))
      _csv_row "$OUT_CSV" "$r_ts" "$ip" "" "false" "" "" "" "" "" "" "$r_reset" "$r_inf1" "$r_inf2" "" "FAIL" "$r_note" ""
      continue
    fi

    local info_file
    info_file=$(_get_device_info "$ip" "$used_user" "$used_pass" "$((SSH_TIMEOUT * 2))")

    r_mac=$(_read_info_field "$info_file" "MAC")
    r_model=$(_read_info_field "$info_file" "MODEL")
    r_host=$(_read_info_field "$info_file" "HOSTNAME")
    r_fw=$(_read_info_field "$info_file" "FIRMWARE")
    r_adopt=$(_read_info_field "$info_file" "STATUS")
    r_inform=$(_read_info_field "$info_file" "INFORM_URL")
    r_debug=$(_read_info_raw "$info_file" | head -5 | tr '\n' ' ')
    rm -f "$info_file"

    # SANITY
    if [ "$MODE" = "SANITY" ]; then
      r_status="OK"
      count_ok=$((count_ok + 1))
      _device_line "$ip" "$r_model" "OK" "${r_adopt:-unknown}"
      _csv_row "$OUT_CSV" "$r_ts" "$ip" "$r_mac" "true" "$used_user" \
        "$r_model" "$r_host" "$r_fw" "$r_adopt" "$r_inform" \
        "$r_reset" "$r_inf1" "$r_inf2" "$r_method" "OK" "" "$r_debug"
      continue
    fi

    # ADOPT reset
    if [ "$MODE" = "ADOPT" ] && [ "$RESET_FIRST" -eq 1 ]; then
      local reset_out
      reset_out=$(_send_factory_reset "$ip" "$used_user" "$used_pass" "$((SSH_TIMEOUT * 2))")
      local reset_method
      reset_method=$(echo "$reset_out" | grep '^METHOD=' | sed 's/METHOD=//')
      if [ "$reset_method" != "none" ]; then
        r_reset="OK ($reset_method)"
        _debug "Reset OK: $reset_method"
        _info "${ip}: reset sent, waiting 90s..."
        sleep 90
        used_user="ubnt"; used_pass="ubnt"
        if ! _test_ssh "$ip" "$used_user" "$used_pass" "$SSH_TIMEOUT"; then
          r_reset="Sent (device not back)"
          r_note="Reset sent, device not back within 90s"
          _warn "${ip}: not back after reset"
        fi
      else
        r_reset="Failed"
        r_note="Factory reset failed"
        _warn "${ip}: reset failed"
      fi
    fi

    # MIGRATE / ADOPT: set-inform
    if [ "$MODE" = "MIGRATE" ] || [ "$MODE" = "ADOPT" ]; then
      local inform_out
      inform_out=$(_send_set_inform "$ip" "$used_user" "$used_pass" "$controller_url" "$((SSH_TIMEOUT * 2))" 2>&1) || true

      local inf_method inf_success inf_output
      inf_method=$(echo "$inform_out" | grep '^METHOD=' | sed 's/METHOD=//')
      inf_success=$(echo "$inform_out" | grep '^SUCCESS=' | sed 's/SUCCESS=//')
      inf_output=$(echo "$inform_out" | grep '^OUTPUT=' | sed 's/OUTPUT=//')

      r_inf1="$inf_output"
      r_method="$inf_method"

      local inform_out2
      inform_out2=$(_send_set_inform "$ip" "$used_user" "$used_pass" "$controller_url" "$((SSH_TIMEOUT * 2))" 2>&1) || true
      r_inf2=$(echo "$inform_out2" | grep '^OUTPUT=' | sed 's/OUTPUT=//')

      if [ "$inf_success" = "1" ]; then
        r_status="OK"
        count_ok=$((count_ok + 1))
        _device_line "$ip" "$r_model" "OK" "set-inform accepted (${inf_method})"
      else
        r_status="CHECK"
        count_check=$((count_check + 1))
        r_note="${r_note}${r_note:+; }set-inform may have failed"
        _device_line "$ip" "$r_model" "CHECK" "verify in controller"
      fi

      _csv_row "$OUT_CSV" "$r_ts" "$ip" "$r_mac" "true" "$used_user" \
        "$r_model" "$r_host" "$r_fw" "$r_adopt" "$r_inform" \
        "$r_reset" "$r_inf1" "$r_inf2" "$r_method" "$r_status" "$r_note" "$r_debug"
    fi
  done

  # ── Results ──
  _rule "Results"

  local total_processed=$((count_ok + count_check + count_fail))

  echo -e "  ${C_GLD}┌──────────────────────────────────┐${RST}"
  echo -e "  ${C_GLD}│${RST}  ${C_DIM}Scanned${RST}          ${C_CYN}${C_BLD}${total}${RST}              ${C_GLD}│${RST}"
  echo -e "  ${C_GLD}│${RST}  ${C_DIM}SSH accessible${RST}   ${C_TXT}${total_processed}${RST}              ${C_GLD}│${RST}"
  echo -e "  ${C_GLD}│${RST}  ${C_DIM}Successful${RST}       ${C_GRN}${C_BLD}${count_ok}${RST}              ${C_GLD}│${RST}"
  if [ "$count_check" -gt 0 ]; then
    echo -e "  ${C_GLD}│${RST}  ${C_DIM}Needs attention${RST}  ${C_WRN}${C_BLD}${count_check}${RST}              ${C_GLD}│${RST}"
  fi
  if [ "$count_fail" -gt 0 ]; then
    echo -e "  ${C_GLD}│${RST}  ${C_DIM}Failed${RST}           ${C_RED}${C_BLD}${count_fail}${RST}              ${C_GLD}│${RST}"
  fi
  echo -e "  ${C_GLD}├──────────────────────────────────┤${RST}"
  echo -e "  ${C_GLD}│${RST}  ${C_DIM}Output${RST}  ${C_GLD}${OUT_CSV}${RST}"
  echo -e "  ${C_GLD}└──────────────────────────────────┘${RST}"

  echo ""
  case "$MODE" in
    SANITY)  _ok "Sanity check complete." ;;
    MIGRATE) _ok "Migration complete. Devices should appear on ${C_BLD}${CONTROLLER}${RST} shortly." ;;
    ADOPT)   _ok "Adoption run complete. Check controller for pending devices." ;;
  esac
  echo ""
}

# ===================================================================
# ARGUMENT PARSING
# ===================================================================

_show_help() {
  _setup_colors
  echo ""
  echo -e "  ${C_TXT}${C_BLD}UniFi Sovereign${RST} ${C_DIM}v${SCRIPT_VERSION}${RST}"
  echo -e "  ${C_DIM}SSH Device Migration & Adoption Toolkit${RST}"
  echo ""
  echo -e "  ${C_GLD}USAGE${RST}"
  echo -e "    $(basename "$0") [OPTIONS]"
  echo ""
  echo -e "  ${C_GLD}OPTIONS${RST}"
  echo -e "    --mode MODE          ${C_DIM}SANITY | MIGRATE | ADOPT${RST}"
  echo -e "    --cidr SUBNET        ${C_DIM}Target subnet (e.g. 192.168.1.0/24)${RST}"
  echo -e "    --ips IP1,IP2,...    ${C_DIM}Comma-separated IP list${RST}"
  echo -e "    --controller IP      ${C_DIM}Target controller IP/hostname${RST}"
  echo -e "    --username USER      ${C_DIM}SSH username (default: ubnt)${RST}"
  echo -e "    --password PASS      ${C_DIM}SSH password${RST}"
  echo -e "    --reset              ${C_DIM}Factory reset before adoption${RST}"
  echo -e "    --ssh-timeout SEC    ${C_DIM}SSH timeout (default: 7)${RST}"
  echo -e "    --scan-timeout SEC   ${C_DIM}Port scan timeout (default: 3)${RST}"
  echo -e "    --output FILE        ${C_DIM}CSV output path${RST}"
  echo -e "    --dry-run            ${C_DIM}Plan without executing${RST}"
  echo -e "    --verbose, -v        ${C_DIM}Debug output${RST}"
  echo -e "    --quiet, -q          ${C_DIM}Minimal output${RST}"
  echo -e "    --no-color           ${C_DIM}Disable colors${RST}"
  echo -e "    --version            ${C_DIM}Print version${RST}"
  echo -e "    --help, -h           ${C_DIM}This help${RST}"
  echo ""
  echo -e "  ${C_GLD}EXAMPLES${RST}"
  echo -e "    ${C_DIM}# Interactive${RST}"
  echo -e "    $(basename "$0")"
  echo ""
  echo -e "    ${C_DIM}# Migrate a subnet${RST}"
  echo -e "    $(basename "$0") --mode MIGRATE --cidr 192.168.1.0/24 --controller 10.0.0.5"
  echo ""
  echo -e "    ${C_DIM}# Dry run${RST}"
  echo -e "    $(basename "$0") --mode SANITY --cidr 10.0.1.0/24 --dry-run"
  echo ""
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode)        MODE="$2"; shift 2 ;;
    --cidr)        CIDR="$2"; shift 2 ;;
    --ips)         IPS_ARG="$2"; shift 2 ;;
    --controller)  CONTROLLER="$2"; shift 2 ;;
    --username)    USERNAME="$2"; shift 2 ;;
    --password)    PASSWORD="$2"; shift 2 ;;
    --reset)       RESET_FIRST=1; shift ;;
    --ssh-timeout) SSH_TIMEOUT="$2"; shift 2 ;;
    --scan-timeout) SCAN_TIMEOUT="$2"; shift 2 ;;
    --output)      OUT_CSV="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --verbose|-v)  VERBOSE=1; shift ;;
    --quiet|-q)    QUIET=1; shift ;;
    --no-color)    NO_COLOR=1; shift ;;
    --version)     echo "UniFi Sovereign v${SCRIPT_VERSION}"; exit 0 ;;
    --help|-h)     _show_help; exit 0 ;;
    *)             echo "Unknown option: $1"; echo "Try --help"; exit 1 ;;
  esac
done

main
